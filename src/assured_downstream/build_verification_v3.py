from __future__ import annotations

import collections
import hashlib
import hmac
import json
import math
import os
import re
import stat
import tempfile
import unicodedata
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from assured_downstream import archive_validation_v3
from assured_downstream.archive_validation_v3 import (
    ArchiveValidationError,
    validate_artifact_transforms as validate_archive_transforms,
)
from assured_downstream.build_verification_trust_v3 import (
    TRUSTED_ARCHIVE_VALIDATOR_IMPORT,
    TRUSTED_ARCHIVE_VALIDATOR_MODULE,
    TRUSTED_BUILD_VERIFIER_IMPORT,
    TRUSTED_BUILD_VERIFIER_MODULE,
    BuildVerificationTrustError,
    require_trusted_build_v3_policy,
    require_trusted_build_v3_sources,
)
from assured_downstream.command_runner import CommandRunner, display_command
from assured_downstream.release_verification import (
    GITHUB_ACTIONS_OIDC_ISSUER,
    GITHUB_WORKFLOW_BUILD_TYPE,
    MAX_EXECUTABLE_BYTES,
    MAX_JSON_BYTES,
    SLSA_PROVENANCE_PREDICATE_TYPE,
    SPDX_23_PREDICATE_TYPE,
    TRUSTED_RELEASE_VERIFICATION_POLICY_SHA256,
    VERIFIER_TIMEOUT_SECONDS,
    ReleaseVerificationError,
    VerificationRunner,
    copy_verified_file,
    github_attestation_verify_command,
    isolated_verifier_environment,
    require_exact_keys,
    require_git_sha,
    require_sha256,
    require_successful_verifier_result,
    resolve_evidence_entry,
    snapshot_bytes,
    statement_subjects,
    validate_release_verification_policy,
)


BUILD_VERIFICATION_POLICY_SCHEMA_VERSION = 4
BUILD_VERIFICATION_RECORD_SCHEMA_VERSION = 2
BUILD_PREDICATE_TYPE = "https://assured-downstream.dev/attestation/build/v2"
MAX_APPROVED_CALLER_DIGESTS = 8
BUILD_BUNDLE_FILENAMES = {
    "provenance": "provenance.sigstore.json",
    "sbom": "sbom.sigstore.json",
    "build": "build.sigstore.json",
}
BUILD_CLAIM_LIMIT = (
    "The workflow signs these run, source, artifact, SBOM, and builder "
    "observations. Source ancestry, workflow implementation, builder "
    "containment, provider independence, and semantic safety require "
    "separate verification."
)
V3_EXPECTED_TRACE_ARGV = [
    "/usr/bin/strace",
    "-u",
    "assured",
    "-ff",
    "-qq",
    "-ttt",
    "-T",
    "-yy",
    "-s",
    "4096",
    "-o",
    "/out/traces/raw/strace",
    "--",
    "/usr/local/bin/python",
    "-I",
    "-m",
    "build",
    "--no-isolation",
    "--outdir",
    "/workspace/output/dist",
    "/workspace/source",
]
RAW_SYSCALL_PATTERN = re.compile(
    r"^(?P<timestamp>[0-9]+\.[0-9]+)\s+"
    r"(?P<name>[A-Za-z0-9_]+)\((?P<args>.*)\)\s+=\s+"
    r"(?P<result>.*?)(?:\s+<[0-9.]+>)?$"
)
RAW_SIGNAL_PATTERN = re.compile(
    r"^(?P<timestamp>[0-9]+\.[0-9]+)\s+---\s+"
    r"(?P<name>SIG[A-Z0-9]+)\s+\{.*\}\s+---$"
)
RAW_EXIT_PATTERN = re.compile(
    r"^(?P<timestamp>[0-9]+\.[0-9]+)\s+\+\+\+\s+"
    r"(?P<status>exited with [0-9]+|killed by SIG[A-Z0-9]+(?: \(core dumped\))?)"
    r"\s+\+\+\+$"
)
RAW_QUOTED_PATTERN = re.compile(r'"((?:[^"\\]|\\.)*)"')
RAW_TRACE_PATH_PATTERN = re.compile(r"^traces/raw/strace\.[0-9]+$")
FILE_OPERATIONS = {
    "creat": "create",
    "mkdir": "create",
    "mkdirat": "create",
    "open": "access",
    "openat": "access",
    "openat2": "access",
    "readlink": "access",
    "readlinkat": "access",
    "rename": "rename",
    "renameat": "rename",
    "renameat2": "rename",
    "rmdir": "delete",
    "stat": "access",
    "unlink": "delete",
    "unlinkat": "delete",
}
NETWORK_OPERATIONS = {
    "accept",
    "accept4",
    "bind",
    "connect",
    "listen",
    "recvfrom",
    "sendto",
}
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
MAX_RAW_TRACE_FILE_BYTES = 64 * 1024 * 1024
MAX_RAW_TRACE_TOTAL_BYTES = 256 * 1024 * 1024
MAX_EVIDENCE_ENTRIES = 10_000
MAX_EVIDENCE_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
SPDX_NORMALIZATION_POLICY_ID = "spdx-2.3-syft-canonical-v1"
CANONICALIZATION_POLICY_ID = "python-sdist-pax-v1"
PROFILE_ID = "python-wheel-v3"
BUILDER_IMAGE = "ghcr.io/saucetaster/assured-downstream-python-builder"
BUILDER_DIGEST = (
    "sha256:5f52c4bfe05c4947877d6d80f2124062b79a46764cc2161dc4caaa631d65833a"
)
MIN_SOURCE_DATE_EPOCH = 1
MAX_SOURCE_DATE_EPOCH = 4_294_967_295


class BuildVerificationError(RuntimeError):
    pass


def decode_json_object(payload: bytes | str, *, label: str) -> dict[str, Any]:
    value = decode_json_value(payload, label=label)
    if not isinstance(value, dict):
        raise BuildVerificationError(f"{label.capitalize()} must contain an object")
    return value


def decode_json_array(payload: bytes | str, *, label: str) -> list[Any]:
    value = decode_json_value(payload, label=label)
    if not isinstance(value, list):
        raise BuildVerificationError(f"{label.capitalize()} must contain an array")
    return value


def decode_json_value(payload: bytes | str, *, label: str) -> Any:
    try:
        text = (
            payload.decode("utf-8", "strict") if isinstance(payload, bytes) else payload
        )
    except UnicodeDecodeError as exc:
        raise BuildVerificationError(f"{label.capitalize()} is not UTF-8") from exc
    if text.startswith("\ufeff"):
        raise BuildVerificationError(f"{label.capitalize()} has a UTF-8 BOM")
    try:
        value = json.loads(
            text,
            object_pairs_hook=duplicate_rejecting_object,
            parse_constant=reject_json_constant,
            parse_int=bounded_json_integer,
            parse_float=bounded_json_float,
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise BuildVerificationError(f"Could not parse {label}") from exc
    validate_json_shape(value)
    return value


def duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise BuildVerificationError(f"JSON object contains duplicate key: {key}")
        value[key] = item
    return value


def reject_json_constant(value: str) -> None:
    raise BuildVerificationError(f"JSON contains unsupported constant: {value}")


def bounded_json_integer(value: str) -> int:
    if len(value) > 128:
        raise ValueError("JSON integer is oversized")
    return int(value)


def bounded_json_float(value: str) -> float:
    if len(value) > 128:
        raise ValueError("JSON float is oversized")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("JSON float is not finite")
    return result


def validate_json_shape(value: Any, *, depth: int = 0) -> int:
    if depth > 128:
        raise BuildVerificationError("JSON nesting exceeds its limit")
    count = 1
    if isinstance(value, dict):
        for item in value.values():
            count += validate_json_shape(item, depth=depth + 1)
    elif isinstance(value, list):
        for item in value:
            count += validate_json_shape(item, depth=depth + 1)
    if count > 1_000_000:
        raise BuildVerificationError("JSON value count exceeds its limit")
    return count


def validate_local_verifier_sources(policy: dict[str, Any]) -> dict[str, str]:
    verifier = policy["verifier"]
    verifier_source = Path(__file__)
    if __name__ != TRUSTED_BUILD_VERIFIER_IMPORT:
        raise BuildVerificationError("Portable v3 verifier import identity is invalid")
    _, verifier_sha256 = snapshot_bytes(
        verifier_source,
        label="portable v3 verifier source",
        max_bytes=MAX_EXECUTABLE_BYTES,
    )
    archive_source = getattr(archive_validation_v3, "__file__", None)
    if (
        archive_validation_v3.__name__ != TRUSTED_ARCHIVE_VALIDATOR_IMPORT
        or not isinstance(archive_source, str)
        or not archive_source.endswith(".py")
    ):
        raise BuildVerificationError("Portable archive validator source is unavailable")
    _, archive_sha256 = snapshot_bytes(
        Path(archive_source),
        label="portable v3 archive validator source",
        max_bytes=MAX_EXECUTABLE_BYTES,
    )
    if not hmac.compare_digest(
        verifier_sha256,
        verifier["source_sha256"],
    ) or not hmac.compare_digest(
        archive_sha256,
        verifier["archive_validator_sha256"],
    ):
        raise BuildVerificationError("Portable v3 verifier source is not policy-anchored")
    try:
        require_trusted_build_v3_sources(
            verifier_module=verifier["module"],
            verifier_source_sha256=verifier_sha256,
            archive_validator_module=verifier["archive_validator_module"],
            archive_validator_source_sha256=archive_sha256,
        )
    except BuildVerificationTrustError as exc:
        raise BuildVerificationError(str(exc)) from exc
    return {
        "trust_root": "assured_downstream.build_verification_trust_v3",
        "module": TRUSTED_BUILD_VERIFIER_MODULE,
        "source_sha256": verifier_sha256,
        "archive_validator_module": TRUSTED_ARCHIVE_VALIDATOR_MODULE,
        "archive_validator_sha256": archive_sha256,
    }


def verify_build_attestations(
    *,
    evidence_path: Path,
    policy_path: Path,
    trust_policy_path: Path,
    runner: VerificationRunner | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    try:
        return _verify_build_attestations(
            evidence_path=evidence_path,
            policy_path=policy_path,
            trust_policy_path=trust_policy_path,
            runner=runner,
            now=now,
        )
    except BuildVerificationError:
        raise
    except ReleaseVerificationError as exc:
        raise BuildVerificationError(str(exc)) from exc


def _verify_build_attestations(
    *,
    evidence_path: Path,
    policy_path: Path,
    trust_policy_path: Path,
    runner: VerificationRunner | None,
    now: datetime | None,
) -> dict[str, Any]:
    evidence_path = Path(os.path.abspath(evidence_path.expanduser()))
    policy_path = Path(os.path.abspath(policy_path.expanduser()))
    trust_policy_path = Path(os.path.abspath(trust_policy_path.expanduser()))
    evidence_bytes, evidence_sha256 = snapshot_bytes(
        evidence_path,
        label="build evidence manifest",
        max_bytes=MAX_JSON_BYTES,
    )
    policy_bytes, policy_sha256 = snapshot_bytes(
        policy_path,
        label="build verification policy",
        max_bytes=MAX_JSON_BYTES,
    )
    try:
        require_trusted_build_v3_policy(policy_sha256)
    except BuildVerificationTrustError as exc:
        raise BuildVerificationError(str(exc)) from exc
    policy = validate_build_verification_policy(
        decode_json_object(policy_bytes, label="build verification policy")
    )
    verifier_sources = validate_local_verifier_sources(policy)
    trust_policy_bytes, trust_policy_sha256 = snapshot_bytes(
        trust_policy_path,
        label="Sigstore trust policy",
        max_bytes=MAX_JSON_BYTES,
    )
    if not hmac.compare_digest(
        trust_policy_sha256,
        policy["trust_policy_sha256"],
    ) or not hmac.compare_digest(
        trust_policy_sha256,
        TRUSTED_RELEASE_VERIFICATION_POLICY_SHA256,
    ):
        raise BuildVerificationError("Sigstore trust policy digest is not approved")
    trust_policy = validate_release_verification_policy(
        decode_json_object(trust_policy_bytes, label="Sigstore trust policy")
    )
    evidence = decode_json_object(evidence_bytes, label="build evidence manifest")
    roles = validate_v3_evidence_manifest(evidence, base_dir=evidence_path.parent)
    project = validate_build_project(evidence.get("project"), policy=policy)
    evidence_roles = evidence.get("evidence")
    if not isinstance(evidence_roles, dict):
        raise BuildVerificationError("Build evidence roles are invalid")
    artifact_entries = roles["artifacts"]
    if not artifact_entries:
        raise BuildVerificationError("Build evidence has no artifact subjects")
    if len(roles["sboms"]) != 2:
        raise BuildVerificationError(
            "Build verification requires raw and normalized SPDX"
        )
    bundles = identify_build_bundles(roles["attestations"])
    artifact_records = [
        validate_artifact_manifest_entry(entry) for entry in artifact_entries
    ]
    validate_artifact_record_set(artifact_records)
    expected_subjects = {
        (record["path"], record["sha256"]) for record in artifact_records
    }
    if len(expected_subjects) != len(artifact_entries):
        raise BuildVerificationError("Artifact evidence contains duplicate subjects")

    reports = require_entry_list(evidence_roles.get("reports"), label="reports")
    traces = require_entry_list(evidence_roles.get("traces"), label="traces")
    raw_artifacts = require_entry_list(
        evidence_roles.get("raw_artifacts"),
        label="raw artifacts",
    )
    if len(raw_artifacts) != len(artifact_entries):
        raise BuildVerificationError("Raw artifact evidence set is incomplete")
    subject_manifest_entry = unique_entry_by_path(
        reports,
        "reports/artifact-subjects.sha256",
    )
    validate_subject_checksum_evidence(
        subject_manifest_entry,
        artifacts=artifact_records,
        base_dir=evidence_path.parent,
    )
    spdx_report_entry = unique_entry_by_path(
        reports,
        "reports/spdx-normalization.json",
    )
    spdx_report_path = resolve_evidence_entry(
        spdx_report_entry,
        base_dir=evidence_path.parent,
        label="SPDX normalization report",
    )
    spdx_report_bytes, spdx_report_sha256 = snapshot_bytes(
        spdx_report_path,
        label="SPDX normalization report",
        max_bytes=MAX_JSON_BYTES,
    )
    if not hmac.compare_digest(
        spdx_report_sha256,
        require_sha256(
            spdx_report_entry.get("sha256"),
            label="SPDX normalization report digest",
        ),
    ):
        raise BuildVerificationError("SPDX normalization report changed")
    spdx_report = decode_json_object(
        spdx_report_bytes,
        label="SPDX normalization report",
    )
    raw_sbom_entry = unique_entry_by_path(roles["sboms"], "sbom/raw/syft.spdx.json")
    sbom_entry = unique_entry_by_path(roles["sboms"], "sbom/sbom.spdx.json")
    raw_sbom_path = resolve_evidence_entry(
        raw_sbom_entry,
        base_dir=evidence_path.parent,
        label="raw Syft SBOM",
    )
    raw_sbom_bytes, raw_sbom_sha256 = snapshot_bytes(
        raw_sbom_path,
        label="raw Syft SBOM",
        max_bytes=MAX_JSON_BYTES,
    )
    if not hmac.compare_digest(
        raw_sbom_sha256,
        require_sha256(raw_sbom_entry.get("sha256"), label="raw SBOM digest"),
    ):
        raise BuildVerificationError("Raw SPDX SBOM changed before verification")
    sbom_path = resolve_evidence_entry(
        sbom_entry,
        base_dir=evidence_path.parent,
        label="SBOM",
    )
    sbom_bytes, sbom_sha256 = snapshot_bytes(
        sbom_path,
        label="SPDX SBOM",
        max_bytes=MAX_JSON_BYTES,
    )
    if not hmac.compare_digest(
        sbom_sha256,
        require_sha256(sbom_entry.get("sha256"), label="SBOM digest"),
    ):
        raise BuildVerificationError("SPDX SBOM changed before verification")
    sbom = decode_json_object(sbom_bytes, label="SPDX SBOM")
    spdx_bindings = validate_spdx_evidence(
        raw_bytes=raw_sbom_bytes,
        normalized_bytes=sbom_bytes,
        normalized=sbom,
        artifacts=artifact_records,
        policy=policy,
        report=spdx_report,
    )
    report_entries = {
        "artifact_inventory": unique_entry_by_path(
            reports, "reports/artifact-inventory.json"
        ),
        "artifact_transform": unique_entry_by_path(
            reports, "reports/artifact-transforms.json"
        ),
        "builder_report": unique_entry_by_path(reports, "reports/builder.json"),
        "source_inventory": unique_entry_by_path(
            reports, "reports/source-inventory.json"
        ),
        "trusted_source_inventory": unique_entry_by_path(
            reports, "reports/trusted-source-inventory.json"
        ),
        "handoff_seal": unique_entry_by_path(reports, "reports/handoff-seal.json"),
        "trace": unique_entry_by_path(traces, "traces/observed-trace.json"),
    }
    retained_reports = validate_retained_v3_reports(
        entries=report_entries,
        raw_artifact_entries=raw_artifacts,
        artifact_entries=artifact_entries,
        artifacts=artifact_records,
        policy=policy,
        base_dir=evidence_path.parent,
        raw_trace_entries=[
            entry
            for entry in reports
            if entry_logical_path(entry).startswith("traces/raw/")
        ],
    )

    predicate_entry = unique_entry_by_path(reports, "predicates/build.json")
    predicate_path = resolve_evidence_entry(
        predicate_entry,
        base_dir=evidence_path.parent,
        label="build predicate",
    )
    predicate_bytes, predicate_sha256 = snapshot_bytes(
        predicate_path,
        label="build predicate",
        max_bytes=MAX_JSON_BYTES,
    )
    if not hmac.compare_digest(
        predicate_sha256,
        require_sha256(predicate_entry.get("sha256"), label="build predicate digest"),
    ):
        raise BuildVerificationError("Build predicate changed before verification")
    build_predicate = decode_json_object(predicate_bytes, label="build predicate")
    caller_digest = validate_build_predicate(
        build_predicate,
        policy=policy,
        artifact_records=artifact_records,
        evidence_entries={
            "artifact_inventory": report_entries["artifact_inventory"],
            "builder_report": report_entries["builder_report"],
            "artifact_transform": report_entries["artifact_transform"],
            "artifact_subject_manifest": unique_entry_by_path(
                reports, "reports/artifact-subjects.sha256"
            ),
            "source_inventory": report_entries["source_inventory"],
            "trusted_source_inventory": report_entries["trusted_source_inventory"],
            "handoff_seal": report_entries["handoff_seal"],
            "trace": report_entries["trace"],
            "raw_sbom": raw_sbom_entry,
            "sbom": sbom_entry,
            "spdx_normalization": spdx_report_entry,
        },
        spdx_bindings=spdx_bindings,
        source_filesystem_sha256=retained_reports["source_filesystem_sha256"],
    )
    trace_entry = unique_entry_by_path(traces, "traces/observed-trace.json")
    trace_path = resolve_evidence_entry(
        trace_entry,
        base_dir=evidence_path.parent,
        label="observed trace",
    )
    trace_bytes, _ = snapshot_bytes(
        trace_path,
        label="observed trace",
        max_bytes=MAX_JSON_BYTES,
    )
    trace = decode_json_object(trace_bytes, label="observed trace")
    raw_trace_counts = verify_raw_trace_records(
        [
            entry
            for entry in reports
            if entry_logical_path(entry).startswith("traces/raw/")
        ],
        base_dir=evidence_path.parent,
    )
    validate_complete_trace(trace, raw_trace_counts=raw_trace_counts)

    verifier = trust_policy["verifier"]
    executable = Path(verifier["executable"]).expanduser().resolve()
    executable_bytes, executable_sha256 = snapshot_bytes(
        executable,
        label="build verifier executable",
        max_bytes=MAX_EXECUTABLE_BYTES,
    )
    if not hmac.compare_digest(executable_sha256, verifier["sha256"]):
        raise BuildVerificationError("Build verifier executable digest is invalid")
    trusted_root_bytes = (
        json.dumps(
            trust_policy["sigstore_trusted_root"],
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    trusted_root_sha256 = hashlib.sha256(trusted_root_bytes).hexdigest()

    signer = policy["signer"]
    effective_runner = runner or CommandRunner(execute=True)
    expected_predicates = {
        "provenance": None,
        "sbom": sbom,
        "build": build_predicate,
    }
    bundle_results: dict[str, dict[str, Any]] = {}
    commands: list[str] = []
    with tempfile.TemporaryDirectory(prefix="assured-build-verify-") as tmp:
        isolation_root = Path(tmp)
        home = isolation_root / "home"
        gh_config = isolation_root / "gh-config"
        temp_root = isolation_root / "tmp"
        home.mkdir(mode=0o700)
        gh_config.mkdir(mode=0o700)
        temp_root.mkdir(mode=0o700)
        staged_executable = isolation_root / "gh"
        staged_executable.write_bytes(executable_bytes)
        staged_executable.chmod(0o500)
        staged_trusted_root = isolation_root / "sigstore-trusted-root.jsonl"
        staged_trusted_root.write_bytes(trusted_root_bytes)
        staged_trusted_root.chmod(0o400)
        artifact_entry = artifact_entries[0]
        artifact = resolve_evidence_entry(
            artifact_entry,
            base_dir=evidence_path.parent,
            label="artifact",
        )
        staged_artifact = isolation_root / "artifact.subject"
        copy_verified_file(
            artifact,
            staged_artifact,
            expected_sha256=require_sha256(
                artifact_entry.get("sha256"),
                label="artifact digest",
            ),
        )

        for role in ("provenance", "sbom", "build"):
            entry = bundles[role]
            bundle_path = resolve_evidence_entry(
                entry,
                base_dir=evidence_path.parent,
                label=f"{role} bundle",
            )
            bundle_bytes, bundle_sha256 = snapshot_bytes(
                bundle_path,
                label=f"{role} bundle",
                max_bytes=MAX_JSON_BYTES,
            )
            if not hmac.compare_digest(
                bundle_sha256,
                require_sha256(entry.get("sha256"), label=f"{role} bundle digest"),
            ):
                raise BuildVerificationError(
                    f"{role.capitalize()} bundle changed before verification"
                )
            staged_bundle = isolation_root / BUILD_BUNDLE_FILENAMES[role]
            staged_bundle.write_bytes(bundle_bytes)
            staged_bundle.chmod(0o400)
            command = github_attestation_verify_command(
                artifact_path=staged_artifact,
                bundle_path=staged_bundle,
                predicate_type=policy["predicates"][role],
                target_repository=policy["control_repository"],
                source_digest=caller_digest,
                signer_digest=signer["workflow_digest"],
                source_ref=signer["source_ref"],
                certificate_identity=signer["certificate_identity"],
                oidc_issuer=signer["oidc_issuer"],
                deny_self_hosted_runners=signer["deny_self_hosted_runners"],
                executable_path=staged_executable,
                trusted_root_path=staged_trusted_root,
            )
            result = effective_runner.run(
                command,
                cwd=str(isolation_root),
                env=isolated_verifier_environment(
                    home=home,
                    gh_config=gh_config,
                    temp_root=temp_root,
                ),
                timeout_seconds=VERIFIER_TIMEOUT_SECONDS,
                inherit_env=False,
            )
            require_successful_verifier_result(result, role=role)
            entries = decode_json_array(
                result.stdout,
                label=f"{role} verifier output",
            )
            timestamp_count = validate_build_verification_output(
                entries,
                role=role,
                predicate_type=policy["predicates"][role],
                expected_subjects=expected_subjects,
                expected_predicate=expected_predicates[role],
                policy=policy,
                caller_digest=caller_digest,
                run_claim=build_predicate["run"],
            )
            bundle_results[role] = {
                "predicate_type": policy["predicates"][role],
                "sha256": bundle_sha256,
                "verified_transparency_timestamp_count": timestamp_count,
            }
            commands.append(display_command(command))

    verified_at = (
        (now or datetime.now(UTC)).astimezone(UTC).isoformat(timespec="seconds")
    )
    request = policy["approved_request"]
    return {
        "schema_version": BUILD_VERIFICATION_RECORD_SCHEMA_VERSION,
        "status": "verified-evidence-candidate",
        "ok": True,
        "authority": "code-anchored-reusable-workflow-sigstore",
        "verification_type": "retained-build-sigstore-bundles",
        "verified_at": verified_at,
        "case_id": request["case_id"],
        "evidence_sha256": evidence_sha256,
        "policy_sha256": policy_sha256,
        "trust_policy_sha256": trust_policy_sha256,
        "verifier_sha256": executable_sha256,
        "portable_verifier_sources": verifier_sources,
        "sigstore_trusted_root_sha256": trusted_root_sha256,
        "target_full_name": project["target_full_name"],
        "source_repository": request["source_repository"],
        "source_commit": request["source_commit"],
        "caller_repository": policy["control_repository"],
        "caller_digest": caller_digest,
        "signer": (f"{policy['control_repository']}/{signer['workflow_path']}"),
        "signer_digest": signer["workflow_digest"],
        "certificate_identity": signer["certificate_identity"],
        "builder_image": (
            f"{policy['builder']['image']}@{policy['builder']['image_digest']}"
        ),
        "verified_subjects": [
            {"name": name, "sha256": digest}
            for name, digest in sorted(expected_subjects)
        ],
        "spdx_referenced_subjects": spdx_bindings,
        "workflow_run": build_predicate["run"],
        "caller_workflow": build_predicate["caller"],
        "called_workflow": build_predicate["called"],
        "normalized_spdx_sha256": sbom_sha256,
        "raw_spdx_sha256": raw_sbom_sha256,
        "trace": {
            "coverage": trace["coverage"],
            "raw_file_count": trace["raw_file_count"],
            "parsed_line_count": trace["parsed_line_count"],
            "unparsed_line_count": trace["unparsed_line_count"],
        },
        "verified_controls": [
            "bundle-signature",
            "sigstore-trusted-root",
            "transparency-timestamp",
            "reusable-workflow-certificate-identity",
            "caller-workflow-commit",
            "signer-workflow-commit",
            "github-hosted-runner",
            "artifact-subject-set",
            "spdx-artifact-reference",
            "spdx-canonical-bytes",
            "spdx-deterministic-namespace",
            "build-predicate-content",
            "run-invocation-certificate-binding",
            "retained-trace-parser-pass",
            "attested-source-snapshot-comparison",
            "attested-live-ownership-boundary-seal",
        ],
        "attested_claims": {
            "upstream_repository": request["upstream_repository"],
            "upstream_commit": request["upstream_commit"],
            "source_tree": request["source_tree"],
            "target_repository": request["target_repository"],
            "host_source_snapshot_comparison": True,
            "root_ownership_boundary_observed": True,
            "fixed_build_argv": V3_EXPECTED_TRACE_ARGV,
        },
        "independently_verified": {
            "sigstore_bundles": True,
            "artifact_subjects": True,
            "sbom_artifact_binding": True,
            "deterministic_spdx": True,
            "run_invocation": True,
            "actor_identity": False,
            "retained_trace_parser_pass": True,
            "build_invocation_from_trace": False,
            "trace_lifecycle": False,
            "source_snapshot_comparison": False,
            "ownership_boundary_observation": False,
            "upstream_lineage": False,
            "builder_isolation": False,
            "collector_tamper_resistance": False,
            "workflow_implementation": False,
            "reproducibility": False,
            "semantic_safety": False,
        },
        "bundles": bundle_results,
        "commands": commands,
        "claim_limit": policy["claim_limit"],
    }


def validate_build_verification_policy(policy: dict[str, Any]) -> dict[str, Any]:
    require_exact_keys(
        policy,
        {
            "schema_version",
            "status",
            "control_repository",
            "signer",
            "approved_request",
            "builder",
            "spdx",
            "actions",
            "predicates",
            "verifier",
            "trust_policy_sha256",
            "claim_limit",
        },
        label="build verification policy",
    )
    if (
        type(policy.get("schema_version")) is not int
        or policy["schema_version"] != BUILD_VERIFICATION_POLICY_SCHEMA_VERSION
        or policy.get("status") != "active-dev-case-study"
        or policy.get("control_repository") != "SauceTaster/assured-downstream"
    ):
        raise BuildVerificationError("Build verification policy identity is invalid")

    signer = policy.get("signer")
    if not isinstance(signer, dict):
        raise BuildVerificationError("Build signer policy is invalid")
    require_exact_keys(
        signer,
        {
            "workflow_path",
            "workflow_digest",
            "certificate_identity",
            "caller_workflow_path",
            "caller_digests",
            "source_ref",
            "trigger",
            "oidc_issuer",
            "deny_self_hosted_runners",
            "workflow_name",
            "actor",
            "triggering_actor",
            "run_attempt",
        },
        label="build signer policy",
    )
    expected_signer_fields = {
        "workflow_path": ".github/workflows/reusable-python-build-v3.yml",
        "caller_workflow_path": ".github/workflows/case-study-bandit-build-v3.yml",
        "source_ref": "refs/heads/main",
        "trigger": "workflow_dispatch",
        "oidc_issuer": GITHUB_ACTIONS_OIDC_ISSUER,
        "deny_self_hosted_runners": True,
        "workflow_name": "Case Study 001 Bandit Build Canary v3",
        "actor": "SauceTaster",
        "triggering_actor": "SauceTaster",
        "run_attempt": "1",
    }
    if any(
        signer.get(field) != value for field, value in expected_signer_fields.items()
    ):
        raise BuildVerificationError("Build signer policy boundary is invalid")
    workflow_digest = require_git_sha(
        signer.get("workflow_digest"),
        label="signer workflow digest",
    )
    callers = signer.get("caller_digests")
    if not isinstance(callers, list) or len(callers) != 1:
        raise BuildVerificationError("Build signer requires one pinned caller")
    caller_digest = require_git_sha(callers[0], label="caller workflow digest")
    if caller_digest == workflow_digest:
        raise BuildVerificationError("Called and caller workflow commits must differ")
    expected_identity = (
        "https://github.com/SauceTaster/assured-downstream/"
        f"{signer['workflow_path']}@{workflow_digest}"
    )
    if signer.get("certificate_identity") != expected_identity:
        raise BuildVerificationError("Build signer certificate identity is not exact")

    request = policy.get("approved_request")
    if not isinstance(request, dict):
        raise BuildVerificationError("Approved build request is invalid")
    require_exact_keys(
        request,
        {
            "case_id",
            "source_repository",
            "source_commit",
            "source_tree",
            "source_date_epoch",
            "upstream_repository",
            "upstream_commit",
            "target_repository",
            "project_version",
            "release_tag",
        },
        label="approved build request",
    )
    expected_request = {
        "case_id": "case-001-bandit-source-canary-v3",
        "source_repository": "PyCQA/bandit",
        "source_commit": "c45446eaa30c4f28289c3b8ba9a955e1d78ba715",
        "source_tree": "5313408ad294e5a95f214620ec3064f8e40bc608",
        "source_date_epoch": "1783382521",
        "upstream_repository": "PyCQA/bandit",
        "upstream_commit": "c45446eaa30c4f28289c3b8ba9a955e1d78ba715",
        "target_repository": "SauceTaster/assured-bandit",
        "project_version": "1.9.4",
        "release_tag": "case-001-bandit-source-canary-v3",
    }
    if request != expected_request:
        raise BuildVerificationError("Approved build request is not the Bandit v3 case")

    builder = policy.get("builder")
    if not isinstance(builder, dict):
        raise BuildVerificationError("Build image policy is invalid")
    require_exact_keys(
        builder,
        {
            "profile",
            "image",
            "image_digest",
            "handoff_verifier_commit",
            "handoff_verifier_sha256",
            "canonicalization_policy",
            "base_image_index_digest",
            "source_digests",
        },
        label="build image policy",
    )
    if (
        builder.get("profile") != PROFILE_ID
        or builder.get("image") != BUILDER_IMAGE
        or builder.get("image_digest") != BUILDER_DIGEST
        or builder.get("canonicalization_policy") != CANONICALIZATION_POLICY_ID
        or builder.get("base_image_index_digest")
        != "sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7"
    ):
        raise BuildVerificationError("Build image policy is not the fixed v3 profile")
    require_git_sha(
        builder.get("handoff_verifier_commit"),
        label="handoff verifier commit",
    )
    require_sha256(
        builder.get("handoff_verifier_sha256"),
        label="handoff verifier digest",
    )
    expected_sources = {
        "builders/python-v3/Dockerfile": "def67c917675090d4b147f1b89b6ce5bedeb803591fae8322adb70dac3db88a6",
        "builders/python-v3/entrypoint.py": "9601c51e015dd7b45cb4e78f62f4de6af98fdeff048f0c23af467ae5c27d6884",
        "builders/python-v3/requirements.lock": "6a060a27d9e1d93a78a969d67b7d5e7f9508b73b99c0332315f8646ae80fd2a6",
    }
    if builder.get("source_digests") != expected_sources:
        raise BuildVerificationError("Builder source digest policy is invalid")

    spdx = policy.get("spdx")
    expected_spdx = {
        "normalization_policy": SPDX_NORMALIZATION_POLICY_ID,
        "syft_version": "1.42.3",
        "creators": ["Organization: Anchore, Inc", "Tool: syft-1.42.3"],
        "license_list_version": "3.28",
    }
    if spdx != expected_spdx:
        raise BuildVerificationError("SPDX normalization policy is invalid")
    expected_actions = {
        "actions/attest": "a1948c3f048ba23858d222213b7c278aabede763",
        "actions/checkout": "34e114876b0b11c390a56381ad16ebd13914f8d5",
        "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "anchore/sbom-action": "e22c389904149dbc22b58101806040fa8d37a610",
    }
    if policy.get("actions") != expected_actions:
        raise BuildVerificationError("Build action pin policy is invalid")
    if policy.get("predicates") != {
        "provenance": SLSA_PROVENANCE_PREDICATE_TYPE,
        "sbom": SPDX_23_PREDICATE_TYPE,
        "build": BUILD_PREDICATE_TYPE,
    }:
        raise BuildVerificationError("Build predicate policy is invalid")
    verifier = policy.get("verifier")
    if not isinstance(verifier, dict):
        raise BuildVerificationError("Portable verifier source policy is invalid")
    require_exact_keys(
        verifier,
        {
            "module",
            "source_sha256",
            "archive_validator_module",
            "archive_validator_sha256",
        },
        label="portable verifier source policy",
    )
    if (
        verifier.get("module") != TRUSTED_BUILD_VERIFIER_MODULE
        or verifier.get("archive_validator_module")
        != TRUSTED_ARCHIVE_VALIDATOR_MODULE
    ):
        raise BuildVerificationError("Portable verifier source identity is invalid")
    require_sha256(
        verifier.get("source_sha256"),
        label="portable verifier source digest",
    )
    require_sha256(
        verifier.get("archive_validator_sha256"),
        label="portable archive validator source digest",
    )
    require_sha256(policy.get("trust_policy_sha256"), label="trust policy digest")
    if policy.get("claim_limit") != (
        "This policy verifies one bounded Bandit v3 evidence candidate. It "
        "does not establish upstream ancestry, provider-independent rebuilds, "
        "builder or collector tamper resistance, or semantic safety."
    ):
        raise BuildVerificationError("Build verification claim limit is invalid")
    return policy


def validate_v3_evidence_manifest(
    manifest: dict[str, Any],
    *,
    base_dir: Path,
) -> dict[str, list[dict[str, Any]]]:
    if set(manifest) != {"evidence", "generated_at", "project", "schema_version"}:
        raise BuildVerificationError("Build evidence manifest fields are not exact")
    generated_at = manifest.get("generated_at")
    try:
        generated_time = datetime.fromisoformat(generated_at)
    except (TypeError, ValueError) as exc:
        raise BuildVerificationError(
            "Build evidence generation time is invalid"
        ) from exc
    if (
        type(manifest.get("schema_version")) is not int
        or manifest["schema_version"] != 2
        or generated_time.tzinfo is None
        or generated_time.utcoffset() != UTC.utcoffset(generated_time)
        or generated_time.isoformat(timespec="seconds") != generated_at
    ):
        raise BuildVerificationError("Build evidence manifest identity is invalid")
    roles = manifest.get("evidence")
    required_roles = {
        "artifacts",
        "attestations",
        "raw_artifacts",
        "reports",
        "sboms",
        "traces",
    }
    if not isinstance(roles, dict) or set(roles) != required_roles:
        raise BuildVerificationError("Build evidence roles are not exact")

    total_entries = 0
    total_bytes = 0
    logical_paths: set[str] = set()
    storage_paths: set[str] = set()
    validated: dict[str, list[dict[str, Any]]] = {}
    for role in sorted(required_roles):
        entries = roles[role]
        if not isinstance(entries, list) or not entries:
            raise BuildVerificationError(f"Build evidence {role} are invalid")
        validated_entries: list[dict[str, Any]] = []
        role_logical_paths: list[str] = []
        for position, entry in enumerate(entries, start=1):
            if not isinstance(entry, dict) or set(entry) != {
                "logical_path",
                "name",
                "path",
                "role",
                "sha256",
                "size",
            }:
                raise BuildVerificationError(
                    "Build evidence entry fields are not exact"
                )
            logical_path = require_safe_logical_path(
                entry.get("logical_path"),
                label="evidence logical path",
            )
            storage_path = require_safe_logical_path(
                entry.get("path"),
                label="evidence storage path",
            )
            digest = require_sha256(entry.get("sha256"), label="evidence digest")
            size = entry.get("size")
            name = entry.get("name")
            if (
                entry.get("role") != role
                or not isinstance(name, str)
                or name != PurePosixPath(logical_path).name
                or type(size) is not int
                or size < 0
                or not valid_evidence_role_path(role, logical_path)
            ):
                raise BuildVerificationError("Build evidence entry identity is invalid")
            expected_staged_path = f"files/{role}/{digest}-{position:05d}-{name}"
            if storage_path not in {logical_path, expected_staged_path}:
                raise BuildVerificationError(
                    "Build evidence logical and storage paths are not bound"
                )
            logical_folded = logical_path.casefold()
            storage_folded = storage_path.casefold()
            if logical_folded in logical_paths or storage_folded in storage_paths:
                raise BuildVerificationError(
                    "Build evidence path is duplicated or aliased"
                )
            logical_paths.add(logical_folded)
            storage_paths.add(storage_folded)
            total_entries += 1
            total_bytes += size
            if (
                total_entries > MAX_EVIDENCE_ENTRIES
                or total_bytes > MAX_EVIDENCE_TOTAL_BYTES
            ):
                raise BuildVerificationError("Build evidence exceeds aggregate limits")
            max_bytes = (
                MAX_ARTIFACT_BYTES
                if role in {"artifacts", "raw_artifacts"}
                else MAX_RAW_TRACE_FILE_BYTES
                if logical_path.startswith("traces/raw/")
                else MAX_JSON_BYTES
            )
            if size > max_bytes:
                raise BuildVerificationError(
                    "Build evidence file exceeds its role limit"
                )
            path = resolve_v3_storage_path(storage_path, base_dir=base_dir)
            observed_size, observed_digest = stream_file_identity(
                path,
                label=f"{role} evidence",
                max_bytes=max_bytes,
            )
            if observed_size != size or not hmac.compare_digest(
                observed_digest, digest
            ):
                raise BuildVerificationError("Build evidence file identity is invalid")
            validated_entries.append(entry)
            role_logical_paths.append(logical_path)
        if role_logical_paths != sorted(
            role_logical_paths,
            key=lambda value: value.encode("utf-8"),
        ):
            raise BuildVerificationError(
                f"Build evidence {role} order is not canonical"
            )
        validated[role] = validated_entries
    return validated


def valid_evidence_role_path(role: str, logical_path: str) -> bool:
    if role == "artifacts":
        return logical_path.startswith("dist/")
    if role == "raw_artifacts":
        return logical_path.startswith("raw-artifacts/")
    if role == "attestations":
        return logical_path.startswith("attestations/")
    if role == "sboms":
        return logical_path.startswith("sbom/")
    if role == "traces":
        return logical_path.startswith("traces/")
    return logical_path.startswith(("predicates/", "reports/", "traces/raw/"))


def resolve_v3_storage_path(value: str, *, base_dir: Path) -> Path:
    root = base_dir.resolve(strict=True)
    if not root.is_dir():
        raise BuildVerificationError("Build evidence root is invalid")
    candidate = root
    parts = PurePosixPath(value).parts
    for position, part in enumerate(parts):
        candidate /= part
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise BuildVerificationError("Build evidence file is missing") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise BuildVerificationError(
                "Build evidence storage path contains a symlink"
            )
        if position < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise BuildVerificationError("Build evidence storage path is invalid")
    if not stat.S_ISREG(candidate.lstat().st_mode):
        raise BuildVerificationError("Build evidence storage is not a regular file")
    return candidate


def stream_file_identity(
    path: Path,
    *,
    label: str,
    max_bytes: int,
) -> tuple[int, str]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BuildVerificationError(f"Could not open {label}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > max_bytes
        ):
            raise BuildVerificationError(f"{label.capitalize()} is not standalone")
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(descriptor, min(1024 * 1024, max_bytes - size + 1)):
            size += len(chunk)
            if size > max_bytes:
                raise BuildVerificationError(f"{label.capitalize()} exceeds its limit")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            stable_stat_identity(before) != stable_stat_identity(after)
            or size != before.st_size
        ):
            raise BuildVerificationError(f"{label.capitalize()} changed while hashing")
        return size, digest.hexdigest()
    finally:
        os.close(descriptor)


def stable_stat_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def validate_build_project(value: Any, *, policy: dict[str, Any]) -> dict[str, str]:
    if not isinstance(value, dict):
        raise BuildVerificationError("Build evidence project is invalid")
    request = policy["approved_request"]
    expected = {
        "source_full_name": request["source_repository"],
        "target_full_name": request["target_repository"],
        "upstream_ref": request["upstream_commit"],
        "overlay_ref": request["source_commit"],
        "release_tag": request["release_tag"],
        "assurance": "Evidence-candidate",
    }
    if value != expected:
        raise BuildVerificationError("Build evidence project does not match policy")
    return expected


def identify_build_bundles(
    entries: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    if len(entries) != len(BUILD_BUNDLE_FILENAMES):
        raise BuildVerificationError("Build verification requires three bundles")
    found: dict[str, dict[str, Any]] = {}
    for entry in entries:
        name = entry.get("name")
        if not isinstance(name, str):
            raise BuildVerificationError("Build bundle name is invalid")
        matches = [
            role
            for role, filename in BUILD_BUNDLE_FILENAMES.items()
            if name.endswith(filename)
        ]
        if len(matches) != 1 or matches[0] in found:
            raise BuildVerificationError(f"Build bundle role is ambiguous: {name}")
        found[matches[0]] = entry
    if set(found) != set(BUILD_BUNDLE_FILENAMES):
        raise BuildVerificationError("Build bundle set is incomplete")
    return found


def require_entry_list(value: Any, *, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise BuildVerificationError(f"Build evidence {label} are invalid")
    return value


def unique_entry_by_path(
    entries: list[dict[str, Any]],
    expected_path: str,
) -> dict[str, Any]:
    matches = [entry for entry in entries if entry_logical_path(entry) == expected_path]
    if len(matches) != 1:
        raise BuildVerificationError(
            f"Build evidence requires exactly one {expected_path} entry"
        )
    return matches[0]


def entry_logical_path(entry: dict[str, Any]) -> str:
    value = entry.get("logical_path")
    return value if isinstance(value, str) else ""


def validate_artifact_manifest_entry(entry: dict[str, Any]) -> dict[str, Any]:
    if set(entry) != {
        "logical_path",
        "name",
        "path",
        "role",
        "sha256",
        "size",
    }:
        raise BuildVerificationError("Artifact manifest entry fields are not exact")
    path = require_safe_logical_path(
        entry.get("logical_path"),
        label="artifact path",
    )
    name = entry.get("name")
    size = entry.get("size")
    if (
        entry.get("role") != "artifacts"
        or not path.startswith("dist/")
        or path.count("/") != 1
        or name != PurePosixPath(path).name
        or type(size) is not int
        or size < 0
    ):
        raise BuildVerificationError("Artifact manifest entry is invalid")
    return {
        "path": path,
        "size": size,
        "sha256": require_sha256(entry.get("sha256"), label="artifact digest"),
    }


def validate_artifact_record_set(records: list[dict[str, Any]]) -> None:
    if records != sorted(records, key=lambda item: item["path"].encode("utf-8")):
        raise BuildVerificationError("Artifact manifest order is not canonical")
    folded: set[str] = set()
    for record in records:
        candidate = record["path"].casefold()
        if candidate in folded:
            raise BuildVerificationError("Artifact manifest contains a path alias")
        folded.add(candidate)


def evidence_record(entry: dict[str, Any]) -> dict[str, Any]:
    path = require_safe_logical_path(entry_logical_path(entry), label="evidence path")
    size = entry.get("size")
    if type(size) is not int or size < 0:
        raise BuildVerificationError("Evidence size is invalid")
    return {
        "path": path,
        "size": size,
        "sha256": evidence_sha256(entry),
    }


def evidence_sha256(entry: dict[str, Any]) -> str:
    return require_sha256(entry.get("sha256"), label="evidence digest")


def validate_subject_checksum_evidence(
    entry: dict[str, Any],
    *,
    artifacts: list[dict[str, Any]],
    base_dir: Path,
) -> None:
    expected = "".join(
        f"{item['sha256']}  {item['path']}\n" for item in artifacts
    ).encode("ascii")
    path = resolve_evidence_entry(
        entry,
        base_dir=base_dir,
        label="artifact subject checksum manifest",
    )
    payload, digest = snapshot_bytes(
        path,
        label="artifact subject checksum manifest",
        max_bytes=MAX_JSON_BYTES,
    )
    if (
        payload != expected
        or digest != evidence_sha256(entry)
        or evidence_record(entry)
        != {
            "path": "reports/artifact-subjects.sha256",
            "size": len(expected),
            "sha256": hashlib.sha256(expected).hexdigest(),
        }
    ):
        raise BuildVerificationError("Artifact subject checksum manifest is invalid")


def require_safe_logical_path(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
        or unicodedata.normalize("NFC", value) != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise BuildVerificationError(f"{label.capitalize()} is invalid")
    parts = value.split("/")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in parts)
        or len(value.encode("utf-8")) > 4096
        or any(len(part.encode("utf-8")) > 255 for part in parts)
    ):
        raise BuildVerificationError(f"{label.capitalize()} is not canonical")
    return value


def validate_spdx_evidence(
    *,
    raw_bytes: bytes,
    normalized_bytes: bytes,
    normalized: dict[str, Any],
    artifacts: list[dict[str, Any]],
    policy: dict[str, Any],
    report: dict[str, Any],
) -> dict[str, Any]:
    raw = decode_json_object(raw_bytes, label="raw Syft SPDX document")
    expected, seed_sha256 = independently_normalize_spdx(
        raw,
        artifacts=artifacts,
        policy=policy,
    )
    if normalized != expected or normalized_bytes != canonical_json_bytes(expected):
        raise BuildVerificationError("Normalized SPDX document is not canonical")
    request = policy["approved_request"]
    creation_time = format_spdx_time(request["source_date_epoch"])
    expected_report = {
        "schema_version": 1,
        "status": "succeeded",
        "policy_id": policy["spdx"]["normalization_policy"],
        "source_date_epoch": request["source_date_epoch"],
        "creation_time": creation_time,
        "document_namespace": expected["documentNamespace"],
        "namespace_seed_sha256": seed_sha256,
        "raw": {
            "path": "sbom/raw/syft.spdx.json",
            "size": len(raw_bytes),
            "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        },
        "normalized": {
            "path": "sbom/sbom.spdx.json",
            "size": len(normalized_bytes),
            "sha256": hashlib.sha256(normalized_bytes).hexdigest(),
        },
        "artifact_bindings": artifacts,
    }
    if report != expected_report:
        raise BuildVerificationError("SPDX normalization report is invalid")
    bindings = [{"path": item["path"], "sha256": item["sha256"]} for item in artifacts]
    return {
        "bindings": bindings,
        "document_namespace": expected["documentNamespace"],
        "creation_time": creation_time,
    }


def independently_normalize_spdx(
    raw: dict[str, Any],
    *,
    artifacts: list[dict[str, Any]],
    policy: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    allowed = {
        "SPDXID",
        "creationInfo",
        "dataLicense",
        "documentNamespace",
        "files",
        "name",
        "packages",
        "relationships",
        "spdxVersion",
    }
    if not (allowed - {"files"}).issubset(raw) or not set(raw).issubset(allowed):
        raise BuildVerificationError("Raw SPDX fields are not supported")
    if (
        raw.get("spdxVersion") != "SPDX-2.3"
        or raw.get("dataLicense") != "CC0-1.0"
        or raw.get("SPDXID") != "SPDXRef-DOCUMENT"
        or not isinstance(raw.get("name"), str)
        or not raw["name"]
        or not isinstance(raw.get("documentNamespace"), str)
        or not raw["documentNamespace"]
    ):
        raise BuildVerificationError("Raw SPDX identity is invalid")
    creation = raw.get("creationInfo")
    spdx_policy = policy["spdx"]
    if (
        not isinstance(creation, dict)
        or set(creation) != {"created", "creators", "licenseListVersion"}
        or sorted(creation.get("creators", [])) != spdx_policy["creators"]
        or creation.get("licenseListVersion") != spdx_policy["license_list_version"]
        or not isinstance(creation.get("created"), str)
        or not creation["created"]
    ):
        raise BuildVerificationError("Raw SPDX creation info is invalid")
    packages = require_object_list(raw.get("packages"), label="SPDX packages")
    files = require_object_list(raw.get("files", []), label="SPDX files")
    relationships = require_object_list(
        raw.get("relationships"),
        label="SPDX relationships",
    )
    if len(packages) + len(files) + len(relationships) > 100_000:
        raise BuildVerificationError("SPDX collection exceeds the item limit")

    request = policy["approved_request"]
    document_name = f"{request['source_repository']}@{request['source_commit']}"
    old_ids = {"SPDXRef-DOCUMENT"}
    new_ids = {"SPDXRef-DOCUMENT"}
    id_map = {"SPDXRef-DOCUMENT": "SPDXRef-DOCUMENT"}
    normalized_packages: list[dict[str, Any]] = []
    normalized_files: list[dict[str, Any]] = []
    for package in packages:
        candidate = dict(package)
        if candidate.get("name") == raw["name"]:
            candidate["name"] = document_name
        normalized_packages.append(
            independently_normalize_element(
                candidate,
                prefix="Package",
                old_ids=old_ids,
                new_ids=new_ids,
                id_map=id_map,
            )
        )
    artifact_paths = {item["path"].casefold() for item in artifacts}
    raw_paths: set[str] = set()
    for file_entry in files:
        file_name = require_safe_logical_path(
            file_entry.get("fileName"),
            label="SPDX file path",
        )
        folded = file_name.casefold()
        if folded in artifact_paths or folded in raw_paths:
            raise BuildVerificationError("Raw SPDX file path is aliased")
        raw_paths.add(folded)
        normalized_files.append(
            independently_normalize_element(
                file_entry,
                prefix="File",
                old_ids=old_ids,
                new_ids=new_ids,
                id_map=id_map,
            )
        )

    normalized_relationships: list[dict[str, str]] = []
    relationship_keys: set[bytes] = set()
    for relationship in relationships:
        if set(relationship) != {
            "relatedSpdxElement",
            "relationshipType",
            "spdxElementId",
        }:
            raise BuildVerificationError("SPDX relationship fields are invalid")
        source_id = relationship.get("spdxElementId")
        target_id = relationship.get("relatedSpdxElement")
        relation = relationship.get("relationshipType")
        if source_id not in id_map or target_id not in id_map or not relation:
            raise BuildVerificationError("SPDX relationship has a dangling reference")
        item = {
            "spdxElementId": id_map[source_id],
            "relationshipType": relation,
            "relatedSpdxElement": id_map[target_id],
        }
        key = canonical_json_bytes(item)
        if key in relationship_keys:
            raise BuildVerificationError("SPDX relationship is duplicated")
        relationship_keys.add(key)
        normalized_relationships.append(item)

    for artifact in artifacts:
        spdx_id = (
            "SPDXRef-Artifact-"
            + hashlib.sha256(canonical_json_bytes(artifact)).hexdigest()
        )
        if spdx_id in new_ids:
            raise BuildVerificationError("SPDX artifact identifier collision")
        new_ids.add(spdx_id)
        normalized_files.append(
            {
                "SPDXID": spdx_id,
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": artifact["sha256"]}
                ],
                "copyrightText": "NOASSERTION",
                "fileName": artifact["path"],
                "licenseConcluded": "NOASSERTION",
            }
        )
        relationship = {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": spdx_id,
        }
        key = canonical_json_bytes(relationship)
        if key in relationship_keys:
            raise BuildVerificationError("SPDX artifact relationship is duplicated")
        relationship_keys.add(key)
        normalized_relationships.append(relationship)

    normalized_packages.sort(key=lambda item: item["SPDXID"])
    normalized_files.sort(
        key=lambda item: (item["fileName"].encode("utf-8"), item["SPDXID"])
    )
    normalized_relationships.sort(
        key=lambda item: (
            item["spdxElementId"],
            item["relationshipType"],
            item["relatedSpdxElement"],
            canonical_json_bytes(item),
        )
    )
    normalized = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": format_spdx_time(request["source_date_epoch"]),
            "creators": spdx_policy["creators"],
            "licenseListVersion": spdx_policy["license_list_version"],
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": "",
        "files": normalized_files,
        "name": document_name,
        "packages": normalized_packages,
        "relationships": normalized_relationships,
        "spdxVersion": "SPDX-2.3",
    }
    seed_document = dict(normalized)
    seed_document.pop("documentNamespace")
    seed_creation = dict(seed_document["creationInfo"])
    seed_creation.pop("created")
    seed_document["creationInfo"] = seed_creation
    seed = {
        "namespace_schema": 1,
        "profile": PROFILE_ID,
        "normalization_policy": spdx_policy["normalization_policy"],
        "source": {
            "repository": request["source_repository"],
            "commit": request["source_commit"],
            "tree": request["source_tree"],
            "project_version": request["project_version"],
        },
        "source_date_epoch": request["source_date_epoch"],
        "artifacts": artifacts,
        "document": seed_document,
    }
    seed_sha256 = hashlib.sha256(canonical_json_bytes(seed)).hexdigest()
    normalized["documentNamespace"] = (
        f"https://assured-downstream.dev/spdx/{PROFILE_ID}/{seed_sha256}"
    )
    return normalized, seed_sha256


def independently_normalize_element(
    value: dict[str, Any],
    *,
    prefix: str,
    old_ids: set[str],
    new_ids: set[str],
    id_map: dict[str, str],
) -> dict[str, Any]:
    old_id = value.get("SPDXID")
    if (
        not isinstance(old_id, str)
        or re.fullmatch(r"SPDXRef-[A-Za-z0-9.-]+", old_id) is None
        or old_id in old_ids
    ):
        raise BuildVerificationError("SPDX element identifier is invalid")
    old_ids.add(old_id)
    body_value = {key: item for key, item in value.items() if key != "SPDXID"}
    if "checksums" in body_value:
        body_value["checksums"] = independently_normalize_checksums(
            body_value["checksums"]
        )
    if contains_inline_spdx_reference(body_value):
        raise BuildVerificationError(
            "SPDX inline identifier references are unsupported"
        )
    body = {key: canonicalize_spdx_value(item) for key, item in body_value.items()}
    generated = (
        f"SPDXRef-{prefix}-" + hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    )
    if generated in new_ids:
        raise BuildVerificationError("SPDX normalized element is duplicated")
    new_ids.add(generated)
    id_map[old_id] = generated
    return {"SPDXID": generated, **body}


def independently_normalize_checksums(value: Any) -> list[dict[str, str]]:
    checksums = require_object_list(value, label="SPDX checksums")
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for checksum in checksums:
        if set(checksum) != {"algorithm", "checksumValue"}:
            raise BuildVerificationError("SPDX checksum fields are invalid")
        algorithm = checksum.get("algorithm")
        digest = checksum.get("checksumValue")
        if not isinstance(algorithm, str) or not isinstance(digest, str):
            raise BuildVerificationError("SPDX checksum is invalid")
        identity = (algorithm.upper(), digest.lower())
        if (
            identity in seen
            or re.fullmatch(r"[A-Z0-9-]+", identity[0]) is None
            or re.fullmatch(r"[0-9a-f]+", identity[1]) is None
        ):
            raise BuildVerificationError("SPDX checksum is duplicated or malformed")
        seen.add(identity)
        normalized.append({"algorithm": identity[0], "checksumValue": identity[1]})
    return sorted(
        normalized,
        key=lambda item: (item["algorithm"], item["checksumValue"]),
    )


def contains_inline_spdx_reference(value: Any) -> bool:
    if isinstance(value, str):
        return (
            re.fullmatch(
                r"(?:DocumentRef-[A-Za-z0-9.-]+:)?SPDXRef-[A-Za-z0-9.-]+",
                value,
            )
            is not None
        )
    if isinstance(value, dict):
        return any(contains_inline_spdx_reference(item) for item in value.values())
    if isinstance(value, list):
        return any(contains_inline_spdx_reference(item) for item in value)
    return False


def require_object_list(value: Any, *, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise BuildVerificationError(f"{label} must be a list of objects")
    return value


def canonicalize_spdx_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool)):
        return value
    if type(value) is int:
        return value
    if isinstance(value, float):
        raise BuildVerificationError("Floating-point SPDX values are unsupported")
    if isinstance(value, dict):
        return {
            key: canonicalize_spdx_value(item) for key, item in sorted(value.items())
        }
    if isinstance(value, list):
        items = [canonicalize_spdx_value(item) for item in value]
        items.sort(key=canonical_json_bytes)
        if any(items[index] == items[index - 1] for index in range(1, len(items))):
            raise BuildVerificationError("SPDX collection contains a duplicate")
        return items
    raise BuildVerificationError("SPDX value type is unsupported")


def canonical_json_bytes(value: Any) -> bytes:
    try:
        payload = json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise BuildVerificationError("Value is not canonical JSON") from exc
    return (payload + "\n").encode("utf-8")


def format_spdx_time(source_date_epoch: str) -> str:
    if (
        not isinstance(source_date_epoch, str)
        or not source_date_epoch.isdigit()
        or str(int(source_date_epoch)) != source_date_epoch
        or not MIN_SOURCE_DATE_EPOCH <= int(source_date_epoch) <= MAX_SOURCE_DATE_EPOCH
    ):
        raise BuildVerificationError("SPDX source date epoch is invalid")
    return datetime.fromtimestamp(int(source_date_epoch), UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def validate_retained_v3_reports(
    *,
    entries: dict[str, dict[str, Any]],
    raw_artifact_entries: list[dict[str, Any]],
    artifact_entries: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    policy: dict[str, Any],
    base_dir: Path,
    raw_trace_entries: list[dict[str, Any]],
) -> dict[str, str]:
    documents = {
        name: snapshot_json_evidence(entry, label=name, base_dir=base_dir)
        for name, entry in entries.items()
    }
    inventory = documents["artifact_inventory"]
    if inventory != {"schema_version": 1, "artifacts": artifacts}:
        raise BuildVerificationError("Artifact inventory is not exact")

    source_inventory = documents["source_inventory"]
    if set(source_inventory) != {"entries", "schema_version", "tree_sha256"}:
        raise BuildVerificationError("Source inventory fields are not exact")
    source_entries = source_inventory.get("entries")
    if (
        type(source_inventory.get("schema_version")) is not int
        or source_inventory["schema_version"] != 1
        or not isinstance(source_entries, list)
        or not source_entries
    ):
        raise BuildVerificationError("Source inventory is invalid")
    validate_source_inventory_entries(source_entries)
    calculated_tree = hashlib.sha256(
        json.dumps(source_entries, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if source_inventory.get("tree_sha256") != calculated_tree:
        raise BuildVerificationError("Source inventory tree digest is invalid")
    expected_source_identity = {
        "repository": policy["approved_request"]["source_repository"],
        "commit": policy["approved_request"]["source_commit"],
        "tree": policy["approved_request"]["source_tree"],
    }
    trusted_source = documents["trusted_source_inventory"]
    if trusted_source != {
        "schema_version": 1,
        "source": expected_source_identity,
        "inventory": source_inventory,
    }:
        raise BuildVerificationError("Trusted source inventory binding is invalid")
    validate_retained_handoff_seal(
        documents["handoff_seal"],
        expected_source_identity=expected_source_identity,
        trusted_source_entry=entries["trusted_source_inventory"],
        source_tree_sha256=calculated_tree,
        raw_trace_entries=raw_trace_entries,
    )

    raw_artifacts = [
        validate_raw_artifact_manifest_entry(entry) for entry in raw_artifact_entries
    ]
    if raw_artifacts != sorted(
        raw_artifacts,
        key=lambda item: item["path"].encode("utf-8"),
    ):
        raise BuildVerificationError("Raw artifact manifest order is not canonical")
    artifact_storage_paths = {
        entry_logical_path(entry): resolve_v3_storage_path(
            entry["path"],
            base_dir=base_dir,
        )
        for entry in [*raw_artifact_entries, *artifact_entries]
    }
    validate_transform_report(
        documents["artifact_transform"],
        raw_artifacts=raw_artifacts,
        artifacts=artifacts,
        policy=policy,
        root=base_dir,
        artifact_storage_paths=artifact_storage_paths,
    )
    validate_builder_report(
        documents["builder_report"],
        transform_entry=entries["artifact_transform"],
        source_inventory_sha256=calculated_tree,
        trace=documents["trace"],
        policy=policy,
    )
    return {"source_filesystem_sha256": calculated_tree}


def validate_retained_handoff_seal(
    value: dict[str, Any],
    *,
    expected_source_identity: dict[str, str],
    trusted_source_entry: dict[str, Any],
    source_tree_sha256: str,
    raw_trace_entries: list[dict[str, Any]],
) -> None:
    if set(value) != {
        "boundary",
        "claim_limit",
        "schema_version",
        "source",
        "status",
        "trusted_source",
    }:
        raise BuildVerificationError("Handoff seal fields are not exact")
    if (
        type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or value.get("status") != "validated"
        or value.get("source") != expected_source_identity
        or value.get("trusted_source")
        != {
            "path": "reports/trusted-source-inventory.json",
            "sha256": evidence_sha256(trusted_source_entry),
            "tree_sha256": source_tree_sha256,
        }
        or value.get("claim_limit")
        != (
            "This seal records a host-side source comparison and live ownership "
            "check before the evidence bundle was made read-only."
        )
    ):
        raise BuildVerificationError("Handoff seal identity is invalid")
    boundary = value.get("boundary")
    if (
        not isinstance(boundary, dict)
        or boundary.get("evidence_root")
        != {
            "uid": 0,
            "gid": 0,
            "mode": "0700",
        }
        or boundary.get("raw_trace_directory")
        != {
            "uid": 0,
            "gid": 0,
            "mode": "0700",
        }
        or set(boundary)
        != {
            "evidence_root",
            "raw_trace_directory",
            "raw_trace_files",
        }
    ):
        raise BuildVerificationError("Handoff seal root boundary is invalid")
    raw_files = boundary.get("raw_trace_files")
    expected_paths = [entry_logical_path(entry) for entry in raw_trace_entries]
    if (
        not isinstance(raw_files, list)
        or not all(isinstance(item, dict) for item in raw_files)
        or [item.get("path") for item in raw_files] != expected_paths
    ):
        raise BuildVerificationError("Handoff seal raw trace set is invalid")
    for item in raw_files:
        mode = item.get("mode")
        if (
            set(item) != {"gid", "mode", "path", "uid"}
            or item.get("uid") != 0
            or item.get("gid") != 0
            or not isinstance(mode, str)
            or re.fullmatch(r"0[0-7]{3}", mode) is None
            or int(mode, 8) & 0o022
        ):
            raise BuildVerificationError("Handoff seal raw trace boundary is invalid")


def snapshot_json_evidence(
    entry: dict[str, Any],
    *,
    label: str,
    base_dir: Path,
) -> dict[str, Any]:
    path = resolve_evidence_entry(entry, base_dir=base_dir, label=label)
    payload, digest = snapshot_bytes(
        path,
        label=label,
        max_bytes=MAX_JSON_BYTES,
    )
    if digest != evidence_sha256(entry):
        raise BuildVerificationError(
            f"{label.capitalize()} changed before verification"
        )
    return decode_json_object(payload, label=label)


def validate_source_inventory_entries(entries: list[Any]) -> None:
    paths: list[str] = []
    folded: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("type") not in {"file", "symlink"}:
            raise BuildVerificationError("Source inventory entry is invalid")
        path = require_safe_logical_path(entry.get("path"), label="source path")
        if path.casefold() in folded:
            raise BuildVerificationError("Source inventory path is aliased")
        folded.add(path.casefold())
        paths.append(path)
        if entry["type"] == "file":
            if (
                set(entry) != {"executable", "path", "sha256", "size", "type"}
                or type(entry.get("executable")) is not bool
                or type(entry.get("size")) is not int
                or entry["size"] < 0
            ):
                raise BuildVerificationError("Source file inventory entry is invalid")
            require_sha256(entry.get("sha256"), label="source file digest")
        elif set(entry) != {"path", "target", "type"} or not isinstance(
            entry.get("target"), str
        ):
            raise BuildVerificationError("Source symlink inventory entry is invalid")
    if paths != sorted(paths, key=lambda path: PurePosixPath(path).parts):
        raise BuildVerificationError("Source inventory order is not canonical")


def validate_raw_artifact_manifest_entry(entry: dict[str, Any]) -> dict[str, Any]:
    if set(entry) != {
        "logical_path",
        "name",
        "path",
        "role",
        "sha256",
        "size",
    }:
        raise BuildVerificationError("Raw artifact manifest fields are not exact")
    path = require_safe_logical_path(
        entry.get("logical_path"),
        label="raw artifact path",
    )
    size = entry.get("size")
    if (
        entry.get("role") != "raw_artifacts"
        or not path.startswith("raw-artifacts/")
        or path.count("/") != 1
        or entry.get("name") != PurePosixPath(path).name
        or type(size) is not int
        or size < 0
    ):
        raise BuildVerificationError("Raw artifact manifest entry is invalid")
    return {
        "path": path,
        "size": size,
        "sha256": require_sha256(entry.get("sha256"), label="raw artifact digest"),
    }


def validate_transform_report(
    value: dict[str, Any],
    *,
    raw_artifacts: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    policy: dict[str, Any],
    root: Path,
    artifact_storage_paths: dict[str, Path],
) -> None:
    request = policy["approved_request"]
    if (
        set(value) != {"artifacts", "error", "policy", "schema_version", "status"}
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or value.get("status") != "succeeded"
        or value.get("error") is not None
        or value.get("policy")
        != expected_canonicalization_policy(request["source_date_epoch"])
        or not isinstance(value.get("artifacts"), list)
    ):
        raise BuildVerificationError("Artifact transform report is invalid")
    raw_by_name = {
        item["path"].removeprefix("raw-artifacts/"): item for item in raw_artifacts
    }
    final_by_name = {item["path"].removeprefix("dist/"): item for item in artifacts}
    if set(raw_by_name) != set(final_by_name):
        raise BuildVerificationError("Raw and canonical artifact names differ")
    seen: set[str] = set()
    wheel_count = 0
    sdist_count = 0
    for item in value["artifacts"]:
        if not isinstance(item, dict) or set(item) != {
            "changed",
            "final",
            "format",
            "member_count",
            "original",
            "path",
            "payload_sha256",
            "payload_size",
            "sdist_layout",
        }:
            raise BuildVerificationError("Artifact transform entry is invalid")
        name = item.get("path")
        if not isinstance(name, str) or name in seen or name not in raw_by_name:
            raise BuildVerificationError("Artifact transform path is invalid")
        seen.add(name)
        if (
            item.get("original") != raw_by_name[name]
            or item.get("final") != final_by_name[name]
        ):
            raise BuildVerificationError("Artifact transform file identity is invalid")
        expected_changed = raw_by_name[name]["sha256"] != final_by_name[name]["sha256"]
        if type(item.get("changed")) is not bool or item["changed"] != expected_changed:
            raise BuildVerificationError("Artifact transform changed flag is invalid")
        payload_size = item.get("payload_size")
        payload_digest = item.get("payload_sha256")
        if type(payload_size) is not int or payload_size < 0:
            raise BuildVerificationError("Artifact transform payload size is invalid")
        require_sha256(payload_digest, label="artifact transform payload digest")
        if name.endswith(".whl"):
            wheel_count += 1
            if (
                item.get("format") != "pass-through"
                or item.get("member_count") is not None
                or item.get("sdist_layout") is not None
                or item["changed"]
                or payload_size != raw_by_name[name]["size"]
                or payload_digest != raw_by_name[name]["sha256"]
            ):
                raise BuildVerificationError("Wheel transform is invalid")
        elif name.endswith(".tar.gz"):
            sdist_count += 1
            if (
                item.get("format") != "python-sdist-tar-gzip"
                or type(item.get("member_count")) is not int
                or item["member_count"] <= 0
                or item.get("sdist_layout")
                not in {"legacy-setup-py", "modern-pyproject"}
            ):
                raise BuildVerificationError("Source distribution transform is invalid")
        else:
            raise BuildVerificationError("Transform contains an unsupported artifact")
    if seen != set(raw_by_name) or wheel_count == 0 or sdist_count == 0:
        raise BuildVerificationError("Artifact transform set is incomplete")
    expected_order = sorted(raw_by_name, key=lambda item: item.encode("utf-8"))
    if [item["path"] for item in value["artifacts"]] != expected_order:
        raise BuildVerificationError("Artifact transform order is not canonical")
    try:
        validate_archive_transforms(
            root,
            value,
            source_date_epoch=int(policy["approved_request"]["source_date_epoch"]),
            paths_by_logical_name=artifact_storage_paths,
        )
    except ArchiveValidationError as exc:
        raise BuildVerificationError(str(exc)) from exc


def expected_canonicalization_policy(source_date_epoch: str) -> dict[str, Any]:
    return {
        "id": CANONICALIZATION_POLICY_ID,
        "source_date_epoch": source_date_epoch,
        "archive_format": "posix-pax",
        "member_order": "utf8-byte-order",
        "tar_padding": "zero-filled-members-and-two-block-end-marker",
        "accepted_sdist_layouts": ["modern-pyproject", "legacy-setup-py"],
        "artifact_namespace": "flat-casefold-unique",
        "member_metadata": {
            "uid": 0,
            "gid": 0,
            "uname": "",
            "gname": "",
            "mtime": source_date_epoch,
            "file_modes": ["0644", "0755"],
            "directory_mode": "0755",
        },
        "gzip": {
            "compression_level": 9,
            "filename": "",
            "flags": 0,
            "mtime": source_date_epoch,
            "xfl": 2,
            "os": 255,
        },
        "limits": {
            "compressed_bytes": 536_870_912,
            "artifact_total_bytes": 1_073_741_824,
            "uncompressed_stream_bytes": 1_140_850_688,
            "payload_bytes": 1_073_741_824,
            "members": 100_000,
            "path_bytes": 4096,
            "path_segment_bytes": 255,
            "pax_headers_per_member": 16,
            "pax_bytes_per_member": 65_536,
            "source_date_epoch_min": MIN_SOURCE_DATE_EPOCH,
            "source_date_epoch_max": MAX_SOURCE_DATE_EPOCH,
        },
    }


def validate_builder_report(
    value: dict[str, Any],
    *,
    transform_entry: dict[str, Any],
    source_inventory_sha256: str,
    trace: dict[str, Any],
    policy: dict[str, Any],
) -> None:
    if set(value) != {
        "artifact_transforms",
        "builder",
        "claim_limit",
        "execution",
        "profile",
        "schema_version",
        "source",
        "status",
        "trace",
    }:
        raise BuildVerificationError("Builder report fields are not exact")
    if (
        type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or value.get("status") != "succeeded"
        or value.get("profile") != PROFILE_ID
        or value.get("claim_limit")
        != (
            "This report declares a root-owned collector and evidence boundary. "
            "Container isolation, source lineage, and resistance to collector "
            "exploitation still require independent verification."
        )
    ):
        raise BuildVerificationError("Builder report identity is invalid")
    builder_policy = policy["builder"]
    expected_builder = {
        "architecture": "x86_64",
        "image": builder_policy["image"],
        "image_digest": builder_policy["image_digest"],
        "python": "3.12.11",
        "tools": {
            "build": "1.5.1",
            "packaging": "26.2",
            "pbr": "7.0.3",
            "pyproject-hooks": "1.2.0",
            "setuptools": "83.0.0",
            "wheel": "0.47.0",
        },
    }
    if value.get("builder") != expected_builder:
        raise BuildVerificationError("Builder report image identity is invalid")
    request = policy["approved_request"]
    expected_source = {
        "repository": request["source_repository"],
        "commit": request["source_commit"],
        "git_tree": request["source_tree"],
        "filesystem_sha256": source_inventory_sha256,
        "project_version": request["project_version"],
        "source_date_epoch": request["source_date_epoch"],
    }
    if value.get("source") != expected_source:
        raise BuildVerificationError("Builder report source identity is invalid")
    if value.get("artifact_transforms") != {
        "policy_id": builder_policy["canonicalization_policy"],
        "report_path": "reports/artifact-transforms.json",
        "report_sha256": evidence_sha256(transform_entry),
    }:
        raise BuildVerificationError("Builder transform pointer is invalid")
    execution = value.get("execution")
    if (
        not isinstance(execution, dict)
        or set(execution)
        != {
            "argv",
            "cwd",
            "finished_at",
            "identity_boundary",
            "network_policy",
            "returncode",
            "started_at",
            "validation_error",
        }
        or execution.get("argv") != V3_EXPECTED_TRACE_ARGV
        or execution.get("cwd") != "/workspace/source"
        or execution.get("network_policy") != "deny"
        or type(execution.get("returncode")) is not int
        or execution["returncode"] != 0
        or execution.get("validation_error") is not None
    ):
        raise BuildVerificationError("Builder execution report is invalid")
    if not validate_raw_identity_boundary(execution.get("identity_boundary")):
        raise BuildVerificationError("Builder identity boundary is invalid")
    expected_trace = {
        field: trace[field]
        for field in (
            "collector",
            "coverage",
            "exit_line_count",
            "parsed_line_count",
            "raw_file_count",
            "signal_line_count",
            "syscall_line_count",
            "unparsed_line_count",
        )
    }
    if value.get("trace") != expected_trace:
        raise BuildVerificationError("Builder trace summary is invalid")


def validate_raw_identity_boundary(value: Any) -> bool:
    expected = {
        "build_gid": 65532,
        "build_uid": 65532,
        "collector_gid": 0,
        "collector_output_writable_by_build": False,
        "collector_uid": 0,
        "evidence_gid": 0,
        "evidence_mode": "0700",
        "evidence_uid": 0,
        "quiescence_barrier": "private-pid-namespace-sigkill",
        "raw_trace_owner_gid": 0,
        "raw_trace_owner_uid": 0,
        "remaining_process_count": 0,
        "separate_collector_identity": True,
    }
    if not isinstance(value, dict) or set(value) != {*expected, "killed_process_count"}:
        return False
    if any(
        value.get(field) != item or type(value.get(field)) is not type(item)
        for field, item in expected.items()
    ):
        return False
    return (
        type(value.get("killed_process_count")) is int
        and value["killed_process_count"] >= 0
    )


def validate_build_predicate(
    value: dict[str, Any],
    *,
    policy: dict[str, Any],
    artifact_records: list[dict[str, Any]],
    evidence_entries: dict[str, dict[str, Any]],
    spdx_bindings: dict[str, Any],
    source_filesystem_sha256: str,
) -> str:
    require_exact_keys(
        value,
        {
            "schemaVersion",
            "predicateType",
            "profile",
            "source",
            "downstream",
            "caller",
            "called",
            "run",
            "builder",
            "materials",
            "artifacts",
            "sbom",
            "evidence",
            "claimLimit",
        },
        label="build predicate",
    )
    if (
        type(value.get("schemaVersion")) is not int
        or value["schemaVersion"] != 2
        or value.get("predicateType") != BUILD_PREDICATE_TYPE
        or value.get("profile") != PROFILE_ID
    ):
        raise BuildVerificationError("Build predicate identity is invalid")
    request = policy["approved_request"]
    source = value.get("source")
    expected_source = {
        "repository": request["source_repository"],
        "commit": request["source_commit"],
        "tree": request["source_tree"],
        "upstreamRepository": request["upstream_repository"],
        "upstreamCommit": request["upstream_commit"],
        "projectVersion": request["project_version"],
        "sourceDateEpoch": request["source_date_epoch"],
    }
    if not isinstance(source, dict) or set(source) != {
        *expected_source,
        "filesystemSha256",
    }:
        raise BuildVerificationError("Build predicate source fields are invalid")
    if any(
        source.get(field) != expected for field, expected in expected_source.items()
    ):
        raise BuildVerificationError("Build predicate source does not match policy")
    if source.get("filesystemSha256") != source_filesystem_sha256:
        raise BuildVerificationError("Build predicate source inventory is invalid")
    expected_downstream = {
        "caseId": request["case_id"],
        "releaseTag": request["release_tag"],
        "targetRepository": request["target_repository"],
    }
    if value.get("downstream") != expected_downstream:
        raise BuildVerificationError("Build predicate downstream claim is invalid")

    signer = policy["signer"]
    caller = value.get("caller")
    if not isinstance(caller, dict):
        raise BuildVerificationError("Build predicate caller claim is invalid")
    caller_digest = require_git_sha(
        caller.get("workflowSha"),
        label="build predicate caller commit",
    )
    if caller_digest not in signer["caller_digests"]:
        raise BuildVerificationError("Build predicate caller commit is not approved")
    expected_caller = {
        "repository": policy["control_repository"],
        "workflowPath": signer["caller_workflow_path"],
        "workflowRef": (
            f"{policy['control_repository']}/{signer['caller_workflow_path']}"
            f"@{signer['source_ref']}"
        ),
        "workflowSha": caller_digest,
    }
    if caller != expected_caller:
        raise BuildVerificationError("Build predicate caller identity is invalid")
    expected_called = {
        "repository": policy["control_repository"],
        "workflowPath": signer["workflow_path"],
        "workflowRef": (
            f"{policy['control_repository']}/{signer['workflow_path']}"
            f"@{signer['workflow_digest']}"
        ),
        "workflowSha": signer["workflow_digest"],
    }
    if value.get("called") != expected_called:
        raise BuildVerificationError("Build predicate called workflow is invalid")

    run = value.get("run")
    if not isinstance(run, dict) or set(run) != {
        "id",
        "attempt",
        "event",
        "actor",
        "triggeringActor",
        "runnerEnvironment",
    }:
        raise BuildVerificationError("Build predicate run fields are invalid")
    run_id = run.get("id")
    if (
        not isinstance(run_id, str)
        or not run_id.isdigit()
        or str(int(run_id)) != run_id
        or int(run_id) <= 0
        or run.get("attempt") != signer["run_attempt"]
        or run.get("event") != signer["trigger"]
        or run.get("actor") != signer["actor"]
        or run.get("triggeringActor") != signer["triggering_actor"]
        or run.get("runnerEnvironment") != "github-hosted"
    ):
        raise BuildVerificationError("Build predicate run identity is invalid")

    builder_policy = policy["builder"]
    expected_builder = {
        "image": builder_policy["image"],
        "imageDigest": builder_policy["image_digest"],
        "network": "none",
        "traceArgv": V3_EXPECTED_TRACE_ARGV,
        "canonicalizationPolicy": builder_policy["canonicalization_policy"],
        "handoffVerifierCommit": builder_policy["handoff_verifier_commit"],
    }
    if not validate_v3_predicate_builder(
        value.get("builder"), expected=expected_builder
    ):
        raise BuildVerificationError("Build predicate builder claim is invalid")
    expected_materials = {
        "builderSources": [
            {"path": path, "sha256": digest}
            for path, digest in sorted(builder_policy["source_digests"].items())
        ],
        "baseImageIndexDigest": builder_policy["base_image_index_digest"],
        "actionPins": policy["actions"],
    }
    if value.get("materials") != expected_materials:
        raise BuildVerificationError("Build predicate materials are invalid")
    if value.get("artifacts") != artifact_records:
        raise BuildVerificationError("Build predicate artifact list is invalid")

    expected_sbom = {
        "normalizationPolicy": policy["spdx"]["normalization_policy"],
        "raw": evidence_record(evidence_entries["raw_sbom"]),
        "normalized": evidence_record(evidence_entries["sbom"]),
        "normalizationReport": {
            "path": "reports/spdx-normalization.json",
            "sha256": evidence_sha256(evidence_entries["spdx_normalization"]),
        },
        "documentNamespace": spdx_bindings["document_namespace"],
        "creationTime": spdx_bindings["creation_time"],
        "artifactBindings": spdx_bindings["bindings"],
    }
    if value.get("sbom") != expected_sbom:
        raise BuildVerificationError("Build predicate SBOM claim is invalid")
    expected_evidence = {
        "artifactSubjectManifest": evidence_record(
            evidence_entries["artifact_subject_manifest"]
        ),
        "artifactInventorySha256": evidence_sha256(
            evidence_entries["artifact_inventory"]
        ),
        "artifactTransformSha256": evidence_sha256(
            evidence_entries["artifact_transform"]
        ),
        "builderReportSha256": evidence_sha256(evidence_entries["builder_report"]),
        "sourceInventorySha256": evidence_sha256(evidence_entries["source_inventory"]),
        "trustedSourceInventorySha256": evidence_sha256(
            evidence_entries["trusted_source_inventory"]
        ),
        "handoffSealSha256": evidence_sha256(evidence_entries["handoff_seal"]),
        "traceSha256": evidence_sha256(evidence_entries["trace"]),
    }
    if value.get("evidence") != expected_evidence:
        raise BuildVerificationError("Build predicate evidence digests are invalid")
    if value.get("claimLimit") != BUILD_CLAIM_LIMIT:
        raise BuildVerificationError("Build predicate claim boundary is invalid")
    return caller_digest


def validate_v3_predicate_builder(value: Any, *, expected: dict[str, Any]) -> bool:
    if not isinstance(value, dict) or set(value) != {*expected, "identityBoundary"}:
        return False
    if any(value.get(field) != item for field, item in expected.items()):
        return False
    boundary = value.get("identityBoundary")
    expected_boundary = {
        "collectorUid": 0,
        "collectorGid": 0,
        "buildUid": 65532,
        "buildGid": 65532,
        "evidenceUid": 0,
        "evidenceGid": 0,
        "evidenceMode": "0700",
        "separateCollectorIdentity": True,
        "collectorOutputWritableByBuild": False,
        "quiescenceBarrier": "private-pid-namespace-sigkill",
        "remainingProcessCount": 0,
    }
    if not isinstance(boundary, dict) or set(boundary) != {
        *expected_boundary,
        "killedProcessCount",
    }:
        return False
    if any(
        boundary.get(field) != item or type(boundary.get(field)) is not type(item)
        for field, item in expected_boundary.items()
    ):
        return False
    return type(boundary.get("killedProcessCount")) is int and (
        boundary["killedProcessCount"] >= 0
    )


def verify_raw_trace_records(
    entries: list[dict[str, Any]],
    *,
    base_dir: Path,
) -> dict[str, Any]:
    if not entries:
        raise BuildVerificationError("Build evidence has no raw trace files")
    paths = [entry_logical_path(entry) for entry in entries]
    if any(
        not isinstance(path, str) or RAW_TRACE_PATH_PATTERN.fullmatch(path) is None
        for path in paths
    ) or len(set(paths)) != len(paths):
        raise BuildVerificationError("Raw trace evidence paths are invalid")
    counts = {"raw": 0, "parsed": 0, "syscall": 0, "signal": 0, "exit": 0}
    events: collections.Counter[tuple[str, ...]] = collections.Counter()
    total_bytes = 0
    for entry in entries:
        path = resolve_evidence_entry(
            entry,
            base_dir=base_dir,
            label="raw trace",
        )
        raw, digest = snapshot_bytes(
            path,
            label="raw trace",
            max_bytes=MAX_RAW_TRACE_FILE_BYTES,
        )
        if not hmac.compare_digest(
            digest,
            require_sha256(entry.get("sha256"), label="raw trace digest"),
        ):
            raise BuildVerificationError("Raw trace changed before verification")
        total_bytes += len(raw)
        if total_bytes > MAX_RAW_TRACE_TOTAL_BYTES:
            raise BuildVerificationError("Raw trace evidence exceeds total size limit")
        try:
            lines = raw.decode("utf-8").splitlines()
        except UnicodeDecodeError as exc:
            raise BuildVerificationError("Raw trace is not valid UTF-8") from exc
        if len(lines) > 10_000_000 or any(
            len(line.encode("utf-8")) > 1024 * 1024 for line in lines
        ):
            raise BuildVerificationError("Raw trace line limit is exceeded")
        counts["raw"] += 1
        for line in lines:
            syscall = RAW_SYSCALL_PATTERN.fullmatch(line)
            if syscall is not None:
                counts["syscall"] += 1
                name = syscall.group("name")
                arguments = syscall.group("args")
                outcome = (
                    "failed" if syscall.group("result").startswith("-1 ") else "success"
                )
                events[("syscall", name, outcome)] += 1
                for event in independently_derived_trace_events(
                    name,
                    arguments,
                    outcome,
                ):
                    events[event] += 1
            elif (signal := RAW_SIGNAL_PATTERN.fullmatch(line)) is not None:
                counts["signal"] += 1
                events[("signal", signal.group("name"))] += 1
            elif (process_exit := RAW_EXIT_PATTERN.fullmatch(line)) is not None:
                counts["exit"] += 1
                events[("process-exit", process_exit.group("status"))] += 1
            else:
                raise BuildVerificationError(
                    "Raw trace contains a record outside the independent grammar"
                )
            counts["parsed"] += 1
    if counts["parsed"] == 0 or counts["syscall"] == 0:
        raise BuildVerificationError("Raw trace has no independently parsed syscalls")
    counts["events"] = [
        independent_trace_event_from_key(key, count)
        for key, count in sorted(events.items())
    ]
    return counts


def independently_derived_trace_events(
    name: str,
    arguments: str,
    outcome: str,
) -> list[tuple[str, ...]]:
    events: list[tuple[str, ...]] = []
    values = independently_decode_quoted_values(arguments)
    if name in {"execve", "execveat"}:
        executable = values[0] if values else "unknown"
        events.append(("process", executable, outcome))
    operation = FILE_OPERATIONS.get(name)
    if operation is not None and values:
        if name in {"open", "openat", "openat2"} and any(
            flag in arguments for flag in WRITE_FLAGS
        ):
            operation = "write"
        events.append(("file", operation, values[0], outcome))
    if name in NETWORK_OPERATIONS and "AF_UNIX" not in arguments:
        host = "unknown"
        port = ""
        ipv4 = re.search(r'inet_addr\("([^"]+)"\)', arguments)
        ipv6 = re.search(r'inet_pton\(AF_INET6, "([^"]+)"', arguments)
        port_match = re.search(r"sin6?_port=htons\(([0-9]+)\)", arguments)
        if ipv4:
            host = ipv4.group(1)
        elif ipv6:
            host = ipv6.group(1)
        if port_match:
            port = port_match.group(1)
        events.append(("network", name, host, port, outcome))
    return events


def independently_decode_quoted_values(value: str) -> list[str]:
    values: list[str] = []
    for match in RAW_QUOTED_PATTERN.finditer(value):
        encoded = f'"{match.group(1)}"'
        try:
            decoded = json.loads(encoded)
        except json.JSONDecodeError:
            decoded = match.group(1)
        values.append(decoded)
    return values


def independent_trace_event_from_key(
    key: tuple[str, ...],
    count: int,
) -> dict[str, Any]:
    kind = key[0]
    if kind == "syscall":
        return {"kind": kind, "name": key[1], "outcome": key[2], "count": count}
    if kind == "process":
        return {
            "kind": kind,
            "exe": key[1],
            "argv": [key[1]],
            "outcome": key[2],
            "count": count,
        }
    if kind == "signal":
        return {"kind": kind, "name": key[1], "count": count}
    if kind == "process-exit":
        return {"kind": kind, "status": key[1], "count": count}
    if kind == "file":
        return {
            "kind": kind,
            "operation": key[1],
            "path": key[2],
            "outcome": key[3],
            "count": count,
        }
    return {
        "kind": kind,
        "operation": key[1],
        "host": key[2],
        "port": int(key[3]) if key[3] else "",
        "protocol": "tcp",
        "outcome": key[4],
        "count": count,
    }


def validate_complete_trace(
    value: dict[str, Any],
    *,
    raw_trace_counts: dict[str, Any],
) -> None:
    coverage = value.get("coverage")
    if (
        set(value)
        != {
            "collector",
            "coverage",
            "coverage_basis",
            "events",
            "exit_line_count",
            "parsed_line_count",
            "raw_file_count",
            "schema_version",
            "signal_line_count",
            "syscall_line_count",
            "unparsed_line_count",
        }
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or value.get("collector")
        != {
            "name": "strace",
            "version": "6.1",
            "platform": "linux",
            "mode": "follow-forks-full-syscall",
        }
        or not isinstance(coverage, dict)
        or set(coverage) != {"process", "file", "network", "syscall"}
        or not all(item is True for item in coverage.values())
        or value.get("coverage_basis") != "complete-parser-pass"
    ):
        raise BuildVerificationError("Observed trace coverage is incomplete")
    required_positive = ("raw_file_count", "parsed_line_count", "syscall_line_count")
    if any(
        not isinstance(value.get(field), int)
        or isinstance(value[field], bool)
        or value[field] <= 0
        for field in required_positive
    ):
        raise BuildVerificationError("Observed trace counts are invalid")
    for field in ("signal_line_count", "exit_line_count"):
        count = value.get(field)
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise BuildVerificationError("Observed trace lifecycle counts are invalid")
    if (
        type(value.get("unparsed_line_count")) is not int
        or value["unparsed_line_count"] != 0
    ):
        raise BuildVerificationError("Observed trace contains unparsed records")
    if value["raw_file_count"] != raw_trace_counts["raw"]:
        raise BuildVerificationError("Observed trace raw-file count is inconsistent")
    expected_counts = {
        "parsed_line_count": raw_trace_counts["parsed"],
        "syscall_line_count": raw_trace_counts["syscall"],
        "signal_line_count": raw_trace_counts["signal"],
        "exit_line_count": raw_trace_counts["exit"],
    }
    if any(value.get(field) != count for field, count in expected_counts.items()):
        raise BuildVerificationError(
            "Observed trace counts do not match independently parsed raw records"
        )
    if value.get("events") != raw_trace_counts["events"]:
        raise BuildVerificationError(
            "Observed trace events do not match independently parsed raw records"
        )


def validate_build_verification_output(
    entries: list[Any],
    *,
    role: str,
    predicate_type: str,
    expected_subjects: set[tuple[str, str]],
    expected_predicate: dict[str, Any] | None,
    policy: dict[str, Any],
    caller_digest: str,
    run_claim: dict[str, Any],
) -> int:
    if len(entries) != 1 or not isinstance(entries[0], dict):
        raise BuildVerificationError(
            f"{role.capitalize()} verifier must return one attestation"
        )
    verification = entries[0].get("verificationResult")
    if not isinstance(verification, dict):
        raise BuildVerificationError(f"{role.capitalize()} verification is missing")
    statement = verification.get("statement")
    signature = verification.get("signature")
    timestamps = verification.get("verifiedTimestamps")
    if (
        not isinstance(statement, dict)
        or not isinstance(signature, dict)
        or not isinstance(timestamps, list)
        or not timestamps
    ):
        raise BuildVerificationError(
            f"{role.capitalize()} verification output is incomplete"
        )
    transparency = [
        timestamp
        for timestamp in timestamps
        if isinstance(timestamp, dict)
        and isinstance(timestamp.get("type"), str)
        and (
            "tlog" in timestamp["type"].casefold()
            or "transparency" in timestamp["type"].casefold()
        )
    ]
    if not transparency:
        raise BuildVerificationError(
            f"{role.capitalize()} verification has no transparency timestamp"
        )
    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        raise BuildVerificationError(f"{role.capitalize()} is not in-toto v1")
    if statement.get("predicateType") != predicate_type:
        raise BuildVerificationError(f"{role.capitalize()} predicate type is invalid")
    if statement_subjects(statement) != expected_subjects:
        raise BuildVerificationError(f"{role.capitalize()} subjects are invalid")
    validate_build_certificate(
        signature.get("certificate"),
        policy=policy,
        caller_digest=caller_digest,
        run_claim=run_claim,
    )
    predicate = statement.get("predicate")
    if role == "provenance":
        validate_build_provenance(
            predicate,
            policy=policy,
            caller_digest=caller_digest,
            run_claim=run_claim,
        )
    elif predicate != expected_predicate:
        raise BuildVerificationError(
            f"{role.capitalize()} predicate does not match retained evidence"
        )
    return len(transparency)


def validate_build_certificate(
    value: Any,
    *,
    policy: dict[str, Any],
    caller_digest: str,
    run_claim: dict[str, Any],
) -> None:
    if not isinstance(value, dict):
        raise BuildVerificationError("Verified build attestation has no certificate")
    signer = policy["signer"]
    if caller_digest not in signer["caller_digests"]:
        raise BuildVerificationError("Verified build caller commit is not approved")
    control_repository = policy["control_repository"]
    caller_identity = (
        f"https://github.com/{control_repository}/{signer['caller_workflow_path']}"
        f"@{signer['source_ref']}"
    )
    expected = {
        "subjectAlternativeName": signer["certificate_identity"],
        "issuer": signer["oidc_issuer"],
        "githubWorkflowSHA": caller_digest,
        "githubWorkflowName": signer["workflow_name"],
        "githubWorkflowRepository": control_repository,
        "githubWorkflowRef": signer["source_ref"],
        "githubWorkflowTrigger": signer["trigger"],
        "buildSignerURI": signer["certificate_identity"],
        "buildSignerDigest": signer["workflow_digest"],
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": f"https://github.com/{control_repository}",
        "sourceRepositoryDigest": caller_digest,
        "sourceRepositoryRef": signer["source_ref"],
        "buildConfigURI": caller_identity,
        "buildConfigDigest": caller_digest,
        "buildTrigger": signer["trigger"],
        "runInvocationURI": (
            f"https://github.com/{control_repository}/actions/runs/"
            f"{run_claim['id']}/attempts/{run_claim['attempt']}"
        ),
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            raise BuildVerificationError(
                f"Verified build certificate does not match {field}"
            )


def validate_build_provenance(
    value: Any,
    *,
    policy: dict[str, Any],
    caller_digest: str,
    run_claim: dict[str, Any],
) -> None:
    if not isinstance(value, dict):
        raise BuildVerificationError("Build provenance predicate is invalid")
    if caller_digest not in policy["signer"]["caller_digests"]:
        raise BuildVerificationError("Build provenance caller commit is not approved")
    build_definition = value.get("buildDefinition")
    run_details = value.get("runDetails")
    if not isinstance(build_definition, dict) or not isinstance(run_details, dict):
        raise BuildVerificationError("Build provenance predicate is incomplete")
    if build_definition.get("buildType") != GITHUB_WORKFLOW_BUILD_TYPE:
        raise BuildVerificationError("Build provenance type is not GitHub Actions")
    signer = policy["signer"]
    control_repository = policy["control_repository"]
    external = build_definition.get("externalParameters")
    workflow = external.get("workflow") if isinstance(external, dict) else None
    expected_workflow = {
        "path": signer["caller_workflow_path"],
        "ref": signer["source_ref"],
        "repository": f"https://github.com/{control_repository}",
    }
    if workflow != expected_workflow:
        raise BuildVerificationError("Build provenance caller workflow is invalid")
    dependencies = build_definition.get("resolvedDependencies")
    expected_uri = f"git+https://github.com/{control_repository}@{signer['source_ref']}"
    if not isinstance(dependencies, list) or not any(
        isinstance(dependency, dict)
        and dependency.get("uri") == expected_uri
        and isinstance(dependency.get("digest"), dict)
        and dependency["digest"].get("gitCommit") == caller_digest
        for dependency in dependencies
    ):
        raise BuildVerificationError("Build provenance caller commit is invalid")
    builder = run_details.get("builder")
    if (
        not isinstance(builder, dict)
        or builder.get("id") != signer["certificate_identity"]
    ):
        raise BuildVerificationError("Build provenance signer identity is invalid")
    metadata = run_details.get("metadata")
    expected_invocation = (
        f"https://github.com/{control_repository}/actions/runs/"
        f"{run_claim['id']}/attempts/{run_claim['attempt']}"
    )
    if (
        not isinstance(metadata, dict)
        or metadata.get("invocationId") != expected_invocation
    ):
        raise BuildVerificationError("Build provenance run invocation is invalid")
