from __future__ import annotations

import hashlib
import hmac
import json
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from assured_downstream.builder_handoff import (
    CUSTOM_PREDICATE_TYPE as BUILD_PREDICATE_TYPE,
)
from assured_downstream.command_runner import CommandRunner, display_command
from assured_downstream.evidence import verify_evidence_manifest
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
    decode_json_array,
    decode_json_object,
    github_attestation_verify_command,
    isolated_verifier_environment,
    require_evidence_roles,
    require_exact_keys,
    require_git_sha,
    require_repository,
    require_sha256,
    require_subject_name,
    require_successful_verifier_result,
    resolve_evidence_entry,
    snapshot_bytes,
    statement_subjects,
    validate_release_verification_policy,
    validate_spdx_subject_binding,
)


BUILD_VERIFICATION_POLICY_SCHEMA_VERSION = 1
BUILD_VERIFICATION_RECORD_SCHEMA_VERSION = 1
TRUSTED_BUILD_VERIFICATION_POLICY_SHA256 = (
    "e6e26dbb4df43fb8c4dc169b594d1d527842619d1199b9e2d8bcb76604440080"
)
BUILD_BUNDLE_FILENAMES = {
    "provenance": "provenance.sigstore.json",
    "sbom": "sbom.sigstore.json",
    "build": "build.sigstore.json",
}
BUILD_CLAIM_LIMIT = (
    "The workflow signs these build observations. Source ancestry, workflow "
    "approval, builder containment, and semantic safety require independent "
    "verification."
)
RAW_SYSCALL_PATTERN = re.compile(
    r"^[0-9]+\.[0-9]+\s+[A-Za-z0-9_]+\(.*\)\s+=\s+"
    r".*?(?:\s+<[0-9.]+>)?$"
)
RAW_SIGNAL_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\s+---\s+SIG[A-Z0-9]+\s+\{.*\}\s+---$")
RAW_EXIT_PATTERN = re.compile(
    r"^[0-9]+\.[0-9]+\s+\+\+\+\s+"
    r"(?:exited with [0-9]+|killed by SIG[A-Z0-9]+(?: \(core dumped\))?)"
    r"\s+\+\+\+$"
)
RAW_TRACE_PATH_PATTERN = re.compile(r"^traces/raw/strace\.[0-9]+$")
MAX_RAW_TRACE_FILE_BYTES = 64 * 1024 * 1024
MAX_RAW_TRACE_TOTAL_BYTES = 256 * 1024 * 1024


class BuildVerificationError(RuntimeError):
    pass


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
    evidence_path = evidence_path.expanduser().resolve()
    policy_path = policy_path.expanduser().resolve()
    trust_policy_path = trust_policy_path.expanduser().resolve()
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
    if not hmac.compare_digest(
        policy_sha256,
        TRUSTED_BUILD_VERIFICATION_POLICY_SHA256,
    ):
        raise BuildVerificationError(
            "Build verification policy is not anchored by this build"
        )
    policy = validate_build_verification_policy(
        decode_json_object(policy_bytes, label="build verification policy")
    )
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
    try:
        evidence_verification = verify_evidence_manifest(
            evidence,
            base_dir=evidence_path.parent,
        )
    except (AttributeError, KeyError, OSError, TypeError, ValueError) as exc:
        raise BuildVerificationError("Build evidence manifest is invalid") from exc
    if not evidence_verification["ok"]:
        raise BuildVerificationError(
            "Build evidence manifest failed local verification: "
            + "; ".join(evidence_verification["failures"])
        )

    project = validate_build_project(evidence.get("project"), policy=policy)
    roles = require_evidence_roles(evidence.get("evidence"))
    artifact_entries = roles["artifacts"]
    if not artifact_entries:
        raise BuildVerificationError("Build evidence has no artifact subjects")
    if len(roles["sboms"]) != 1:
        raise BuildVerificationError("Build verification requires one SPDX SBOM")
    bundles = identify_build_bundles(roles["attestations"])
    expected_subjects = {
        (
            require_subject_name(entry.get("name"), label="artifact subject name"),
            require_sha256(entry.get("sha256"), label="artifact digest"),
        )
        for entry in artifact_entries
    }
    if len(expected_subjects) != len(artifact_entries):
        raise BuildVerificationError("Artifact evidence contains duplicate subjects")

    evidence_roles = evidence.get("evidence")
    if not isinstance(evidence_roles, dict):
        raise BuildVerificationError("Build evidence roles are invalid")
    reports = require_entry_list(evidence_roles.get("reports"), label="reports")
    traces = require_entry_list(evidence_roles.get("traces"), label="traces")
    sbom_entry = roles["sboms"][0]
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
    if sbom.get("spdxVersion") != "SPDX-2.3":
        raise BuildVerificationError("SBOM is not an SPDX 2.3 document")
    spdx_subjects = validate_spdx_subject_binding(
        sbom,
        expected_subjects=expected_subjects,
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
    validate_build_predicate(
        build_predicate,
        policy=policy,
        artifact_count=len(expected_subjects),
        evidence_entries={
            "artifact_inventory": unique_entry_by_path(
                reports, "reports/artifact-inventory.json"
            ),
            "builder_report": unique_entry_by_path(reports, "reports/builder.json"),
            "source_inventory": unique_entry_by_path(
                reports, "reports/source-inventory.json"
            ),
            "trace": unique_entry_by_path(traces, "traces/observed-trace.json"),
            "sbom": sbom_entry,
        },
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
                source_digest=signer["caller_digest"],
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
        "sigstore_trusted_root_sha256": trusted_root_sha256,
        "target_full_name": project["target_full_name"],
        "source_repository": request["source_repository"],
        "source_commit": request["source_commit"],
        "caller_repository": policy["control_repository"],
        "caller_digest": signer["caller_digest"],
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
        "spdx_referenced_subjects": [
            {"sha256": digest} for digest in sorted(spdx_subjects)
        ],
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
            "build-predicate-content",
            "complete-trace-parser-pass",
        ],
        "attested_claims": {
            "upstream_repository": request["upstream_repository"],
            "upstream_commit": request["upstream_commit"],
            "source_tree": request["source_tree"],
            "target_repository": request["target_repository"],
        },
        "independently_verified": {
            "sigstore_bundles": True,
            "artifact_subjects": True,
            "sbom_artifact_binding": True,
            "trace_parser_completeness": True,
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
            "predicates",
            "trust_policy_sha256",
            "claim_limit",
        },
        label="build verification policy",
    )
    if policy.get("schema_version") != BUILD_VERIFICATION_POLICY_SCHEMA_VERSION:
        raise BuildVerificationError("Unsupported build verification policy schema")
    if policy.get("status") != "active-dev-case-study":
        raise BuildVerificationError("Build verification policy is not active")
    control_repository = require_repository(
        policy.get("control_repository"),
        label="control repository",
    )
    if control_repository != "SauceTaster/assured-downstream":
        raise BuildVerificationError("Build verifier control repository is invalid")
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
            "caller_digest",
            "source_ref",
            "trigger",
            "oidc_issuer",
            "deny_self_hosted_runners",
        },
        label="build signer policy",
    )
    for field in ("workflow_path", "caller_workflow_path"):
        value = signer.get(field)
        if (
            not isinstance(value, str)
            or not value.startswith(".github/workflows/")
            or not value.endswith((".yml", ".yaml"))
            or ".." in value
        ):
            raise BuildVerificationError(f"Build signer {field} is invalid")
    workflow_digest = require_git_sha(
        signer.get("workflow_digest"), label="signer workflow digest"
    )
    require_git_sha(signer.get("caller_digest"), label="caller workflow digest")
    expected_identity = (
        f"https://github.com/{control_repository}/{signer['workflow_path']}"
        f"@{workflow_digest}"
    )
    if signer.get("certificate_identity") != expected_identity:
        raise BuildVerificationError("Build signer certificate identity is not exact")
    if signer.get("source_ref") != "refs/heads/main":
        raise BuildVerificationError("Build signer source ref is not protected main")
    if signer.get("trigger") != "workflow_dispatch":
        raise BuildVerificationError("Build signer trigger is not approved")
    if signer.get("oidc_issuer") != GITHUB_ACTIONS_OIDC_ISSUER:
        raise BuildVerificationError("Build signer OIDC issuer is not approved")
    if signer.get("deny_self_hosted_runners") is not True:
        raise BuildVerificationError("Build signer must reject self-hosted runners")

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
            "upstream_repository",
            "upstream_commit",
            "target_repository",
            "project_version",
            "release_tag",
        },
        label="approved build request",
    )
    for field in ("source_repository", "upstream_repository", "target_repository"):
        require_repository(request.get(field), label=field)
    for field in ("source_commit", "source_tree", "upstream_commit"):
        require_git_sha(request.get(field), label=field)
    for field in ("case_id", "project_version", "release_tag"):
        if not isinstance(request.get(field), str) or not request[field]:
            raise BuildVerificationError(f"Approved request {field} is invalid")
    if not request["target_repository"].startswith("SauceTaster/assured-"):
        raise BuildVerificationError("Approved target repository is outside policy")

    builder = policy.get("builder")
    if not isinstance(builder, dict):
        raise BuildVerificationError("Build image policy is invalid")
    require_exact_keys(
        builder,
        {"profile", "image", "image_digest", "handoff_verifier_commit"},
        label="build image policy",
    )
    if builder.get("profile") != "python-wheel-v1":
        raise BuildVerificationError("Build profile is not approved")
    image = builder.get("image")
    image_digest = builder.get("image_digest")
    if image != "ghcr.io/saucetaster/assured-downstream-python-builder":
        raise BuildVerificationError("Build image repository is not approved")
    if (
        not isinstance(image_digest, str)
        or not image_digest.startswith("sha256:")
        or require_sha256(image_digest.removeprefix("sha256:"), label="image digest")
        != image_digest.removeprefix("sha256:")
    ):
        raise BuildVerificationError("Build image digest is invalid")
    require_git_sha(
        builder.get("handoff_verifier_commit"),
        label="handoff verifier commit",
    )
    predicates = policy.get("predicates")
    expected_predicates = {
        "provenance": SLSA_PROVENANCE_PREDICATE_TYPE,
        "sbom": SPDX_23_PREDICATE_TYPE,
        "build": BUILD_PREDICATE_TYPE,
    }
    if predicates != expected_predicates:
        raise BuildVerificationError("Build predicate policy is invalid")
    require_sha256(
        policy.get("trust_policy_sha256"),
        label="trust policy digest",
    )
    if not isinstance(policy.get("claim_limit"), str) or not policy["claim_limit"]:
        raise BuildVerificationError("Build verification claim limit is invalid")
    return policy


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
    }
    if any(
        value.get(field) != expected_value for field, expected_value in expected.items()
    ):
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
    value = entry.get("original_path", entry.get("path"))
    return value if isinstance(value, str) else ""


def validate_build_predicate(
    value: dict[str, Any],
    *,
    policy: dict[str, Any],
    artifact_count: int,
    evidence_entries: dict[str, dict[str, Any]],
) -> None:
    require_exact_keys(
        value,
        {
            "schemaVersion",
            "predicateType",
            "source",
            "downstream",
            "caller",
            "builder",
            "evidence",
            "claimLimit",
        },
        label="build predicate",
    )
    request = policy["approved_request"]
    signer = policy["signer"]
    builder_policy = policy["builder"]
    if (
        value.get("schemaVersion") != 1
        or value.get("predicateType") != BUILD_PREDICATE_TYPE
    ):
        raise BuildVerificationError("Build predicate identity is invalid")
    source = value.get("source")
    if not isinstance(source, dict):
        raise BuildVerificationError("Build predicate source is invalid")
    expected_source = {
        "repository": request["source_repository"],
        "commit": request["source_commit"],
        "tree": request["source_tree"],
        "projectVersion": request["project_version"],
        "upstreamRepository": request["upstream_repository"],
        "upstreamCommit": request["upstream_commit"],
    }
    if any(
        source.get(field) != expected for field, expected in expected_source.items()
    ):
        raise BuildVerificationError("Build predicate source does not match policy")
    source_date_epoch = source.get("sourceDateEpoch")
    if not isinstance(source_date_epoch, str) or not source_date_epoch.isdigit():
        raise BuildVerificationError("Build predicate source date is invalid")
    expected_downstream = {
        "caseId": request["case_id"],
        "releaseTag": request["release_tag"],
        "targetRepository": request["target_repository"],
    }
    if value.get("downstream") != expected_downstream:
        raise BuildVerificationError("Build predicate downstream claim is invalid")
    expected_caller = {
        "repository": policy["control_repository"],
        "commit": signer["caller_digest"],
        "ref": signer["source_ref"],
    }
    if value.get("caller") != expected_caller:
        raise BuildVerificationError("Build predicate caller claim is invalid")
    expected_builder = {
        "profile": builder_policy["profile"],
        "image": builder_policy["image"],
        "imageDigest": builder_policy["image_digest"],
        "uid": 65532,
        "gid": 65532,
        "network": "none",
        "readOnlyRoot": True,
        "capabilities": [],
        "noNewPrivileges": True,
    }
    if value.get("builder") != expected_builder:
        raise BuildVerificationError("Build predicate builder claim is invalid")
    expected_evidence = {
        "artifactCount": artifact_count,
        "artifactInventorySha256": evidence_entries["artifact_inventory"]["sha256"],
        "builderReportSha256": evidence_entries["builder_report"]["sha256"],
        "sourceInventorySha256": evidence_entries["source_inventory"]["sha256"],
        "traceSha256": evidence_entries["trace"]["sha256"],
        "sbomSha256": evidence_entries["sbom"]["sha256"],
    }
    evidence_claim = value.get("evidence")
    if not isinstance(evidence_claim, dict):
        raise BuildVerificationError("Build predicate evidence claim is invalid")
    if evidence_claim != expected_evidence:
        raise BuildVerificationError("Build predicate evidence digests are invalid")
    if value.get("claimLimit") != BUILD_CLAIM_LIMIT:
        raise BuildVerificationError("Build predicate claim boundary is invalid")


def verify_raw_trace_records(
    entries: list[dict[str, Any]],
    *,
    base_dir: Path,
) -> dict[str, int]:
    if not entries:
        raise BuildVerificationError("Build evidence has no raw trace files")
    paths = [entry_logical_path(entry) for entry in entries]
    if any(
        not isinstance(path, str) or RAW_TRACE_PATH_PATTERN.fullmatch(path) is None
        for path in paths
    ) or len(set(paths)) != len(paths):
        raise BuildVerificationError("Raw trace evidence paths are invalid")
    counts = {"raw": 0, "parsed": 0, "syscall": 0, "signal": 0, "exit": 0}
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
        counts["raw"] += 1
        for line in lines:
            if RAW_SYSCALL_PATTERN.fullmatch(line) is not None:
                counts["syscall"] += 1
            elif RAW_SIGNAL_PATTERN.fullmatch(line) is not None:
                counts["signal"] += 1
            elif RAW_EXIT_PATTERN.fullmatch(line) is not None:
                counts["exit"] += 1
            else:
                raise BuildVerificationError(
                    "Raw trace contains a record outside the independent grammar"
                )
            counts["parsed"] += 1
    if counts["parsed"] == 0 or counts["syscall"] == 0:
        raise BuildVerificationError("Raw trace has no independently parsed syscalls")
    return counts


def validate_complete_trace(
    value: dict[str, Any],
    *,
    raw_trace_counts: dict[str, int],
) -> None:
    coverage = value.get("coverage")
    if (
        not isinstance(coverage, dict)
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
    if value.get("unparsed_line_count") != 0:
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


def validate_build_verification_output(
    entries: list[Any],
    *,
    role: str,
    predicate_type: str,
    expected_subjects: set[tuple[str, str]],
    expected_predicate: dict[str, Any] | None,
    policy: dict[str, Any],
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
    validate_build_certificate(signature.get("certificate"), policy=policy)
    predicate = statement.get("predicate")
    if role == "provenance":
        validate_build_provenance(predicate, policy=policy)
    elif predicate != expected_predicate:
        raise BuildVerificationError(
            f"{role.capitalize()} predicate does not match retained evidence"
        )
    return len(transparency)


def validate_build_certificate(value: Any, *, policy: dict[str, Any]) -> None:
    if not isinstance(value, dict):
        raise BuildVerificationError("Verified build attestation has no certificate")
    signer = policy["signer"]
    control_repository = policy["control_repository"]
    caller_identity = (
        f"https://github.com/{control_repository}/{signer['caller_workflow_path']}"
        f"@{signer['source_ref']}"
    )
    expected = {
        "subjectAlternativeName": signer["certificate_identity"],
        "issuer": signer["oidc_issuer"],
        "githubWorkflowSHA": signer["caller_digest"],
        "githubWorkflowRepository": control_repository,
        "githubWorkflowRef": signer["source_ref"],
        "githubWorkflowTrigger": signer["trigger"],
        "buildSignerURI": signer["certificate_identity"],
        "buildSignerDigest": signer["workflow_digest"],
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": f"https://github.com/{control_repository}",
        "sourceRepositoryDigest": signer["caller_digest"],
        "sourceRepositoryRef": signer["source_ref"],
        "buildConfigURI": caller_identity,
        "buildConfigDigest": signer["caller_digest"],
        "buildTrigger": signer["trigger"],
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            raise BuildVerificationError(
                f"Verified build certificate does not match {field}"
            )


def validate_build_provenance(value: Any, *, policy: dict[str, Any]) -> None:
    if not isinstance(value, dict):
        raise BuildVerificationError("Build provenance predicate is invalid")
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
        and dependency["digest"].get("gitCommit") == signer["caller_digest"]
        for dependency in dependencies
    ):
        raise BuildVerificationError("Build provenance caller commit is invalid")
    builder = run_details.get("builder")
    if (
        not isinstance(builder, dict)
        or builder.get("id") != signer["certificate_identity"]
    ):
        raise BuildVerificationError("Build provenance signer identity is invalid")
