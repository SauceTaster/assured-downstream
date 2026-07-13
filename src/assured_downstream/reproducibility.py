from __future__ import annotations

import copy
import gzip
import hashlib
import hmac
import json
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from assured_downstream.agent_contracts import content_digest
from assured_downstream.behavior import compare_behavior_reports, normalize_trace
from assured_downstream.catalog import utc_now
from assured_downstream.evidence import sha256_file
from assured_downstream.release_verification import (
    ReleaseVerificationError,
    resolve_evidence_entry,
    snapshot_bytes,
)


MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_PAYLOAD_BYTES = 2 * 1024 * 1024 * 1024
MAX_REPORTED_DIFFERENCES = 50
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
COMPARABLE_VERIFICATION_FIELDS = (
    "authority",
    "builder_image",
    "case_id",
    "policy_sha256",
    "signer",
    "signer_digest",
    "source_commit",
    "source_repository",
    "target_full_name",
    "trust_policy_sha256",
)
TRACE_SUMMARY_FIELDS = (
    "collector",
    "coverage",
    "coverage_basis",
    "exit_line_count",
    "parsed_line_count",
    "raw_file_count",
    "signal_line_count",
    "syscall_line_count",
    "unparsed_line_count",
)


class ReproducibilityError(RuntimeError):
    pass


@dataclass(frozen=True)
class ArchiveInspection:
    summary: dict[str, Any]
    payload_members: dict[str, dict[str, Any]]
    metadata_members: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class ReproducibilityAnalysis:
    report: dict[str, Any]
    left_behavior: dict[str, Any]
    right_behavior: dict[str, Any]


def compare_verified_builds(
    *,
    left_evidence_path: Path,
    right_evidence_path: Path,
    left_verification: dict[str, Any],
    right_verification: dict[str, Any],
    left_execution_id: str,
    right_execution_id: str,
) -> ReproducibilityAnalysis:
    left_execution_id = require_execution_id(left_execution_id, label="left")
    right_execution_id = require_execution_id(right_execution_id, label="right")
    if left_execution_id == right_execution_id:
        raise ReproducibilityError("Rebuild execution identifiers must be distinct")

    validate_verification_record(left_verification, label="left")
    validate_verification_record(right_verification, label="right")
    identity_checks = comparable_identity_checks(
        left_verification,
        right_verification,
    )
    failed_identity = [check for check in identity_checks if not check["passed"]]
    if failed_identity:
        names = ", ".join(check["field"] for check in failed_identity)
        raise ReproducibilityError(
            f"Verified rebuild identities are not comparable: {names}"
        )

    left_manifest = read_verified_manifest(
        left_evidence_path,
        expected_sha256=left_verification.get("evidence_sha256"),
        label="left evidence",
    )
    right_manifest = read_verified_manifest(
        right_evidence_path,
        expected_sha256=right_verification.get("evidence_sha256"),
        label="right evidence",
    )
    artifacts = compare_artifacts(
        left_manifest,
        right_manifest,
        left_root=left_evidence_path.resolve().parent,
        right_root=right_evidence_path.resolve().parent,
    )
    sbom = compare_sboms(
        left_manifest,
        right_manifest,
        left_root=left_evidence_path.resolve().parent,
        right_root=right_evidence_path.resolve().parent,
    )
    materials = compare_json_report(
        left_manifest,
        right_manifest,
        name="source-inventory.json",
        left_root=left_evidence_path.resolve().parent,
        right_root=right_evidence_path.resolve().parent,
    )
    left_builder, left_builder_entry = load_json_entry(
        left_manifest,
        role="reports",
        name="builder.json",
        root=left_evidence_path.resolve().parent,
    )
    right_builder, right_builder_entry = load_json_entry(
        right_manifest,
        role="reports",
        name="builder.json",
        root=right_evidence_path.resolve().parent,
    )
    builder = compare_builder_reports(
        left_builder,
        right_builder,
        left_entry=left_builder_entry,
        right_entry=right_builder_entry,
    )
    if not builder["distinct_execution_windows"]:
        raise ReproducibilityError(
            "Rebuild evidence does not contain distinct builder execution windows"
        )
    if not distinct_attestation_sets(left_verification, right_verification):
        raise ReproducibilityError(
            "Rebuild evidence reuses the same verified attestation set"
        )

    trace, left_behavior, right_behavior = compare_trace_diagnostics(
        left_manifest,
        right_manifest,
        left_root=left_evidence_path.resolve().parent,
        right_root=right_evidence_path.resolve().parent,
        left_builder=left_builder,
        right_builder=right_builder,
    )
    blocking_findings = build_blocking_findings(
        artifacts=artifacts,
        sbom=sbom,
        materials=materials,
        builder=builder,
    )
    warnings = build_warnings(
        left_verification=left_verification,
        right_verification=right_verification,
        trace=trace,
    )
    reproducible = not blocking_findings
    report = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": "matched" if reproducible else "mismatch",
        "ok": reproducible,
        "reproducible": reproducible,
        "comparison_eligible": True,
        "provider_independent": False,
        "execution": {
            "declared_left_id": left_execution_id,
            "declared_right_id": right_execution_id,
            "declared_ids_distinct": True,
            "identifiers_attested": False,
            "independence": "not-established",
            "identity_authority": "externally-supplied-run-identifiers",
            "distinct_attestation_sets": True,
            "distinct_builder_windows": True,
        },
        "identity": {
            "checks": identity_checks,
            "left_caller_digest": left_verification.get("caller_digest"),
            "right_caller_digest": right_verification.get("caller_digest"),
            "same_caller_digest": left_verification.get("caller_digest")
            == right_verification.get("caller_digest"),
        },
        "artifacts": artifacts,
        "sbom": sbom,
        "materials": materials,
        "builder": builder,
        "behavior_diagnostic": trace,
        "blocking_findings": blocking_findings,
        "warnings": warnings,
        "claim_limit": (
            "This compares two retained evidence sets after independently "
            "reverifying their GitHub-hosted-runner attestations. Their signed "
            "attestation sets and builder windows differ, but the supplied run "
            "identifiers are not attested. It does not establish independent "
            "builders, collector tamper resistance, source ancestry, semantic "
            "safety, or behavior-reproducible assurance."
        ),
    }
    return ReproducibilityAnalysis(
        report=report,
        left_behavior=left_behavior,
        right_behavior=right_behavior,
    )


def compare_artifacts(
    left: dict[str, Any],
    right: dict[str, Any],
    *,
    left_root: Path,
    right_root: Path,
) -> dict[str, Any]:
    left_entries = entry_index(left, role="artifacts")
    right_entries = entry_index(right, role="artifacts")
    names = sorted(set(left_entries) | set(right_entries))
    comparisons = []
    for name in names:
        left_entry = left_entries.get(name)
        right_entry = right_entries.get(name)
        if left_entry is None or right_entry is None:
            comparisons.append(
                {
                    "name": name,
                    "classification": "missing-artifact",
                    "exact_match": False,
                    "payload_equivalent": False,
                    "left": entry_identity(left_entry),
                    "right": entry_identity(right_entry),
                }
            )
            continue
        left_path = verified_entry_path(left_entry, root=left_root, label=name)
        right_path = verified_entry_path(right_entry, root=right_root, label=name)
        exact_match = (
            left_entry["sha256"] == right_entry["sha256"]
            and left_entry["size"] == right_entry["size"]
        )
        comparison: dict[str, Any] = {
            "name": name,
            "classification": "exact-match" if exact_match else "byte-mismatch",
            "exact_match": exact_match,
            "payload_equivalent": exact_match,
            "left": entry_identity(left_entry),
            "right": entry_identity(right_entry),
        }
        if not exact_match and is_tar_gzip(name):
            archive = compare_tar_archives(left_path, right_path)
            comparison["archive"] = archive
            comparison["payload_equivalent"] = archive["payload_equivalent"]
            comparison["classification"] = (
                "archive-metadata-only"
                if archive["payload_equivalent"]
                else "archive-payload-mismatch"
            )
        comparisons.append(comparison)
    return {
        "exact_match": bool(comparisons)
        and all(item["exact_match"] for item in comparisons),
        "payload_equivalent": bool(comparisons)
        and all(item["payload_equivalent"] for item in comparisons),
        "count": len(comparisons),
        "comparisons": comparisons,
    }


def compare_tar_archives(left_path: Path, right_path: Path) -> dict[str, Any]:
    left = inspect_tar_archive(left_path)
    right = inspect_tar_archive(right_path)
    payload_equivalent = left.payload_members == right.payload_members
    metadata_fields = differing_archive_metadata_fields(left, right)
    payload_differences = compare_member_maps(
        left.payload_members,
        right.payload_members,
    )
    return {
        "payload_equivalent": payload_equivalent,
        "left": left.summary,
        "right": right.summary,
        "metadata_difference_fields": metadata_fields,
        "payload_differences": payload_differences,
    }


def inspect_tar_archive(path: Path) -> ArchiveInspection:
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ReproducibilityError(f"Archive exceeds compressed size limit: {path}")
    payload_members: dict[str, dict[str, Any]] = {}
    metadata_members: dict[str, dict[str, Any]] = {}
    total_payload_bytes = 0
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            for member_number, member in enumerate(archive, start=1):
                if member_number > MAX_ARCHIVE_MEMBERS:
                    raise ReproducibilityError(
                        f"Archive exceeds member count limit: {path}"
                    )
                name = safe_archive_member_name(member.name)
                if name in payload_members:
                    raise ReproducibilityError(
                        f"Archive contains a duplicate member: {name}"
                    )
                if member.isdir():
                    member_type = "directory"
                    member_sha256 = None
                    member_size = 0
                elif member.isfile():
                    member_type = "file"
                    member_size = member.size
                    if member_size < 0:
                        raise ReproducibilityError(
                            f"Archive member size is invalid: {name}"
                        )
                    total_payload_bytes += member_size
                    if total_payload_bytes > MAX_ARCHIVE_PAYLOAD_BYTES:
                        raise ReproducibilityError(
                            f"Archive exceeds payload size limit: {path}"
                        )
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise ReproducibilityError(
                            f"Unable to read archive member: {name}"
                        )
                    member_sha256 = digest_stream(
                        extracted,
                        expected_size=member_size,
                    )
                else:
                    raise ReproducibilityError(
                        f"Archive link or special member is forbidden: {name}"
                    )
                payload_members[name] = {
                    "mode": member.mode,
                    "sha256": member_sha256,
                    "size": member_size,
                    "type": member_type,
                }
                metadata_members[name] = {
                    "gid": member.gid,
                    "gname": member.gname,
                    "mtime": member.mtime,
                    "uid": member.uid,
                    "uname": member.uname,
                }
    except (gzip.BadGzipFile, tarfile.TarError, EOFError, OSError) as exc:
        raise ReproducibilityError(f"Unable to inspect tar archive: {path}") from exc

    payload_digest = content_digest(
        [
            {"path": name, **payload_members[name]}
            for name in sorted(payload_members)
        ]
    )
    metadata_digest = content_digest(
        [
            {"path": name, **metadata_members[name]}
            for name in sorted(metadata_members)
        ]
    )
    mtimes = sorted({value["mtime"] for value in metadata_members.values()})
    summary = {
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
        "member_count": len(payload_members),
        "payload_size": total_payload_bytes,
        "payload_sha256": payload_digest,
        "metadata_sha256": metadata_digest,
        "gzip_mtime": gzip_mtime(path),
        "member_mtime": {
            "minimum": mtimes[0] if mtimes else None,
            "maximum": mtimes[-1] if mtimes else None,
            "unique_count": len(mtimes),
        },
    }
    return ArchiveInspection(
        summary=summary,
        payload_members=payload_members,
        metadata_members=metadata_members,
    )


def compare_sboms(
    left: dict[str, Any],
    right: dict[str, Any],
    *,
    left_root: Path,
    right_root: Path,
) -> dict[str, Any]:
    left_sbom, left_entry = load_only_json_entry(
        left,
        role="sboms",
        root=left_root,
    )
    right_sbom, right_entry = load_only_json_entry(
        right,
        role="sboms",
        root=right_root,
    )
    left_packages = canonical_spdx_packages(left_sbom)
    right_packages = canonical_spdx_packages(right_sbom)
    left_bindings = canonical_spdx_bindings(left_sbom)
    right_bindings = canonical_spdx_bindings(right_sbom)
    left_semantics = canonical_spdx_semantics(left_sbom)
    right_semantics = canonical_spdx_semantics(right_sbom)
    return {
        "exact_match": left_entry["sha256"] == right_entry["sha256"]
        and left_entry["size"] == right_entry["size"],
        "left": entry_identity(left_entry),
        "right": entry_identity(right_entry),
        "package_inventory_match": left_packages == right_packages,
        "package_inventory_sha256": {
            "left": content_digest(left_packages),
            "right": content_digest(right_packages),
        },
        "artifact_bindings_match": left_bindings == right_bindings,
        "artifact_bindings": {"left": left_bindings, "right": right_bindings},
        "semantics_without_volatile_metadata_match": left_semantics
        == right_semantics,
        "volatile_metadata": {
            "creationInfo.created": {
                "left": nested_value(left_sbom, "creationInfo", "created"),
                "right": nested_value(right_sbom, "creationInfo", "created"),
            },
            "documentNamespace": {
                "left": left_sbom.get("documentNamespace"),
                "right": right_sbom.get("documentNamespace"),
            },
        },
    }


def compare_builder_reports(
    left: dict[str, Any],
    right: dict[str, Any],
    *,
    left_entry: dict[str, Any],
    right_entry: dict[str, Any],
) -> dict[str, Any]:
    left_stable = stable_builder_projection(left)
    right_stable = stable_builder_projection(right)
    left_window = builder_execution_window(left)
    right_window = builder_execution_window(right)
    return {
        "exact_match": left_entry["sha256"] == right_entry["sha256"],
        "stable_match": left_stable == right_stable,
        "stable_sha256": {
            "left": content_digest(left_stable),
            "right": content_digest(right_stable),
        },
        "execution_windows": {"left": left_window, "right": right_window},
        "distinct_execution_windows": left_window != right_window,
    }


def compare_trace_diagnostics(
    left: dict[str, Any],
    right: dict[str, Any],
    *,
    left_root: Path,
    right_root: Path,
    left_builder: dict[str, Any],
    right_builder: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    left_trace, left_entry = load_json_entry(
        left,
        role="traces",
        name="observed-trace.json",
        root=left_root,
    )
    right_trace, right_entry = load_json_entry(
        right,
        role="traces",
        name="observed-trace.json",
        root=right_root,
    )
    left_summary = {field: left_trace.get(field) for field in TRACE_SUMMARY_FIELDS}
    right_summary = {field: right_trace.get(field) for field in TRACE_SUMMARY_FIELDS}
    left_behavior = normalize_trace(
        left_trace,
        workspace_root=infer_workspace_root(left_builder),
    )
    right_behavior = normalize_trace(
        right_trace,
        workspace_root=infer_workspace_root(right_builder),
    )
    behavior = compare_behavior_reports(left_behavior, right_behavior)
    return (
        {
            "promotion_gate": False,
            "exact_trace_match": left_entry["sha256"] == right_entry["sha256"],
            "raw_summary_match": left_summary == right_summary,
            "raw_summary_sha256": {
                "left": content_digest(left_summary),
                "right": content_digest(right_summary),
            },
            "normalized_match": behavior["ok"],
            "normalized_digest": {
                "left": left_behavior["digest"],
                "right": right_behavior["digest"],
            },
            "normalized_summary": {
                "left": left_behavior["summary"],
                "right": right_behavior["summary"],
            },
            "differences": cap_behavior_differences(behavior["differences"]),
            "claim_limit": (
                "Behavior comparison is diagnostic and does not gate promotion "
                "until artifact reproducibility and divergence policy are stable."
            ),
        },
        left_behavior,
        right_behavior,
    )


def compare_json_report(
    left: dict[str, Any],
    right: dict[str, Any],
    *,
    name: str,
    left_root: Path,
    right_root: Path,
) -> dict[str, Any]:
    left_value, left_entry = load_json_entry(
        left,
        role="reports",
        name=name,
        root=left_root,
    )
    right_value, right_entry = load_json_entry(
        right,
        role="reports",
        name=name,
        root=right_root,
    )
    return {
        "name": name,
        "exact_match": left_entry["sha256"] == right_entry["sha256"],
        "semantic_match": left_value == right_value,
        "left": entry_identity(left_entry),
        "right": entry_identity(right_entry),
    }


def create_rebuild_mismatch_packet(
    comparison: dict[str, Any],
    *,
    comparison_sha256: str,
) -> dict[str, Any]:
    findings = comparison.get("blocking_findings")
    if not isinstance(findings, list) or not findings:
        raise ReproducibilityError(
            "A mismatch packet requires at least one blocking finding"
        )
    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": "needs-human-review",
        "comparison_sha256": comparison_sha256,
        "source_repository": identity_check_value(
            comparison,
            "source_repository",
        ),
        "target_full_name": identity_check_value(
            comparison,
            "target_full_name",
        ),
        "reproducible": False,
        "provider_independent": False,
        "blocking_findings": findings,
        "warnings": comparison.get("warnings", []),
        "claim_limit": comparison.get("claim_limit"),
    }


def build_blocking_findings(
    *,
    artifacts: dict[str, Any],
    sbom: dict[str, Any],
    materials: dict[str, Any],
    builder: dict[str, Any],
) -> list[dict[str, Any]]:
    findings = []
    for artifact in artifacts["comparisons"]:
        if not artifact["exact_match"]:
            findings.append(
                finding(
                    code="artifact-byte-mismatch",
                    subject=artifact["name"],
                    classification=artifact["classification"],
                    detail=(
                        "Artifact payloads are equivalent but archive bytes differ."
                        if artifact["payload_equivalent"]
                        else "Artifact bytes or payloads differ between rebuilds."
                    ),
                )
            )
    if not sbom["exact_match"]:
        findings.append(
            finding(
                code="sbom-byte-mismatch",
                subject="sbom.spdx.json",
                classification=(
                    "volatile-metadata-only"
                    if sbom["semantics_without_volatile_metadata_match"]
                    else "semantic-or-binding-mismatch"
                ),
                detail="SPDX documents are not byte-for-byte identical.",
            )
        )
    if not materials["semantic_match"]:
        findings.append(
            finding(
                code="source-inventory-mismatch",
                subject=materials["name"],
                classification="material-mismatch",
                detail="Source inventory content differs between rebuilds.",
            )
        )
    if not builder["stable_match"]:
        findings.append(
            finding(
                code="builder-environment-mismatch",
                subject="builder.json",
                classification="stable-builder-mismatch",
                detail="Stable builder configuration or outcomes differ.",
            )
        )
    return sorted(findings, key=lambda item: (item["code"], item["subject"]))


def build_warnings(
    *,
    left_verification: dict[str, Any],
    right_verification: dict[str, Any],
    trace: dict[str, Any],
) -> list[dict[str, str]]:
    warnings = [
        {
            "code": "provider-independence-unproven",
            "detail": "Both executions used GitHub-hosted infrastructure.",
        },
        {
            "code": "execution-identifiers-not-attested",
            "detail": (
                "Workflow run identifiers were supplied to the comparison and are "
                "not fields in the signed build predicate."
            ),
        },
    ]
    if left_verification.get("caller_digest") != right_verification.get(
        "caller_digest"
    ):
        warnings.append(
            {
                "code": "caller-workflow-commit-differs",
                "detail": (
                    "The approved caller repository commits differ; the reusable "
                    "signer and builder profile remain fixed."
                ),
            }
        )
    if not trace["normalized_match"]:
        warnings.append(
            {
                "code": "diagnostic-behavior-mismatch",
                "detail": (
                    "Normalized observed behavior differs, but this stage does not "
                    "grant or enforce behavior-reproducible assurance."
                ),
            }
        )
    return sorted(warnings, key=lambda item: item["code"])


def comparable_identity_checks(
    left: dict[str, Any], right: dict[str, Any]
) -> list[dict[str, Any]]:
    return [
        {
            "field": field,
            "passed": left.get(field) == right.get(field),
            "left": left.get(field),
            "right": right.get(field),
        }
        for field in COMPARABLE_VERIFICATION_FIELDS
    ]


def validate_verification_record(record: dict[str, Any], *, label: str) -> None:
    if not isinstance(record, dict):
        raise ReproducibilityError(f"{label.capitalize()} verification is invalid")
    if (
        record.get("ok") is not True
        or record.get("status") != "verified-evidence-candidate"
        or record.get("authority") != "code-anchored-reusable-workflow-sigstore"
    ):
        raise ReproducibilityError(
            f"{label.capitalize()} build evidence was not authoritatively verified"
        )
    for field in COMPARABLE_VERIFICATION_FIELDS:
        if not isinstance(record.get(field), str) or not record[field]:
            raise ReproducibilityError(
                f"{label.capitalize()} verification field is invalid: {field}"
            )
    if not valid_sha256(record.get("evidence_sha256")):
        raise ReproducibilityError(
            f"{label.capitalize()} verification evidence digest is invalid"
        )


def distinct_attestation_sets(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return attestation_digest_set(left) != attestation_digest_set(right)


def attestation_digest_set(record: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    bundles = record.get("bundles")
    if not isinstance(bundles, dict) or not bundles:
        raise ReproducibilityError("Verified build record has no attestation bundles")
    values = []
    for role, bundle in bundles.items():
        digest = bundle.get("sha256") if isinstance(bundle, dict) else None
        if not isinstance(role, str) or not valid_sha256(digest):
            raise ReproducibilityError(
                "Verified build record has an invalid attestation bundle"
            )
        values.append((role, digest))
    return tuple(sorted(values))


def entry_index(manifest: dict[str, Any], *, role: str) -> dict[str, dict[str, Any]]:
    evidence = manifest.get("evidence")
    entries = evidence.get(role) if isinstance(evidence, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ReproducibilityError(f"Evidence role is missing or empty: {role}")
    index = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ReproducibilityError(f"Evidence entry is invalid: {role}")
        name = entry.get("name")
        if not isinstance(name, str) or not name or name in index:
            raise ReproducibilityError(
                f"Evidence entry name is invalid or duplicated: {role}"
            )
        if not valid_sha256(entry.get("sha256")):
            raise ReproducibilityError(f"Evidence digest is invalid: {role}/{name}")
        size = entry.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ReproducibilityError(f"Evidence size is invalid: {role}/{name}")
        index[name] = entry
    return index


def load_json_entry(
    manifest: dict[str, Any],
    *,
    role: str,
    name: str,
    root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    entry = entry_index(manifest, role=role).get(name)
    if entry is None:
        raise ReproducibilityError(f"Required evidence entry is missing: {role}/{name}")
    path = verified_entry_path(entry, root=root, label=name)
    return read_json_object(path, label=name), entry


def load_only_json_entry(
    manifest: dict[str, Any],
    *,
    role: str,
    root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    entries = entry_index(manifest, role=role)
    if len(entries) != 1:
        raise ReproducibilityError(f"Evidence role must contain one entry: {role}")
    name, entry = next(iter(entries.items()))
    path = verified_entry_path(entry, root=root, label=name)
    return read_json_object(path, label=name), entry


def verified_entry_path(
    entry: dict[str, Any], *, root: Path, label: str
) -> Path:
    try:
        path = resolve_evidence_entry(entry, base_dir=root, label=label)
    except ReleaseVerificationError as exc:
        raise ReproducibilityError(str(exc)) from exc
    if path.stat().st_size != entry["size"] or sha256_file(path) != entry["sha256"]:
        raise ReproducibilityError(f"Evidence entry changed before comparison: {label}")
    return path


def read_json_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReproducibilityError(f"Unable to read JSON evidence: {label}") from exc
    if not isinstance(value, dict):
        raise ReproducibilityError(f"JSON evidence must be an object: {label}")
    return value


def read_verified_manifest(
    path: Path,
    *,
    expected_sha256: Any,
    label: str,
) -> dict[str, Any]:
    if not valid_sha256(expected_sha256):
        raise ReproducibilityError(
            f"{label.capitalize()} verification evidence digest is invalid"
        )
    try:
        payload, actual_sha256 = snapshot_bytes(
            path,
            label=label,
            max_bytes=MAX_MANIFEST_BYTES,
        )
    except ReleaseVerificationError as exc:
        raise ReproducibilityError(str(exc)) from exc
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        raise ReproducibilityError(
            f"{label.capitalize()} digest does not match its verification record"
        )
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReproducibilityError(f"Unable to read JSON evidence: {label}") from exc
    if not isinstance(value, dict):
        raise ReproducibilityError(f"JSON evidence must be an object: {label}")
    return value


def canonical_spdx_packages(sbom: dict[str, Any]) -> list[dict[str, Any]]:
    packages = sbom.get("packages")
    if not isinstance(packages, list):
        raise ReproducibilityError("SPDX package inventory is invalid")
    if any(not isinstance(package, dict) for package in packages):
        raise ReproducibilityError("SPDX package inventory is invalid")
    return sorted(copy.deepcopy(packages), key=content_digest)


def canonical_spdx_bindings(sbom: dict[str, Any]) -> list[dict[str, str]]:
    files = sbom.get("files")
    if not isinstance(files, list):
        raise ReproducibilityError("SPDX file bindings are invalid")
    bindings = []
    for entry in files:
        if not isinstance(entry, dict) or not isinstance(entry.get("fileName"), str):
            raise ReproducibilityError("SPDX file binding is invalid")
        checksums = entry.get("checksums")
        if not isinstance(checksums, list):
            raise ReproducibilityError("SPDX file checksum is invalid")
        sha256_values = [
            checksum.get("checksumValue")
            for checksum in checksums
            if isinstance(checksum, dict) and checksum.get("algorithm") == "SHA256"
        ]
        if len(sha256_values) != 1 or not valid_sha256(sha256_values[0]):
            raise ReproducibilityError("SPDX file checksum is invalid")
        bindings.append(
            {"file_name": entry["fileName"], "sha256": sha256_values[0]}
        )
    return sorted(bindings, key=lambda value: (value["file_name"], value["sha256"]))


def canonical_spdx_semantics(sbom: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(sbom)
    value.pop("documentNamespace", None)
    creation = value.get("creationInfo")
    if isinstance(creation, dict):
        creation.pop("created", None)
    for field in ("files", "packages", "relationships"):
        entries = value.get(field)
        if isinstance(entries, list):
            value[field] = sorted(entries, key=content_digest)
    return value


def stable_builder_projection(report: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(report)
    execution = value.get("execution")
    if isinstance(execution, dict):
        execution.pop("started_at", None)
        execution.pop("finished_at", None)
    return value


def builder_execution_window(report: dict[str, Any]) -> dict[str, Any]:
    execution = report.get("execution")
    if not isinstance(execution, dict):
        raise ReproducibilityError("Builder execution report is invalid")
    started_at = execution.get("started_at")
    finished_at = execution.get("finished_at")
    if not isinstance(started_at, str) or not isinstance(finished_at, str):
        raise ReproducibilityError("Builder execution window is invalid")
    return {"started_at": started_at, "finished_at": finished_at}


def infer_workspace_root(builder: dict[str, Any]) -> Path | None:
    execution = builder.get("execution")
    cwd = execution.get("cwd") if isinstance(execution, dict) else None
    if not isinstance(cwd, str) or not cwd.startswith("/"):
        return None
    path = PurePosixPath(cwd)
    root = path.parent if path.name == "source" else path
    return Path(root.as_posix())


def differing_archive_metadata_fields(
    left: ArchiveInspection,
    right: ArchiveInspection,
) -> list[str]:
    fields = set()
    if left.summary["gzip_mtime"] != right.summary["gzip_mtime"]:
        fields.add("gzip_mtime")
    names = set(left.metadata_members) | set(right.metadata_members)
    for name in names:
        left_value = left.metadata_members.get(name, {})
        right_value = right.metadata_members.get(name, {})
        for field in ("gid", "gname", "mtime", "uid", "uname"):
            if left_value.get(field) != right_value.get(field):
                fields.add(field)
    return sorted(fields)


def compare_member_maps(
    left: dict[str, dict[str, Any]],
    right: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    only_left = sorted(set(left) - set(right))
    only_right = sorted(set(right) - set(left))
    changed = sorted(
        name for name in set(left) & set(right) if left[name] != right[name]
    )
    total = len(only_left) + len(only_right) + len(changed)
    return {
        "only_left": only_left[:MAX_REPORTED_DIFFERENCES],
        "only_right": only_right[:MAX_REPORTED_DIFFERENCES],
        "changed": changed[:MAX_REPORTED_DIFFERENCES],
        "total": total,
        "truncated": total > MAX_REPORTED_DIFFERENCES,
    }


def cap_behavior_differences(
    differences: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    capped = {}
    for category in sorted(differences):
        value = differences[category]
        left = value.get("only_left", [])
        right = value.get("only_right", [])
        total = len(left) + len(right)
        capped[category] = {
            "only_left": left[:MAX_REPORTED_DIFFERENCES],
            "only_right": right[:MAX_REPORTED_DIFFERENCES],
            "total": total,
            "truncated": total > MAX_REPORTED_DIFFERENCES,
        }
    return capped


def safe_archive_member_name(value: str) -> str:
    if not value or "\\" in value:
        raise ReproducibilityError("Archive member path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise ReproducibilityError(f"Archive member path is unsafe: {value}")
    normalized = path.as_posix()
    if normalized in {"", "."}:
        raise ReproducibilityError("Archive member path is invalid")
    return normalized.rstrip("/")


def gzip_mtime(path: Path) -> int:
    try:
        with path.open("rb") as handle:
            header = handle.read(10)
    except OSError as exc:
        raise ReproducibilityError(f"Unable to inspect gzip header: {path}") from exc
    if len(header) != 10 or header[:3] != b"\x1f\x8b\x08":
        raise ReproducibilityError(f"Archive has an invalid gzip header: {path}")
    return int.from_bytes(header[4:8], byteorder="little", signed=False)


def digest_stream(handle: Any, *, expected_size: int) -> str:
    digest = hashlib.sha256()
    total = 0
    while chunk := handle.read(1024 * 1024):
        total += len(chunk)
        if total > expected_size:
            raise ReproducibilityError("Archive member exceeds its declared size")
        digest.update(chunk)
    if total != expected_size:
        raise ReproducibilityError("Archive member does not match its declared size")
    return digest.hexdigest()


def finding(
    *, code: str, subject: str, classification: str, detail: str
) -> dict[str, str]:
    return {
        "code": code,
        "subject": subject,
        "classification": classification,
        "detail": detail,
    }


def entry_identity(entry: dict[str, Any] | None) -> dict[str, Any] | None:
    if entry is None:
        return None
    return {"sha256": entry["sha256"], "size": entry["size"]}


def is_tar_gzip(name: str) -> bool:
    return name.endswith((".tar.gz", ".tgz"))


def nested_value(value: dict[str, Any], *path: str) -> Any:
    current: Any = value
    for component in path:
        if not isinstance(current, dict):
            return None
        current = current.get(component)
    return current


def require_execution_id(value: str, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ReproducibilityError(
            f"{label.capitalize()} rebuild execution identifier is invalid"
        )
    return value.strip()


def valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def identity_check_value(comparison: dict[str, Any], field: str) -> Any:
    checks = comparison.get("identity", {}).get("checks", [])
    for check in checks:
        if check.get("field") == field:
            return check.get("left")
    return None
