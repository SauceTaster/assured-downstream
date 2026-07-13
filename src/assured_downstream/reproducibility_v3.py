from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from assured_downstream.behavior import compare_behavior_reports, normalize_trace
from assured_downstream.build_verification_v3 import (
    BuildVerificationError,
    decode_json_object,
    entry_logical_path,
    evidence_sha256,
    resolve_v3_storage_path,
    validate_v3_evidence_manifest,
)
from assured_downstream.release_verification import (
    MAX_JSON_BYTES,
    require_sha256,
    snapshot_bytes,
)


COMPARABLE_FIELDS = (
    "authority",
    "builder_image",
    "case_id",
    "caller_digest",
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
REPRODUCIBILITY_V3_CORE_CHECKS = frozenset(
    {
        "artifacts",
        "distinct_attestation_sets",
        "identity",
        "normalized_spdx",
        "project",
        "source_inventory",
        "stable_builder",
        "trusted_source_inventory",
    }
)


class ReproducibilityV3Error(RuntimeError):
    pass


@dataclass(frozen=True)
class ReproducibilityV3Analysis:
    report: dict[str, Any]
    left_behavior: dict[str, Any]
    right_behavior: dict[str, Any]


@dataclass(frozen=True)
class VerifiedBundle:
    manifest: dict[str, Any]
    roles: dict[str, list[dict[str, Any]]]
    root: Path
    verification: dict[str, Any]


def compare_verified_builds_v3(
    *,
    left_evidence_path: Path,
    right_evidence_path: Path,
    left_verification: dict[str, Any],
    right_verification: dict[str, Any],
    left_execution_id: str,
    right_execution_id: str,
    now: datetime | None = None,
) -> ReproducibilityV3Analysis:
    left_run_id = require_execution_id(left_execution_id, label="left")
    right_run_id = require_execution_id(right_execution_id, label="right")
    if left_run_id == right_run_id:
        raise ReproducibilityV3Error("Rebuild execution identifiers must be distinct")
    left = load_verified_bundle(
        left_evidence_path,
        verification=left_verification,
        label="left",
    )
    right = load_verified_bundle(
        right_evidence_path,
        verification=right_verification,
        label="right",
    )
    validate_verified_attestation_entries(left, label="left")
    validate_verified_attestation_entries(right, label="right")
    validate_run_binding(left.verification, expected_run_id=left_run_id, label="left")
    validate_run_binding(
        right.verification,
        expected_run_id=right_run_id,
        label="right",
    )

    identity_checks = [
        {
            "field": field,
            "passed": left.verification.get(field) == right.verification.get(field),
            "left": left.verification.get(field),
            "right": right.verification.get(field),
        }
        for field in COMPARABLE_FIELDS
    ]
    project_match = left.manifest["project"] == right.manifest["project"]
    artifacts_left = artifact_records(left)
    artifacts_right = artifact_records(right)
    artifact_match = artifacts_left == artifacts_right
    validate_verified_subjects(left.verification, artifacts=artifacts_left, label="left")
    validate_verified_subjects(
        right.verification,
        artifacts=artifacts_right,
        label="right",
    )

    normalized_sbom_left, normalized_sbom_left_entry = load_json_by_logical_path(
        left,
        role="sboms",
        logical_path="sbom/sbom.spdx.json",
    )
    normalized_sbom_right, normalized_sbom_right_entry = load_json_by_logical_path(
        right,
        role="sboms",
        logical_path="sbom/sbom.spdx.json",
    )
    normalized_sbom_match = (
        evidence_sha256(normalized_sbom_left_entry)
        == evidence_sha256(normalized_sbom_right_entry)
        and normalized_sbom_left == normalized_sbom_right
    )
    raw_sbom_left = entry_by_logical_path(
        left,
        role="sboms",
        logical_path="sbom/raw/syft.spdx.json",
    )
    raw_sbom_right = entry_by_logical_path(
        right,
        role="sboms",
        logical_path="sbom/raw/syft.spdx.json",
    )

    source_left, source_left_entry = load_json_by_logical_path(
        left,
        role="reports",
        logical_path="reports/source-inventory.json",
    )
    source_right, source_right_entry = load_json_by_logical_path(
        right,
        role="reports",
        logical_path="reports/source-inventory.json",
    )
    source_match = (
        evidence_sha256(source_left_entry) == evidence_sha256(source_right_entry)
        and source_left == source_right
    )
    trusted_left = entry_by_logical_path(
        left,
        role="reports",
        logical_path="reports/trusted-source-inventory.json",
    )
    trusted_right = entry_by_logical_path(
        right,
        role="reports",
        logical_path="reports/trusted-source-inventory.json",
    )
    trusted_source_match = evidence_sha256(trusted_left) == evidence_sha256(
        trusted_right
    )

    builder_left, builder_left_entry = load_json_by_logical_path(
        left,
        role="reports",
        logical_path="reports/builder.json",
    )
    builder_right, builder_right_entry = load_json_by_logical_path(
        right,
        role="reports",
        logical_path="reports/builder.json",
    )
    stable_builder_left = stable_builder_projection(builder_left)
    stable_builder_right = stable_builder_projection(builder_right)
    stable_builder_match = stable_builder_left == stable_builder_right

    trace_left, trace_left_entry = load_json_by_logical_path(
        left,
        role="traces",
        logical_path="traces/observed-trace.json",
    )
    trace_right, trace_right_entry = load_json_by_logical_path(
        right,
        role="traces",
        logical_path="traces/observed-trace.json",
    )
    trace_summary_left = {
        field: trace_left.get(field) for field in TRACE_SUMMARY_FIELDS
    }
    trace_summary_right = {
        field: trace_right.get(field) for field in TRACE_SUMMARY_FIELDS
    }
    left_behavior = normalize_trace(trace_left, workspace_root=Path("/workspace"))
    right_behavior = normalize_trace(trace_right, workspace_root=Path("/workspace"))
    behavior_comparison = compare_behavior_reports(left_behavior, right_behavior)

    raw_artifacts_left = records_for_role(left, role="raw_artifacts")
    raw_artifacts_right = records_for_role(right, role="raw_artifacts")
    raw_artifact_differences = compare_record_sets(
        raw_artifacts_left,
        raw_artifacts_right,
    )
    bundle_sets_distinct = attestation_digest_set(left.verification) != (
        attestation_digest_set(right.verification)
    )
    core_checks = {
        "identity": all(item["passed"] for item in identity_checks),
        "project": project_match,
        "artifacts": artifact_match,
        "normalized_spdx": normalized_sbom_match,
        "source_inventory": source_match,
        "trusted_source_inventory": trusted_source_match,
        "stable_builder": stable_builder_match,
        "distinct_attestation_sets": bundle_sets_distinct,
    }
    blocking_findings = [
        {"code": f"{name}-mismatch", "check": name}
        for name, passed in sorted(core_checks.items())
        if not passed
    ]
    reproducible = not blocking_findings
    behavior_reproducible = reproducible and behavior_comparison["ok"]
    verified_at = (now or datetime.now(UTC)).astimezone(UTC).isoformat(
        timespec="seconds"
    )
    report = {
        "schema_version": 1,
        "status": "matched" if reproducible else "mismatch",
        "ok": reproducible,
        "reproducible": reproducible,
        "artifact_reproducibility_candidate": reproducible,
        "behavior_reproducibility_candidate": behavior_reproducible,
        "provider_independent": False,
        "promotion_authority": "none",
        "verified_at": verified_at,
        "executions": {
            "left": left_execution_id,
            "right": right_execution_id,
        },
        "evidence": {
            "left_sha256": left.verification["evidence_sha256"],
            "right_sha256": right.verification["evidence_sha256"],
        },
        "identity_checks": identity_checks,
        "core_checks": core_checks,
        "artifacts": {
            "exact_match": artifact_match,
            "left": artifacts_left,
            "right": artifacts_right,
        },
        "sbom": {
            "normalized_exact_match": normalized_sbom_match,
            "normalized_sha256": {
                "left": evidence_sha256(normalized_sbom_left_entry),
                "right": evidence_sha256(normalized_sbom_right_entry),
            },
            "raw_exact_match": evidence_sha256(raw_sbom_left)
            == evidence_sha256(raw_sbom_right),
            "raw_sha256": {
                "left": evidence_sha256(raw_sbom_left),
                "right": evidence_sha256(raw_sbom_right),
            },
        },
        "source": {
            "inventory_exact_match": source_match,
            "trusted_inventory_exact_match": trusted_source_match,
            "tree_sha256": source_left.get("tree_sha256"),
        },
        "builder": {
            "exact_report_match": evidence_sha256(builder_left_entry)
            == evidence_sha256(builder_right_entry),
            "stable_match": stable_builder_match,
            "stable_sha256": {
                "left": canonical_digest(stable_builder_left),
                "right": canonical_digest(stable_builder_right),
            },
        },
        "trace": {
            "exact_match": evidence_sha256(trace_left_entry)
            == evidence_sha256(trace_right_entry),
            "summary_match": trace_summary_left == trace_summary_right,
            "summary": {
                "left": trace_summary_left,
                "right": trace_summary_right,
            },
            "normalized_match": behavior_comparison["ok"],
            "normalized_digest": {
                "left": left_behavior["digest"],
                "right": right_behavior["digest"],
            },
            "normalized_summary": {
                "left": left_behavior["summary"],
                "right": right_behavior["summary"],
            },
            "differences": behavior_comparison["differences"],
        },
        "raw_artifacts": {
            "exact_match": not raw_artifact_differences,
            "differences": raw_artifact_differences,
            "claim": "Raw build output may differ before canonicalization.",
        },
        "distinct_attestation_sets": bundle_sets_distinct,
        "blocking_findings": blocking_findings,
        "warnings": [
            {
                "code": "provider-independence-unproven",
                "detail": "Both executions used GitHub-hosted infrastructure.",
            }
        ],
        "claim_limit": (
            "This comparison establishes one same-provider Bandit artifact and "
            "normalized-behavior reproducibility candidate. It does not establish "
            "provider independence, upstream ancestry, containment, or semantic safety."
        ),
    }
    return ReproducibilityV3Analysis(
        report=report,
        left_behavior=left_behavior,
        right_behavior=right_behavior,
    )


def load_verified_bundle(
    evidence_path: Path,
    *,
    verification: dict[str, Any],
    label: str,
) -> VerifiedBundle:
    validate_verification_record(verification, label=label)
    path = Path(os.path.abspath(evidence_path.expanduser()))
    payload, digest = snapshot_bytes(
        path,
        label=f"{label} v3 evidence manifest",
        max_bytes=MAX_JSON_BYTES,
    )
    if not hmac.compare_digest(digest, verification["evidence_sha256"]):
        raise ReproducibilityV3Error(
            f"{label.capitalize()} evidence digest does not match verification"
        )
    manifest = decode_json_object(payload, label=f"{label} v3 evidence manifest")
    try:
        roles = validate_v3_evidence_manifest(manifest, base_dir=path.parent)
    except BuildVerificationError as exc:
        raise ReproducibilityV3Error(str(exc)) from exc
    return VerifiedBundle(
        manifest=manifest,
        roles=roles,
        root=path.parent,
        verification=verification,
    )


def validate_verification_record(value: dict[str, Any], *, label: str) -> None:
    if (
        not isinstance(value, dict)
        or value.get("ok") is not True
        or value.get("status") != "verified-evidence-candidate"
        or value.get("authority") != "code-anchored-reusable-workflow-sigstore"
    ):
        raise ReproducibilityV3Error(
            f"{label.capitalize()} verification is not authoritative"
        )
    require_sha256(value.get("evidence_sha256"), label=f"{label} evidence digest")
    for field in COMPARABLE_FIELDS:
        if not isinstance(value.get(field), str) or not value[field]:
            raise ReproducibilityV3Error(
                f"{label.capitalize()} verification field is invalid: {field}"
            )


def require_execution_id(value: str, *, label: str) -> str:
    prefix = "github-actions:"
    run_id = value.removeprefix(prefix) if isinstance(value, str) else ""
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or not run_id.isdigit()
        or str(int(run_id)) != run_id
        or int(run_id) <= 0
    ):
        raise ReproducibilityV3Error(f"{label.capitalize()} execution id is invalid")
    return run_id


def validate_run_binding(
    verification: dict[str, Any],
    *,
    expected_run_id: str,
    label: str,
) -> None:
    run = verification.get("workflow_run")
    if not isinstance(run, dict) or run.get("id") != expected_run_id:
        raise ReproducibilityV3Error(
            f"{label.capitalize()} execution id is not bound to verification"
        )


def artifact_records(bundle: VerifiedBundle) -> list[dict[str, Any]]:
    return records_for_role(bundle, role="artifacts")


def records_for_role(
    bundle: VerifiedBundle,
    *,
    role: str,
) -> list[dict[str, Any]]:
    return [
        {
            "path": entry_logical_path(entry),
            "size": entry["size"],
            "sha256": evidence_sha256(entry),
        }
        for entry in bundle.roles[role]
    ]


def validate_verified_subjects(
    verification: dict[str, Any],
    *,
    artifacts: list[dict[str, Any]],
    label: str,
) -> None:
    expected = [
        {"name": item["path"], "sha256": item["sha256"]} for item in artifacts
    ]
    if verification.get("verified_subjects") != expected:
        raise ReproducibilityV3Error(
            f"{label.capitalize()} verified subjects do not match evidence"
        )


def validate_verified_attestation_entries(
    bundle: VerifiedBundle,
    *,
    label: str,
) -> None:
    expected_names = {
        "build": "attestations/build.sigstore.json",
        "provenance": "attestations/provenance.sigstore.json",
        "sbom": "attestations/sbom.sigstore.json",
    }
    verified = bundle.verification.get("bundles")
    if not isinstance(verified, dict) or set(verified) != set(expected_names):
        raise ReproducibilityV3Error(
            f"{label.capitalize()} verification attestation set is invalid"
        )
    for role, logical_path in expected_names.items():
        entry = entry_by_logical_path(
            bundle,
            role="attestations",
            logical_path=logical_path,
        )
        record = verified[role]
        if not isinstance(record, dict) or record.get("sha256") != evidence_sha256(
            entry
        ):
            raise ReproducibilityV3Error(
                f"{label.capitalize()} {role} bundle is not bound to evidence"
            )


def entry_by_logical_path(
    bundle: VerifiedBundle,
    *,
    role: str,
    logical_path: str,
) -> dict[str, Any]:
    matches = [
        entry
        for entry in bundle.roles[role]
        if entry_logical_path(entry) == logical_path
    ]
    if len(matches) != 1:
        raise ReproducibilityV3Error(
            f"Evidence requires exactly one {logical_path} entry"
        )
    return matches[0]


def load_json_by_logical_path(
    bundle: VerifiedBundle,
    *,
    role: str,
    logical_path: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    entry = entry_by_logical_path(
        bundle,
        role=role,
        logical_path=logical_path,
    )
    path = resolve_v3_storage_path(entry["path"], base_dir=bundle.root)
    payload, digest = snapshot_bytes(
        path,
        label=logical_path,
        max_bytes=MAX_JSON_BYTES,
    )
    if not hmac.compare_digest(digest, evidence_sha256(entry)):
        raise ReproducibilityV3Error(f"Evidence changed before comparison: {logical_path}")
    return decode_json_object(payload, label=logical_path), entry


def stable_builder_projection(value: dict[str, Any]) -> dict[str, Any]:
    projection = copy.deepcopy(value)
    execution = projection.get("execution")
    if not isinstance(execution, dict):
        raise ReproducibilityV3Error("Builder execution report is invalid")
    started_at = execution.pop("started_at", None)
    finished_at = execution.pop("finished_at", None)
    if not isinstance(started_at, str) or not isinstance(finished_at, str):
        raise ReproducibilityV3Error("Builder execution window is invalid")
    transforms = projection.get("artifact_transforms")
    if not isinstance(transforms, dict) or not isinstance(
        transforms.pop("report_sha256", None),
        str,
    ):
        raise ReproducibilityV3Error("Builder transform pointer is invalid")
    return projection


def attestation_digest_set(value: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    bundles = value.get("bundles")
    if not isinstance(bundles, dict) or set(bundles) != {
        "build",
        "provenance",
        "sbom",
    }:
        raise ReproducibilityV3Error("Verification has no exact attestation set")
    if not all(isinstance(item, dict) for item in bundles.values()):
        raise ReproducibilityV3Error("Verification attestation set is malformed")
    return tuple(
        sorted(
            (
                role,
                require_sha256(item.get("sha256"), label=f"{role} bundle digest"),
            )
            for role, item in bundles.items()
        )
    )


def compare_record_sets(
    left: list[dict[str, Any]],
    right: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    left_by_path = {item["path"]: item for item in left}
    right_by_path = {item["path"]: item for item in right}
    return [
        {
            "path": path,
            "left": left_by_path.get(path),
            "right": right_by_path.get(path),
        }
        for path in sorted(set(left_by_path) | set(right_by_path))
        if left_by_path.get(path) != right_by_path.get(path)
    ]


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
