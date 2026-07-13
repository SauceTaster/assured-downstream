from __future__ import annotations

import re
from typing import Any

from assured_downstream.catalog import utc_now


ASSURANCE_ORDER = {
    "Hardened": 1,
    "Attested": 2,
    "Reproducible": 3,
    "Behavior-Reproducible": 4,
    "Validated": 5,
}
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def evaluate_release(
    *,
    evidence: dict[str, Any],
    target: str,
    evidence_verification: dict[str, Any] | None = None,
    attestation_verification: dict[str, Any] | None = None,
    tooling_verification: dict[str, Any] | None = None,
    workflow_risk_verification: dict[str, Any] | None = None,
    evidence_comparison: dict[str, Any] | None = None,
    behavior_comparison: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = evaluate_release_candidate(
        evidence=evidence,
        target=target,
        evidence_verification=evidence_verification,
        attestation_verification=attestation_verification,
        tooling_verification=tooling_verification,
        workflow_risk_verification=workflow_risk_verification,
        evidence_comparison=evidence_comparison,
        behavior_comparison=behavior_comparison,
    )
    if target_at_least(target, "Attested"):
        result["failures"].append(
            "production Attested promotion requires code-anchored lineage, "
            "builder, tooling, and workflow verification composed with the "
            "Sigstore result"
        )
        result["decision"] = "block"
        result["promoted_assurance"] = None
    elif result["decision"] == "candidate":
        result["decision"] = "pass"
        result["promoted_assurance"] = target
        result["candidate_assurance"] = None
    return result


def evaluate_release_candidate(
    *,
    evidence: dict[str, Any],
    target: str,
    evidence_verification: dict[str, Any] | None = None,
    attestation_verification: dict[str, Any] | None = None,
    tooling_verification: dict[str, Any] | None = None,
    workflow_risk_verification: dict[str, Any] | None = None,
    evidence_comparison: dict[str, Any] | None = None,
    behavior_comparison: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if target not in ASSURANCE_ORDER:
        raise ValueError(f"Unsupported assurance target: {target}")

    failures = []
    warnings = []

    project = evidence.get("project") or {}
    evidence_roles = evidence.get("evidence") or {}
    if not project.get("source_full_name"):
        failures.append("missing source_full_name")
    if not project.get("upstream_ref"):
        failures.append("missing upstream_ref")
    if not project.get("overlay_ref"):
        failures.append("missing overlay_ref")
    if not project.get("release_tag"):
        failures.append("missing release_tag")

    if target_at_least(target, "Attested"):
        require_role(evidence_roles, "artifacts", failures)
        require_role(evidence_roles, "sboms", failures)
        require_role(evidence_roles, "attestations", failures)
        if evidence_verification is None:
            failures.append("missing evidence verification result for attested target")
        elif not evidence_verification.get("ok"):
            failures.append("evidence manifest verification failed")
        validate_attestation_claim_shape(
            evidence_roles,
            attestation_verification,
            failures,
        )
        validate_tooling_claim_shape(tooling_verification, failures)
        validate_workflow_risk_claim_shape(workflow_risk_verification, failures)
        if not evidence_roles.get("traces"):
            warnings.append(
                "trace evidence is absent; Attested does not imply behavior coverage"
            )

    if target_at_least(target, "Reproducible"):
        validate_reproducibility_gate_shape(evidence_comparison, failures)

    if target_at_least(target, "Behavior-Reproducible"):
        if not behavior_comparison:
            failures.append(
                "missing behavior comparison for behavior reproducibility target"
            )
        elif not behavior_comparison.get("ok"):
            failures.append("behavior comparison did not match")

    if target_at_least(target, "Validated"):
        require_role(evidence_roles, "reports", failures)

    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "target": target,
        "decision": "block" if failures else "candidate",
        "promoted_assurance": None,
        "candidate_assurance": None if failures else target,
        "authority": "untrusted-input-shape-only",
        "failures": failures,
        "warnings": warnings,
        "input_claims": {
            "evidence_consistency_ok": None
            if evidence_verification is None
            else bool(evidence_verification.get("ok")),
            "attestation_claim_ok": (
                None
                if attestation_verification is None
                else bool(attestation_verification.get("ok"))
            ),
            "tooling_claim_ok": (
                None
                if tooling_verification is None
                else bool(tooling_verification.get("ok"))
            ),
            "workflow_risk_claim_ok": (
                None
                if workflow_risk_verification is None
                else bool(workflow_risk_verification.get("ok"))
            ),
            "reproducibility_candidate_gate_ok": (
                None
                if evidence_comparison is None
                else evidence_comparison.get("passed") is True
            ),
        },
    }


def target_at_least(target: str, stage: str) -> bool:
    return ASSURANCE_ORDER[target] >= ASSURANCE_ORDER[stage]


def require_role(
    evidence_roles: dict[str, list[dict[str, Any]]],
    role: str,
    failures: list[str],
) -> None:
    if not evidence_roles.get(role):
        failures.append(f"missing required evidence role: {role}")


def validate_reproducibility_gate_shape(
    gate: dict[str, Any] | None,
    failures: list[str],
) -> None:
    if gate is None:
        failures.append(
            "missing durable reproducibility candidate gate for reproducibility target"
        )
        return
    if gate.get("schema_version") != 1:
        failures.append("reproducibility gate schema is invalid")
    if gate.get("gate") != "artifact-reproducibility-candidate":
        failures.append("evidence comparison is not a reproducibility candidate gate")
    if gate.get("authority") != "durable-reproducibility-candidate-gate":
        failures.append("reproducibility gate authority is invalid")
    if gate.get("passed") is not True:
        failures.append("evidence comparison did not match")
    if gate.get("promotion_authorized") is not False:
        failures.append("reproducibility candidate gate overstates promotion authority")
    comparison = gate.get("comparison")
    if (
        not isinstance(comparison, dict)
        or not is_sha256(comparison.get("sha256"))
        or type(comparison.get("size")) is not int
        or comparison["size"] < 1
    ):
        failures.append("reproducibility gate comparison reference is invalid")


def validate_attestation_claim_shape(
    evidence_roles: dict[str, list[dict[str, Any]]],
    verification: dict[str, Any] | None,
    failures: list[str],
) -> None:
    if verification is None:
        failures.append("missing attestation verification claim document")
        return
    if verification.get("ok") is not True:
        failures.append("attestation verification document reports failure")
        return
    if verification.get("verification_type") != "sigstore-bundle":
        failures.append("attestation document does not claim a Sigstore bundle")
    if not verification.get("issuer") or not verification.get("signer"):
        failures.append("attestation document is missing issuer or signer identity")
    verified_subjects = verification.get("verified_subjects")
    if not isinstance(verified_subjects, list):
        failures.append("attestation document has no represented subject set")
        return
    verified_digests = {
        item.get("sha256")
        for item in verified_subjects
        if isinstance(item, dict) and is_sha256(item.get("sha256"))
    }
    artifact_digests = {
        item.get("sha256")
        for item in evidence_roles.get("artifacts", [])
        if isinstance(item, dict) and is_sha256(item.get("sha256"))
    }
    if not artifact_digests:
        failures.append("artifact evidence has no valid SHA-256 subjects")
        return
    missing = sorted(artifact_digests - verified_digests)
    if missing:
        failures.append(
            "attestation document does not represent every artifact subject: "
            + ", ".join(missing)
        )


def validate_tooling_claim_shape(
    verification: dict[str, Any] | None,
    failures: list[str],
) -> None:
    if verification is None:
        failures.append("missing approved-tooling verification claim document")
        return
    if verification.get("ok") is not True:
        failures.append("approved-tooling document reports failure")
    if not is_sha256(verification.get("policy_sha256")):
        failures.append("approved-tooling document has no policy digest")
    if not is_sha256(verification.get("lock_sha256")):
        failures.append("approved-tooling document has no lock digest")


def validate_workflow_risk_claim_shape(
    verification: dict[str, Any] | None,
    failures: list[str],
) -> None:
    if verification is None:
        failures.append("missing workflow-risk verification claim document")
        return
    if verification.get("ok") is not True:
        failures.append("workflow-risk document reports failure")
    if not is_sha256(verification.get("analyzed_workflow_sha256")):
        failures.append("workflow-risk document has no analyzed workflow digest")
    findings = verification.get("findings")
    if not isinstance(findings, list):
        failures.append("workflow-risk document findings are invalid")


def is_sha256(value: Any) -> bool:
    return isinstance(value, str) and SHA256_PATTERN.fullmatch(value) is not None
