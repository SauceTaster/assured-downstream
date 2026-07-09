from __future__ import annotations

from typing import Any

from assured_downstream.catalog import utc_now


ASSURANCE_ORDER = {
    "Hardened": 1,
    "Attested": 2,
    "Reproducible": 3,
    "Behavior-Reproducible": 4,
    "Validated": 5,
}


def evaluate_release(
    *,
    evidence: dict[str, Any],
    target: str,
    evidence_verification: dict[str, Any] | None = None,
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

    if target_at_least(target, "Reproducible"):
        if not evidence_comparison:
            failures.append("missing evidence comparison for reproducibility target")
        elif not evidence_comparison.get("ok"):
            failures.append("evidence comparison did not match")

    if target_at_least(target, "Behavior-Reproducible"):
        if not behavior_comparison:
            failures.append("missing behavior comparison for behavior reproducibility target")
        elif not behavior_comparison.get("ok"):
            failures.append("behavior comparison did not match")

    if target_at_least(target, "Validated"):
        require_role(evidence_roles, "reports", failures)

    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "target": target,
        "decision": "block" if failures else "pass",
        "promoted_assurance": None if failures else target,
        "failures": failures,
        "warnings": warnings,
        "verification": {
            "evidence_ok": None if evidence_verification is None else bool(evidence_verification.get("ok")),
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
