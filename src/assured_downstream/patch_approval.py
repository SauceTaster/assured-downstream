from __future__ import annotations

import hmac
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from assured_downstream.evidence import sha256_file
from assured_downstream.overlay_render import normalize_pin_map, render_change
from assured_downstream.secure_patch import SecurePatchError, require_full_sha, require_sha256


PATCH_APPROVAL_SCHEMA_VERSION = 1
ADDITIVE_BASELINE_POLICY = "policy:additive-baseline-v1"
MAX_APPROVAL_LIFETIME = timedelta(days=7)
POLICY_CHANGE_CONTRACTS = {
    "dependabot-baseline": {
        "action": "add",
        "paths": [".github/dependabot.yml"],
        "rendered_path": ".github/dependabot.yml",
    },
    "dependency-review": {
        "action": "add",
        "paths": [".github/workflows/assured-downstream-dependency-review.yml"],
        "rendered_path": ".github/workflows/assured-downstream-dependency-review.yml",
    },
    "gha-bootstrap": {
        "action": "add",
        "paths": [".github/workflows/assured-downstream-ci.yml"],
        "rendered_path": ".github/workflows/assured-downstream-ci.yml",
    },
    "in-toto-evidence": {
        "action": "add",
        "paths": ["evidence/assured-downstream/"],
        "rendered_path": "evidence/assured-downstream/README.md",
    },
    "scorecard-evidence": {
        "action": "add",
        "paths": [".github/workflows/assured-downstream-scorecard.yml"],
        "rendered_path": ".github/workflows/assured-downstream-scorecard.yml",
    },
}


class PatchApprovalError(RuntimeError):
    pass


def create_patch_approval(
    *,
    analysis_index: dict[str, Any],
    analysis_index_sha256: str,
    pin_lock: dict[str, Any],
    pin_lock_sha256: str,
    tooling_policy: dict[str, Any],
    tooling_policy_sha256: str,
    target_full_name: str,
    auto_approve_safe: bool = False,
) -> dict[str, Any]:
    require_sha256(analysis_index_sha256, label="analysis index digest")
    require_sha256(pin_lock_sha256, label="pin lock digest")
    require_sha256(tooling_policy_sha256, label="tooling policy digest")
    repository = find_repository(analysis_index, target_full_name)
    overlay_path = verified_file(
        repository.get("overlay_plan_path"),
        repository.get("overlay_plan_sha256"),
        label="overlay plan",
    )
    overlay = read_json(overlay_path)
    eligible = policy_eligible_change_ids(
        overlay,
        pin_lock=pin_lock,
        tooling_policy=tooling_policy,
        tooling_policy_sha256=tooling_policy_sha256,
    )
    now = datetime.now(UTC)
    approved_at = now.isoformat(timespec="seconds") if auto_approve_safe else None
    return {
        "schema_version": PATCH_APPROVAL_SCHEMA_VERSION,
        "status": "approved" if auto_approve_safe and eligible else "pending",
        "approval_type": "policy" if auto_approve_safe and eligible else None,
        "approved_by": ADDITIVE_BASELINE_POLICY if auto_approve_safe and eligible else None,
        "approved_at": approved_at,
        "expires_at": (
            (now + timedelta(days=7)).isoformat(timespec="seconds")
            if auto_approve_safe and eligible
            else None
        ),
        "authentication": "deterministic-policy" if auto_approve_safe and eligible else None,
        "analysis_index_sha256": analysis_index_sha256,
        "pin_lock_sha256": pin_lock_sha256,
        "tooling_policy_sha256": tooling_policy_sha256,
        "repository": {
            "source_full_name": repository["source_full_name"],
            "target_full_name": repository["target_full_name"],
            "default_branch": repository["default_branch"],
            "analysis_sha": repository["analysis_sha"],
            "secure_branch_sha": repository["secure_branch_sha"],
            "overlay_plan_path": str(overlay_path),
            "overlay_plan_sha256": repository["overlay_plan_sha256"],
            "policy_eligible_change_ids": eligible,
            "approved_change_ids": eligible if auto_approve_safe else [],
            "publish_secure_branch": False,
            "expected_remote_sha": None,
        },
        "limitations": [
            "Policy approval covers only supported additive files.",
            "Existing paths, workflow modifications, release logic, and human-review items are excluded.",
            (
                "Human-record patch approval cannot authorize a remote push; "
                "a separate attested publication authorization is required."
            ),
        ],
    }


def validate_patch_approval(
    approval: dict[str, Any],
    *,
    analysis_index: dict[str, Any],
    analysis_index_sha256: str,
    pin_lock: dict[str, Any],
    pin_lock_sha256: str,
    tooling_policy: dict[str, Any],
    tooling_policy_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if approval.get("schema_version") != PATCH_APPROVAL_SCHEMA_VERSION:
        raise PatchApprovalError("Unsupported patch approval schema")
    if approval.get("status") != "approved":
        raise PatchApprovalError("Patch approval status is not approved")
    if approval.get("approval_type") not in {"policy", "human-record"}:
        raise PatchApprovalError("Patch approval type must be policy or human-record")
    if not hmac.compare_digest(
        str(approval.get("analysis_index_sha256")),
        analysis_index_sha256,
    ):
        raise PatchApprovalError("Patch approval does not bind this analysis index")
    if not hmac.compare_digest(
        str(approval.get("pin_lock_sha256")),
        pin_lock_sha256,
    ):
        raise PatchApprovalError("Patch approval does not bind this pin lock")
    try:
        require_sha256(tooling_policy_sha256, label="tooling policy digest")
    except SecurePatchError as exc:
        raise PatchApprovalError(str(exc)) from exc
    if not hmac.compare_digest(
        str(approval.get("tooling_policy_sha256")),
        tooling_policy_sha256,
    ):
        raise PatchApprovalError("Patch approval does not bind the tooling policy")
    validate_approval_time(approval)
    approved_by = approval.get("approved_by")
    if not isinstance(approved_by, str) or not approved_by:
        raise PatchApprovalError("Patch approval has no approver identity")

    approval_repo = approval.get("repository")
    if not isinstance(approval_repo, dict):
        raise PatchApprovalError("Patch approval has no repository decision")
    target = approval_repo.get("target_full_name")
    if not isinstance(target, str) or not target:
        raise PatchApprovalError("Patch approval has no target repository")
    repository = find_repository(analysis_index, target)
    for field in (
        "source_full_name",
        "target_full_name",
        "default_branch",
        "analysis_sha",
        "secure_branch_sha",
        "overlay_plan_sha256",
    ):
        if approval_repo.get(field) != repository.get(field):
            raise PatchApprovalError(
                f"Patch approval repository field does not match analysis: {field}"
            )
    require_full_sha(repository.get("analysis_sha"), label="analysis commit")
    require_full_sha(repository.get("secure_branch_sha"), label="secure branch commit")

    overlay_path = verified_file(
        repository.get("overlay_plan_path"),
        repository.get("overlay_plan_sha256"),
        label="overlay plan",
    )
    if Path(str(approval_repo.get("overlay_plan_path"))).resolve() != overlay_path:
        raise PatchApprovalError("Patch approval overlay path does not match analysis")
    overlay = read_json(overlay_path)
    approved_ids = approval_repo.get("approved_change_ids")
    if (
        not isinstance(approved_ids, list)
        or not approved_ids
        or not all(isinstance(item, str) and item for item in approved_ids)
        or len(set(approved_ids)) != len(approved_ids)
    ):
        raise PatchApprovalError("Patch approval has no valid approved change set")

    if pin_lock.get("status") != "complete":
        raise PatchApprovalError("Approved tooling pin lock is incomplete")
    coverage = pin_lock.get("coverage") or {}
    if coverage.get("missing_actions"):
        raise PatchApprovalError("Approved tooling pin lock has missing actions")
    validate_policy_bound_pin_lock(
        pin_lock,
        tooling_policy=tooling_policy,
        tooling_policy_sha256=tooling_policy_sha256,
    )
    if approval.get("approval_type") == "policy":
        if approved_by != ADDITIVE_BASELINE_POLICY:
            raise PatchApprovalError("Unknown automated patch approval policy")
        if approval.get("authentication") != "deterministic-policy":
            raise PatchApprovalError("Policy approval has invalid authentication mode")
        eligible = policy_eligible_change_ids(
            overlay,
            pin_lock=pin_lock,
            tooling_policy=tooling_policy,
            tooling_policy_sha256=tooling_policy_sha256,
        )
        if sorted(approved_ids) != eligible:
            raise PatchApprovalError(
                "Policy approval change set differs from deterministic eligibility"
            )
        if approval_repo.get("publish_secure_branch") is True:
            raise PatchApprovalError("Policy approval cannot authorize a remote push")

    publish = approval_repo.get("publish_secure_branch")
    if not isinstance(publish, bool):
        raise PatchApprovalError("Patch approval has invalid publication decision")
    expected_remote = approval_repo.get("expected_remote_sha")
    if expected_remote is not None:
        require_full_sha(expected_remote, label="expected remote secure commit")
    if publish and approval.get("approval_type") != "human-record":
        raise PatchApprovalError("Remote publication requires a human-record approval")
    if approval.get("approval_type") == "human-record" and approval.get(
        "authentication"
    ) != "local-record-only":
        raise PatchApprovalError("Human approval has invalid authentication mode")
    if (
        publish
        and expected_remote is not None
        and expected_remote != repository.get("secure_branch_sha")
    ):
        raise PatchApprovalError(
            "Expected remote secure commit must match the approved local secure base"
        )
    return repository, overlay


def policy_eligible_change_ids(
    overlay: dict[str, Any],
    *,
    pin_lock: dict[str, Any],
    tooling_policy: dict[str, Any],
    tooling_policy_sha256: str,
) -> list[str]:
    coverage = pin_lock.get("coverage") or {}
    if pin_lock.get("status") != "complete" or coverage.get("missing_actions"):
        return []
    try:
        validate_policy_bound_pin_lock(
            pin_lock,
            tooling_policy=tooling_policy,
            tooling_policy_sha256=tooling_policy_sha256,
        )
    except PatchApprovalError:
        return []
    pin_map = normalize_pin_map(pin_lock)
    eligible = []
    for change in overlay.get("proposed_changes", []):
        if not isinstance(change, dict):
            continue
        change_id = change.get("id")
        contract = POLICY_CHANGE_CONTRACTS.get(change_id)
        if contract is None:
            continue
        paths = change.get("paths")
        if (
            change.get("action") != contract["action"]
            or change.get("human_review_required") is not False
            or not isinstance(paths, list)
            or not all(isinstance(path, str) for path in paths)
            or sorted(paths) != sorted(contract["paths"])
        ):
            continue
        rendered = render_change(change, overlay=overlay, pins=pin_map)
        if rendered is not None and rendered[0] == contract["rendered_path"]:
            eligible.append(change_id)
    return sorted(eligible)


def validate_policy_bound_pin_lock(
    pin_lock: dict[str, Any],
    *,
    tooling_policy: dict[str, Any],
    tooling_policy_sha256: str,
) -> None:
    if pin_lock.get("schema_version") != 1:
        raise PatchApprovalError("Unsupported approved tooling pin lock schema")
    try:
        require_sha256(tooling_policy_sha256, label="tooling policy digest")
        require_sha256(pin_lock.get("source_policy_sha256"), label="pin policy digest")
    except SecurePatchError as exc:
        raise PatchApprovalError(str(exc)) from exc
    if not hmac.compare_digest(
        str(pin_lock.get("source_policy_sha256")),
        tooling_policy_sha256,
    ):
        raise PatchApprovalError("Pin lock does not bind the supplied tooling policy")
    policy_actions = required_tooling_policy_actions(tooling_policy)
    source_policy_status = pin_lock.get("source_policy_status")
    if source_policy_status != tooling_policy.get("status"):
        raise PatchApprovalError("Pin lock tooling policy status does not match policy")
    coverage = pin_lock.get("coverage")
    if not isinstance(coverage, dict):
        raise PatchApprovalError("Pin lock has no coverage record")
    required_actions = coverage.get("required_actions")
    resolved_actions = coverage.get("resolved_actions")
    missing_actions = coverage.get("missing_actions")
    if (
        not isinstance(required_actions, list)
        or not required_actions
        or not all(isinstance(name, str) and name for name in required_actions)
        or len(set(required_actions)) != len(required_actions)
    ):
        raise PatchApprovalError("Pin lock has no valid required action set")
    if set(required_actions) != set(policy_actions):
        raise PatchApprovalError("Pin lock action coverage differs from tooling policy")
    if (
        not isinstance(resolved_actions, list)
        or not all(isinstance(name, str) and name for name in resolved_actions)
        or len(set(resolved_actions)) != len(resolved_actions)
        or sorted(resolved_actions) != sorted(required_actions)
        or missing_actions != []
    ):
        raise PatchApprovalError("Pin lock coverage is incomplete or inconsistent")
    entries = pin_lock.get("entries")
    if not isinstance(entries, dict) or not entries:
        raise PatchApprovalError("Pin lock has no action entries")
    declared_pins = pin_lock.get("pins")
    if not isinstance(declared_pins, dict):
        raise PatchApprovalError("Pin lock has no resolved pin map")
    pin_map = normalize_pin_map(pin_lock)
    if set(pin_map) != set(required_actions):
        raise PatchApprovalError("Pin lock action entries do not match policy coverage")
    if set(entries) != set(required_actions) or set(declared_pins) != set(
        required_actions
    ):
        raise PatchApprovalError("Pin lock contains undeclared or missing action entries")
    now = datetime.now(UTC)
    for name in required_actions:
        if len(name.split("/")) < 2 or any(not part for part in name.split("/")):
            raise PatchApprovalError(f"Pin lock has an invalid action name: {name}")
        sha = pin_map.get(name)
        entry = entries.get(name)
        expected_repository = "/".join(name.split("/")[:2])
        if (
            not isinstance(entry, dict)
            or entry.get("status") != "resolved"
            or entry.get("repository") != expected_repository
            or not isinstance(entry.get("ref"), str)
            or not entry["ref"]
            or entry.get("ref") != policy_actions[name]
            or entry.get("resolved_ref") != policy_actions[name]
            or entry.get("sha") != sha
            or declared_pins.get(name) != sha
            or entry.get("requires_full_sha_pin") is not True
            or entry.get("refresh_status") != "current"
        ):
            raise PatchApprovalError(f"Pin lock entry lacks policy provenance: {name}")
        try:
            require_full_sha(sha, label=f"approved action pin {name}")
        except SecurePatchError as exc:
            raise PatchApprovalError(str(exc)) from exc
        resolved_at = parse_pin_time(
            entry.get("resolved_at"),
            name=name,
            field="resolved_at",
        )
        expires_at = parse_pin_time(
            entry.get("expires_at"),
            name=name,
            field="expires_at",
        )
        if resolved_at > now:
            raise PatchApprovalError(f"Pin lock entry was resolved in the future: {name}")
        if expires_at <= resolved_at or expires_at <= now:
            raise PatchApprovalError(f"Pin lock entry is stale: {name}")


def required_tooling_policy_actions(tooling_policy: dict[str, Any]) -> dict[str, str]:
    if tooling_policy.get("schema_version") != 1:
        raise PatchApprovalError("Unsupported tooling policy schema")
    status = tooling_policy.get("status")
    if not isinstance(status, str) or not status:
        raise PatchApprovalError("Tooling policy has no status")
    actions = tooling_policy.get("github_actions")
    if not isinstance(actions, list) or not actions:
        raise PatchApprovalError("Tooling policy has no GitHub Actions")
    required: dict[str, str] = {}
    for action in actions:
        if not isinstance(action, dict):
            raise PatchApprovalError("Tooling policy action entries must be objects")
        if action.get("requires_full_sha_pin") is not True:
            continue
        name = action.get("name")
        ref = action.get("ref")
        if (
            not isinstance(name, str)
            or not name
            or len(name.split("/")) < 2
            or any(not part for part in name.split("/"))
            or not isinstance(ref, str)
            or not ref
        ):
            raise PatchApprovalError("Tooling policy has an invalid pinned action")
        if name in required:
            raise PatchApprovalError(f"Tooling policy repeats action: {name}")
        required[name] = ref
    if not required:
        raise PatchApprovalError("Tooling policy has no required pinned actions")
    return required


def find_repository(
    analysis_index: dict[str, Any],
    target_full_name: str,
) -> dict[str, Any]:
    matches = [
        repository
        for repository in analysis_index.get("repositories", [])
        if isinstance(repository, dict)
        and str(repository.get("target_full_name", "")).casefold()
        == target_full_name.casefold()
    ]
    if len(matches) != 1:
        raise PatchApprovalError(
            f"Analysis index must contain exactly one {target_full_name} entry"
        )
    return matches[0]


def validate_approval_time(approval: dict[str, Any]) -> None:
    approved_at = parse_time(approval.get("approved_at"), label="approved_at")
    expires_at = parse_time(approval.get("expires_at"), label="expires_at")
    now = datetime.now(UTC)
    if approved_at > now:
        raise PatchApprovalError("Patch approval is future-dated")
    if expires_at <= approved_at:
        raise PatchApprovalError("Patch approval expires before it is approved")
    if expires_at - approved_at > MAX_APPROVAL_LIFETIME:
        raise PatchApprovalError("Patch approval lifetime exceeds seven days")
    if expires_at <= now:
        raise PatchApprovalError("Patch approval has expired")


def parse_time(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise PatchApprovalError(f"Patch approval has no {label} timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PatchApprovalError(f"Patch approval has invalid {label}") from exc
    if parsed.tzinfo is None:
        raise PatchApprovalError(f"Patch approval {label} must include a timezone")
    return parsed.astimezone(UTC)


def parse_pin_time(value: Any, *, name: str, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise PatchApprovalError(f"Pin lock entry has no {field}: {name}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PatchApprovalError(f"Pin lock entry has invalid {field}: {name}") from exc
    if parsed.tzinfo is None:
        raise PatchApprovalError(
            f"Pin lock entry {field} must include a timezone: {name}"
        )
    return parsed.astimezone(UTC)


def verified_file(path_value: Any, digest_value: Any, *, label: str) -> Path:
    try:
        require_sha256(digest_value, label=f"{label} digest")
    except SecurePatchError as exc:
        raise PatchApprovalError(str(exc)) from exc
    if not isinstance(path_value, str) or not path_value:
        raise PatchApprovalError(f"{label} path is invalid")
    path = Path(path_value).resolve()
    if not path.is_file():
        raise PatchApprovalError(f"{label} is missing: {path}")
    actual = sha256_file(path)
    if not hmac.compare_digest(actual, digest_value):
        raise PatchApprovalError(f"{label} digest verification failed: {path}")
    return path


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise PatchApprovalError(f"Expected a JSON object: {path}")
    return payload
