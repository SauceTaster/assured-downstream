from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from assured_downstream.command_runner import display_command


ACCOUNT_BOUNDARY_SCHEMA_VERSION = 1


class AccountBoundaryError(RuntimeError):
    pass


def default_github_account_boundary_path() -> Path:
    return Path(__file__).resolve().parents[2] / "policies" / "github-account-boundary.json"


def load_github_account_boundary(path: Path | None = None) -> dict[str, Any]:
    boundary_path = path or default_github_account_boundary_path()
    with boundary_path.open("r", encoding="utf-8") as handle:
        policy = json.load(handle)
    return validate_github_account_boundary(policy)


def validate_github_account_boundary(policy: dict[str, Any]) -> dict[str, Any]:
    required_keys = {
        "schema_version",
        "status",
        "github_host",
        "required_actor",
        "allowed_target_owners",
        "controls",
    }
    if set(policy) != required_keys:
        raise AccountBoundaryError("GitHub account boundary fields are invalid")
    if policy.get("schema_version") != ACCOUNT_BOUNDARY_SCHEMA_VERSION:
        raise AccountBoundaryError("Unsupported GitHub account boundary schema")
    if policy.get("status") != "active":
        raise AccountBoundaryError("GitHub account boundary is not active")
    if policy.get("github_host") != "github.com":
        raise AccountBoundaryError("GitHub account boundary host is not approved")

    actor = policy.get("required_actor")
    if not isinstance(actor, str) or not actor:
        raise AccountBoundaryError("GitHub account boundary actor is invalid")
    owners = policy.get("allowed_target_owners")
    if (
        not isinstance(owners, list)
        or not owners
        or not all(isinstance(owner, str) and owner for owner in owners)
        or len({owner.casefold() for owner in owners}) != len(owners)
    ):
        raise AccountBoundaryError("GitHub account boundary owners are invalid")

    controls = policy.get("controls")
    expected_controls = {
        "allow_auth_switch",
        "allow_external_collaborators",
        "allow_external_reviewers",
        "require_identity_check_before_mutation",
        "on_identity_mismatch",
        "on_independent_approval_unavailable",
    }
    if not isinstance(controls, dict) or set(controls) != expected_controls:
        raise AccountBoundaryError("GitHub account boundary controls are invalid")
    for key in (
        "allow_auth_switch",
        "allow_external_collaborators",
        "allow_external_reviewers",
    ):
        if controls.get(key) is not False:
            raise AccountBoundaryError(f"GitHub account boundary must disable {key}")
    if controls.get("require_identity_check_before_mutation") is not True:
        raise AccountBoundaryError("GitHub mutations must require an identity check")
    for key in ("on_identity_mismatch", "on_independent_approval_unavailable"):
        if controls.get(key) != "fail_closed":
            raise AccountBoundaryError(f"GitHub account boundary must fail closed for {key}")
    return policy


def require_allowed_target_owner(policy: dict[str, Any], owner: str) -> str:
    effective = validate_github_account_boundary(policy)
    if not isinstance(owner, str) or not owner:
        raise AccountBoundaryError("GitHub mutation target owner is invalid")
    allowed = {item.casefold() for item in effective["allowed_target_owners"]}
    if owner.casefold() not in allowed:
        raise AccountBoundaryError(
            f"GitHub mutation target owner {owner!r} is outside the account boundary"
        )
    return owner


def verify_authenticated_actor(
    result: Any,
    policy: dict[str, Any],
) -> tuple[bool, dict[str, Any]]:
    effective = validate_github_account_boundary(policy)
    expected_actor = effective["required_actor"]
    detail = {
        "command": display_command(result.command),
        "executed": result.executed,
        "returncode": result.returncode,
        "expected_login": expected_actor,
    }
    if result.stderr:
        detail["stderr"] = result.stderr.strip()
    if not result.ok:
        detail["reason"] = "authenticated GitHub user lookup failed"
        return False, detail
    try:
        payload = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        detail["reason"] = "authenticated GitHub user lookup returned invalid JSON"
        return False, detail
    actual_actor = payload.get("login")
    detail["actual_login"] = actual_actor
    verified = (
        isinstance(actual_actor, str)
        and actual_actor.casefold() == expected_actor.casefold()
    )
    if not verified:
        detail["reason"] = "authenticated GitHub user does not match the account boundary"
    return verified, detail

