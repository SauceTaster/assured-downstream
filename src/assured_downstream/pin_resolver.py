from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Protocol


class CommitResolver(Protocol):
    def resolve_commit(self, owner: str, name: str, ref: str) -> str:
        """Resolve a repository ref to a commit SHA."""


def resolve_tooling_pins(
    tooling_policy: dict[str, Any],
    *,
    client: CommitResolver,
    ttl_days: int = 30,
    source_policy_sha256: str | None = None,
) -> dict[str, Any]:
    resolved_at = utc_now()
    expires_at = (datetime.now(UTC) + timedelta(days=ttl_days)).isoformat(timespec="seconds")
    pins = {}
    entries = {}
    required_actions = []

    for action in tooling_policy.get("github_actions", []):
        if not action.get("requires_full_sha_pin"):
            continue
        name = action["name"]
        required_actions.append(name)
        ref = action.get("ref")
        if not ref:
            entries[name] = {
                "status": "skipped",
                "requires_full_sha_pin": True,
                "usage": action.get("usage"),
                "reason": "missing ref",
            }
            continue

        owner, repo = action_repository(name)
        try:
            sha = client.resolve_commit(owner, repo, ref)
        except Exception as exc:  # noqa: BLE001 - record per-action resolution errors.
            entries[name] = {
                "status": "failed",
                "requires_full_sha_pin": True,
                "usage": action.get("usage"),
                "ref": ref,
                "resolved_ref": ref,
                "reason": str(exc),
            }
            continue

        pins[name] = sha
        entries[name] = {
            "status": "resolved",
            "requires_full_sha_pin": True,
            "usage": action.get("usage"),
            "repository": f"{owner}/{repo}",
            "ref": ref,
            "resolved_ref": ref,
            "sha": sha,
            "resolved_at": resolved_at,
            "expires_at": expires_at,
            "refresh_status": "current",
        }

    missing_actions = sorted(name for name in required_actions if name not in pins)
    return {
        "schema_version": 1,
        "generated_at": resolved_at,
        "source_policy_status": tooling_policy.get("status"),
        "source_policy_sha256": source_policy_sha256,
        "status": "complete" if not missing_actions else "incomplete",
        "coverage": {
            "required_actions": sorted(required_actions),
            "resolved_actions": sorted(pins),
            "missing_actions": missing_actions,
        },
        "pins": pins,
        "entries": entries,
    }


def action_repository(action_name: str) -> tuple[str, str]:
    parts = action_name.split("/")
    if len(parts) < 2:
        raise ValueError(f"Invalid GitHub Action name: {action_name}")
    return parts[0], parts[1]


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")
