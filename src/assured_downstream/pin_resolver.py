from __future__ import annotations

from typing import Any, Protocol

from assured_downstream.catalog import utc_now


class CommitResolver(Protocol):
    def resolve_commit(self, owner: str, name: str, ref: str) -> str:
        """Resolve a repository ref to a commit SHA."""


def resolve_tooling_pins(
    tooling_policy: dict[str, Any],
    *,
    client: CommitResolver,
) -> dict[str, Any]:
    pins = {}
    entries = {}

    for action in tooling_policy.get("github_actions", []):
        if not action.get("requires_full_sha_pin"):
            continue
        name = action["name"]
        ref = action.get("ref")
        if not ref:
            entries[name] = {
                "status": "skipped",
                "reason": "missing ref",
            }
            continue

        owner, repo = action_repository(name)
        try:
            sha = client.resolve_commit(owner, repo, ref)
        except Exception as exc:  # noqa: BLE001 - record per-action resolution errors.
            entries[name] = {
                "status": "failed",
                "ref": ref,
                "reason": str(exc),
            }
            continue

        pins[name] = sha
        entries[name] = {
            "status": "resolved",
            "repository": f"{owner}/{repo}",
            "ref": ref,
            "sha": sha,
        }

    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "source_policy_status": tooling_policy.get("status"),
        "pins": pins,
        "entries": entries,
    }


def action_repository(action_name: str) -> tuple[str, str]:
    parts = action_name.split("/")
    if len(parts) < 2:
        raise ValueError(f"Invalid GitHub Action name: {action_name}")
    return parts[0], parts[1]

