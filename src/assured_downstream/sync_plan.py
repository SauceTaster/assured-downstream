from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from assured_downstream.catalog import utc_now
from assured_downstream.command_runner import display_command


SYNC_PLAN_SCHEMA_VERSION = 2


def create_sync_plan(
    fork_plan: dict[str, Any],
    *,
    workspace: Path,
    allow_local_remotes: bool = False,
) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    repositories = []
    for entry in fork_plan.get("forks", []):
        default_branch = (
            entry.get("metadata", {}).get("default_branch")
            or "main"
        )
        validate_default_branch(default_branch)
        local_path = workspace / safe_repo_dir(entry["target_full_name"])
        source_url = planned_clone_url(
            entry,
            override_key="source_clone_url",
            full_name=entry["source_full_name"],
            allow_local_remotes=allow_local_remotes,
        )
        target_url = planned_clone_url(
            entry,
            override_key="target_clone_url",
            full_name=entry["target_full_name"],
            allow_local_remotes=allow_local_remotes,
        )
        operations = sync_operations(
            source_url=source_url,
            target_url=target_url,
            local_path=local_path,
            default_branch=default_branch,
        )
        repositories.append(
            {
                "source_full_name": entry["source_full_name"],
                "target_full_name": entry["target_full_name"],
                "source_url": source_url,
                "target_url": target_url,
                "default_branch": default_branch,
                "local_path": str(local_path),
                "branch_model": {
                    "origin_default_ref": f"refs/remotes/origin/{default_branch}",
                    "upstream_default_ref": f"refs/remotes/upstream/{default_branch}",
                    "upstream_mirror_branch": f"upstream/{default_branch}",
                    "secure_branch": f"secure/{default_branch}",
                },
                "commands": [
                    {
                        **operation,
                        "display": display_command(operation["argv"]),
                    }
                    for operation in operations
                ],
            }
        )

    return {
        "schema_version": SYNC_PLAN_SCHEMA_VERSION,
        "created_at": utc_now(),
        "mode": "dry_run",
        "workspace": str(workspace),
        "reconciliation_policy": {
            "checkout": "clone-if-missing-validate-if-present",
            "origin_remote": "validate-only",
            "upstream_remote": "add-if-missing-validate-if-present",
            "upstream_mirror_branch": "force-to-fetched-upstream",
            "secure_branch": "create-if-missing-preserve-if-present",
            "upstream_tags": "refs/tags/upstream/*",
            "remote_pushes": "disabled",
            "local_remotes": "test-only" if allow_local_remotes else "forbidden",
        },
        "repositories": repositories,
    }


def sync_commands(
    entry: dict[str, Any],
    *,
    local_path: Path,
    default_branch: str,
) -> list[list[str]]:
    source_url = github_clone_url(entry["source_full_name"])
    target_url = github_clone_url(entry["target_full_name"])
    return [
        operation["argv"]
        for operation in sync_operations(
            source_url=source_url,
            target_url=target_url,
            local_path=local_path,
            default_branch=default_branch,
        )
    ]


def sync_operations(
    *,
    source_url: str,
    target_url: str,
    local_path: Path,
    default_branch: str,
    origin_fetch_url: str | None = None,
    upstream_fetch_url: str | None = None,
) -> list[dict[str, Any]]:
    origin_fetch_url = origin_fetch_url or target_url
    upstream_fetch_url = upstream_fetch_url or source_url
    upstream_branch_refspec = "+refs/heads/*:refs/remotes/upstream/*"
    upstream_tag_refspec = "+refs/tags/*:refs/tags/upstream/*"
    return [
        {
            "operation": "clone-checkout",
            "when": "checkout-missing",
            "argv": [
                "git",
                "clone",
                "--filter=blob:none",
                "--origin",
                "origin",
                target_url,
                str(local_path),
            ],
        },
        {
            "operation": "add-upstream-remote",
            "when": "upstream-remote-missing",
            "argv": [
                "git",
                "-C",
                str(local_path),
                "remote",
                "add",
                "upstream",
                source_url,
            ],
        },
        {
            "operation": "fetch-origin",
            "when": "always",
            "argv": [
                "git",
                "-C",
                str(local_path),
                "fetch",
                "--prune",
                "--no-tags",
                origin_fetch_url,
                "+refs/heads/*:refs/remotes/origin/*",
            ],
        },
        {
            "operation": "fetch-upstream",
            "when": "always",
            "argv": [
                "git",
                "-C",
                str(local_path),
                "fetch",
                "--prune",
                "--no-tags",
                upstream_fetch_url,
                upstream_branch_refspec,
                upstream_tag_refspec,
            ],
        },
        {
            "operation": "update-upstream-mirror",
            "when": "mirror-not-checked-out",
            "argv": [
                "git",
                "-C",
                str(local_path),
                "branch",
                "-f",
                f"upstream/{default_branch}",
                f"refs/remotes/upstream/{default_branch}",
            ],
        },
        {
            "operation": "create-secure-branch",
            "when": "secure-branch-missing",
            "argv": [
                "git",
                "-C",
                str(local_path),
                "branch",
                f"secure/{default_branch}",
                f"refs/remotes/upstream/{default_branch}",
            ],
        },
    ]


def safe_repo_dir(full_name: str) -> str:
    parts = full_name.split("/")
    if len(parts) != 2 or not all(parts):
        raise ValueError(f"Invalid GitHub repository full name: {full_name!r}")
    safe_parts = [re.sub(r"[^A-Za-z0-9._-]", "_", part) for part in parts]
    if any(part in {"", ".", ".."} for part in safe_parts):
        raise ValueError(f"Unsafe GitHub repository full name: {full_name!r}")
    return "__".join(safe_parts)


def github_clone_url(full_name: str) -> str:
    safe_repo_dir(full_name)
    return f"https://github.com/{full_name}.git"


def planned_clone_url(
    entry: dict[str, Any],
    *,
    override_key: str,
    full_name: str,
    allow_local_remotes: bool,
) -> str:
    canonical = github_clone_url(full_name)
    override = entry.get(override_key)
    if override is None:
        return canonical
    if not allow_local_remotes:
        raise ValueError(
            f"Fork plan field {override_key!r} is forbidden outside test-only local reconciliation"
        )
    if not isinstance(override, str) or not override:
        raise ValueError(f"Fork plan field {override_key!r} must be a non-empty string")
    reject_credential_bearing_url(override)
    return override


def reject_credential_bearing_url(value: str) -> None:
    parsed = urlsplit(value)
    if parsed.scheme in {"http", "https"} and (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "HTTP Git remote URLs may not embed credentials, query strings, or fragments"
        )


def validate_default_branch(branch: str) -> None:
    invalid_characters = set(" ~^:?*[\\")
    components = branch.split("/")
    if (
        not branch
        or branch.startswith("-")
        or branch.startswith("/")
        or branch.endswith(("/", ".", ".lock"))
        or any(not component for component in components)
        or any(component.startswith(".") for component in components)
        or any(component.endswith(".lock") for component in components)
        or ".." in branch
        or "@{" in branch
        or any(
            character in invalid_characters or ord(character) < 32 or ord(character) == 127
            for character in branch
        )
    ):
        raise ValueError(f"Invalid default branch name: {branch!r}")
