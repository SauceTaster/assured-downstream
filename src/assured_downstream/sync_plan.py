from __future__ import annotations

from pathlib import Path
from typing import Any

from assured_downstream.catalog import utc_now
from assured_downstream.command_runner import display_command


def create_sync_plan(
    fork_plan: dict[str, Any],
    *,
    workspace: Path,
) -> dict[str, Any]:
    repositories = []
    for entry in fork_plan.get("forks", []):
        default_branch = (
            entry.get("metadata", {}).get("default_branch")
            or "main"
        )
        local_path = workspace / safe_repo_dir(entry["target_full_name"])
        commands = sync_commands(entry, local_path=local_path, default_branch=default_branch)
        repositories.append(
            {
                "source_full_name": entry["source_full_name"],
                "target_full_name": entry["target_full_name"],
                "default_branch": default_branch,
                "local_path": str(local_path),
                "commands": [
                    {
                        "argv": command,
                        "display": display_command(command),
                    }
                    for command in commands
                ],
            }
        )

    return {
        "created_at": utc_now(),
        "mode": "dry_run",
        "workspace": str(workspace),
        "repositories": repositories,
    }


def sync_commands(
    entry: dict[str, Any],
    *,
    local_path: Path,
    default_branch: str,
) -> list[list[str]]:
    source_url = f"https://github.com/{entry['source_full_name']}.git"
    target_url = f"https://github.com/{entry['target_full_name']}.git"
    return [
        ["git", "clone", target_url, str(local_path)],
        ["git", "-C", str(local_path), "remote", "add", "upstream", source_url],
        ["git", "-C", str(local_path), "fetch", "upstream", "--tags"],
        [
            "git",
            "-C",
            str(local_path),
            "checkout",
            "-B",
            f"upstream/{default_branch}",
            f"refs/remotes/upstream/{default_branch}",
        ],
        [
            "git",
            "-C",
            str(local_path),
            "branch",
            f"secure/{default_branch}",
            f"refs/remotes/upstream/{default_branch}",
        ],
    ]


def safe_repo_dir(full_name: str) -> str:
    return full_name.replace("/", "__")
