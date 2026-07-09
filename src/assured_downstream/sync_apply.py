from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from assured_downstream.command_runner import CommandRunner, display_command
from assured_downstream.lifecycle import StateStore


@dataclass(frozen=True)
class SyncApplyResult:
    succeeded: int
    failed: int


def apply_sync_plan(
    plan: dict[str, Any],
    *,
    state: StateStore,
    execute: bool = False,
    runner: CommandRunner | None = None,
) -> SyncApplyResult:
    runner = runner or CommandRunner(execute=execute)
    succeeded = 0
    failed = 0

    for repo in plan.get("repositories", []):
        source = repo["source_full_name"]
        target = repo["target_full_name"]
        command_results = []
        repo_ok = True

        for command_entry in repo.get("commands", []):
            command = command_entry["argv"]
            result = runner.run(command)
            command_results.append(
                {
                    "command": display_command(command),
                    "executed": result.executed,
                    "returncode": result.returncode,
                    "stdout": result.stdout.strip(),
                    "stderr": result.stderr.strip(),
                }
            )
            if not result.ok:
                repo_ok = False
                break

        event = "Synced" if execute else "SyncPlanned"
        state.record(
            source_full_name=source,
            target_full_name=target,
            event=event,
            status="ok" if repo_ok else "failed",
            detail={
                "local_path": repo.get("local_path"),
                "commands": command_results,
            },
        )

        if repo_ok:
            succeeded += 1
        else:
            failed += 1

    return SyncApplyResult(succeeded=succeeded, failed=failed)

