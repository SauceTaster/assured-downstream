from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from assured_downstream.command_runner import CommandRunner, display_command
from assured_downstream.lifecycle import StateStore


@dataclass(frozen=True)
class ForkApplyResult:
    succeeded: int
    failed: int
    skipped: int


def apply_fork_plan(
    plan: dict[str, Any],
    *,
    state: StateStore,
    execute: bool = False,
    runner: CommandRunner | None = None,
) -> ForkApplyResult:
    runner = runner or CommandRunner(execute=execute)
    succeeded = 0
    failed = 0
    skipped = 0

    for entry in plan.get("forks", []):
        source = entry["source_full_name"]
        target = entry["target_full_name"]
        command = fork_command(source, plan["org"])
        result = runner.run(command)
        event = "Forked" if execute else "ForkPlanned"
        status = "ok" if result.ok else "failed"
        detail = {
            "command": display_command(command),
            "executed": result.executed,
            "returncode": result.returncode,
        }
        if result.stdout:
            detail["stdout"] = result.stdout.strip()
        if result.stderr:
            detail["stderr"] = result.stderr.strip()

        state.record(
            source_full_name=source,
            target_full_name=target,
            event=event,
            status=status,
            detail=detail,
        )

        if result.ok:
            succeeded += 1
        else:
            failed += 1

    return ForkApplyResult(succeeded=succeeded, failed=failed, skipped=skipped)


def fork_command(source_full_name: str, org: str) -> list[str]:
    return [
        "gh",
        "repo",
        "fork",
        source_full_name,
        "--org",
        org,
        "--clone=false",
    ]

