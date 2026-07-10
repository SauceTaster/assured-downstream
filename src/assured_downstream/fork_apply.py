from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from assured_downstream.command_runner import CommandRunner, display_command
from assured_downstream.fork_plan import fork_command, fork_target_from_plan
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
    fork_target = fork_target_from_plan(plan)
    entries = plan.get("forks", [])
    succeeded = 0
    failed = 0
    skipped = 0

    if execute and entries and fork_target["owner_type"] == "user":
        identity = runner.run(authenticated_user_lookup_command())
        identity_ok, identity_detail = verify_authenticated_user(
            identity,
            fork_target["owner"],
        )
        if not identity_ok:
            for entry in entries:
                state.record(
                    source_full_name=entry["source_full_name"],
                    target_full_name=entry["target_full_name"],
                    event="ForkPreflightFailed",
                    status="failed",
                    detail=identity_detail,
                )
            return ForkApplyResult(succeeded=0, failed=len(entries), skipped=0)

    for entry in entries:
        source = entry["source_full_name"]
        target = entry["target_full_name"]
        target_repo_name = entry.get("target_repo_name") or target.partition("/")[2]
        expected_target = f"{fork_target['owner']}/{target_repo_name}"
        if target.casefold() != expected_target.casefold():
            state.record(
                source_full_name=source,
                target_full_name=target,
                event="ForkConflict",
                status="failed",
                detail={
                    "reason": "target does not match the fork plan owner and repository name",
                    "expected_target": expected_target,
                },
            )
            failed += 1
            continue

        command = fork_command(
            source,
            target_owner=fork_target["owner"],
            target_owner_type=fork_target["owner_type"],
            target_repo_name=target_repo_name,
        )

        if execute:
            lookup = runner.run(repository_lookup_command(target))
            if lookup.ok:
                verified, verification = verify_fork_lookup(lookup, source)
                state.record(
                    source_full_name=source,
                    target_full_name=target,
                    event="ForkVerified" if verified else "ForkConflict",
                    status="ok" if verified else "failed",
                    detail=verification,
                )
                if verified:
                    skipped += 1
                else:
                    failed += 1
                continue
            if not repository_was_not_found(lookup):
                state.record(
                    source_full_name=source,
                    target_full_name=target,
                    event="ForkPreflightFailed",
                    status="failed",
                    detail=command_result_detail(lookup),
                )
                failed += 1
                continue

        result = runner.run(command)
        event = "Forked" if execute else "ForkPlanned"
        status = "ok" if result.ok else "failed"
        detail = command_result_detail(result)

        if execute and result.ok:
            lookup = runner.run(repository_lookup_command(target))
            verified, verification = verify_fork_lookup(lookup, source)
            detail["verification"] = verification
            if not verified:
                status = "failed"

        state.record(
            source_full_name=source,
            target_full_name=target,
            event=event,
            status=status,
            detail=detail,
        )

        if status == "ok":
            succeeded += 1
        else:
            failed += 1

    return ForkApplyResult(succeeded=succeeded, failed=failed, skipped=skipped)


def repository_lookup_command(target_full_name: str) -> list[str]:
    return ["gh", "api", f"repos/{target_full_name}"]


def authenticated_user_lookup_command() -> list[str]:
    return ["gh", "api", "user"]


def verify_authenticated_user(
    result: Any,
    expected_login: str,
) -> tuple[bool, dict[str, Any]]:
    detail = command_result_detail(result, include_stdout=False)
    detail["expected_login"] = expected_login
    if not result.ok:
        detail["reason"] = "authenticated GitHub user lookup failed"
        return False, detail

    try:
        payload = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        detail["reason"] = "authenticated GitHub user lookup returned invalid JSON"
        return False, detail

    actual_login = payload.get("login")
    detail["actual_login"] = actual_login
    verified = (
        isinstance(actual_login, str)
        and actual_login.casefold() == expected_login.casefold()
    )
    if not verified:
        detail["reason"] = "authenticated GitHub user does not match the target owner"
    return verified, detail


def verify_fork_lookup(result: Any, source_full_name: str) -> tuple[bool, dict[str, Any]]:
    detail = command_result_detail(result, include_stdout=False)
    if not result.ok:
        detail["reason"] = "target repository lookup failed"
        return False, detail

    try:
        payload = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        detail["reason"] = "target repository lookup returned invalid JSON"
        return False, detail

    parent = payload.get("parent") or {}
    parent_full_name = parent.get("full_name")
    detail.update(
        {
            "is_fork": payload.get("fork") is True,
            "parent_full_name": parent_full_name,
            "expected_parent_full_name": source_full_name,
        }
    )
    verified = (
        payload.get("fork") is True
        and isinstance(parent_full_name, str)
        and parent_full_name.casefold() == source_full_name.casefold()
    )
    if not verified:
        detail["reason"] = "target is not a fork of the requested source repository"
    return verified, detail


def repository_was_not_found(result: Any) -> bool:
    error = f"{result.stdout}\n{result.stderr}".casefold()
    return not result.ok and "404" in error and "not found" in error


def command_result_detail(result: Any, *, include_stdout: bool = True) -> dict[str, Any]:
    detail = {
        "command": display_command(result.command),
        "executed": result.executed,
        "returncode": result.returncode,
    }
    if include_stdout and result.stdout:
        detail["stdout"] = result.stdout.strip()
    if result.stderr:
        detail["stderr"] = result.stderr.strip()
    return detail
