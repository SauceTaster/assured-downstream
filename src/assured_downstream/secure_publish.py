from __future__ import annotations

from pathlib import Path
from typing import Any

from assured_downstream.command_runner import CommandResult, CommandRunner
from assured_downstream.secure_patch import require_full_sha
from assured_downstream.sync_apply import (
    display_safe_command,
    redact_remote_url,
    reject_embedded_http_credentials,
    validate_planned_repository_url,
)
from assured_downstream.sync_plan import validate_default_branch


class SecurePublishError(RuntimeError):
    pass


PUBLISH_ENV = {
    "GIT_CONFIG_COUNT": "0",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_PARAMETERS": "",
    "GIT_TERMINAL_PROMPT": "0",
}


def publish_secure_branch(
    *,
    checkout_path: Path,
    target_full_name: str,
    secure_branch: str,
    patch_sha: str,
    expected_remote_sha: str | None,
    execute: bool,
    allow_local_remotes: bool = False,
    runner: CommandRunner | None = None,
) -> dict[str, Any]:
    checkout_path = checkout_path.resolve()
    validate_default_branch(secure_branch)
    patch_sha = require_full_sha(patch_sha, label="secure patch commit")
    if expected_remote_sha is not None:
        expected_remote_sha = require_full_sha(
            expected_remote_sha,
            label="expected remote secure commit",
        )
    runner = runner or CommandRunner(execute=True)

    root = run_required(
        runner,
        git_command(checkout_path, "rev-parse", "--show-toplevel"),
    )
    if Path(root).resolve() != checkout_path:
        raise SecurePublishError(
            f"Managed checkout is not its Git root: {checkout_path}"
        )
    reject_repository_url_rewrites(runner, checkout_path=checkout_path)
    secure_ref = f"refs/heads/{secure_branch}"
    local_sha = run_required(
        runner,
        git_command(checkout_path, "show-ref", "--verify", "--hash", secure_ref),
    )
    if local_sha != patch_sha:
        raise SecurePublishError(
            f"Local {secure_ref} is {local_sha}, expected approved patch {patch_sha}"
        )

    origin_url = run_required(
        runner,
        git_command(checkout_path, "remote", "get-url", "origin"),
    )
    reject_embedded_http_credentials(origin_url)
    try:
        validate_planned_repository_url(
            origin_url,
            expected_full_name=target_full_name,
            allow_local_remotes=allow_local_remotes,
        )
    except Exception as exc:
        raise SecurePublishError(str(exc)) from exc

    destination_ref = secure_ref
    lease = f"--force-with-lease={destination_ref}:{expected_remote_sha or ''}"
    push_command = git_command(
        checkout_path,
        "push",
        "--porcelain",
        lease,
        origin_url,
        f"{patch_sha}:{destination_ref}",
    )
    result = {
        "schema_version": 1,
        "status": "planned",
        "executed": False,
        "target_full_name": target_full_name,
        "origin_url": redact_remote_url(origin_url),
        "secure_branch": secure_branch,
        "secure_ref": secure_ref,
        "patch_sha": patch_sha,
        "expected_remote_sha": expected_remote_sha,
        "remote_before_sha": None,
        "remote_after_sha": None,
        "command": display_safe_command(push_command),
    }
    if not execute:
        return result

    remote_before = remote_ref_sha(
        runner,
        checkout_path=checkout_path,
        origin_url=origin_url,
        remote_ref=destination_ref,
    )
    if remote_before == patch_sha:
        return {
            **result,
            "status": "already-published",
            "remote_before_sha": remote_before,
            "remote_after_sha": remote_before,
            "reconciled_existing_side_effect": True,
        }
    if remote_before != expected_remote_sha:
        raise SecurePublishError(
            f"Remote {destination_ref} is {remote_before or '<absent>'}, expected "
            f"{expected_remote_sha or '<absent>'}"
        )
    pushed = runner.run(push_command, env=PUBLISH_ENV)
    if not pushed.ok:
        raise SecurePublishError(command_failure(pushed))
    remote_after = remote_ref_sha(
        runner,
        checkout_path=checkout_path,
        origin_url=origin_url,
        remote_ref=destination_ref,
    )
    if remote_after != patch_sha:
        raise SecurePublishError(
            f"Remote {destination_ref} verification returned "
            f"{remote_after or '<absent>'}, expected {patch_sha}"
        )
    return {
        **result,
        "status": "published",
        "executed": True,
        "remote_before_sha": remote_before,
        "remote_after_sha": remote_after,
    }


def remote_ref_sha(
    runner: CommandRunner,
    *,
    checkout_path: Path,
    origin_url: str,
    remote_ref: str,
) -> str | None:
    command = git_command(
        checkout_path,
        "ls-remote",
        "--heads",
        origin_url,
        remote_ref,
    )
    output = run_required(
        runner,
        command,
        env=PUBLISH_ENV,
    )
    lines = [line for line in output.splitlines() if line]
    if not lines:
        return None
    if len(lines) != 1:
        raise SecurePublishError(f"Remote returned duplicate refs for {remote_ref}")
    fields = lines[0].split()
    if len(fields) != 2 or fields[1] != remote_ref:
        raise SecurePublishError(f"Remote returned malformed ref data for {remote_ref}")
    return require_full_sha(fields[0], label=f"remote {remote_ref}")


def reject_repository_url_rewrites(
    runner: CommandRunner,
    *,
    checkout_path: Path,
) -> None:
    result = runner.run(
        git_command(
            checkout_path,
            "config",
            "--get-regexp",
            r"^url\..*\.(instead|pushinstead)of$",
        ),
        env=PUBLISH_ENV,
    )
    if result.returncode == 1 and not result.stdout.strip():
        return
    if not result.ok:
        raise SecurePublishError(command_failure(result))
    if result.stdout.strip():
        raise SecurePublishError(
            "Managed checkout contains a Git URL rewrite; publication is blocked"
        )


def git_command(checkout_path: Path, *args: str) -> list[str]:
    return [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-C",
        str(checkout_path),
        *args,
    ]


def run_required(
    runner: CommandRunner,
    command: list[str],
    *,
    env: dict[str, str] | None = None,
) -> str:
    result = runner.run(command, env=env or PUBLISH_ENV)
    if not result.ok:
        raise SecurePublishError(command_failure(result))
    return result.stdout.strip()


def command_failure(result: CommandResult) -> str:
    detail = (result.stderr or result.stdout).strip() or "unknown Git error"
    if len(detail) > 2048:
        detail = detail[:2048] + "...<truncated>"
    return f"Git command failed: {display_safe_command(result.command)}: {detail}"
