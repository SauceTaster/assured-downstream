from __future__ import annotations

from datetime import UTC, datetime
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


MIN_MUTATION_WINDOW_SECONDS = 15
MAX_PUSH_SECONDS = 120
PUBLISH_ENV = {
    "GIT_CONFIG_COUNT": "0",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_PARAMETERS": "",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_TERMINAL_PROMPT": "0",
}


def publish_secure_branch(
    *,
    checkout_path: Path,
    target_full_name: str,
    secure_branch: str,
    patch_sha: str,
    patch_base_sha: str,
    required_upstream_sha: str,
    authorization_expires_at: str,
    lease_expires_at: str,
    expected_remote_sha: str | None,
    execute: bool,
    allow_local_remotes: bool = False,
    runner: CommandRunner | None = None,
) -> dict[str, Any]:
    checkout_path = checkout_path.resolve()
    validate_default_branch(secure_branch)
    patch_sha = require_full_sha(patch_sha, label="secure patch commit")
    patch_base_sha = require_full_sha(
        patch_base_sha,
        label="secure patch base commit",
    )
    required_upstream_sha = require_full_sha(
        required_upstream_sha,
        label="required upstream commit",
    )
    authorization_expiry = parse_deadline(
        authorization_expires_at,
        label="publication authorization expiry",
    )
    lease_expiry = parse_deadline(
        lease_expires_at,
        label="publisher lease expiry",
    )
    if execute:
        mutation_timeout_seconds(authorization_expiry, lease_expiry)
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
    commit = run_required(
        runner,
        git_command(checkout_path, "cat-file", "commit", patch_sha),
    )
    headers = commit.split("\n\n", 1)[0].splitlines()
    parents = [
        line.removeprefix("parent ")
        for line in headers
        if line.startswith("parent ")
    ]
    if parents != [patch_base_sha]:
        raise SecurePublishError(
            "Authorized patch commit does not have exactly the approved base parent"
        )
    ancestry = runner.run(
        git_command(
            checkout_path,
            "merge-base",
            "--is-ancestor",
            required_upstream_sha,
            patch_base_sha,
        ),
        env=PUBLISH_ENV,
    )
    if not ancestry.ok:
        raise SecurePublishError(
            "Authorized patch base does not contain the required upstream commit"
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
        "patch_base_sha": patch_base_sha,
        "required_upstream_sha": required_upstream_sha,
        "authorization_expires_at": authorization_expires_at,
        "lease_expires_at": lease_expires_at,
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
    push_timeout = mutation_timeout_seconds(
        authorization_expiry,
        lease_expiry,
    )
    pushed = runner.run(
        push_command,
        env=PUBLISH_ENV,
        timeout_seconds=push_timeout,
    )
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


def parse_deadline(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise SecurePublishError(f"{label.capitalize()} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SecurePublishError(f"{label.capitalize()} is invalid") from exc
    if parsed.tzinfo is None:
        raise SecurePublishError(f"{label.capitalize()} must include a timezone")
    return parsed.astimezone(UTC)


def mutation_timeout_seconds(
    authorization_expiry: datetime,
    lease_expiry: datetime,
) -> int:
    remaining = min(authorization_expiry, lease_expiry) - datetime.now(UTC)
    seconds = int(remaining.total_seconds())
    if seconds < MIN_MUTATION_WINDOW_SECONDS:
        raise SecurePublishError(
            "Publication authorization or publisher lease expires too soon for mutation"
        )
    return min(seconds, MAX_PUSH_SECONDS)
