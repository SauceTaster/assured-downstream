from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

from assured_downstream.command_runner import (
    CommandResult,
    CommandRunner,
    display_command,
)
from assured_downstream.lifecycle import StateStore
from assured_downstream.sync_plan import sync_operations, validate_default_branch


MAX_CAPTURED_OUTPUT = 4096


@dataclass(frozen=True)
class SyncApplyResult:
    succeeded: int
    failed: int
    review_required: int = 0


class SyncReconciliationError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        event: str,
        detail: dict[str, Any],
    ) -> None:
        super().__init__(message)
        self.event = event
        self.detail = detail


class CommandJournal:
    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner
        self.entries: list[dict[str, Any]] = []

    def run(
        self,
        command: list[str],
        *,
        allow_failure: bool = False,
        include_stdout: bool = True,
    ) -> CommandResult:
        result = self.runner.run(command)
        entry = command_result_detail(result, include_stdout=include_stdout)
        self.entries.append(entry)
        if not result.ok and not allow_failure:
            raise SyncReconciliationError(
                f"Git reconciliation command failed: {display_safe_command(command)}",
                event="SyncFailed",
                detail={
                    "reason": "git reconciliation command failed",
                    "failed_command": entry,
                    "commands": list(self.entries),
                },
            )
        return result


def apply_sync_plan(
    plan: dict[str, Any],
    *,
    state: StateStore,
    execute: bool = False,
    runner: CommandRunner | None = None,
    allow_local_remotes: bool = False,
) -> SyncApplyResult:
    runner = runner or CommandRunner(execute=execute)
    repositories = plan.get("repositories", [])
    if not isinstance(repositories, list):
        raise ValueError("Sync plan repositories must be a list")

    if not execute:
        for repo in repositories:
            record_dry_run(repo, state=state)
        return SyncApplyResult(succeeded=len(repositories), failed=0)

    if plan.get("schema_version") != 2:
        for index, repo in enumerate(repositories):
            source, target = reconciliation_state_identity(repo, index=index)
            state.record(
                source_full_name=source,
                target_full_name=target,
                event="SyncConflict",
                status="failed",
                detail={
                    "reason": "live reconciliation requires a schema_version 2 sync plan",
                    "action": "regenerate the sync plan before executing it",
                },
            )
        return SyncApplyResult(succeeded=0, failed=len(repositories))

    workspace = Path(require_string(plan, "workspace")).expanduser().resolve()
    succeeded = 0
    failed = 0
    review_required = 0

    for index, repo in enumerate(repositories):
        source, target = reconciliation_state_identity(repo, index=index)
        local_path = repo.get("local_path") if isinstance(repo, dict) else None
        try:
            if not isinstance(repo, dict):
                raise ValueError("Sync plan repository entry must be an object")
            source = require_string(repo, "source_full_name")
            target = require_string(repo, "target_full_name")
            detail = reconcile_repository(
                repo,
                workspace=workspace,
                runner=runner,
                allow_local_remotes=allow_local_remotes,
            )
        except SyncReconciliationError as exc:
            detail = {
                "local_path": local_path,
                **exc.detail,
            }
            state.record(
                source_full_name=source,
                target_full_name=target,
                event=exc.event,
                status="failed",
                detail=detail,
            )
            failed += 1
            continue
        except ValueError as exc:
            state.record(
                source_full_name=source,
                target_full_name=target,
                event="SyncConflict",
                status="failed",
                detail={
                    "local_path": local_path,
                    "reason": "sync plan repository entry is invalid",
                    "error": str(exc),
                },
            )
            failed += 1
            continue

        needs_review = bool(detail.get("review_required"))
        state.record(
            source_full_name=source,
            target_full_name=target,
            event="SyncReviewRequired" if needs_review else "Synced",
            status="ok",
            detail=detail,
        )
        succeeded += 1
        if needs_review:
            review_required += 1

    return SyncApplyResult(
        succeeded=succeeded,
        failed=failed,
        review_required=review_required,
    )


def record_dry_run(repo: dict[str, Any], *, state: StateStore) -> None:
    commands = []
    for command_entry in repo.get("commands", []):
        command = command_entry["argv"]
        commands.append(
            {
                "operation": command_entry.get("operation"),
                "when": command_entry.get("when", "always"),
                "command": display_safe_command(command),
                "executed": False,
            }
        )
    state.record(
        source_full_name=repo["source_full_name"],
        target_full_name=repo["target_full_name"],
        event="SyncPlanned",
        status="ok",
        detail={
            "local_path": repo.get("local_path"),
            "commands": commands,
        },
    )


def reconcile_repository(
    repo: dict[str, Any],
    *,
    workspace: Path,
    runner: CommandRunner,
    allow_local_remotes: bool = False,
) -> dict[str, Any]:
    source_full_name = require_string(repo, "source_full_name")
    target_full_name = require_string(repo, "target_full_name")
    source_url = require_string(repo, "source_url")
    target_url = require_string(repo, "target_url")
    reject_embedded_http_credentials(source_url)
    reject_embedded_http_credentials(target_url)
    validate_planned_repository_url(
        source_url,
        expected_full_name=source_full_name,
        allow_local_remotes=allow_local_remotes,
    )
    validate_planned_repository_url(
        target_url,
        expected_full_name=target_full_name,
        allow_local_remotes=allow_local_remotes,
    )

    default_branch = require_string(repo, "default_branch")
    validate_default_branch(default_branch)
    local_path = guarded_local_path(
        require_string(repo, "local_path"),
        workspace=workspace,
    )
    branch_model = {
        "origin_default_ref": f"refs/remotes/origin/{default_branch}",
        "upstream_default_ref": f"refs/remotes/upstream/{default_branch}",
        "upstream_mirror_branch": f"upstream/{default_branch}",
        "secure_branch": f"secure/{default_branch}",
    }
    if repo.get("branch_model") != branch_model:
        raise SyncReconciliationError(
            "Sync plan branch model does not match the derived default-branch policy",
            event="SyncConflict",
            detail={
                "reason": "sync plan contains a missing or tampered branch model",
                "expected_branch_model": branch_model,
            },
        )
    origin_ref = branch_model["origin_default_ref"]
    upstream_ref = branch_model["upstream_default_ref"]
    mirror_branch = branch_model["upstream_mirror_branch"]
    secure_branch = branch_model["secure_branch"]

    operations = {
        item["operation"]: item["argv"]
        for item in sync_operations(
            source_url=source_url,
            target_url=target_url,
            local_path=local_path,
            default_branch=default_branch,
        )
    }
    journal = CommandJournal(runner)
    checkout_action = "reused"

    if local_path.exists():
        if not local_path.is_dir():
            raise_conflict(
                "managed checkout path exists but is not a directory",
                journal,
                local_path=str(local_path),
            )
        top_level = journal.run(
            ["git", "-C", str(local_path), "rev-parse", "--show-toplevel"],
            include_stdout=False,
        )
        if Path(top_level.stdout.strip()).resolve() != local_path:
            raise_conflict(
                "managed checkout path is not the root of its Git worktree",
                journal,
                local_path=str(local_path),
            )
    else:
        workspace.mkdir(parents=True, exist_ok=True)
        journal.run(operations["clone-checkout"])
        checkout_action = "created"

    remote_names_result = journal.run(
        ["git", "-C", str(local_path), "remote"],
        include_stdout=False,
    )
    remote_names = set(remote_names_result.stdout.splitlines())
    if "origin" not in remote_names:
        raise_conflict("managed checkout has no origin remote", journal)

    origin_url_result = journal.run(
        ["git", "-C", str(local_path), "remote", "get-url", "origin"],
        include_stdout=False,
    )
    origin_url = origin_url_result.stdout.strip()
    reject_embedded_http_credentials(origin_url)
    if not remote_urls_match(origin_url, target_url):
        raise_conflict(
            "origin remote does not match the planned downstream repository",
            journal,
            expected_url=redact_remote_url(target_url),
            actual_url=redact_remote_url(origin_url),
        )

    upstream_action = "preserved"
    if "upstream" not in remote_names:
        journal.run(operations["add-upstream-remote"])
        upstream_action = "added"
        upstream_url = source_url
    else:
        upstream_url_result = journal.run(
            ["git", "-C", str(local_path), "remote", "get-url", "upstream"],
            include_stdout=False,
        )
        upstream_url = upstream_url_result.stdout.strip()
        reject_embedded_http_credentials(upstream_url)
        if not remote_urls_match(upstream_url, source_url):
            raise_conflict(
                "upstream remote does not match the planned source repository",
                journal,
                expected_url=redact_remote_url(source_url),
                actual_url=redact_remote_url(upstream_url),
            )

    operations = {
        item["operation"]: item["argv"]
        for item in sync_operations(
            source_url=source_url,
            target_url=target_url,
            local_path=local_path,
            default_branch=default_branch,
            origin_fetch_url=origin_url,
            upstream_fetch_url=upstream_url,
        )
    }
    journal.run(operations["fetch-origin"])
    journal.run(operations["fetch-upstream"])

    upstream_sha = require_ref(journal, local_path, upstream_ref)
    origin_sha = require_ref(journal, local_path, origin_ref)
    current_branch = current_branch_name(journal, local_path)
    if current_branch == mirror_branch:
        raise_conflict(
            "upstream mirror branch is currently checked out and cannot be moved safely",
            journal,
            current_branch=current_branch,
        )

    mirror_ref = f"refs/heads/{mirror_branch}"
    secure_ref = f"refs/heads/{secure_branch}"
    previous_mirror_sha = optional_ref(journal, local_path, mirror_ref)
    journal.run(operations["update-upstream-mirror"])
    mirror_sha = require_ref(journal, local_path, mirror_ref)

    previous_secure_sha = optional_ref(journal, local_path, secure_ref)
    secure_action = "preserved"
    if previous_secure_sha is None:
        journal.run(operations["create-secure-branch"])
        secure_action = "created"
    secure_sha = require_ref(journal, local_path, secure_ref)

    upstream_only, secure_only = branch_divergence(
        journal,
        local_path,
        left_ref=mirror_ref,
        right_ref=secure_ref,
    )
    upstream_tags = upstream_tag_names(journal, local_path)
    review_required = upstream_only > 0 and secure_only > 0
    review_reasons = []
    if review_required:
        review_reasons.append(
            "secure branch and upstream mirror both contain unique commits; overlay replay requires review"
        )

    return {
        "local_path": str(local_path),
        "checkout_action": checkout_action,
        "default_branch": default_branch,
        "origin_remote": {
            "action": "validated",
            "url": redact_remote_url(origin_url),
        },
        "upstream_remote": {
            "action": upstream_action,
            "url": redact_remote_url(upstream_url),
        },
        "origin_default_sha": origin_sha,
        "upstream_default_sha": upstream_sha,
        "fork_default_matches_upstream": origin_sha == upstream_sha,
        "fork_default_update_required": origin_sha != upstream_sha,
        "upstream_mirror_branch": mirror_branch,
        "upstream_mirror_previous_sha": previous_mirror_sha,
        "upstream_mirror_sha": mirror_sha,
        "upstream_mirror_updated": previous_mirror_sha != mirror_sha,
        "secure_branch": secure_branch,
        "secure_branch_action": secure_action,
        "secure_branch_previous_sha": previous_secure_sha,
        "secure_branch_sha": secure_sha,
        "secure_branch_preserved": (
            previous_secure_sha is None or previous_secure_sha == secure_sha
        ),
        "secure_upstream_commits": upstream_only,
        "secure_unique_commits": secure_only,
        "secure_update_required": upstream_only > 0,
        "upstream_tag_count": len(upstream_tags),
        "latest_upstream_tag": upstream_tags[0] if upstream_tags else None,
        "remote_pushes_executed": False,
        "review_required": review_required,
        "review_reasons": review_reasons,
        "commands": journal.entries,
    }


def guarded_local_path(value: str, *, workspace: Path) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        raise SyncReconciliationError(
            "Managed checkout path must be absolute",
            event="SyncConflict",
            detail={"reason": "managed checkout path must be absolute"},
        )
    resolved = candidate.resolve()
    if resolved == workspace or not resolved.is_relative_to(workspace):
        raise SyncReconciliationError(
            "Managed checkout path escapes the declared workspace",
            event="SyncConflict",
            detail={
                "reason": "managed checkout path escapes the declared workspace",
                "workspace": str(workspace),
                "local_path": str(resolved),
            },
        )
    return resolved


def require_ref(journal: CommandJournal, local_path: Path, ref: str) -> str:
    sha = optional_ref(journal, local_path, ref)
    if sha is None:
        raise_conflict(
            "required Git ref is missing after fetch",
            journal,
            missing_ref=ref,
        )
    return sha


def optional_ref(
    journal: CommandJournal,
    local_path: Path,
    ref: str,
) -> str | None:
    result = journal.run(
        ["git", "-C", str(local_path), "show-ref", "--verify", "--hash", ref],
        allow_failure=True,
        include_stdout=False,
    )
    if not result.ok:
        return None
    return result.stdout.strip()


def current_branch_name(journal: CommandJournal, local_path: Path) -> str | None:
    result = journal.run(
        ["git", "-C", str(local_path), "symbolic-ref", "--quiet", "--short", "HEAD"],
        allow_failure=True,
        include_stdout=False,
    )
    return result.stdout.strip() if result.ok else None


def branch_divergence(
    journal: CommandJournal,
    local_path: Path,
    *,
    left_ref: str,
    right_ref: str,
) -> tuple[int, int]:
    result = journal.run(
        [
            "git",
            "-C",
            str(local_path),
            "rev-list",
            "--left-right",
            "--count",
            f"{left_ref}...{right_ref}",
        ],
        include_stdout=False,
    )
    values = result.stdout.split()
    if len(values) != 2 or not all(value.isdigit() for value in values):
        raise_conflict(
            "Git returned an invalid branch divergence count",
            journal,
            output=truncate_output(result.stdout),
        )
    return int(values[0]), int(values[1])


def upstream_tag_names(journal: CommandJournal, local_path: Path) -> list[str]:
    result = journal.run(
        [
            "git",
            "-C",
            str(local_path),
            "for-each-ref",
            "--sort=-creatordate",
            "--format=%(refname:strip=3)",
            "refs/tags/upstream/",
        ],
        include_stdout=False,
    )
    return [line for line in result.stdout.splitlines() if line]


def raise_conflict(
    reason: str,
    journal: CommandJournal,
    **extra: Any,
) -> None:
    raise SyncReconciliationError(
        reason,
        event="SyncConflict",
        detail={
            "reason": reason,
            **extra,
            "commands": list(journal.entries),
        },
    )


def remote_urls_match(actual: str, expected: str) -> bool:
    actual_identity = github_repository_identity(actual)
    expected_identity = github_repository_identity(expected)
    if actual_identity is not None or expected_identity is not None:
        return actual_identity is not None and actual_identity == expected_identity
    return normalized_non_github_url(actual) == normalized_non_github_url(expected)


def validate_planned_repository_url(
    value: str,
    *,
    expected_full_name: str,
    allow_local_remotes: bool,
) -> None:
    identity = github_repository_identity(value)
    if identity == expected_full_name.casefold():
        return
    if allow_local_remotes and identity is None:
        return
    raise SyncReconciliationError(
        "Planned Git remote URL does not match its repository identity",
        event="SyncConflict",
        detail={
            "reason": "planned Git remote identity does not match source/target metadata",
            "expected_full_name": expected_full_name,
            "url": redact_remote_url(value),
        },
    )


def github_repository_identity(value: str) -> str | None:
    scp_match = re.fullmatch(
        r"(?:[^@]+@)?github\.com:([^/]+)/(.+?)(?:\.git)?/?",
        value.strip(),
        flags=re.IGNORECASE,
    )
    if scp_match:
        return f"{scp_match.group(1)}/{scp_match.group(2)}".casefold()

    parsed = urlsplit(value.strip())
    if (parsed.hostname or "").casefold() != "github.com":
        return None
    parts = parsed.path.strip("/").split("/")
    if len(parts) != 2 or not all(parts):
        return None
    repository = parts[1][:-4] if parts[1].endswith(".git") else parts[1]
    return f"{parts[0]}/{repository}".casefold()


def normalized_non_github_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme == "file":
        return str(Path(unquote(parsed.path)).expanduser().resolve())
    if not parsed.scheme and "://" not in value:
        return str(Path(value).expanduser().resolve())
    return value.strip().rstrip("/")


def reject_embedded_http_credentials(value: str) -> None:
    parsed = urlsplit(value)
    if parsed.scheme in {"http", "https"} and (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise SyncReconciliationError(
            "HTTP Git remote URLs may not embed credentials, query strings, or fragments",
            event="SyncConflict",
            detail={
                "reason": "planned Git remote URL contains forbidden credential material",
                "url": redact_remote_url(value),
            },
        )


def redact_remote_url(value: str) -> str:
    scp_match = re.fullmatch(r"([^@]+)@([^:]+):(.+)", value)
    if scp_match:
        return f"<redacted>@{scp_match.group(2)}:{scp_match.group(3)}"
    parsed = urlsplit(value)
    if not parsed.scheme or parsed.scheme == "file":
        return value
    hostname = parsed.hostname or ""
    if parsed.port:
        hostname = f"{hostname}:{parsed.port}"
    if parsed.username is not None or parsed.password is not None:
        hostname = f"<redacted>@{hostname}"
    return urlunsplit((parsed.scheme, hostname, parsed.path, "", ""))


def command_result_detail(
    result: CommandResult,
    *,
    include_stdout: bool = True,
) -> dict[str, Any]:
    detail: dict[str, Any] = {
        "command": display_safe_command(result.command),
        "executed": result.executed,
        "returncode": result.returncode,
    }
    if include_stdout and result.stdout:
        detail["stdout"] = truncate_output(result.stdout)
    if result.stderr:
        detail["stderr"] = truncate_output(result.stderr)
    return detail


def display_safe_command(command: list[str]) -> str:
    return display_command([redact_remote_url(part) for part in command])


def truncate_output(value: str) -> str:
    stripped = value.strip()
    if len(stripped) <= MAX_CAPTURED_OUTPUT:
        return stripped
    return stripped[:MAX_CAPTURED_OUTPUT] + "...<truncated>"


def require_string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Sync plan field {key!r} must be a non-empty string")
    return value


def reconciliation_state_identity(
    repo: Any,
    *,
    index: int,
) -> tuple[str, str]:
    if isinstance(repo, dict):
        source = repo.get("source_full_name")
        target = repo.get("target_full_name")
    else:
        source = None
        target = None
    return (
        source if isinstance(source, str) and source else f"<invalid-source-{index}>",
        target if isinstance(target, str) and target else f"<invalid-target-{index}>",
    )
