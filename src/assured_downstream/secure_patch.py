from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from assured_downstream.command_runner import CommandResult, CommandRunner, display_command
from assured_downstream.overlay_render import normalize_pin_map, render_change
from assured_downstream.sync_apply import (
    reject_embedded_http_credentials,
    validate_planned_repository_url,
)
from assured_downstream.sync_plan import validate_default_branch


PATCH_SCHEMA_VERSION = 1
FULL_SHA_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
SAFE_PATCH_PATH_PATTERN = re.compile(r"[A-Za-z0-9._/-]+")
GIT_ENV = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
}


class SecurePatchError(RuntimeError):
    pass


@dataclass(frozen=True)
class TreeEntry:
    mode: str
    object_type: str
    object_id: str
    path: str


def build_rendered_patch(
    overlay: dict[str, Any],
    *,
    pins: dict[str, Any],
    approved_change_ids: list[str],
) -> dict[str, Any]:
    if overlay.get("schema_version") != 1:
        raise SecurePatchError("Unsupported overlay plan schema")
    if (
        not isinstance(approved_change_ids, list)
        or not approved_change_ids
        or not all(isinstance(item, str) and item for item in approved_change_ids)
    ):
        raise SecurePatchError("Approval must select at least one overlay change")
    if len(set(approved_change_ids)) != len(approved_change_ids):
        raise SecurePatchError("Approval contains duplicate overlay change ids")

    changes: dict[str, dict[str, Any]] = {}
    for change in overlay.get("proposed_changes", []):
        if not isinstance(change, dict):
            raise SecurePatchError("Overlay proposed_changes entries must be objects")
        change_id = change.get("id")
        if not isinstance(change_id, str) or not change_id:
            raise SecurePatchError("Overlay change has no valid id")
        if change_id in changes:
            raise SecurePatchError(f"Overlay contains duplicate change id: {change_id}")
        changes[change_id] = change

    pin_map = normalize_pin_map(pins)
    files = []
    claimed_paths: set[str] = set()
    for change_id in sorted(approved_change_ids):
        change = changes.get(change_id)
        if change is None:
            raise SecurePatchError(f"Approved overlay change is missing: {change_id}")
        rendered = render_change(change, overlay=overlay, pins=pin_map)
        if rendered is None:
            raise SecurePatchError(
                f"Approved overlay change is not safely renderable: {change_id}"
            )
        relative_path, content = rendered
        declared_paths = change.get("paths")
        if (
            change.get("action") != "add"
            or not isinstance(change.get("human_review_required"), bool)
            or not isinstance(declared_paths, list)
            or not all(isinstance(path, str) for path in declared_paths)
            or not any(
                relative_path == path.rstrip("/")
                or relative_path.startswith(path.rstrip("/") + "/")
                for path in declared_paths
            )
        ):
            raise SecurePatchError(
                f"Approved overlay change contract does not match renderer: {change_id}"
            )
        validate_patch_path(relative_path)
        if relative_path in claimed_paths:
            raise SecurePatchError(
                f"Multiple approved changes render the same path: {relative_path}"
            )
        claimed_paths.add(relative_path)
        encoded = content.encode("utf-8")
        files.append(
            {
                "change_id": change_id,
                "path": relative_path,
                "sha256": hashlib.sha256(encoded).hexdigest(),
                "size": len(encoded),
                "content": content,
            }
        )

    return {
        "schema_version": PATCH_SCHEMA_VERSION,
        "overlay_target": overlay.get("target"),
        "approved_change_ids": sorted(approved_change_ids),
        "unapproved_change_ids": sorted(set(changes) - set(approved_change_ids)),
        "files": sorted(files, key=lambda item: item["path"]),
    }


def rendered_patch_manifest(rendered_patch: dict[str, Any]) -> dict[str, Any]:
    return {
        **{key: value for key, value in rendered_patch.items() if key != "files"},
        "files": [
            {key: value for key, value in item.items() if key != "content"}
            for item in rendered_patch.get("files", [])
        ],
    }


def apply_secure_patch(
    *,
    checkout_path: Path,
    target_full_name: str,
    secure_branch: str,
    expected_secure_sha: str,
    required_upstream_sha: str,
    rendered_patch: dict[str, Any],
    approval_sha256: str,
    approved_at: str,
    run_dir: Path,
    execute: bool,
    allow_local_remotes: bool = False,
    runner: CommandRunner | None = None,
) -> dict[str, Any]:
    checkout_path = checkout_path.resolve()
    run_dir = run_dir.resolve()
    validate_default_branch(secure_branch)
    expected_secure_sha = require_full_sha(
        expected_secure_sha,
        label="expected secure branch commit",
    )
    required_upstream_sha = require_full_sha(
        required_upstream_sha,
        label="required synchronized upstream commit",
    )
    require_sha256(approval_sha256, label="approval digest")
    commit_date = normalized_git_date(approved_at)
    runner = runner or CommandRunner(execute=True)

    root = run_git_required(
        runner,
        git_command(checkout_path, "rev-parse", "--show-toplevel"),
    )
    if Path(root).resolve() != checkout_path:
        raise SecurePatchError(f"Managed checkout is not its Git root: {checkout_path}")
    origin_url = run_git_required(
        runner,
        git_command(checkout_path, "remote", "get-url", "origin"),
    )
    try:
        reject_embedded_http_credentials(origin_url)
        validate_planned_repository_url(
            origin_url,
            expected_full_name=target_full_name,
            allow_local_remotes=allow_local_remotes,
        )
    except Exception as exc:
        raise SecurePatchError(str(exc)) from exc
    run_git_required(
        runner,
        git_command(checkout_path, "cat-file", "-e", f"{expected_secure_sha}^{{commit}}"),
    )
    run_git_required(
        runner,
        git_command(checkout_path, "cat-file", "-e", f"{required_upstream_sha}^{{commit}}"),
    )
    ancestry = runner.run(
        git_command(
            checkout_path,
            "merge-base",
            "--is-ancestor",
            required_upstream_sha,
            expected_secure_sha,
        ),
        env=GIT_ENV,
    )
    if not ancestry.ok:
        raise SecurePatchError(
            "Approved secure base does not contain the synchronized upstream commit"
        )

    secure_ref = f"refs/heads/{secure_branch}"
    current_secure_sha = require_ref(runner, checkout_path, secure_ref)
    base_state = inspect_desired_paths(
        runner,
        checkout_path=checkout_path,
        commit_sha=expected_secure_sha,
        rendered_patch=rendered_patch,
    )
    message = patch_commit_message(approval_sha256)

    if current_secure_sha != expected_secure_sha:
        if approved_commit_matches(
            runner,
            checkout_path=checkout_path,
            commit_sha=current_secure_sha,
            parent_sha=expected_secure_sha,
            message=message,
            rendered_patch=rendered_patch,
            expected_added_paths=base_state["additions"],
        ):
            return patch_result(
                action="reused-approved-commit",
                execute=execute,
                secure_branch=secure_branch,
                base_sha=expected_secure_sha,
                patch_sha=current_secure_sha,
                path_state=base_state,
            )
        raise SecurePatchError(
            f"Secure branch moved from approved base {expected_secure_sha} to "
            f"{current_secure_sha}"
        )

    if not execute:
        return patch_result(
            action="planned",
            execute=False,
            secure_branch=secure_branch,
            base_sha=expected_secure_sha,
            patch_sha=None,
            path_state=base_state,
        )

    if not base_state["additions"]:
        return patch_result(
            action="already-present",
            execute=True,
            secure_branch=secure_branch,
            base_sha=expected_secure_sha,
            patch_sha=expected_secure_sha,
            path_state=base_state,
        )

    index_dir = run_dir / "git-indexes"
    index_dir.mkdir(parents=True, exist_ok=True)
    index_path = index_dir / f"patch-{uuid.uuid4().hex}.index"
    index_env = {
        **GIT_ENV,
        "GIT_INDEX_FILE": str(index_path),
    }
    try:
        run_git_required(
            runner,
            git_command(checkout_path, "read-tree", expected_secure_sha),
            env=index_env,
        )
        files_by_path = {
            item["path"]: item
            for item in rendered_patch.get("files", [])
        }
        for relative_path in base_state["additions"]:
            item = files_by_path[relative_path]
            blob_sha = run_git_required(
                runner,
                git_command(checkout_path, "hash-object", "-w", "--stdin"),
                env=GIT_ENV,
                input_text=item["content"],
            )
            run_git_required(
                runner,
                git_command(
                    checkout_path,
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    "100644",
                    blob_sha,
                    relative_path,
                ),
                env=index_env,
            )
        tree_sha = run_git_required(
            runner,
            git_command(checkout_path, "write-tree"),
            env=index_env,
        )
        commit_env = {
            **GIT_ENV,
            "GIT_AUTHOR_NAME": "Assured Downstream",
            "GIT_AUTHOR_EMAIL": "automation@assured-downstream.invalid",
            "GIT_COMMITTER_NAME": "Assured Downstream",
            "GIT_COMMITTER_EMAIL": "automation@assured-downstream.invalid",
            "GIT_AUTHOR_DATE": commit_date,
            "GIT_COMMITTER_DATE": commit_date,
        }
        patch_sha = run_git_required(
            runner,
            git_command(
                checkout_path,
                "commit-tree",
                tree_sha,
                "-p",
                expected_secure_sha,
            ),
            env=commit_env,
            input_text=message,
        )
    finally:
        index_path.unlink(missing_ok=True)

    update = runner.run(
        git_command(
            checkout_path,
            "update-ref",
            secure_ref,
            patch_sha,
            expected_secure_sha,
        ),
        env=GIT_ENV,
    )
    if not update.ok:
        actual = require_ref(runner, checkout_path, secure_ref)
        if actual != patch_sha:
            raise SecurePatchError(
                "Secure branch compare-and-swap failed: "
                f"{command_failure(update)}"
            )

    if not approved_commit_matches(
        runner,
        checkout_path=checkout_path,
        commit_sha=patch_sha,
        parent_sha=expected_secure_sha,
        message=message,
        rendered_patch=rendered_patch,
        expected_added_paths=base_state["additions"],
    ):
        raise SecurePatchError("Created patch commit failed post-write verification")
    return patch_result(
        action="committed",
        execute=True,
        secure_branch=secure_branch,
        base_sha=expected_secure_sha,
        patch_sha=patch_sha,
        path_state=base_state,
    )


def inspect_desired_paths(
    runner: CommandRunner,
    *,
    checkout_path: Path,
    commit_sha: str,
    rendered_patch: dict[str, Any],
) -> dict[str, list[str]]:
    additions = []
    unchanged = []
    for item in rendered_patch.get("files", []):
        relative_path = item["path"]
        validate_patch_path(relative_path)
        validate_parent_tree(
            runner,
            checkout_path=checkout_path,
            commit_sha=commit_sha,
            relative_path=relative_path,
        )
        entry = tree_entry(
            runner,
            checkout_path=checkout_path,
            commit_sha=commit_sha,
            relative_path=relative_path,
        )
        if entry is None:
            additions.append(relative_path)
            continue
        if entry.object_type != "blob" or entry.mode != "100644":
            raise SecurePatchError(
                f"Approved additive path already has incompatible type: {relative_path}"
            )
        desired_blob = run_git_required(
            runner,
            git_command(checkout_path, "hash-object", "--stdin"),
            input_text=item["content"],
        )
        if entry.object_id != desired_blob:
            raise SecurePatchError(
                f"Approved additive path already exists with different content: "
                f"{relative_path}"
            )
        unchanged.append(relative_path)
    return {
        "additions": sorted(additions),
        "unchanged": sorted(unchanged),
    }


def validate_parent_tree(
    runner: CommandRunner,
    *,
    checkout_path: Path,
    commit_sha: str,
    relative_path: str,
) -> None:
    parts = PurePosixPath(relative_path).parts
    for length in range(1, len(parts)):
        parent = "/".join(parts[:length])
        entry = tree_entry(
            runner,
            checkout_path=checkout_path,
            commit_sha=commit_sha,
            relative_path=parent,
        )
        if entry is not None and entry.object_type != "tree":
            raise SecurePatchError(
                f"Approved patch path traverses a non-directory tree entry: {parent}"
            )


def tree_entry(
    runner: CommandRunner,
    *,
    checkout_path: Path,
    commit_sha: str,
    relative_path: str,
) -> TreeEntry | None:
    result = runner.run(
        git_command(
            checkout_path,
            "ls-tree",
            "-z",
            commit_sha,
            "--",
            relative_path,
        ),
        env=GIT_ENV,
    )
    if not result.ok:
        raise SecurePatchError(command_failure(result))
    records = [record for record in result.stdout.split("\0") if record]
    exact = []
    for record in records:
        metadata, separator, path = record.partition("\t")
        values = metadata.split()
        if separator and path == relative_path and len(values) == 3:
            exact.append(TreeEntry(values[0], values[1], values[2], path))
    if len(exact) > 1:
        raise SecurePatchError(f"Git returned duplicate tree entries: {relative_path}")
    return exact[0] if exact else None


def approved_commit_matches(
    runner: CommandRunner,
    *,
    checkout_path: Path,
    commit_sha: str,
    parent_sha: str,
    message: str,
    rendered_patch: dict[str, Any],
    expected_added_paths: list[str],
) -> bool:
    parents = run_git_optional(
        runner,
        git_command(checkout_path, "show", "-s", "--format=%P", commit_sha),
    )
    if parents is None or parents.split() != [parent_sha]:
        return False
    actual_message = run_git_optional(
        runner,
        git_command(checkout_path, "show", "-s", "--format=%B", commit_sha),
    )
    if actual_message is None or actual_message.rstrip("\n") != message.rstrip("\n"):
        return False
    changed = run_git_optional(
        runner,
        git_command(
            checkout_path,
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            "-z",
            commit_sha,
        ),
    )
    if changed is None:
        return False
    changed_paths = sorted(path for path in changed.split("\0") if path)
    if changed_paths != sorted(expected_added_paths):
        return False
    for item in rendered_patch.get("files", []):
        entry = tree_entry(
            runner,
            checkout_path=checkout_path,
            commit_sha=commit_sha,
            relative_path=item["path"],
        )
        desired_blob = run_git_optional_with_input(
            runner,
            git_command(checkout_path, "hash-object", "--stdin"),
            input_text=item["content"],
        )
        if (
            entry is None
            or entry.mode != "100644"
            or entry.object_type != "blob"
            or desired_blob is None
            or entry.object_id != desired_blob
        ):
            return False
    return True


def patch_result(
    *,
    action: str,
    execute: bool,
    secure_branch: str,
    base_sha: str,
    patch_sha: str | None,
    path_state: dict[str, list[str]],
) -> dict[str, Any]:
    return {
        "schema_version": PATCH_SCHEMA_VERSION,
        "action": action,
        "executed": execute,
        "secure_branch": secure_branch,
        "base_sha": base_sha,
        "patch_sha": patch_sha,
        "added_paths": path_state["additions"],
        "unchanged_paths": path_state["unchanged"],
        "remote_pushes_executed": False,
    }


def require_ref(runner: CommandRunner, checkout_path: Path, ref: str) -> str:
    value = run_git_required(
        runner,
        git_command(checkout_path, "show-ref", "--verify", "--hash", ref),
    )
    return require_full_sha(value, label=ref)


def validate_patch_path(value: str) -> None:
    path = PurePosixPath(value)
    if (
        not value
        or not SAFE_PATCH_PATH_PATTERN.fullmatch(value)
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise SecurePatchError(f"Unsafe rendered patch path: {value!r}")


def require_full_sha(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or FULL_SHA_PATTERN.fullmatch(value) is None:
        raise SecurePatchError(f"{label} is not a full Git object id")
    return value


def require_sha256(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SecurePatchError(f"{label} is not a SHA-256 digest")
    return value


def normalized_git_date(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise SecurePatchError("Approval has no approved_at timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SecurePatchError("Approval has an invalid approved_at timestamp") from exc
    if parsed.tzinfo is None:
        raise SecurePatchError("Approval approved_at timestamp must include a timezone")
    return parsed.astimezone(UTC).isoformat(timespec="seconds")


def patch_commit_message(approval_sha256: str) -> str:
    return (
        "chore(security): apply assured downstream baseline\n\n"
        f"Assured-Downstream-Approval: {approval_sha256}\n"
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


def run_git_required(
    runner: CommandRunner,
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
) -> str:
    result = runner.run(command, env=env or GIT_ENV, input_text=input_text)
    if not result.ok:
        raise SecurePatchError(command_failure(result))
    return result.stdout.rstrip("\n")


def run_git_optional(runner: CommandRunner, command: list[str]) -> str | None:
    result = runner.run(command, env=GIT_ENV)
    return result.stdout.rstrip("\n") if result.ok else None


def run_git_optional_with_input(
    runner: CommandRunner,
    command: list[str],
    *,
    input_text: str,
) -> str | None:
    result = runner.run(command, env=GIT_ENV, input_text=input_text)
    return result.stdout.rstrip("\n") if result.ok else None


def command_failure(result: CommandResult) -> str:
    detail = (result.stderr or result.stdout).strip() or "unknown Git error"
    if len(detail) > 2048:
        detail = detail[:2048] + "...<truncated>"
    return f"Git command failed: {display_command(result.command)}: {detail}"
