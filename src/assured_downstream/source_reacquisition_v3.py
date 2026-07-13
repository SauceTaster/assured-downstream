from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from assured_downstream.builder_handoff_v3 import (
    MAX_TOTAL_BYTES,
    BuilderHandoffError,
    safe_spdx_path,
    validate_source_inventory,
)
from assured_downstream.command_runner import display_command
from assured_downstream.release_verification import (
    MAX_EXECUTABLE_BYTES,
    MAX_JSON_BYTES,
    ReleaseVerificationError,
    snapshot_bytes,
)
from assured_downstream.sync_plan import validate_default_branch


SOURCE_REACQUISITION_SCHEMA_VERSION = 1
MAX_TREE_ENTRIES = 10_000
MAX_TREE_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_COMMAND_STDERR_BYTES = 1024 * 1024
MAX_COMMAND_STDOUT_BYTES = 4 * 1024 * 1024
MAX_SYMLINK_BYTES = 4096
MAX_RECORDED_FINDINGS = 100
DEFAULT_GIT_TIMEOUT_SECONDS = 300.0
MAX_ACQUISITION_SECONDS = 600.0
MAX_ACQUISITION_CPU_SECONDS = 300.0
MAX_ACQUISITION_COMMANDS = MAX_TREE_ENTRIES + 20
MAX_ACQUISITION_STDOUT_BYTES = (
    MAX_TOTAL_BYTES + MAX_TREE_OUTPUT_BYTES + (64 * 1024 * 1024)
)
MAX_ACQUISITION_STDERR_BYTES = 16 * 1024 * 1024
MAX_FETCHED_REPOSITORY_BYTES = 2 * 1024 * 1024 * 1024
MAX_FETCHED_REPOSITORY_ENTRIES = 100_000
DEFAULT_OBJECT_MEMORY_LIMIT = 2 * 1024 * 1024 * 1024
DEFAULT_PROCESS_FILE_LIMIT = MAX_FETCHED_REPOSITORY_BYTES
MAX_SOURCE_BLOB_BYTES = 256 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 1024 * 1024 * 1024
OBJECT_ID_LENGTHS = {"sha1": 40, "sha256": 64}
GIT_BUILTIN_HELPERS = (
    "git-fetch-pack",
    "git-index-pack",
    "git-unpack-objects",
    "git-upload-pack",
)
NATIVE_EXECUTABLE_MAGICS = (
    b"\x7fELF",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
)
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
TREE_HEADER_PATTERN = re.compile(
    rb"^(?P<mode>[0-9]{6}) (?P<type>[a-z]+) "
    rb"(?P<object>[0-9a-f]+) +(?P<size>-|[0-9]+)$"
)
SOURCE_REACQUISITION_CLAIM_LIMIT = (
    "At acquisition time, the selected source transport exposed the requested "
    "commit reachable from the requested ref, and its Git tree matched the "
    "retained v3 source inventory on every applicable field. No source was "
    "checked out or executed. This does not establish authorship, persistent "
    "branch identity, upstream ownership, host or provider independence, "
    "builder containment, workflow integrity, or semantic safety."
    " Aggregate storage is polled and lacks a kernel-enforced filesystem quota; "
    "dynamic libraries and the surrounding operating system toolchain are not "
    "independently verified."
)
GIT_CONFIG_ARGUMENTS = (
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "credential.helper=",
    "-c",
    "protocol.file.allow=never",
    "-c",
    "protocol.ext.allow=never",
    "-c",
    "protocol.ssh.allow=never",
    "-c",
    "protocol.git.allow=never",
    "-c",
    "protocol.http.allow=never",
    "-c",
    "protocol.https.allow=always",
    "-c",
    "fetch.fsckObjects=true",
    "-c",
    "transfer.fsckObjects=true",
)


class SourceReacquisitionError(RuntimeError):
    pass


@dataclass(frozen=True)
class BoundedCommandResult:
    command: list[str]
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_seconds: float
    timed_out: bool = False
    output_limited: bool = False
    storage_limited: bool = False

    @property
    def ok(self) -> bool:
        return (
            self.returncode == 0
            and not self.timed_out
            and not self.output_limited
            and not self.storage_limited
        )


@dataclass(frozen=True)
class SourceReacquisitionResult:
    inventory: dict[str, Any]
    report: dict[str, Any]


class AcquisitionBudget:
    def __init__(self) -> None:
        self.started_at = time.monotonic()
        self.started_cpu_seconds = process_tree_cpu_seconds()

    def check(self, operation: str) -> None:
        if time.monotonic() - self.started_at > MAX_ACQUISITION_SECONDS:
            raise SourceReacquisitionError(
                f"Source acquisition wall-clock limit exceeded during {operation}"
            )
        if (
            process_tree_cpu_seconds() - self.started_cpu_seconds
            > MAX_ACQUISITION_CPU_SECONDS
        ):
            raise SourceReacquisitionError(
                f"Source acquisition CPU limit exceeded during {operation}"
            )

    def remaining_seconds(self) -> float:
        return MAX_ACQUISITION_SECONDS - (time.monotonic() - self.started_at)


class BoundedGitRunner:
    def __init__(
        self,
        *,
        environment_root: Path,
        git_path: Path,
        expected_git_sha256: str,
        https_helper_path: Path,
        expected_https_helper_sha256: str,
        storage_root: Path | None = None,
        allowed_protocols: str = "https",
        cpu_limit_seconds: int = 180,
        memory_limit_bytes: int = DEFAULT_OBJECT_MEMORY_LIMIT,
        file_limit_bytes: int = DEFAULT_PROCESS_FILE_LIMIT,
    ) -> None:
        executable = git_path.expanduser()
        if not executable.is_absolute():
            raise SourceReacquisitionError(
                "A trusted absolute Git executable is required"
            )
        self.environment_root = environment_root.resolve()
        self.environment_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.source_git_path = require_regular_executable(executable)
        if sys.platform == "darwin" and self.source_git_path == Path("/usr/bin/git"):
            raise SourceReacquisitionError(
                "Apple's /usr/bin/git dispatcher is not an acceptable pinned Git binary"
            )
        helper = https_helper_path.expanduser()
        if not helper.is_absolute():
            raise SourceReacquisitionError(
                "A trusted absolute Git HTTPS helper is required"
            )
        self.source_https_helper_path = require_regular_executable(helper)
        private_bin = self.environment_root / "bin"
        self.exec_path = self.environment_root / "libexec" / "git-core"
        private_bin.mkdir(mode=0o700)
        self.exec_path.mkdir(parents=True, mode=0o700)
        self.git_path, self.git_sha256, self.git_identity = stage_native_executable(
            self.source_git_path,
            target=private_bin / "git",
            expected_sha256=expected_git_sha256,
            label="Git executable",
        )
        (
            self.https_helper_path,
            self.https_helper_sha256,
            self.https_helper_identity,
        ) = stage_native_executable(
            self.source_https_helper_path,
            target=self.exec_path / "git-remote-https",
            expected_sha256=expected_https_helper_sha256,
            label="Git HTTPS helper",
        )
        for helper_name in GIT_BUILTIN_HELPERS:
            os.link(self.git_path, self.exec_path / helper_name)
        self.git_identity = file_identity(self.git_path.lstat())
        fsync_directory(private_bin)
        fsync_directory(self.exec_path)
        self.home = self.environment_root / "home"
        self.home.mkdir(mode=0o700)
        self.tmp = self.environment_root / "tmp"
        self.tmp.mkdir(mode=0o700)
        self.allowed_protocols = allowed_protocols
        self.cpu_limit_seconds = cpu_limit_seconds
        self.memory_limit_bytes = memory_limit_bytes
        self.file_limit_bytes = file_limit_bytes
        self.storage_root = None if storage_root is None else storage_root.resolve()

    def run(
        self,
        arguments: Iterable[str],
        *,
        cwd: Path | None = None,
        timeout_seconds: float = DEFAULT_GIT_TIMEOUT_SECONDS,
        max_stdout_bytes: int = MAX_COMMAND_STDOUT_BYTES,
        max_stderr_bytes: int = MAX_COMMAND_STDERR_BYTES,
    ) -> BoundedCommandResult:
        protocol_arguments = (
            ["-c", "protocol.file.allow=always"]
            if self.allowed_protocols == "file"
            else []
        )
        command = [
            str(self.git_path),
            *GIT_CONFIG_ARGUMENTS,
            *protocol_arguments,
            *list(arguments),
        ]
        verify_git_executable_identity(self.git_path, self.git_identity)
        verify_git_executable_identity(
            self.https_helper_path,
            self.https_helper_identity,
        )
        started = time.monotonic()
        process = subprocess.Popen(
            command,
            cwd=None if cwd is None else str(cwd),
            env=self.isolated_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            preexec_fn=self.apply_resource_limits,
        )
        stdout, stderr, timed_out, output_limited, storage_limited = (
            collect_bounded_output(
                process,
                timeout_seconds=timeout_seconds,
                max_stdout_bytes=max_stdout_bytes,
                max_stderr_bytes=max_stderr_bytes,
                storage_root=self.storage_root,
            )
        )
        verify_git_executable_identity(self.git_path, self.git_identity)
        verify_git_executable_identity(
            self.https_helper_path,
            self.https_helper_identity,
        )
        duration = time.monotonic() - started
        return BoundedCommandResult(
            command=command,
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            timed_out=timed_out,
            output_limited=output_limited,
            storage_limited=storage_limited,
        )

    def isolated_environment(self) -> dict[str, str]:
        false_path = "/usr/bin/false" if Path("/usr/bin/false").exists() else "false"
        return {
            "HOME": str(self.home),
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "XDG_CACHE_HOME": str(self.home / ".cache"),
            "TMPDIR": str(self.tmp),
            "TMP": str(self.tmp),
            "TEMP": str(self.tmp),
            "PATH": f"{self.git_path.parent}:/usr/bin:/bin",
            "GIT_EXEC_PATH": str(self.exec_path),
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": false_path,
            "SSH_ASKPASS": false_path,
            "GIT_SSH_COMMAND": false_path,
            "GIT_ALLOW_PROTOCOL": self.allowed_protocols,
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
        }

    def apply_resource_limits(self) -> None:
        limits = (
            (resource.RLIMIT_CPU, self.cpu_limit_seconds),
            (resource.RLIMIT_AS, self.memory_limit_bytes),
            (resource.RLIMIT_FSIZE, self.file_limit_bytes),
            (resource.RLIMIT_NOFILE, 256),
        )
        for kind, limit in limits:
            try:
                hard = resource.getrlimit(kind)[1]
                effective = (
                    limit if hard == resource.RLIM_INFINITY else min(limit, hard)
                )
                resource.setrlimit(kind, (effective, effective))
            except (OSError, ValueError):
                continue


class GitSession:
    def __init__(
        self,
        runner: BoundedGitRunner,
        *,
        private_root: Path,
        budget: AcquisitionBudget,
    ) -> None:
        self.runner = runner
        self.private_root = private_root.resolve()
        self.budget = budget
        self.executions: list[dict[str, Any]] = []
        self.total_stdout_bytes = 0
        self.total_stderr_bytes = 0

    def required(
        self,
        operation: str,
        arguments: list[str],
        *,
        allowed_returncodes: set[int] | None = None,
        timeout_seconds: float = DEFAULT_GIT_TIMEOUT_SECONDS,
        max_stdout_bytes: int = MAX_COMMAND_STDOUT_BYTES,
        max_stderr_bytes: int = MAX_COMMAND_STDERR_BYTES,
    ) -> BoundedCommandResult:
        self.budget.check(operation)
        if len(self.executions) >= MAX_ACQUISITION_COMMANDS:
            raise SourceReacquisitionError("Source acquisition command limit exceeded")
        remaining_time = self.budget.remaining_seconds()
        if remaining_time <= 0:
            raise SourceReacquisitionError(
                "Source acquisition wall-clock limit exceeded"
            )
        result = self.runner.run(
            arguments,
            timeout_seconds=min(timeout_seconds, remaining_time),
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )
        allowed = allowed_returncodes or {0}
        self.executions.append(self.execution_record(operation, result))
        self.total_stdout_bytes += len(result.stdout)
        self.total_stderr_bytes += len(result.stderr)
        if (
            self.total_stdout_bytes > MAX_ACQUISITION_STDOUT_BYTES
            or self.total_stderr_bytes > MAX_ACQUISITION_STDERR_BYTES
        ):
            raise SourceReacquisitionError("Source acquisition output budget exceeded")
        self.budget.check(operation)
        if result.timed_out:
            raise SourceReacquisitionError(f"Git operation timed out: {operation}")
        if result.output_limited:
            raise SourceReacquisitionError(
                f"Git operation exceeded its output limit: {operation}"
            )
        if result.storage_limited:
            raise SourceReacquisitionError(
                f"Git operation exceeded the acquisition storage limit: {operation}"
            )
        if result.returncode not in allowed:
            detail = bounded_text(result.stderr or result.stdout)
            raise SourceReacquisitionError(
                f"Git operation failed: {operation}: {detail or 'no diagnostic'}"
            )
        return result

    def execution_record(
        self,
        operation: str,
        result: BoundedCommandResult,
    ) -> dict[str, Any]:
        command = [
            part.replace(str(self.private_root), "$ACQUISITION_ROOT")
            for part in result.command
        ]
        return {
            "operation": operation,
            "command": display_command(command),
            "returncode": result.returncode,
            "duration_milliseconds": round(result.duration_seconds * 1000),
            "stdout_size": len(result.stdout),
            "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
            "stderr_size": len(result.stderr),
            "timed_out": result.timed_out,
            "output_limited": result.output_limited,
            "storage_limited": result.storage_limited,
        }


def collect_bounded_output(
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    storage_root: Path | None = None,
) -> tuple[bytes, bytes, bool, bool, bool]:
    if process.stdout is None or process.stderr is None:
        raise RuntimeError("Bounded process pipes are unavailable")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": max_stdout_bytes, "stderr": max_stderr_bytes}
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    output_limited = False
    storage_limited = False
    next_storage_check = time.monotonic()
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                terminate_process_group(process)
                break
            if storage_root is not None and time.monotonic() >= next_storage_check:
                if not directory_within_budget(storage_root):
                    storage_limited = True
                    terminate_process_group(process)
                    break
                next_storage_check = time.monotonic() + 0.25
            events = selector.select(min(0.1, remaining))
            for key, _ in events:
                stream_name = str(key.data)
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = buffers[stream_name]
                limit = limits[stream_name]
                remaining_capacity = max(0, limit - len(target))
                target.extend(chunk[:remaining_capacity])
                if len(chunk) > remaining_capacity:
                    output_limited = True
                    terminate_process_group(process)
                    break
            if output_limited or storage_limited:
                break
        if not timed_out and not output_limited and not storage_limited:
            process.wait(timeout=max(1.0, deadline - time.monotonic()))
            if storage_root is not None and not directory_within_budget(storage_root):
                storage_limited = True
        else:
            wait_for_terminated_process(process)
    except subprocess.TimeoutExpired:
        timed_out = True
        terminate_process_group(process)
        wait_for_terminated_process(process)
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return (
        bytes(buffers["stdout"]),
        bytes(buffers["stderr"]),
        timed_out,
        output_limited,
        storage_limited,
    )


def directory_within_budget(root: Path) -> bool:
    try:
        metadata = root.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if not stat.S_ISDIR(metadata.st_mode) or root.is_symlink():
        return False
    entries = 0
    total_bytes = 0
    pending = [root]
    try:
        while pending:
            directory = pending.pop()
            try:
                children = os.scandir(directory)
            except FileNotFoundError:
                continue
            with children:
                for child in children:
                    entries += 1
                    if entries > MAX_FETCHED_REPOSITORY_ENTRIES:
                        return False
                    try:
                        child_stat = child.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if stat.S_ISDIR(child_stat.st_mode):
                        pending.append(Path(child.path))
                    elif stat.S_ISREG(child_stat.st_mode):
                        total_bytes += child_stat.st_size
                        if total_bytes > MAX_FETCHED_REPOSITORY_BYTES:
                            return False
                    else:
                        return False
    except OSError:
        return False
    return True


def terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (PermissionError, ProcessLookupError):
        try:
            process.kill()
        except ProcessLookupError:
            pass


def wait_for_terminated_process(process: subprocess.Popen[bytes]) -> None:
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def reacquire_source(
    *,
    trusted_inventory_path: Path,
    source_ref: str,
    object_format: str,
    expected_trusted_inventory_sha256: str,
    git_path: Path,
    expected_git_sha256: str,
    https_helper_path: Path,
    expected_https_helper_sha256: str,
    scratch_parent: Path | None = None,
    remote_url: str | None = None,
    allow_local_remote: bool = False,
    now: datetime | None = None,
) -> SourceReacquisitionResult:
    budget = AcquisitionBudget()
    trusted_report, trusted_sha256 = load_trusted_source_report(
        trusted_inventory_path,
        object_format=object_format,
        expected_sha256=expected_trusted_inventory_sha256,
    )
    budget.check("trusted inventory validation")
    source = trusted_report["source"]
    repository = source["repository"]
    validate_source_ref(source_ref)
    canonical_url = canonical_github_url(repository)
    effective_url, transport = validate_remote_url(
        remote_url or canonical_url,
        canonical_url=canonical_url,
        allow_local_remote=allow_local_remote,
    )
    scratch = None if scratch_parent is None else scratch_parent.expanduser().resolve()
    if scratch is not None:
        scratch.mkdir(parents=True, exist_ok=True, mode=0o700)

    with tempfile.TemporaryDirectory(prefix="source-reacquire-v3-", dir=scratch) as tmp:
        private_root = Path(tmp).resolve()
        private_root.chmod(0o700)
        repository_path = private_root / "objects.git"
        allowed_protocols = "file" if transport == "test-local" else "https"
        runner = BoundedGitRunner(
            environment_root=private_root / "environment",
            git_path=git_path,
            expected_git_sha256=expected_git_sha256,
            https_helper_path=https_helper_path,
            expected_https_helper_sha256=expected_https_helper_sha256,
            storage_root=private_root,
            allowed_protocols=allowed_protocols,
        )
        session = GitSession(runner, private_root=private_root, budget=budget)
        result = acquire_with_git(
            session,
            repository_path=repository_path,
            remote_url=effective_url,
            source_ref=source_ref,
            object_format=object_format,
            expected_commit=source["commit"],
            expected_tree=source["tree"],
        )
        acquired_inventory = result["inventory"]
        comparison = compare_source_inventories(
            trusted_report["inventory"],
            acquired_inventory,
            budget=budget,
        )
        if not hmac.compare_digest(hash_executable(runner.git_path), runner.git_sha256):
            raise SourceReacquisitionError(
                "Staged Git executable changed during acquisition"
            )
        if not hmac.compare_digest(
            hash_executable(runner.https_helper_path),
            runner.https_helper_sha256,
        ):
            raise SourceReacquisitionError(
                "Staged Git HTTPS helper changed during acquisition"
            )
        budget.check("final tooling verification")
        matched = comparison["exact_match"]
        acquired_at = (
            (now or datetime.now(UTC)).astimezone(UTC).isoformat(timespec="seconds")
        )
        report = {
            "schema_version": SOURCE_REACQUISITION_SCHEMA_VERSION,
            "status": "matched" if matched else "mismatch",
            "ok": matched,
            "authority": (
                "time-bounded-canonical-github-source-observation"
                if transport == "canonical-github-https"
                else "test-only-local-source-observation"
            ),
            "acquired_at": acquired_at,
            "request": {
                "repository": repository,
                "commit": source["commit"],
                "tree": source["tree"],
                "object_format": object_format,
                "source_ref": source_ref,
                "trusted_inventory_sha256": trusted_sha256,
            },
            "remote": {
                "url": effective_url,
                "transport": transport,
                "canonical_github_url": canonical_url,
            },
            "git": {
                "source_executable": str(runner.source_git_path),
                "sha256": runner.git_sha256,
                "executed_staged_copy": True,
                "digest_matched_request_before_execution": True,
                "identity_checked_before_and_after_each_execution": True,
                "digest_rematched_after_execution": True,
                "https_helper": {
                    "source_executable": str(runner.source_https_helper_path),
                    "sha256": runner.https_helper_sha256,
                    "executed_staged_copy": transport == "canonical-github-https",
                    "digest_matched_request_before_execution": True,
                    "identity_checked_before_and_after_each_execution": True,
                    "digest_rematched_after_execution": True,
                },
                "private_exec_path": True,
                "version": result["git_version"],
                "tooling_independently_verified": False,
            },
            "observation": {
                "fetched_ref_tip": result["fetched_ref_tip"],
                "commit_object_id": result["commit_object_id"],
                "tree_object_id": result["tree_object_id"],
                "commit_reachable_from_ref": True,
                "inventory_tree_sha256": acquired_inventory["tree_sha256"],
                "inventory_exact_match": matched,
                "object_database": result["repository_usage"],
                "resource_enforcement": {
                    "wall_and_cpu_budget_includes_parent_and_children": True,
                    "command_and_output_budgets": True,
                    "per_process_file_limit_requested": True,
                    "aggregate_storage_poll_interval_milliseconds": 250,
                    "kernel_filesystem_quota": False,
                },
                "upstream_code_checked_out": False,
                "upstream_code_executed": False,
            },
            "comparison": comparison,
            "claims": {
                "source_reacquisition_match": matched,
                "canonical_github_transport": transport == "canonical-github-https",
                "upstream_lineage": False,
                "upstream_ownership": False,
                "host_independent": False,
                "provider_independent": False,
                "builder_containment": False,
                "semantic_safety": False,
            },
            "symlink_field_policy": {
                "compared": ["path", "type", "target"],
                "not_applicable": ["size", "sha256", "executable"],
            },
            "executions": session.executions,
            "claim_limit": SOURCE_REACQUISITION_CLAIM_LIMIT,
        }
        budget.check("report finalization")
        final_result = SourceReacquisitionResult(
            inventory=acquired_inventory,
            report=report,
        )
    budget.check("scratch cleanup")
    return final_result


def acquire_with_git(
    session: GitSession,
    *,
    repository_path: Path,
    remote_url: str,
    source_ref: str,
    object_format: str,
    expected_commit: str,
    expected_tree: str,
) -> dict[str, Any]:
    version = (
        session.required(
            "git-version",
            ["--version"],
            max_stdout_bytes=4096,
        )
        .stdout.decode("ascii", "strict")
        .strip()
    )
    session.required(
        "initialize-private-object-database",
        [
            "init",
            "--bare",
            f"--object-format={object_format}",
            str(repository_path),
        ],
    )
    session.required(
        "add-canonical-source-remote",
        ["-C", str(repository_path), "remote", "add", "origin", remote_url],
    )
    configured_url = (
        session.required(
            "verify-source-remote",
            ["-C", str(repository_path), "remote", "get-url", "--all", "origin"],
            max_stdout_bytes=16 * 1024,
        )
        .stdout.decode("utf-8", "strict")
        .splitlines()
    )
    if configured_url != [remote_url]:
        raise SourceReacquisitionError("Git source remote changed before acquisition")
    acquired_ref = "refs/assured-downstream/source"
    session.required(
        "fetch-source-ref",
        [
            "-C",
            str(repository_path),
            "fetch",
            "--quiet",
            "--force",
            "--prune",
            "--no-tags",
            "--no-write-fetch-head",
            "--no-recurse-submodules",
            "origin",
            f"+{source_ref}:{acquired_ref}",
        ],
        timeout_seconds=DEFAULT_GIT_TIMEOUT_SECONDS,
    )
    repository_usage = validate_acquired_repository_storage(
        repository_path,
        budget=session.budget,
    )
    configured_after = (
        session.required(
            "reverify-source-remote",
            ["-C", str(repository_path), "remote", "get-url", "--all", "origin"],
            max_stdout_bytes=16 * 1024,
        )
        .stdout.decode("utf-8", "strict")
        .splitlines()
    )
    if configured_after != [remote_url]:
        raise SourceReacquisitionError("Git source remote changed during acquisition")
    actual_format = decode_ascii_line(
        session.required(
            "verify-object-format",
            ["-C", str(repository_path), "rev-parse", "--show-object-format"],
            max_stdout_bytes=128,
        ).stdout,
        label="Git object format",
    )
    if actual_format != object_format:
        raise SourceReacquisitionError("Acquired Git object format is not requested")
    fetched_ref_tip = require_object_id(
        decode_ascii_line(
            session.required(
                "resolve-fetched-source-ref",
                ["-C", str(repository_path), "rev-parse", "--verify", acquired_ref],
                max_stdout_bytes=256,
            ).stdout,
            label="fetched source ref",
        ),
        object_format=object_format,
        label="fetched source ref",
    )
    try:
        object_type_result = session.required(
            "verify-commit-object-type",
            ["-C", str(repository_path), "cat-file", "-t", expected_commit],
            max_stdout_bytes=64,
        )
    except SourceReacquisitionError as exc:
        raise SourceReacquisitionError(
            "Requested source commit is unavailable from the acquired source ref"
        ) from exc
    object_type = decode_ascii_line(
        object_type_result.stdout,
        label="commit object type",
    )
    if object_type != "commit":
        raise SourceReacquisitionError("Requested source object is not a commit")
    commit_object_id = require_object_id(
        decode_ascii_line(
            session.required(
                "resolve-commit-object",
                [
                    "-C",
                    str(repository_path),
                    "rev-parse",
                    "--verify",
                    f"{expected_commit}^{{commit}}",
                ],
                max_stdout_bytes=256,
            ).stdout,
            label="commit object",
        ),
        object_format=object_format,
        label="commit object",
    )
    if commit_object_id != expected_commit:
        raise SourceReacquisitionError("Acquired commit identity is not exact")
    reachability = session.required(
        "verify-commit-reachability",
        [
            "-C",
            str(repository_path),
            "merge-base",
            "--is-ancestor",
            expected_commit,
            acquired_ref,
        ],
        allowed_returncodes={0, 1},
        max_stdout_bytes=0,
    )
    if reachability.returncode != 0:
        raise SourceReacquisitionError(
            "Requested commit is not reachable from the acquired source ref"
        )
    tree_object_id = require_object_id(
        decode_ascii_line(
            session.required(
                "resolve-source-tree",
                [
                    "-C",
                    str(repository_path),
                    "rev-parse",
                    "--verify",
                    f"{expected_commit}^{{tree}}",
                ],
                max_stdout_bytes=256,
            ).stdout,
            label="source tree",
        ),
        object_format=object_format,
        label="source tree",
    )
    if tree_object_id != expected_tree:
        raise SourceReacquisitionError("Acquired source tree identity is not exact")
    tree_output = session.required(
        "enumerate-source-tree",
        [
            "-C",
            str(repository_path),
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            "-l",
            expected_commit,
        ],
        max_stdout_bytes=MAX_TREE_OUTPUT_BYTES,
    ).stdout
    entries = inventory_git_tree(
        tree_output,
        repository_path=repository_path,
        object_format=object_format,
        session=session,
        budget=session.budget,
    )
    inventory = {
        "schema_version": 1,
        "entries": entries,
        "tree_sha256": hashlib.sha256(
            json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }
    try:
        validate_source_inventory(inventory)
    except BuilderHandoffError as exc:
        raise SourceReacquisitionError(str(exc)) from exc
    return {
        "git_version": version,
        "fetched_ref_tip": fetched_ref_tip,
        "commit_object_id": commit_object_id,
        "tree_object_id": tree_object_id,
        "repository_usage": repository_usage,
        "inventory": inventory,
    }


def inventory_git_tree(
    payload: bytes,
    *,
    repository_path: Path,
    object_format: str,
    session: GitSession,
    budget: AcquisitionBudget | None = None,
) -> list[dict[str, Any]]:
    records = payload.split(b"\0")
    if records and records[-1] == b"":
        records.pop()
    if not records or len(records) > MAX_TREE_ENTRIES:
        raise SourceReacquisitionError("Acquired source tree entry count is invalid")
    entries: list[dict[str, Any]] = []
    folded_paths: set[str] = set()
    path_set: set[str] = set()
    parent_paths: set[str] = set()
    folded_parent_paths: set[str] = set()
    total_file_bytes = 0
    for record in records:
        if budget is not None:
            budget.check("source tree inventory")
        header, separator, path_bytes = record.partition(b"\t")
        match = TREE_HEADER_PATTERN.fullmatch(header)
        if not separator or match is None:
            raise SourceReacquisitionError("Git returned a malformed tree record")
        try:
            path = path_bytes.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise SourceReacquisitionError("Git tree path is not UTF-8") from exc
        try:
            safe_spdx_path(path)
        except BuilderHandoffError as exc:
            raise SourceReacquisitionError(str(exc)) from exc
        if any(part.casefold() == ".git" for part in path.split("/")):
            raise SourceReacquisitionError("Git tree contains a reserved .git path")
        folded_path = path.casefold()
        if (
            path in path_set
            or folded_path in folded_paths
            or path in parent_paths
            or folded_path in folded_parent_paths
        ):
            raise SourceReacquisitionError("Git tree contains a duplicate path alias")
        current_parents = {
            parent.as_posix()
            for parent in PurePosixPath(path).parents
            if parent.as_posix() != "."
        }
        for parent_name in current_parents:
            if parent_name in path_set or parent_name.casefold() in folded_paths:
                raise SourceReacquisitionError(
                    "Git tree contains a path prefix collision"
                )
        path_set.add(path)
        folded_paths.add(folded_path)
        parent_paths.update(current_parents)
        folded_parent_paths.update(parent.casefold() for parent in current_parents)
        mode = match.group("mode").decode("ascii")
        object_type = match.group("type").decode("ascii")
        object_id = require_object_id(
            match.group("object").decode("ascii"),
            object_format=object_format,
            label=f"tree object for {path}",
        )
        size_text = match.group("size").decode("ascii")
        if object_type != "blob" or size_text == "-":
            if mode == "160000" or object_type == "commit":
                raise SourceReacquisitionError(
                    "Gitlinks and submodules are unsupported"
                )
            raise SourceReacquisitionError(
                "Git tree contains an unsupported object type"
            )
        size = int(size_text)
        if mode in {"100644", "100755"}:
            if size > MAX_SOURCE_BLOB_BYTES:
                raise SourceReacquisitionError("Git source blob exceeds its size limit")
            total_file_bytes += size
            if total_file_bytes > MAX_SOURCE_TOTAL_BYTES:
                raise SourceReacquisitionError("Git source tree exceeds its size limit")
            content = read_git_blob(
                session,
                repository_path=repository_path,
                object_id=object_id,
                expected_size=size,
                operation=f"read-source-blob-{len(entries) + 1:05d}",
            )
            entries.append(
                {
                    "type": "file",
                    "path": path,
                    "size": size,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "executable": mode == "100755",
                }
            )
            if budget is not None:
                budget.check("source blob hashing")
        elif mode == "120000":
            if size < 1 or size > MAX_SYMLINK_BYTES:
                raise SourceReacquisitionError("Git symlink target size is invalid")
            content = read_git_blob(
                session,
                repository_path=repository_path,
                object_id=object_id,
                expected_size=size,
                operation=f"read-symlink-blob-{len(entries) + 1:05d}",
            )
            try:
                target = content.decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise SourceReacquisitionError(
                    "Git symlink target is not UTF-8"
                ) from exc
            if not target or "\x00" in target:
                raise SourceReacquisitionError("Git symlink target is invalid")
            entries.append({"type": "symlink", "path": path, "target": target})
        else:
            raise SourceReacquisitionError("Git tree contains an unsupported file mode")
    return sorted(entries, key=lambda entry: PurePosixPath(entry["path"]).parts)


def read_git_blob(
    session: GitSession,
    *,
    repository_path: Path,
    object_id: str,
    expected_size: int,
    operation: str,
) -> bytes:
    content = session.required(
        operation,
        ["-C", str(repository_path), "cat-file", "blob", object_id],
        max_stdout_bytes=expected_size,
    ).stdout
    if len(content) != expected_size:
        raise SourceReacquisitionError("Git blob size changed during acquisition")
    return content


def compare_source_inventories(
    trusted: dict[str, Any],
    acquired: dict[str, Any],
    *,
    budget: AcquisitionBudget | None = None,
) -> dict[str, Any]:
    trusted_entries = {entry["path"]: entry for entry in trusted["entries"]}
    acquired_entries = {entry["path"]: entry for entry in acquired["entries"]}
    findings: list[dict[str, Any]] = []
    for path in sorted(set(trusted_entries) | set(acquired_entries)):
        if budget is not None:
            budget.check("source inventory comparison")
        expected = trusted_entries.get(path)
        observed = acquired_entries.get(path)
        if expected is None:
            findings.append({"code": "unexpected-path", "path": path})
        elif observed is None:
            findings.append({"code": "missing-path", "path": path})
        elif expected != observed:
            changed = sorted(
                key
                for key in set(expected) | set(observed)
                if expected.get(key) != observed.get(key)
            )
            findings.append({"code": "entry-mismatch", "path": path, "fields": changed})
    exact = trusted == acquired
    return {
        "exact_match": exact,
        "trusted_entry_count": len(trusted_entries),
        "acquired_entry_count": len(acquired_entries),
        "trusted_tree_sha256": trusted["tree_sha256"],
        "acquired_tree_sha256": acquired["tree_sha256"],
        "finding_count": len(findings),
        "findings": findings[:MAX_RECORDED_FINDINGS],
        "findings_truncated": len(findings) > MAX_RECORDED_FINDINGS,
    }


def load_trusted_source_report(
    path: Path,
    *,
    object_format: str,
    expected_sha256: str | None = None,
) -> tuple[dict[str, Any], str]:
    require_object_format(object_format)
    try:
        payload, digest = snapshot_bytes(
            path,
            label="trusted source inventory",
            max_bytes=MAX_JSON_BYTES,
        )
    except ReleaseVerificationError as exc:
        raise SourceReacquisitionError(str(exc)) from exc
    if expected_sha256 is not None:
        require_sha256(expected_sha256, label="trusted source inventory digest")
        if not hmac.compare_digest(digest, expected_sha256):
            raise SourceReacquisitionError(
                "Trusted source inventory is not bound to the durable request"
            )
    report = decode_json_object(payload, label="trusted source inventory")
    if set(report) != {"inventory", "schema_version", "source"}:
        raise SourceReacquisitionError("Trusted source report fields are not exact")
    if report.get("schema_version") != 1:
        raise SourceReacquisitionError("Trusted source report schema is unsupported")
    source = report.get("source")
    if not isinstance(source, dict) or set(source) != {"commit", "repository", "tree"}:
        raise SourceReacquisitionError("Trusted source identity is invalid")
    validate_repository(source.get("repository"))
    require_object_id(
        source.get("commit"),
        object_format=object_format,
        label="trusted source commit",
    )
    require_object_id(
        source.get("tree"),
        object_format=object_format,
        label="trusted source tree",
    )
    inventory = report.get("inventory")
    if not isinstance(inventory, dict):
        raise SourceReacquisitionError("Trusted source inventory is invalid")
    try:
        validate_source_inventory(inventory)
    except BuilderHandoffError as exc:
        raise SourceReacquisitionError(str(exc)) from exc
    return report, digest


def decode_json_object(payload: bytes, *, label: str) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8", "strict")
        value = json.loads(
            text,
            object_pairs_hook=duplicate_rejecting_object,
            parse_constant=reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise SourceReacquisitionError(f"Could not parse {label}") from exc
    if not isinstance(value, dict):
        raise SourceReacquisitionError(f"{label.capitalize()} must be an object")
    return value


def duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def reject_json_constant(value: str) -> None:
    raise ValueError(f"unsupported JSON constant: {value}")


def canonical_github_url(repository: str) -> str:
    validate_repository(repository)
    return f"https://github.com/{repository}.git"


def validate_repository(value: Any) -> str:
    if (
        not isinstance(value, str)
        or REPOSITORY_PATTERN.fullmatch(value) is None
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise SourceReacquisitionError("Source repository identity is invalid")
    return value


def validate_source_ref(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("refs/heads/"):
        raise SourceReacquisitionError("Source ref must be a full branch ref")
    branch = value.removeprefix("refs/heads/")
    try:
        validate_default_branch(branch)
    except ValueError as exc:
        raise SourceReacquisitionError(str(exc)) from exc
    return value


def validate_remote_url(
    value: str,
    *,
    canonical_url: str,
    allow_local_remote: bool,
) -> tuple[str, str]:
    if value == canonical_url:
        return value, "canonical-github-https"
    if not allow_local_remote:
        raise SourceReacquisitionError("Source remote is not canonical GitHub HTTPS")
    candidate = Path(value).expanduser()
    if not candidate.is_absolute() or candidate.is_symlink():
        raise SourceReacquisitionError(
            "Test-only source remote must be an absolute path"
        )
    resolved = candidate.resolve()
    if not resolved.is_dir():
        raise SourceReacquisitionError("Test-only source remote is unavailable")
    return str(resolved), "test-local"


def require_object_format(value: str) -> str:
    if value not in OBJECT_ID_LENGTHS:
        raise SourceReacquisitionError("Git object format is unsupported")
    return value


def require_object_id(value: Any, *, object_format: str, label: str) -> str:
    length = OBJECT_ID_LENGTHS[require_object_format(object_format)]
    if (
        not isinstance(value, str)
        or len(value) != length
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SourceReacquisitionError(
            f"{label.capitalize()} is not a full lowercase {object_format} object ID"
        )
    return value


def decode_ascii_line(payload: bytes, *, label: str) -> str:
    try:
        value = payload.decode("ascii", "strict").strip()
    except UnicodeDecodeError as exc:
        raise SourceReacquisitionError(f"{label.capitalize()} is not ASCII") from exc
    if not value or "\n" in value or "\r" in value:
        raise SourceReacquisitionError(f"{label.capitalize()} is not one line")
    return value


def bounded_text(payload: bytes) -> str:
    text = payload.decode("utf-8", "replace").strip()
    return text if len(text) <= 4096 else text[:4096] + "...<truncated>"


def validate_acquired_repository_storage(
    root: Path,
    *,
    budget: AcquisitionBudget | None = None,
) -> dict[str, int]:
    entry_count = 0
    total_bytes = 0
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        if budget is not None:
            budget.check("object database validation")
        for name in directory_names:
            path = directory_path / name
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                raise SourceReacquisitionError(
                    "Acquired Git object database contains an unsafe directory"
                )
            entry_count += 1
        for name in file_names:
            path = directory_path / name
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                raise SourceReacquisitionError(
                    "Acquired Git object database contains an unsafe file"
                )
            entry_count += 1
            total_bytes += metadata.st_size
            if (
                entry_count > MAX_FETCHED_REPOSITORY_ENTRIES
                or total_bytes > MAX_FETCHED_REPOSITORY_BYTES
            ):
                raise SourceReacquisitionError(
                    "Acquired Git object database exceeds its retention limit"
                )
    return {"entry_count": entry_count, "size_bytes": total_bytes}


def require_sha256(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SourceReacquisitionError(f"{label.capitalize()} is not a SHA-256 digest")
    return value


def require_regular_executable(path: Path) -> Path:
    candidate = path.expanduser()
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise SourceReacquisitionError("Git executable is unavailable") from exc
    if (
        candidate.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or not metadata.st_mode & stat.S_IXUSR
    ):
        raise SourceReacquisitionError("Git executable is not a regular executable")
    return candidate.resolve()


def stage_native_executable(
    source: Path,
    *,
    target: Path,
    expected_sha256: str,
    label: str,
) -> tuple[Path, str, tuple[int, int, int, int, int, int]]:
    require_sha256(expected_sha256, label=f"expected {label} digest")
    try:
        before = source.lstat()
    except OSError as exc:
        raise SourceReacquisitionError(f"{label} is unavailable") from exc
    source_flags = os.O_RDONLY
    target_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
        target_flags |= os.O_NOFOLLOW
    try:
        source_descriptor = os.open(source, source_flags)
    except OSError as exc:
        raise SourceReacquisitionError(f"{label} could not be opened") from exc
    target_descriptor: int | None = None
    digest = hashlib.sha256()
    copied_size = 0
    first_bytes = b""
    try:
        opened = os.fstat(source_descriptor)
        if (
            file_identity(opened) != file_identity(before)
            or not stat.S_ISREG(opened.st_mode)
            or not opened.st_mode & stat.S_IXUSR
            or opened.st_size > MAX_EXECUTABLE_BYTES
        ):
            raise SourceReacquisitionError(f"{label} changed before staging")
        target_descriptor = os.open(target, target_flags, 0o500)
        while chunk := os.read(source_descriptor, 1024 * 1024):
            if not first_bytes:
                first_bytes = chunk[:4]
            copied_size += len(chunk)
            if copied_size > MAX_EXECUTABLE_BYTES:
                raise SourceReacquisitionError(f"{label} exceeds its size limit")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(target_descriptor, view)
                if written <= 0:
                    raise SourceReacquisitionError(f"{label} staging write stalled")
                view = view[written:]
        final_source = os.fstat(source_descriptor)
        if (
            file_identity(final_source) != file_identity(opened)
            or copied_size != opened.st_size
        ):
            raise SourceReacquisitionError(f"{label} changed while staging")
        if first_bytes not in NATIVE_EXECUTABLE_MAGICS:
            raise SourceReacquisitionError(f"{label} is not a native executable")
        os.fchmod(target_descriptor, 0o500)
        os.fsync(target_descriptor)
    finally:
        if target_descriptor is not None:
            os.close(target_descriptor)
        os.close(source_descriptor)
    observed_digest = digest.hexdigest()
    if not hmac.compare_digest(observed_digest, expected_sha256):
        raise SourceReacquisitionError(
            f"{label} digest does not match the trusted request"
        )
    fsync_directory(target.parent)
    target = target.resolve()
    if not hmac.compare_digest(hash_executable(target), expected_sha256):
        raise SourceReacquisitionError(f"Staged {label} digest is invalid")
    return target, observed_digest, file_identity(target.lstat())


def hash_executable(path: Path) -> str:
    digest, _ = inspect_stable_executable(path)
    return digest


def inspect_stable_executable(
    path: Path,
) -> tuple[str, tuple[int, int, int, int, int, int]]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise SourceReacquisitionError("Git executable is unavailable") from exc
    if not stat.S_ISREG(before.st_mode) or path.is_symlink():
        raise SourceReacquisitionError("Git executable is not a regular file")
    if before.st_size > MAX_EXECUTABLE_BYTES:
        raise SourceReacquisitionError("Git executable exceeds its size limit")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SourceReacquisitionError("Git executable could not be opened") from exc
    digest = hashlib.sha256()
    read_size = 0
    try:
        opened = os.fstat(descriptor)
        if file_identity(opened) != file_identity(before):
            raise SourceReacquisitionError("Git executable changed before hashing")
        while chunk := os.read(descriptor, 1024 * 1024):
            read_size += len(chunk)
            if read_size > MAX_EXECUTABLE_BYTES:
                raise SourceReacquisitionError("Git executable exceeds its size limit")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if file_identity(after) != file_identity(opened) or read_size != before.st_size:
            raise SourceReacquisitionError("Git executable changed while hashing")
    finally:
        os.close(descriptor)
    return digest.hexdigest(), file_identity(after)


def verify_git_executable_identity(
    path: Path,
    expected_identity: tuple[int, int, int, int, int, int],
) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SourceReacquisitionError("Git executable became unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or not metadata.st_mode & stat.S_IXUSR
        or file_identity(metadata) != expected_identity
    ):
        raise SourceReacquisitionError(
            "Git executable identity changed during acquisition"
        )


def file_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_nlink,
    )


def process_tree_cpu_seconds() -> float:
    self_usage = resource.getrusage(resource.RUSAGE_SELF)
    child_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return (
        self_usage.ru_utime
        + self_usage.ru_stime
        + child_usage.ru_utime
        + child_usage.ru_stime
    )


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
