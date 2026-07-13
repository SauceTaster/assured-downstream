from __future__ import annotations

import collections
import datetime as dt
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


PROFILE_ID = "python-wheel-v2"
BUILD_UID = 65532
BUILD_GID = 65532
BUILD_USER = "assured"
INPUT_ROOT = Path("/input")
WORK_ROOT = Path("/workspace/source")
BUILD_OUTPUT_ROOT = Path("/workspace/output")
BUILD_DIST_ROOT = BUILD_OUTPUT_ROOT / "dist"
OUTPUT_ROOT = Path("/out")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!-]{0,127}$")
SYSCALL_PATTERN = re.compile(
    r"^(?P<timestamp>[0-9]+\.[0-9]+)\s+"
    r"(?P<name>[A-Za-z0-9_]+)\((?P<args>.*)\)\s+=\s+"
    r"(?P<result>.*?)(?:\s+<[0-9.]+>)?$"
)
SIGNAL_PATTERN = re.compile(
    r"^(?P<timestamp>[0-9]+\.[0-9]+)\s+---\s+"
    r"(?P<name>SIG[A-Z0-9]+)\s+\{.*\}\s+---$"
)
EXIT_PATTERN = re.compile(
    r"^(?P<timestamp>[0-9]+\.[0-9]+)\s+\+\+\+\s+"
    r"(?P<status>exited with [0-9]+|killed by SIG[A-Z0-9]+(?: \(core dumped\))?)"
    r"\s+\+\+\+$"
)
QUOTED_PATTERN = re.compile(r'"((?:[^"\\]|\\.)*)"')
FILE_OPERATIONS = {
    "creat": "create",
    "mkdir": "create",
    "mkdirat": "create",
    "open": "access",
    "openat": "access",
    "openat2": "access",
    "readlink": "access",
    "readlinkat": "access",
    "rename": "rename",
    "renameat": "rename",
    "renameat2": "rename",
    "rmdir": "delete",
    "stat": "access",
    "unlink": "delete",
    "unlinkat": "delete",
}
NETWORK_OPERATIONS = {
    "accept",
    "accept4",
    "bind",
    "connect",
    "listen",
    "recvfrom",
    "sendto",
}
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
MAX_ARTIFACTS = 128
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 1024 * 1024 * 1024
COPY_CHUNK_SIZE = 1024 * 1024


class BuilderError(RuntimeError):
    pass


def main() -> int:
    if len(sys.argv) != 1:
        raise BuilderError(f"{PROFILE_ID} does not accept command arguments")
    if os.geteuid() != 0 or os.getegid() != 0:
        raise BuilderError(f"{PROFILE_ID} requires the trusted root supervisor")

    metadata = load_metadata(os.environ)
    prepare_directories()
    copy_source()
    grant_build_ownership(WORK_ROOT)
    source_inventory = inventory_tree(WORK_ROOT)
    write_json(OUTPUT_ROOT / "reports" / "source-inventory.json", source_inventory)

    started_at = utc_now()
    command = collector_command()
    completed = subprocess.run(
        command,
        cwd=WORK_ROOT,
        env=build_environment(metadata),
        check=False,
    )
    quiescence = enforce_process_quiescence()

    trace = parse_strace_directory(OUTPUT_ROOT / "traces" / "raw")
    write_json(OUTPUT_ROOT / "traces" / "observed-trace.json", trace)

    artifact_inventory: dict[str, Any]
    validation_error: str | None = None
    try:
        identity_boundary = verify_identity_boundary(
            OUTPUT_ROOT,
            build_output_root=BUILD_OUTPUT_ROOT,
        )
        identity_boundary.update(quiescence)
        snapshot_artifacts(
            BUILD_DIST_ROOT,
            OUTPUT_ROOT / "dist",
            expected_source_uid=BUILD_UID,
            expected_source_gid=0,
            expected_target_uid=0,
            expected_target_gid=0,
        )
        artifact_inventory = inventory_artifacts(OUTPUT_ROOT / "dist")
    except (BuilderError, OSError) as exc:
        identity_boundary = {
            "collector_uid": 0,
            "build_uid": BUILD_UID,
            "build_gid": BUILD_GID,
            "separate_collector_identity": True,
            "collector_output_writable_by_build": False,
            "validation_error": str(exc),
        }
        artifact_inventory = {"schema_version": 1, "artifacts": []}
        validation_error = str(exc)
    write_json(
        OUTPUT_ROOT / "reports" / "artifact-inventory.json",
        artifact_inventory,
    )

    succeeded = completed.returncode == 0 and validation_error is None
    report = {
        "schema_version": 1,
        "status": "succeeded" if succeeded else "failed",
        "profile": PROFILE_ID,
        "builder": {
            "image": metadata["builder_image"],
            "image_digest": metadata["builder_image_digest"],
            "architecture": platform.machine(),
            "python": platform.python_version(),
            "tools": tool_versions(),
        },
        "source": {
            "repository": metadata["source_repository"],
            "commit": metadata["source_commit"],
            "git_tree": metadata["source_tree"],
            "filesystem_sha256": source_inventory["tree_sha256"],
            "project_version": metadata["project_version"],
            "source_date_epoch": metadata["source_date_epoch"],
        },
        "execution": {
            "argv": command,
            "cwd": str(WORK_ROOT),
            "network_policy": "deny",
            "returncode": completed.returncode,
            "started_at": started_at,
            "finished_at": utc_now(),
            "validation_error": validation_error,
            "identity_boundary": identity_boundary,
        },
        "trace": {
            "collector": trace["collector"],
            "coverage": trace["coverage"],
            "raw_file_count": trace["raw_file_count"],
            "parsed_line_count": trace["parsed_line_count"],
            "syscall_line_count": trace["syscall_line_count"],
            "signal_line_count": trace["signal_line_count"],
            "exit_line_count": trace["exit_line_count"],
            "unparsed_line_count": trace["unparsed_line_count"],
        },
        "claim_limit": (
            "This report declares a root-owned collector and evidence boundary. "
            "Container isolation, source lineage, and resistance to collector "
            "exploitation still require independent verification."
        ),
    }
    write_json(OUTPUT_ROOT / "reports" / "builder.json", report)
    return 0 if succeeded else (completed.returncode or 2)


def collector_command() -> list[str]:
    return [
        "/usr/bin/strace",
        "-u",
        BUILD_USER,
        "-ff",
        "-qq",
        "-ttt",
        "-T",
        "-yy",
        "-s",
        "4096",
        "-o",
        str(OUTPUT_ROOT / "traces" / "raw" / "strace"),
        "--",
        sys.executable,
        "-I",
        "-m",
        "build",
        "--no-isolation",
        "--outdir",
        str(BUILD_DIST_ROOT),
        str(WORK_ROOT),
    ]


def load_metadata(environment: dict[str, str]) -> dict[str, str]:
    values = {
        "source_repository": required(environment, "ASSURED_SOURCE_REPOSITORY"),
        "source_commit": required(environment, "ASSURED_SOURCE_COMMIT"),
        "source_tree": required(environment, "ASSURED_SOURCE_TREE"),
        "project_version": required(environment, "ASSURED_PROJECT_VERSION"),
        "source_date_epoch": required(environment, "SOURCE_DATE_EPOCH"),
        "builder_image": required(environment, "ASSURED_BUILDER_IMAGE"),
        "builder_image_digest": required(environment, "ASSURED_BUILDER_IMAGE_DIGEST"),
    }
    if not REPOSITORY_PATTERN.fullmatch(values["source_repository"]):
        raise BuilderError("source repository must be an owner/name pair")
    for field in ("source_commit", "source_tree"):
        if not SHA_PATTERN.fullmatch(values[field]):
            raise BuilderError(f"{field} must be a lowercase 40-character Git SHA")
    if not VERSION_PATTERN.fullmatch(values["project_version"]):
        raise BuilderError("project version is outside the fixed profile grammar")
    if not values["source_date_epoch"].isdigit():
        raise BuilderError("SOURCE_DATE_EPOCH must be a positive integer")
    digest = values["builder_image_digest"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise BuilderError("builder image digest is invalid")
    if not re.fullmatch(r"ghcr\.io/[a-z0-9._/-]+", values["builder_image"]):
        raise BuilderError("builder image is outside the GHCR grammar")
    return values


def required(environment: dict[str, str], name: str) -> str:
    value = environment.get(name, "")
    if not value:
        raise BuilderError(f"missing required environment variable {name}")
    return value


def prepare_directories() -> None:
    if not INPUT_ROOT.is_dir() or INPUT_ROOT.is_symlink():
        raise BuilderError("/input must be a source directory")
    output_metadata = OUTPUT_ROOT.lstat()
    if (
        not stat.S_ISDIR(output_metadata.st_mode)
        or OUTPUT_ROOT.is_symlink()
        or output_metadata.st_uid != 0
        or output_metadata.st_gid != 0
        or stat.S_IMODE(output_metadata.st_mode) != 0o700
    ):
        raise BuilderError("/out must be a root-owned mode-0700 evidence mount")
    if any(OUTPUT_ROOT.iterdir()):
        raise BuilderError("/out must be empty at builder start")
    for path in (
        WORK_ROOT.parent,
        BUILD_DIST_ROOT,
        OUTPUT_ROOT / "dist",
        OUTPUT_ROOT / "reports",
        OUTPUT_ROOT / "traces" / "raw",
        Path("/tmp/home"),
    ):
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    for path in (
        OUTPUT_ROOT,
        OUTPUT_ROOT / "dist",
        OUTPUT_ROOT / "reports",
        OUTPUT_ROOT / "traces",
        OUTPUT_ROOT / "traces" / "raw",
    ):
        path.chmod(0o700)
    for path in (BUILD_OUTPUT_ROOT, BUILD_DIST_ROOT, Path("/tmp/home")):
        path.chmod(0o750)
        os.chown(path, BUILD_UID, 0)


def copy_source() -> None:
    shutil.copytree(
        INPUT_ROOT,
        WORK_ROOT,
        symlinks=True,
        ignore=shutil.ignore_patterns(".git"),
    )


def grant_build_ownership(root: Path) -> None:
    for path in [root, *sorted(root.rglob("*"))]:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            os.lchown(path, BUILD_UID, 0)
            continue
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            path.chmod(
                mode
                | stat.S_IRUSR
                | stat.S_IWUSR
                | stat.S_IXUSR
                | stat.S_IRGRP
                | stat.S_IXGRP
            )
        elif stat.S_ISREG(metadata.st_mode):
            group_mode = stat.S_IRGRP
            if mode & stat.S_IXUSR:
                group_mode |= stat.S_IXGRP
            path.chmod(mode | stat.S_IRUSR | stat.S_IWUSR | group_mode)
        else:
            raise BuilderError(f"source contains unsupported file type: {path}")
        os.lchown(path, BUILD_UID, 0)


def build_environment(metadata: dict[str, str]) -> dict[str, str]:
    return {
        "HOME": "/tmp/home",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PBR_VERSION": metadata["project_version"],
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "SOURCE_DATE_EPOCH": metadata["source_date_epoch"],
        "TZ": "UTC",
    }


def inventory_tree(root: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if stat.S_ISLNK(mode):
            entries.append(
                {
                    "path": relative,
                    "type": "symlink",
                    "target": os.readlink(path),
                }
            )
            continue
        if not stat.S_ISREG(mode):
            raise BuilderError(f"source contains unsupported file type: {relative}")
        entries.append(
            {
                "path": relative,
                "type": "file",
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
                "executable": bool(mode & stat.S_IXUSR),
            }
        )
    payload = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema_version": 1,
        "tree_sha256": hashlib.sha256(payload).hexdigest(),
        "entries": entries,
    }


def verify_identity_boundary(
    evidence_root: Path,
    *,
    build_output_root: Path,
) -> dict[str, Any]:
    evidence_metadata = evidence_root.lstat()
    if (
        not stat.S_ISDIR(evidence_metadata.st_mode)
        or evidence_metadata.st_uid != 0
        or evidence_metadata.st_gid != 0
        or stat.S_IMODE(evidence_metadata.st_mode) != 0o700
    ):
        raise BuilderError("collector evidence root lost its root-only ownership")
    build_metadata = build_output_root.lstat()
    if (
        not stat.S_ISDIR(build_metadata.st_mode)
        or build_output_root.is_symlink()
        or build_metadata.st_uid != BUILD_UID
        or build_metadata.st_gid != 0
        or stat.S_IMODE(build_metadata.st_mode) != 0o750
    ):
        raise BuilderError("build output root lost its unprivileged ownership")

    raw_traces = sorted((evidence_root / "traces" / "raw").glob("strace.*"))
    if not raw_traces:
        raise BuilderError("collector produced no root-owned raw traces")
    for path in raw_traces:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or path.is_symlink()
            or metadata.st_nlink != 1
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise BuilderError("collector raw trace ownership is not protected")
    return {
        "collector_uid": 0,
        "collector_gid": 0,
        "build_uid": BUILD_UID,
        "build_gid": BUILD_GID,
        "evidence_uid": evidence_metadata.st_uid,
        "evidence_gid": evidence_metadata.st_gid,
        "evidence_mode": f"{stat.S_IMODE(evidence_metadata.st_mode):04o}",
        "raw_trace_owner_uid": 0,
        "raw_trace_owner_gid": 0,
        "separate_collector_identity": True,
        "collector_output_writable_by_build": False,
    }


def enforce_process_quiescence(
    *,
    max_rounds: int = 200,
    delay_seconds: float = 0.01,
) -> dict[str, Any]:
    killed_processes: set[int] = set()
    for _ in range(max_rounds):
        reap_children()
        remaining = remaining_process_ids()
        if not remaining:
            return {
                "quiescence_barrier": "private-pid-namespace-sigkill",
                "killed_process_count": len(killed_processes),
                "remaining_process_count": 0,
            }
        for process_id in remaining:
            try:
                os.kill(process_id, signal.SIGKILL)
            except ProcessLookupError:
                continue
            except PermissionError as exc:
                raise BuilderError(
                    f"collector could not terminate escaped process {process_id}"
                ) from exc
            killed_processes.add(process_id)
        time.sleep(delay_seconds)
    remaining = remaining_process_ids()
    raise BuilderError(
        "build process tree did not quiesce: "
        + ",".join(str(process_id) for process_id in remaining)
    )


def remaining_process_ids() -> list[int]:
    own_process_id = os.getpid()
    process_ids = []
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        process_id = int(path.name)
        if process_id == own_process_id:
            continue
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        process_ids.append(process_id)
    return sorted(process_ids)


def reap_children() -> None:
    while True:
        try:
            process_id, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if process_id == 0:
            return


def snapshot_artifacts(
    source_root: Path,
    target_root: Path,
    *,
    expected_source_uid: int | None = None,
    expected_source_gid: int | None = None,
    expected_target_uid: int | None = None,
    expected_target_gid: int | None = None,
) -> None:
    validate_artifact_directory(
        source_root,
        label="build artifact root",
        expected_uid=expected_source_uid,
        expected_gid=expected_source_gid,
    )
    validate_artifact_directory(
        target_root,
        label="collector artifact root",
        expected_uid=expected_target_uid,
        expected_gid=expected_target_gid,
    )
    if any(target_root.iterdir()):
        raise BuilderError("collector artifact destination must start empty")
    total_bytes = 0
    file_count = 0
    for directory, directory_names, file_names in os.walk(
        source_root,
        topdown=True,
        followlinks=False,
    ):
        directory_path = Path(directory)
        directory_names.sort()
        file_names.sort()
        for name in directory_names:
            source = directory_path / name
            relative = source.relative_to(source_root)
            metadata = source.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or source.is_symlink():
                raise BuilderError(
                    f"artifact directory is not a standalone directory: {relative}"
                )
            (target_root / relative).mkdir(mode=0o700, parents=True, exist_ok=False)
        for name in file_names:
            source = directory_path / name
            relative = source.relative_to(source_root)
            target = target_root / relative
            metadata = source.lstat()
            file_count += 1
            if file_count > MAX_ARTIFACTS:
                raise BuilderError("builder produced too many release artifacts")
            if (
                not stat.S_ISREG(metadata.st_mode)
                or source.is_symlink()
                or metadata.st_nlink != 1
            ):
                raise BuilderError(
                    f"artifact is not a standalone regular file: {relative}"
                )
            if metadata.st_size > MAX_ARTIFACT_BYTES:
                raise BuilderError(f"artifact exceeds size limit: {relative}")
            total_bytes += metadata.st_size
            if total_bytes > MAX_TOTAL_ARTIFACT_BYTES:
                raise BuilderError("builder artifacts exceed the total size limit")
            snapshot_regular_artifact(source, target, expected=metadata)
    if file_count == 0:
        raise BuilderError("builder produced no release artifacts")


def validate_artifact_directory(
    path: Path,
    *,
    label: str,
    expected_uid: int | None,
    expected_gid: int | None,
) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BuilderError(f"{label} is missing") from exc
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        raise BuilderError(f"{label} is not a standalone directory")
    if expected_uid is not None and metadata.st_uid != expected_uid:
        raise BuilderError(f"{label} has the wrong owner")
    if expected_gid is not None and metadata.st_gid != expected_gid:
        raise BuilderError(f"{label} has the wrong group")


def snapshot_regular_artifact(
    source: Path,
    target: Path,
    *,
    expected: os.stat_result,
) -> None:
    source_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
    source_fd = os.open(source, source_flags)
    target_fd: int | None = None
    try:
        opened = os.fstat(source_fd)
        if file_identity(opened) != file_identity(expected):
            raise BuilderError(f"artifact changed before snapshot: {source.name}")
        target_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            target_flags |= os.O_NOFOLLOW
        target_fd = os.open(target, target_flags, 0o400)
        copied = 0
        copied_digest = hashlib.sha256()
        while chunk := os.read(source_fd, COPY_CHUNK_SIZE):
            copied += len(chunk)
            if copied > MAX_ARTIFACT_BYTES:
                raise BuilderError(
                    f"artifact changed size while snapshotting: {source.name}"
                )
            copied_digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(target_fd, view)
                if written <= 0:
                    raise BuilderError(f"artifact snapshot stalled: {source.name}")
                view = view[written:]
        final = os.fstat(source_fd)
        if file_identity(final) != file_identity(opened) or copied != opened.st_size:
            raise BuilderError(f"artifact changed while snapshotting: {source.name}")
        os.lseek(source_fd, 0, os.SEEK_SET)
        verification_digest = hashlib.sha256()
        while chunk := os.read(source_fd, COPY_CHUNK_SIZE):
            verification_digest.update(chunk)
        verified = os.fstat(source_fd)
        if (
            file_identity(verified) != file_identity(opened)
            or verification_digest.digest() != copied_digest.digest()
        ):
            raise BuilderError(f"artifact content was unstable: {source.name}")
        os.fsync(target_fd)
    finally:
        if target_fd is not None:
            os.close(target_fd)
        os.close(source_fd)


def file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def inventory_artifacts(root: Path) -> dict[str, Any]:
    artifacts: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode) or stat.S_ISLNK(mode) or path.stat().st_nlink != 1:
            raise BuilderError(f"artifact is not a regular file: {relative}")
        size = path.stat().st_size
        if size > MAX_ARTIFACT_BYTES:
            raise BuilderError(f"artifact exceeds size limit: {relative}")
        artifacts.append(
            {"path": f"dist/{relative}", "size": size, "sha256": sha256_file(path)}
        )
    if not artifacts:
        raise BuilderError("builder produced no release artifacts")
    if len(artifacts) > MAX_ARTIFACTS:
        raise BuilderError("builder produced too many release artifacts")
    return {"schema_version": 1, "artifacts": artifacts}


def parse_strace_directory(
    root: Path,
    *,
    collector_version: str | None = None,
) -> dict[str, Any]:
    raw_files = sorted(path for path in root.glob("strace.*") if path.is_file())
    events: collections.Counter[tuple[str, ...]] = collections.Counter()
    parsed = 0
    syscalls = 0
    signals = 0
    exits = 0
    unparsed = 0
    for path in raw_files:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            match = SYSCALL_PATTERN.match(line)
            if match is None:
                signal = SIGNAL_PATTERN.match(line)
                if signal is not None:
                    parsed += 1
                    signals += 1
                    events[("signal", signal.group("name"))] += 1
                    continue
                process_exit = EXIT_PATTERN.match(line)
                if process_exit is not None:
                    parsed += 1
                    exits += 1
                    events[("process-exit", process_exit.group("status"))] += 1
                    continue
                unparsed += 1
                continue
            parsed += 1
            syscalls += 1
            name = match.group("name")
            arguments = match.group("args")
            result = match.group("result")
            outcome = "failed" if result.startswith("-1 ") else "success"
            events[("syscall", name, outcome)] += 1
            process = process_event(name, arguments, outcome)
            if process:
                events[process] += 1
            file_event = observed_file_event(name, arguments, outcome)
            if file_event:
                events[file_event] += 1
            network = network_event(name, arguments, outcome)
            if network:
                events[network] += 1

    coverage_recorded = bool(raw_files) and parsed > 0 and unparsed == 0
    return {
        "schema_version": 1,
        "collector": {
            "name": "strace",
            "version": collector_version or strace_version(),
            "platform": "linux",
            "mode": "follow-forks-full-syscall",
        },
        "coverage": {
            "process": coverage_recorded,
            "file": coverage_recorded,
            "network": coverage_recorded,
            "syscall": coverage_recorded,
        },
        "coverage_basis": (
            "complete-parser-pass" if coverage_recorded else "insufficient-parser-pass"
        ),
        "raw_file_count": len(raw_files),
        "parsed_line_count": parsed,
        "syscall_line_count": syscalls,
        "signal_line_count": signals,
        "exit_line_count": exits,
        "unparsed_line_count": unparsed,
        "events": [event_from_key(key, count) for key, count in sorted(events.items())],
    }


def process_event(name: str, arguments: str, outcome: str) -> tuple[str, ...] | None:
    if name not in {"execve", "execveat"}:
        return None
    values = quoted_values(arguments)
    executable = values[0] if values else "unknown"
    return ("process", executable, outcome)


def observed_file_event(
    name: str, arguments: str, outcome: str
) -> tuple[str, ...] | None:
    operation = FILE_OPERATIONS.get(name)
    if operation is None:
        return None
    values = quoted_values(arguments)
    if not values:
        return None
    path = values[0]
    if name in {"open", "openat", "openat2"} and any(
        flag in arguments for flag in WRITE_FLAGS
    ):
        operation = "write"
    return ("file", operation, path, outcome)


def network_event(name: str, arguments: str, outcome: str) -> tuple[str, ...] | None:
    if name not in NETWORK_OPERATIONS or "AF_UNIX" in arguments:
        return None
    host = "unknown"
    port = ""
    ipv4 = re.search(r'inet_addr\("([^"]+)"\)', arguments)
    ipv6 = re.search(r'inet_pton\(AF_INET6, "([^"]+)"', arguments)
    port_match = re.search(r"sin6?_port=htons\(([0-9]+)\)", arguments)
    if ipv4:
        host = ipv4.group(1)
    elif ipv6:
        host = ipv6.group(1)
    if port_match:
        port = port_match.group(1)
    return ("network", name, host, port, outcome)


def event_from_key(key: tuple[str, ...], count: int) -> dict[str, Any]:
    kind = key[0]
    if kind == "syscall":
        return {"kind": kind, "name": key[1], "outcome": key[2], "count": count}
    if kind == "process":
        return {
            "kind": kind,
            "exe": key[1],
            "argv": [key[1]],
            "outcome": key[2],
            "count": count,
        }
    if kind == "signal":
        return {"kind": kind, "name": key[1], "count": count}
    if kind == "process-exit":
        return {"kind": kind, "status": key[1], "count": count}
    if kind == "file":
        return {
            "kind": kind,
            "operation": key[1],
            "path": key[2],
            "outcome": key[3],
            "count": count,
        }
    return {
        "kind": kind,
        "operation": key[1],
        "host": key[2],
        "port": int(key[3]) if key[3] else "",
        "protocol": "tcp",
        "outcome": key[4],
        "count": count,
    }


def quoted_values(value: str) -> list[str]:
    values = []
    for match in QUOTED_PATTERN.finditer(value):
        encoded = f'"{match.group(1)}"'
        try:
            values.append(json.loads(encoded))
        except json.JSONDecodeError:
            values.append(match.group(1))
    return values


def tool_versions() -> dict[str, str]:
    names = ("build", "packaging", "pbr", "pyproject-hooks", "setuptools", "wheel")
    return {name: importlib.metadata.version(name) for name in names}


def strace_version() -> str:
    result = subprocess.run(
        ["/usr/bin/strace", "--version"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    )
    return result.stdout.splitlines()[0].removeprefix("strace -- version ").strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def utc_now() -> str:
    return (
        dt.datetime.now(dt.UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuilderError as error:
        print(f"builder refused input: {error}", file=sys.stderr)
        raise SystemExit(2) from error
