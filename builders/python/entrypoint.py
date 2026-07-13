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
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


PROFILE_ID = "python-wheel-v1"
INPUT_ROOT = Path("/input")
WORK_ROOT = Path("/workspace/source")
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
NETWORK_OPERATIONS = {"accept", "accept4", "bind", "connect", "listen", "recvfrom", "sendto"}
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
MAX_ARTIFACTS = 128
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024


class BuilderError(RuntimeError):
    pass


def main() -> int:
    if len(sys.argv) != 1:
        raise BuilderError("python-wheel-v1 does not accept command arguments")

    metadata = load_metadata(os.environ)
    prepare_directories()
    copy_source()
    source_inventory = inventory_tree(WORK_ROOT)
    write_json(OUTPUT_ROOT / "reports" / "source-inventory.json", source_inventory)

    started_at = utc_now()
    command = [
        "/usr/bin/strace",
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
        str(OUTPUT_ROOT / "dist"),
        str(WORK_ROOT),
    ]
    completed = subprocess.run(
        command,
        cwd=WORK_ROOT,
        env=build_environment(metadata),
        check=False,
    )

    trace = parse_strace_directory(OUTPUT_ROOT / "traces" / "raw")
    write_json(OUTPUT_ROOT / "traces" / "observed-trace.json", trace)

    artifact_inventory: dict[str, Any]
    validation_error: str | None = None
    try:
        artifact_inventory = inventory_artifacts(OUTPUT_ROOT / "dist")
    except BuilderError as exc:
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
            "This report is a builder declaration. Container isolation, source "
            "lineage, and builder identity require independent verification."
        ),
    }
    write_json(OUTPUT_ROOT / "reports" / "builder.json", report)
    return 0 if succeeded else (completed.returncode or 2)


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
    if not INPUT_ROOT.is_dir():
        raise BuilderError("/input must be a source directory")
    if any(OUTPUT_ROOT.iterdir()):
        raise BuilderError("/out must be empty at builder start")
    for path in (
        WORK_ROOT.parent,
        OUTPUT_ROOT / "dist",
        OUTPUT_ROOT / "reports",
        OUTPUT_ROOT / "traces" / "raw",
        Path("/tmp/home"),
    ):
        path.mkdir(parents=True, exist_ok=True)


def copy_source() -> None:
    shutil.copytree(
        INPUT_ROOT,
        WORK_ROOT,
        symlinks=True,
        ignore=shutil.ignore_patterns(".git"),
    )


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


def inventory_artifacts(root: Path) -> dict[str, Any]:
    artifacts: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode) or stat.S_ISLNK(mode):
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


def observed_file_event(name: str, arguments: str, outcome: str) -> tuple[str, ...] | None:
    operation = FILE_OPERATIONS.get(name)
    if operation is None:
        return None
    values = quoted_values(arguments)
    if not values:
        return None
    path = values[0]
    if name in {"open", "openat", "openat2"} and any(flag in arguments for flag in WRITE_FLAGS):
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
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuilderError as error:
        print(f"builder refused input: {error}", file=sys.stderr)
        raise SystemExit(2) from error
