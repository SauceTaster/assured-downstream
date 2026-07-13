from __future__ import annotations

import collections
import datetime as dt
import gzip
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any


PROFILE_ID = "python-wheel-v3"
CANONICALIZATION_POLICY_ID = "python-sdist-pax-v1"
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
MAX_ARCHIVE_STREAM_BYTES = MAX_TOTAL_ARTIFACT_BYTES + 64 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_PATH_BYTES = 4096
MAX_ARCHIVE_SEGMENT_BYTES = 255
MAX_PAX_HEADERS = 16
MAX_PAX_BYTES = 64 * 1024
MIN_MEMBER_MTIME = -(2**63)
MAX_MEMBER_MTIME = 2**63 - 1
MIN_SOURCE_DATE_EPOCH = 1
MAX_SOURCE_DATE_EPOCH = 0xFFFFFFFF
COPY_CHUNK_SIZE = 1024 * 1024


class BuilderError(RuntimeError):
    pass


class StrictTarInfo(tarfile.TarInfo):
    """Reject archive extensions before tarfile can consume unbounded bodies."""

    @classmethod
    def fromtarfile(cls, archive: tarfile.TarFile) -> tarfile.TarInfo:
        header = archive.fileobj.read(tarfile.BLOCKSIZE)
        if not header:
            raise BuilderError("sdist is missing the tar end marker")
        if len(header) != tarfile.BLOCKSIZE:
            raise BuilderError("sdist tar header is truncated")
        if not any(header):
            setattr(archive, "_assured_end_marker_seen", True)
            return cls.frombuf(header, archive.encoding, archive.errors)
        try:
            member = cls.frombuf(header, archive.encoding, archive.errors)
        except tarfile.HeaderError as exc:
            raise BuilderError("sdist tar header is malformed") from exc
        member.offset = archive.fileobj.tell() - tarfile.BLOCKSIZE
        return member._proc_member(archive)

    def _proc_member(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
        if self.type in {
            tarfile.GNUTYPE_LONGNAME,
            tarfile.GNUTYPE_LONGLINK,
            tarfile.GNUTYPE_SPARSE,
        }:
            raise BuilderError("sdist GNU extension members are forbidden")
        if self.type in {tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE}:
            raise BuilderError("sdist global or Solaris PAX headers are forbidden")
        if self.type == tarfile.XHDTYPE:
            return self._proc_pax(archive)
        return super()._proc_member(archive)

    def _proc_pax(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
        if getattr(archive, "_assured_parsing_pax", False):
            raise BuilderError("sdist chained PAX headers are forbidden")
        if self.size <= 0 or self.size > MAX_PAX_BYTES:
            raise BuilderError("sdist PAX record exceeds the pre-parse size limit")

        padded_size = (self.size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE
        padded_size *= tarfile.BLOCKSIZE
        body = read_exact_archive_bytes(archive.fileobj, padded_size)
        if any(body[self.size :]):
            raise BuilderError("sdist PAX padding is not zero-filled")
        headers = parse_pax_records(body[: self.size])

        setattr(archive, "_assured_parsing_pax", True)
        try:
            try:
                header = read_exact_archive_bytes(archive.fileobj, tarfile.BLOCKSIZE)
                private_frombuf = getattr(self.__class__, "_frombuf", None)
                if private_frombuf is None:
                    next_member = self.__class__.frombuf(
                        header,
                        archive.encoding,
                        archive.errors,
                    )
                else:
                    next_member = private_frombuf(
                        header,
                        archive.encoding,
                        archive.errors,
                        dircheck=False,
                    )
                next_member.offset = archive.fileobj.tell() - tarfile.BLOCKSIZE
                next_member = next_member._proc_member(archive)
            except tarfile.HeaderError as exc:
                raise tarfile.SubsequentHeaderError(str(exc)) from None
        finally:
            delattr(archive, "_assured_parsing_pax")

        if "path" in headers:
            next_member.name = headers["path"]
        if "mtime" in headers:
            next_member.mtime = parse_pax_mtime(headers["mtime"])
        next_member.pax_headers = headers.copy()
        next_member.offset = self.offset
        return next_member


class BoundedReader:
    def __init__(self, handle: Any, *, limit: int) -> None:
        self.handle = handle
        self.limit = limit
        self.total = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self.limit - self.total
        requested = remaining + 1 if size < 0 else min(size, remaining + 1)
        payload = self.handle.read(requested)
        self.total += len(payload)
        if self.total > self.limit:
            raise BuilderError("sdist exceeds the uncompressed stream limit")
        return payload


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
    transform_report: dict[str, Any] = {
        "schema_version": 1,
        "status": "not-run",
        "policy": canonicalization_policy(metadata["source_date_epoch"]),
        "artifacts": [],
        "error": None,
    }
    validation_error: str | None = None
    try:
        identity_boundary = verify_identity_boundary(
            OUTPUT_ROOT,
            build_output_root=BUILD_OUTPUT_ROOT,
        )
        identity_boundary.update(quiescence)
        if completed.returncode != 0:
            raise BuilderError("build failed before artifact canonicalization")
        snapshot_artifacts(
            BUILD_DIST_ROOT,
            OUTPUT_ROOT / "raw-artifacts",
            expected_source_uid=BUILD_UID,
            expected_source_gid=0,
            expected_target_uid=0,
            expected_target_gid=0,
        )
        transform_report = canonicalize_build_artifacts(
            OUTPUT_ROOT / "raw-artifacts",
            OUTPUT_ROOT / "dist",
            source_date_epoch=int(metadata["source_date_epoch"]),
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
        if transform_report["status"] != "succeeded":
            transform_report = {
                **transform_report,
                "status": "failed",
                "error": validation_error,
            }
    transform_report_path = OUTPUT_ROOT / "reports" / "artifact-transforms.json"
    write_json(transform_report_path, transform_report)
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
        "artifact_transforms": {
            "policy_id": CANONICALIZATION_POLICY_ID,
            "report_path": "reports/artifact-transforms.json",
            "report_sha256": sha256_file(transform_report_path),
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
    validate_source_date_epoch(int(values["source_date_epoch"]))
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


def validate_source_date_epoch(value: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not MIN_SOURCE_DATE_EPOCH <= value <= MAX_SOURCE_DATE_EPOCH
    ):
        raise BuilderError(
            "SOURCE_DATE_EPOCH must fit the positive 32-bit gzip timestamp range"
        )
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
        OUTPUT_ROOT / "raw-artifacts",
        OUTPUT_ROOT / "reports",
        OUTPUT_ROOT / "traces" / "raw",
        Path("/tmp/home"),
    ):
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    for path in (
        OUTPUT_ROOT,
        OUTPUT_ROOT / "dist",
        OUTPUT_ROOT / "raw-artifacts",
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


def canonicalization_policy(source_date_epoch: str | int) -> dict[str, Any]:
    return {
        "id": CANONICALIZATION_POLICY_ID,
        "source_date_epoch": str(source_date_epoch),
        "archive_format": "posix-pax",
        "member_order": "utf8-byte-order",
        "tar_padding": "zero-filled-members-and-two-block-end-marker",
        "accepted_sdist_layouts": ["modern-pyproject", "legacy-setup-py"],
        "artifact_namespace": "flat-casefold-unique",
        "member_metadata": {
            "uid": 0,
            "gid": 0,
            "uname": "",
            "gname": "",
            "mtime": str(source_date_epoch),
            "file_modes": ["0644", "0755"],
            "directory_mode": "0755",
        },
        "gzip": {
            "compression_level": 9,
            "filename": "",
            "flags": 0,
            "mtime": str(source_date_epoch),
            "xfl": 2,
            "os": 255,
        },
        "limits": {
            "compressed_bytes": MAX_ARTIFACT_BYTES,
            "artifact_total_bytes": MAX_TOTAL_ARTIFACT_BYTES,
            "uncompressed_stream_bytes": MAX_ARCHIVE_STREAM_BYTES,
            "payload_bytes": MAX_TOTAL_ARTIFACT_BYTES,
            "members": MAX_ARCHIVE_MEMBERS,
            "path_bytes": MAX_ARCHIVE_PATH_BYTES,
            "path_segment_bytes": MAX_ARCHIVE_SEGMENT_BYTES,
            "pax_headers_per_member": MAX_PAX_HEADERS,
            "pax_bytes_per_member": MAX_PAX_BYTES,
            "source_date_epoch_min": MIN_SOURCE_DATE_EPOCH,
            "source_date_epoch_max": MAX_SOURCE_DATE_EPOCH,
        },
    }


def canonicalize_build_artifacts(
    source_root: Path,
    target_root: Path,
    *,
    source_date_epoch: int,
) -> dict[str, Any]:
    validate_source_date_epoch(source_date_epoch)
    validate_artifact_directory(
        source_root,
        label="raw artifact root",
        expected_uid=0,
        expected_gid=0,
    )
    validate_artifact_directory(
        target_root,
        label="canonical artifact root",
        expected_uid=0,
        expected_gid=0,
    )
    if any(target_root.iterdir()):
        raise BuilderError("canonical artifact destination must start empty")

    artifacts: list[dict[str, Any]] = []
    file_count = 0
    total_bytes = 0
    final_total_bytes = 0
    wheel_count = 0
    sdist_count = 0
    artifact_names: set[str] = set()
    folded_artifact_names: set[str] = set()
    for directory, directory_names, file_names in os.walk(
        source_root,
        topdown=True,
        followlinks=False,
    ):
        directory_path = Path(directory)
        directory_names.sort(key=lambda value: value.encode("utf-8"))
        file_names.sort(key=lambda value: value.encode("utf-8"))
        if directory_path != source_root or directory_names:
            raise BuilderError("raw release artifact output must be flat")
        for name in file_names:
            source = directory_path / name
            relative = source.relative_to(source_root)
            register_artifact_path(
                relative,
                names=artifact_names,
                folded_names=folded_artifact_names,
            )
            target = target_root / relative
            metadata = source.lstat()
            file_count += 1
            if file_count > MAX_ARTIFACTS:
                raise BuilderError("builder produced too many release artifacts")
            if (
                not stat.S_ISREG(metadata.st_mode)
                or source.is_symlink()
                or metadata.st_nlink != 1
                or metadata.st_uid != 0
                or metadata.st_gid != 0
            ):
                raise BuilderError(
                    f"raw artifact is not a protected regular file: {relative}"
                )
            if metadata.st_size > MAX_ARTIFACT_BYTES:
                raise BuilderError(f"raw artifact exceeds size limit: {relative}")
            total_bytes += metadata.st_size
            if total_bytes > MAX_TOTAL_ARTIFACT_BYTES:
                raise BuilderError("raw artifacts exceed the total size limit")

            original = {
                "path": f"raw-artifacts/{relative.as_posix()}",
                "size": metadata.st_size,
                "sha256": sha256_file(source),
            }
            if relative.name.endswith(".tar.gz"):
                result = canonicalize_sdist(
                    source,
                    target,
                    source_date_epoch=source_date_epoch,
                )
                format_name = "python-sdist-tar-gzip"
                sdist_count += 1
            else:
                snapshot_regular_artifact(source, target, expected=metadata)
                result = {
                    "member_count": None,
                    "payload_size": metadata.st_size,
                    "payload_sha256": original["sha256"],
                    "sdist_layout": None,
                }
                format_name = "pass-through"
                if relative.name.endswith(".whl"):
                    wheel_count += 1
            final_size = target.stat().st_size
            if final_size > MAX_ARTIFACT_BYTES:
                raise BuilderError(f"canonical artifact exceeds size limit: {relative}")
            final_total_bytes += final_size
            if final_total_bytes > MAX_TOTAL_ARTIFACT_BYTES:
                raise BuilderError("canonical artifacts exceed the total size limit")
            final = {
                "path": f"dist/{relative.as_posix()}",
                "size": final_size,
                "sha256": sha256_file(target),
            }
            artifacts.append(
                {
                    "path": relative.as_posix(),
                    "format": format_name,
                    "changed": original["sha256"] != final["sha256"],
                    "original": original,
                    "final": final,
                    "member_count": result["member_count"],
                    "payload_size": result["payload_size"],
                    "payload_sha256": result["payload_sha256"],
                    "sdist_layout": result["sdist_layout"],
                }
            )

    if file_count == 0:
        raise BuilderError("builder produced no release artifacts")
    if wheel_count == 0 or sdist_count == 0:
        raise BuilderError("v3 requires at least one wheel and one source distribution")
    return {
        "schema_version": 1,
        "status": "succeeded",
        "policy": canonicalization_policy(source_date_epoch),
        "artifacts": artifacts,
        "error": None,
    }


def canonicalize_sdist(
    source: Path,
    target: Path,
    *,
    source_date_epoch: int,
) -> dict[str, Any]:
    validate_source_date_epoch(source_date_epoch)
    temporary_path: Path | None = None
    with tempfile.TemporaryDirectory(
        prefix=".assured-sdist-",
        dir=target.parent,
    ) as temporary:
        staging_root = Path(temporary)
        inspection = read_sdist_records(source, staging_root=staging_root)
        expected_root = source.name.removesuffix(".tar.gz")
        if inspection["root"] != expected_root:
            raise BuilderError("sdist root directory does not match its filename")
        temporary_path = staging_root / "canonical.tar.gz"
        write_canonical_sdist(
            temporary_path,
            inspection["records"],
            source_date_epoch=source_date_epoch,
        )
        if temporary_path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise BuilderError("canonical sdist exceeds the compressed size limit")
        verification_root = staging_root / "verify"
        verification_root.mkdir(mode=0o700)
        verification = read_sdist_records(
            temporary_path,
            staging_root=verification_root,
        )
        if (
            verification["payload_sha256"] != inspection["payload_sha256"]
            or verification["payload_size"] != inspection["payload_size"]
            or verification["member_count"] != inspection["member_count"]
            or verification["root"] != inspection["root"]
            or verification["sdist_layout"] != inspection["sdist_layout"]
        ):
            raise BuilderError("canonical sdist changed archive payload semantics")
        expected_metadata = {
            "uid": [0],
            "gid": [0],
            "uname": [""],
            "gname": [""],
            "mtime": [source_date_epoch],
        }
        if verification["metadata"] != expected_metadata:
            raise BuilderError("canonical sdist metadata is not exact")
        header = verification["gzip"]
        if header != {
            "flags": 0,
            "mtime": source_date_epoch,
            "xfl": 2,
            "os": 255,
        }:
            raise BuilderError("canonical gzip header is not exact")
        os.replace(temporary_path, target)
        target.chmod(0o400)
    return {
        "member_count": inspection["member_count"],
        "payload_size": inspection["payload_size"],
        "payload_sha256": inspection["payload_sha256"],
        "sdist_layout": inspection["sdist_layout"],
    }


def read_sdist_records(path: Path, *, staging_root: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_nlink != 1
        or metadata.st_size > MAX_ARTIFACT_BYTES
    ):
        raise BuilderError("sdist is not a bounded standalone regular file")
    gzip_metadata = read_gzip_header(path)
    records: list[dict[str, Any]] = []
    all_paths: set[str] = set()
    folded_paths: set[str] = set()
    file_paths: set[str] = set()
    parent_paths: set[str] = set()
    folded_file_paths: set[str] = set()
    folded_parent_paths: set[str] = set()
    payload_size = 0
    try:
        with path.open("rb") as raw_handle:
            with gzip.GzipFile(fileobj=raw_handle, mode="rb") as gzip_handle:
                bounded = BoundedReader(gzip_handle, limit=MAX_ARCHIVE_STREAM_BYTES)
                with tarfile.open(
                    fileobj=bounded,
                    mode="r|",
                    tarinfo=StrictTarInfo,
                    encoding="utf-8",
                    errors="strict",
                    errorlevel=2,
                ) as archive:
                    for position, member in enumerate(archive, start=1):
                        if position > MAX_ARCHIVE_MEMBERS:
                            raise BuilderError("sdist exceeds the member count limit")
                        if member.issparse():
                            raise BuilderError("sdist sparse members are forbidden")
                        if not (member.isfile() or member.isdir()):
                            raise BuilderError(
                                "sdist links and special members are forbidden"
                            )
                        validate_pax_headers(member.pax_headers)
                        name = safe_archive_member_name(
                            member.name,
                            is_directory=member.isdir(),
                        )
                        folded = name.casefold()
                        if name in all_paths or folded in folded_paths:
                            raise BuilderError(
                                "sdist contains a duplicate or aliased path"
                            )
                        components = name.split("/")
                        prefixes = {
                            "/".join(components[:index])
                            for index in range(1, len(components))
                        }
                        folded_prefixes = {prefix.casefold() for prefix in prefixes}
                        if (
                            prefixes & file_paths
                            or folded_prefixes & folded_file_paths
                            or (
                                member.isfile()
                                and (
                                    name in parent_paths
                                    or folded in folded_parent_paths
                                )
                            )
                        ):
                            raise BuilderError(
                                "sdist contains a file/directory path collision"
                            )
                        all_paths.add(name)
                        folded_paths.add(folded)
                        parent_paths.update(prefixes)
                        folded_parent_paths.update(folded_prefixes)
                        if member.isfile():
                            file_paths.add(name)
                            folded_file_paths.add(folded)
                        mode = canonical_member_mode(member)
                        size = member.size
                        if size < 0 or size > MAX_ARTIFACT_BYTES:
                            raise BuilderError("sdist member size is invalid")
                        if member.isdir() and size != 0:
                            raise BuilderError("sdist directory has a nonzero size")
                        payload_size += size
                        if payload_size > MAX_TOTAL_ARTIFACT_BYTES:
                            raise BuilderError("sdist exceeds the payload size limit")
                        content_path: Path | None = None
                        content_sha256: str | None = None
                        if member.isfile():
                            content_path = staging_root / f"{position:06d}.payload"
                            extracted = archive.extractfile(member)
                            if extracted is None:
                                raise BuilderError("sdist member could not be read")
                            with extracted:
                                content_sha256 = copy_member_payload(
                                    extracted,
                                    content_path,
                                    expected_size=size,
                                )
                            padding_size = -size % tarfile.BLOCKSIZE
                            if padding_size and any(
                                read_exact_archive_bytes(
                                    archive.fileobj,
                                    padding_size,
                                )
                            ):
                                raise BuilderError(
                                    "sdist member padding is not zero-filled"
                                )
                        records.append(
                            {
                                "name": name,
                                "type": "file" if member.isfile() else "directory",
                                "mode": mode,
                                "size": size,
                                "sha256": content_sha256,
                                "content_path": content_path,
                                "metadata": {
                                    "uid": member.uid,
                                    "gid": member.gid,
                                    "uname": member.uname,
                                    "gname": member.gname,
                                    "mtime": validated_member_mtime(member.mtime),
                                },
                            }
                        )
                    if archive.pax_headers:
                        raise BuilderError("sdist global PAX headers are forbidden")
                    if not getattr(archive, "_assured_end_marker_seen", False):
                        raise BuilderError("sdist is missing the tar end marker")
                    trailing_size = 0
                    while trailing := archive.fileobj.read(COPY_CHUNK_SIZE):
                        trailing_size += len(trailing)
                        if any(trailing):
                            raise BuilderError(
                                "sdist contains nonzero trailing tar data"
                            )
                    if trailing_size < tarfile.BLOCKSIZE:
                        raise BuilderError("sdist is missing the second tar end marker")
    except (
        gzip.BadGzipFile,
        EOFError,
        OSError,
        OverflowError,
        UnicodeError,
        ValueError,
        tarfile.TarError,
    ) as exc:
        raise BuilderError("sdist gzip or tar structure is malformed") from exc

    if not records:
        raise BuilderError("sdist is empty")
    records.sort(key=lambda record: record["name"].encode("utf-8"))
    roots = {record["name"].split("/", 1)[0] for record in records}
    if len(roots) != 1:
        raise BuilderError("sdist must contain one top-level directory")
    root = next(iter(roots))
    actual_files = {record["name"] for record in records if record["type"] == "file"}
    if f"{root}/PKG-INFO" not in actual_files:
        raise BuilderError("sdist is missing PKG-INFO")
    if f"{root}/pyproject.toml" in actual_files:
        sdist_layout = "modern-pyproject"
    elif f"{root}/setup.py" in actual_files:
        sdist_layout = "legacy-setup-py"
    else:
        raise BuilderError("sdist has neither pyproject.toml nor legacy setup.py")
    identities = [record_identity(record) for record in records]
    return {
        "records": records,
        "root": root,
        "sdist_layout": sdist_layout,
        "member_count": len(records),
        "payload_size": payload_size,
        "payload_sha256": hashlib.sha256(
            json.dumps(
                identities,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        "metadata": {
            field: sorted({record["metadata"][field] for record in records})
            for field in ("uid", "gid", "uname", "gname", "mtime")
        },
        "gzip": gzip_metadata,
    }


def write_canonical_sdist(
    path: Path,
    records: list[dict[str, Any]],
    *,
    source_date_epoch: int,
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as raw_handle:
            with gzip.GzipFile(
                filename="",
                fileobj=raw_handle,
                mode="wb",
                compresslevel=9,
                mtime=source_date_epoch,
            ) as gzip_handle:
                with tarfile.open(
                    fileobj=gzip_handle,
                    mode="w",
                    format=tarfile.PAX_FORMAT,
                    encoding="utf-8",
                    errors="strict",
                ) as archive:
                    for record in records:
                        member = tarfile.TarInfo(record["name"])
                        member.type = (
                            tarfile.REGTYPE
                            if record["type"] == "file"
                            else tarfile.DIRTYPE
                        )
                        member.mode = record["mode"]
                        member.uid = 0
                        member.gid = 0
                        member.uname = ""
                        member.gname = ""
                        member.mtime = source_date_epoch
                        member.size = record["size"] if record["type"] == "file" else 0
                        member.pax_headers = {}
                        if record["type"] == "file":
                            with record["content_path"].open("rb") as content:
                                archive.addfile(member, content)
                        else:
                            archive.addfile(member)
            raw_handle.flush()
            os.fsync(raw_handle.fileno())
    finally:
        os.close(descriptor)


def copy_member_payload(handle: Any, target: Path, *, expected_size: int) -> str:
    digest = hashlib.sha256()
    copied = 0
    with target.open("xb") as output:
        while chunk := handle.read(COPY_CHUNK_SIZE):
            copied += len(chunk)
            if copied > expected_size:
                raise BuilderError("sdist member exceeds its declared size")
            digest.update(chunk)
            output.write(chunk)
        output.flush()
        os.fsync(output.fileno())
    if copied != expected_size:
        raise BuilderError("sdist member does not match its declared size")
    target.chmod(0o400)
    return digest.hexdigest()


def record_identity(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": record["name"],
        "type": record["type"],
        "mode": record["mode"],
        "size": record["size"],
        "sha256": record["sha256"],
    }


def canonical_member_mode(member: tarfile.TarInfo) -> int:
    if member.mode < 0 or member.mode & ~0o777:
        raise BuilderError("sdist member mode contains special bits")
    if member.isdir():
        return 0o755
    return 0o755 if member.mode & 0o111 else 0o644


def validate_pax_headers(headers: dict[str, str]) -> None:
    if len(headers) > MAX_PAX_HEADERS:
        raise BuilderError("sdist member has too many PAX headers")
    total = 0
    for key, value in headers.items():
        if key not in {"path", "mtime"}:
            raise BuilderError(f"sdist PAX header is unsupported: {key}")
        if not isinstance(value, str):
            raise BuilderError("sdist PAX header value is invalid")
        total += len(key.encode("utf-8")) + len(value.encode("utf-8"))
    if total > MAX_PAX_BYTES:
        raise BuilderError("sdist member PAX headers exceed the size limit")


def read_exact_archive_bytes(handle: Any, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = handle.read(min(remaining, COPY_CHUNK_SIZE))
        if not chunk:
            raise BuilderError("sdist extension body is truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def parse_pax_records(payload: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    position = 0
    while position < len(payload):
        space = payload.find(b" ", position, min(len(payload), position + 24))
        if space < 0:
            raise BuilderError("sdist PAX record length is malformed")
        length_bytes = payload[position:space]
        if (
            not length_bytes
            or not length_bytes.isdigit()
            or (len(length_bytes) > 1 and length_bytes.startswith(b"0"))
        ):
            raise BuilderError("sdist PAX record length is malformed")
        record_length = int(length_bytes)
        record_end = position + record_length
        if record_length < 5 or record_end > len(payload):
            raise BuilderError("sdist PAX record framing is malformed")
        record = payload[space + 1 : record_end]
        if not record.endswith(b"\n"):
            raise BuilderError("sdist PAX record terminator is malformed")
        raw_key, separator, raw_value = record[:-1].partition(b"=")
        if not raw_key or not separator or b"\x00" in raw_key or b"\x00" in raw_value:
            raise BuilderError("sdist PAX key/value framing is malformed")
        try:
            key = raw_key.decode("utf-8", "strict")
            value = raw_value.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise BuilderError("sdist PAX key/value is not UTF-8") from exc
        if key not in {"path", "mtime"}:
            raise BuilderError(f"sdist PAX header is unsupported: {key}")
        if key in headers:
            raise BuilderError("sdist PAX header is duplicated")
        headers[key] = value
        if len(headers) > MAX_PAX_HEADERS:
            raise BuilderError("sdist member has too many PAX headers")
        position = record_end
    if not headers:
        raise BuilderError("sdist PAX record is empty")
    return headers


def parse_pax_mtime(value: str) -> int:
    if len(value.encode("utf-8")) > 64 or not re.fullmatch(
        r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?",
        value,
    ):
        raise BuilderError("sdist PAX mtime is invalid")
    timestamp = int(value.partition(".")[0])
    if not MIN_MEMBER_MTIME <= timestamp <= MAX_MEMBER_MTIME:
        raise BuilderError("sdist PAX mtime is outside the accepted range")
    return timestamp


def validated_member_mtime(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BuilderError("sdist member mtime is invalid")
    if isinstance(value, float) and not math.isfinite(value):
        raise BuilderError("sdist member mtime is not finite")
    timestamp = int(value)
    if not MIN_MEMBER_MTIME <= timestamp <= MAX_MEMBER_MTIME:
        raise BuilderError("sdist member mtime is outside the accepted range")
    return timestamp


def safe_archive_member_name(value: str, *, is_directory: bool) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise BuilderError("sdist member path is invalid")
    candidate = value[:-1] if is_directory and value.endswith("/") else value
    if not candidate or candidate.endswith("/"):
        raise BuilderError("sdist member path is invalid")
    if unicodedata.normalize("NFC", candidate) != candidate:
        raise BuilderError("sdist member path is not Unicode NFC")
    if any(ord(character) < 32 or ord(character) == 127 for character in candidate):
        raise BuilderError("sdist member path contains control characters")
    components = candidate.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise BuilderError("sdist member path contains an alias or traversal")
    path = PurePosixPath(candidate)
    if path.is_absolute() or path.as_posix() != candidate:
        raise BuilderError("sdist member path is not canonical")
    if len(candidate.encode("utf-8")) > MAX_ARCHIVE_PATH_BYTES or any(
        len(component.encode("utf-8")) > MAX_ARCHIVE_SEGMENT_BYTES
        for component in components
    ):
        raise BuilderError("sdist member path exceeds the size limit")
    return candidate


def safe_artifact_path(path: Path, *, is_directory: bool) -> None:
    safe_archive_member_name(path.as_posix(), is_directory=is_directory)


def register_artifact_path(
    path: Path,
    *,
    names: set[str],
    folded_names: set[str],
) -> None:
    safe_artifact_path(path, is_directory=False)
    value = path.as_posix()
    folded = value.casefold()
    if value in names or folded in folded_names:
        raise BuilderError("release artifacts contain an aliased name")
    names.add(value)
    folded_names.add(folded)


def read_gzip_header(path: Path) -> dict[str, int]:
    with path.open("rb") as handle:
        header = handle.read(10)
    if len(header) != 10 or header[:3] != b"\x1f\x8b\x08":
        raise BuilderError("sdist has an invalid gzip header")
    flags = header[3]
    if flags & 0xE0:
        raise BuilderError("sdist gzip header uses reserved flags")
    return {
        "flags": flags,
        "mtime": int.from_bytes(header[4:8], "little", signed=False),
        "xfl": header[8],
        "os": header[9],
    }


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
    artifact_names: set[str] = set()
    folded_artifact_names: set[str] = set()
    for directory, directory_names, file_names in os.walk(
        source_root,
        topdown=True,
        followlinks=False,
    ):
        directory_path = Path(directory)
        directory_names.sort(key=lambda value: value.encode("utf-8"))
        file_names.sort(key=lambda value: value.encode("utf-8"))
        if directory_path != source_root or directory_names:
            raise BuilderError("release artifact output must be flat")
        for name in file_names:
            source = directory_path / name
            relative = source.relative_to(source_root)
            register_artifact_path(
                relative,
                names=artifact_names,
                folded_names=folded_artifact_names,
            )
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
    total_bytes = 0
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
        total_bytes += size
        if total_bytes > MAX_TOTAL_ARTIFACT_BYTES:
            raise BuilderError("artifacts exceed the total size limit")
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
