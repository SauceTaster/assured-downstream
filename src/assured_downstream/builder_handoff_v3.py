from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import os
import re
import stat
import tempfile
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

from assured_downstream.archive_validation_v3 import (
    ArchiveValidationError,
    validate_artifact_transforms as validate_archive_transforms,
)
from assured_downstream.evidence import (
    create_evidence_manifest,
    verify_evidence_manifest,
)


PROFILE_ID = "python-wheel-v3"
BUILDER_IMAGE = "ghcr.io/saucetaster/assured-downstream-python-builder"
BUILDER_DIGEST = (
    "sha256:5f52c4bfe05c4947877d6d80f2124062b79a46764cc2161dc4caaa631d65833a"
)
CUSTOM_PREDICATE_TYPE = "https://assured-downstream.dev/attestation/build/v2"
CANONICALIZATION_POLICY_ID = "python-sdist-pax-v1"
SPDX_NORMALIZATION_POLICY_ID = "spdx-2.3-syft-canonical-v1"
CALLER_WORKFLOW_PATH = ".github/workflows/case-study-bandit-build-v3.yml"
CALLED_WORKFLOW_PATH = ".github/workflows/reusable-python-build-v3.yml"
CONTROL_REPOSITORY = "SauceTaster/assured-downstream"
REQUIRED_ACTOR = "SauceTaster"
REQUIRED_EVENT = "workflow_dispatch"
REQUIRED_REF = "refs/heads/main"
BUILDER_SOURCE_DIGESTS = {
    "builders/python-v3/Dockerfile": "def67c917675090d4b147f1b89b6ce5bedeb803591fae8322adb70dac3db88a6",
    "builders/python-v3/entrypoint.py": "9601c51e015dd7b45cb4e78f62f4de6af98fdeff048f0c23af467ae5c27d6884",
    "builders/python-v3/requirements.lock": "6a060a27d9e1d93a78a969d67b7d5e7f9508b73b99c0332315f8646ae80fd2a6",
}
ACTION_PINS = {
    "actions/attest": "a1948c3f048ba23858d222213b7c278aabede763",
    "actions/checkout": "34e114876b0b11c390a56381ad16ebd13914f8d5",
    "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "anchore/sbom-action": "e22c389904149dbc22b58101806040fa8d37a610",
}
SAFE_PATH_PATTERN = re.compile(r"^[A-Za-z0-9._+/-]+$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
RAW_SYSCALL_PATTERN = re.compile(
    r"^(?P<timestamp>[0-9]+\.[0-9]+)\s+"
    r"(?P<name>[A-Za-z0-9_]+)\((?P<args>.*)\)\s+=\s+"
    r"(?P<result>.*?)(?:\s+<[0-9.]+>)?$"
)
RAW_SIGNAL_PATTERN = re.compile(
    r"^(?P<timestamp>[0-9]+\.[0-9]+)\s+---\s+"
    r"(?P<name>SIG[A-Z0-9]+)\s+\{.*\}\s+---$"
)
RAW_EXIT_PATTERN = re.compile(
    r"^(?P<timestamp>[0-9]+\.[0-9]+)\s+\+\+\+\s+"
    r"(?P<status>exited with [0-9]+|killed by SIG[A-Z0-9]+(?: \(core dumped\))?)"
    r"\s+\+\+\+$"
)
RAW_QUOTED_PATTERN = re.compile(r'"((?:[^"\\]|\\.)*)"')
RAW_TRACE_NAME_PATTERN = re.compile(r"^strace\.[0-9]+$")
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
MAX_FILES = 10_000
MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_SPDX_ITEMS = 100_000
MIN_SOURCE_DATE_EPOCH = 1
MAX_SOURCE_DATE_EPOCH = 4_294_967_295
BUILDER_CLAIM_LIMIT = (
    "This report declares a root-owned collector and evidence boundary. "
    "Container isolation, source lineage, and resistance to collector "
    "exploitation still require independent verification."
)
EXPECTED_TRACE_ARGV = [
    "/usr/bin/strace",
    "-u",
    "assured",
    "-ff",
    "-qq",
    "-ttt",
    "-T",
    "-yy",
    "-s",
    "4096",
    "-o",
    "/out/traces/raw/strace",
    "--",
    "/usr/local/bin/python",
    "-I",
    "-m",
    "build",
    "--no-isolation",
    "--outdir",
    "/workspace/output/dist",
    "/workspace/source",
]


class BuilderHandoffError(RuntimeError):
    pass


def validate_builder_output(
    root: Path,
    *,
    source_repository: str,
    source_commit: str,
    source_tree: str,
    project_version: str,
    require_sbom: bool = False,
    require_attestations: bool = False,
) -> dict[str, Any]:
    root = require_regular_root(root)
    validate_identity(source_repository, source_commit, source_tree)
    validate_regular_tree(root)

    builder_report = read_json(root / "reports" / "builder.json")
    if set(builder_report) != {
        "artifact_transforms",
        "builder",
        "claim_limit",
        "execution",
        "profile",
        "schema_version",
        "source",
        "status",
        "trace",
    }:
        raise BuilderHandoffError("builder report fields are not exact")
    expected_report = {
        "schema_version": 1,
        "status": "succeeded",
        "profile": PROFILE_ID,
    }
    for field, expected in expected_report.items():
        if builder_report.get(field) != expected or type(
            builder_report.get(field)
        ) is not type(expected):
            raise BuilderHandoffError(
                f"builder report {field} does not match the fixed profile"
            )
    if builder_report.get("claim_limit") != BUILDER_CLAIM_LIMIT:
        raise BuilderHandoffError("builder report claim boundary is not exact")
    builder = require_mapping(builder_report.get("builder"), "builder identity")
    expected_tools = {
        "build": "1.5.1",
        "packaging": "26.2",
        "pbr": "7.0.3",
        "pyproject-hooks": "1.2.0",
        "setuptools": "83.0.0",
        "wheel": "0.47.0",
    }
    if (
        set(builder) != {"architecture", "image", "image_digest", "python", "tools"}
        or builder.get("image") != BUILDER_IMAGE
        or builder.get("image_digest") != BUILDER_DIGEST
        or builder.get("architecture") != "x86_64"
        or builder.get("python") != "3.12.11"
        or builder.get("tools") != expected_tools
    ):
        raise BuilderHandoffError("builder report image identity is not approved")
    source = require_mapping(builder_report.get("source"), "builder source")
    if set(source) != {
        "commit",
        "filesystem_sha256",
        "git_tree",
        "project_version",
        "repository",
        "source_date_epoch",
    }:
        raise BuilderHandoffError("builder source fields are not exact")
    expected_source = {
        "repository": source_repository,
        "commit": source_commit,
        "git_tree": source_tree,
        "project_version": project_version,
    }
    for field, expected in expected_source.items():
        if source.get(field) != expected:
            raise BuilderHandoffError(
                f"builder report source {field} does not match the request"
            )
    if (
        not isinstance(source.get("source_date_epoch"), str)
        or not source["source_date_epoch"].isdigit()
        or str(int(source["source_date_epoch"])) != source["source_date_epoch"]
        or not MIN_SOURCE_DATE_EPOCH
        <= int(source["source_date_epoch"])
        <= MAX_SOURCE_DATE_EPOCH
        or not isinstance(source.get("filesystem_sha256"), str)
        or SHA256_PATTERN.fullmatch(source["filesystem_sha256"]) is None
    ):
        raise BuilderHandoffError("builder source snapshot identity is invalid")
    source_inventory = read_json(root / "reports" / "source-inventory.json")
    source_inventory_sha256 = validate_source_inventory(source_inventory)
    if source["filesystem_sha256"] != source_inventory_sha256:
        raise BuilderHandoffError("builder source inventory digest is inconsistent")
    trusted_source_path = root / "reports" / "trusted-source-inventory.json"
    trusted_source = read_json(trusted_source_path)
    validate_trusted_source_binding(
        trusted_source,
        source_repository=source_repository,
        source_commit=source_commit,
        source_tree=source_tree,
        source_inventory=source_inventory,
    )
    validate_handoff_seal(
        read_json(root / "reports" / "handoff-seal.json"),
        root=root,
        source_repository=source_repository,
        source_commit=source_commit,
        source_tree=source_tree,
        trusted_source_sha256=sha256_file(trusted_source_path),
    )
    execution = require_mapping(builder_report.get("execution"), "builder execution")
    if (
        set(execution)
        != {
            "argv",
            "cwd",
            "finished_at",
            "identity_boundary",
            "network_policy",
            "returncode",
            "started_at",
            "validation_error",
        }
        or execution.get("network_policy") != "deny"
        or type(execution.get("returncode")) is not int
        or execution["returncode"] != 0
        or execution.get("validation_error") is not None
        or not isinstance(execution.get("started_at"), str)
        or not execution["started_at"]
        or not isinstance(execution.get("finished_at"), str)
        or not execution["finished_at"]
    ):
        raise BuilderHandoffError("builder execution did not fail closed")
    validate_execution_boundary(execution)

    inventory = read_json(root / "reports" / "artifact-inventory.json")
    actual_artifacts = artifact_entries(root)
    recorded_artifacts = inventory.get("artifacts")
    if (
        set(inventory) != {"artifacts", "schema_version"}
        or type(inventory.get("schema_version")) is not int
        or inventory["schema_version"] != 1
        or not isinstance(recorded_artifacts, list)
        or recorded_artifacts != actual_artifacts
    ):
        raise BuilderHandoffError(
            "artifact inventory does not exactly match the retained artifacts"
        )

    transform_path = root / "reports" / "artifact-transforms.json"
    transform = read_json(transform_path)
    transform_pointer = require_mapping(
        builder_report.get("artifact_transforms"),
        "builder artifact transforms",
    )
    if transform_pointer != {
        "policy_id": CANONICALIZATION_POLICY_ID,
        "report_path": "reports/artifact-transforms.json",
        "report_sha256": sha256_file(transform_path),
    }:
        raise BuilderHandoffError("builder transform report pointer is invalid")
    validate_artifact_transforms(
        root,
        transform,
        expected_artifacts=actual_artifacts,
        source_date_epoch=source["source_date_epoch"],
    )

    trace = read_json(root / "traces" / "observed-trace.json")
    validate_trace(trace)
    validate_raw_trace_files(root / "traces" / "raw", trace=trace)
    reported_trace = require_mapping(
        builder_report.get("trace"),
        "builder trace summary",
    )
    trace_count_fields = {
        "exit_line_count",
        "parsed_line_count",
        "raw_file_count",
        "signal_line_count",
        "syscall_line_count",
        "unparsed_line_count",
    }
    if (
        set(reported_trace)
        != {
            "collector",
            "coverage",
            "exit_line_count",
            "parsed_line_count",
            "raw_file_count",
            "signal_line_count",
            "syscall_line_count",
            "unparsed_line_count",
        }
        or any(
            type(reported_trace.get(field)) is not int for field in trace_count_fields
        )
        or reported_trace.get("collector") != trace["collector"]
        or reported_trace.get("coverage") != trace["coverage"]
        or reported_trace.get("raw_file_count") != trace["raw_file_count"]
        or reported_trace.get("parsed_line_count") != trace["parsed_line_count"]
        or reported_trace.get("syscall_line_count") != trace["syscall_line_count"]
        or reported_trace.get("signal_line_count") != trace["signal_line_count"]
        or reported_trace.get("exit_line_count") != trace["exit_line_count"]
        or reported_trace.get("unparsed_line_count") != trace["unparsed_line_count"]
    ):
        raise BuilderHandoffError(
            "builder trace summary does not match the retained trace"
        )
    if require_sbom:
        validate_spdx_bundle(
            root,
            expected_artifacts=actual_artifacts,
            source_repository=source_repository,
            source_commit=source_commit,
            source_tree=source_tree,
            project_version=project_version,
            source_date_epoch=source["source_date_epoch"],
        )
    if require_attestations:
        names = sorted(
            path.name for path in (root / "attestations").glob("*.sigstore.json")
        )
        if names != [
            "build.sigstore.json",
            "provenance.sigstore.json",
            "sbom.sigstore.json",
        ]:
            raise BuilderHandoffError(
                "retained attestation bundle set is incomplete or ambiguous"
            )
    return {
        "builder_report": builder_report,
        "artifact_inventory": inventory,
        "artifact_transforms": transform,
        "source_inventory": source_inventory,
        "trusted_source_inventory": trusted_source,
        "trace": trace,
    }


def validate_execution_boundary(execution: dict[str, Any]) -> None:
    if (
        execution.get("argv") != EXPECTED_TRACE_ARGV
        or execution.get("cwd") != "/workspace/source"
    ):
        raise BuilderHandoffError("builder execution argv is not the fixed v3 profile")
    boundary = require_mapping(
        execution.get("identity_boundary"),
        "builder identity boundary",
    )
    expected_fields = {
        "build_gid",
        "build_uid",
        "collector_gid",
        "collector_output_writable_by_build",
        "collector_uid",
        "evidence_gid",
        "evidence_mode",
        "evidence_uid",
        "killed_process_count",
        "quiescence_barrier",
        "raw_trace_owner_gid",
        "raw_trace_owner_uid",
        "remaining_process_count",
        "separate_collector_identity",
    }
    if set(boundary) != expected_fields:
        raise BuilderHandoffError("builder identity boundary fields are not exact")
    expected_values = {
        "build_gid": 65532,
        "build_uid": 65532,
        "collector_gid": 0,
        "collector_output_writable_by_build": False,
        "collector_uid": 0,
        "evidence_gid": 0,
        "evidence_mode": "0700",
        "evidence_uid": 0,
        "quiescence_barrier": "private-pid-namespace-sigkill",
        "raw_trace_owner_gid": 0,
        "raw_trace_owner_uid": 0,
        "remaining_process_count": 0,
        "separate_collector_identity": True,
    }
    if any(
        boundary.get(field) != expected
        or type(boundary.get(field)) is not type(expected)
        for field, expected in expected_values.items()
    ):
        raise BuilderHandoffError(
            "builder identity boundary is not the fixed v3 profile"
        )
    killed_process_count = boundary.get("killed_process_count")
    if (
        not isinstance(killed_process_count, int)
        or isinstance(killed_process_count, bool)
        or killed_process_count < 0
    ):
        raise BuilderHandoffError("builder killed process count is invalid")


def validate_source_inventory(value: dict[str, Any]) -> str:
    if set(value) != {"entries", "schema_version", "tree_sha256"}:
        raise BuilderHandoffError("source inventory fields are not exact")
    entries = value.get("entries")
    if (
        type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or not isinstance(entries, list)
        or not entries
        or len(entries) > 100_000
    ):
        raise BuilderHandoffError("source inventory is invalid")
    paths: list[str] = []
    folded_paths: set[str] = set()
    total_size = 0
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("type") not in {"file", "symlink"}:
            raise BuilderHandoffError("source inventory entry is invalid")
        path = safe_spdx_path(entry.get("path"))
        if path.casefold() in folded_paths:
            raise BuilderHandoffError("source inventory contains a path alias")
        folded_paths.add(path.casefold())
        paths.append(path)
        if entry["type"] == "file":
            if (
                set(entry) != {"executable", "path", "sha256", "size", "type"}
                or type(entry.get("executable")) is not bool
                or type(entry.get("size")) is not int
                or entry["size"] < 0
                or entry["size"] > MAX_FILE_BYTES
                or not isinstance(entry.get("sha256"), str)
                or SHA256_PATTERN.fullmatch(entry["sha256"]) is None
            ):
                raise BuilderHandoffError("source file inventory entry is invalid")
            total_size += entry["size"]
            if total_size > MAX_TOTAL_BYTES:
                raise BuilderHandoffError("source inventory exceeds its size limit")
        elif (
            set(entry) != {"path", "target", "type"}
            or not isinstance(entry.get("target"), str)
            or not entry["target"]
            or "\x00" in entry["target"]
        ):
            raise BuilderHandoffError("source symlink inventory entry is invalid")
    if paths != sorted(paths, key=lambda path: PurePosixPath(path).parts):
        raise BuilderHandoffError("source inventory order is not canonical")
    calculated = hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if value.get("tree_sha256") != calculated:
        raise BuilderHandoffError("source inventory tree digest is invalid")
    return calculated


def seal_builder_output(
    root: Path,
    *,
    source_root: Path,
    source_repository: str,
    source_commit: str,
    source_tree: str,
    project_version: str,
) -> dict[str, Any]:
    root = require_regular_root(root)
    validate_identity(source_repository, source_commit, source_tree)
    validate_regular_tree(root)
    trusted_path = root / "reports" / "trusted-source-inventory.json"
    seal_path = root / "reports" / "handoff-seal.json"
    if trusted_path.exists() or seal_path.exists():
        raise BuilderHandoffError("builder output is already sealed")
    boundary = observe_live_evidence_boundary(root)
    trusted_inventory = inventory_trusted_source(source_root)
    builder_inventory = read_json(root / "reports" / "source-inventory.json")
    validate_source_inventory(builder_inventory)
    if trusted_inventory != builder_inventory:
        raise BuilderHandoffError(
            "builder source inventory does not match the trusted checkout snapshot"
        )
    builder_report = read_json(root / "reports" / "builder.json")
    builder_source = require_mapping(builder_report.get("source"), "builder source")
    if (
        builder_source.get("repository") != source_repository
        or builder_source.get("commit") != source_commit
        or builder_source.get("git_tree") != source_tree
        or builder_source.get("project_version") != project_version
        or builder_source.get("filesystem_sha256") != trusted_inventory["tree_sha256"]
    ):
        raise BuilderHandoffError("builder source does not match the trusted request")
    trusted_report = {
        "schema_version": 1,
        "source": {
            "repository": source_repository,
            "commit": source_commit,
            "tree": source_tree,
        },
        "inventory": trusted_inventory,
    }
    write_json_exclusive(trusted_path, trusted_report)
    trusted_sha256 = sha256_file(trusted_path)
    seal = {
        "schema_version": 1,
        "status": "validated",
        "source": trusted_report["source"],
        "trusted_source": {
            "path": "reports/trusted-source-inventory.json",
            "sha256": trusted_sha256,
            "tree_sha256": trusted_inventory["tree_sha256"],
        },
        "boundary": boundary,
        "claim_limit": (
            "This seal records a host-side source comparison and live ownership "
            "check before the evidence bundle was made read-only."
        ),
    }
    write_json_exclusive(seal_path, seal)
    validate_builder_output(
        root,
        source_repository=source_repository,
        source_commit=source_commit,
        source_tree=source_tree,
        project_version=project_version,
    )
    return seal


def inventory_trusted_source(source_root: Path) -> dict[str, Any]:
    source_root = Path(os.path.abspath(source_root.expanduser()))
    try:
        root_metadata = source_root.lstat()
    except OSError as exc:
        raise BuilderHandoffError("trusted source root is missing") from exc
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise BuilderHandoffError("trusted source root is not a regular directory")
    entries: list[dict[str, Any]] = []
    directories = [source_root]
    total_size = 0
    while directories:
        directory = directories.pop()
        try:
            children = sorted(directory.iterdir(), key=lambda path: path.name)
        except OSError as exc:
            raise BuilderHandoffError("trusted source tree could not be read") from exc
        for path in children:
            relative_path = path.relative_to(source_root)
            if ".git" in relative_path.parts:
                continue
            relative = safe_spdx_path(relative_path.as_posix())
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                directories.append(path)
                continue
            if stat.S_ISLNK(metadata.st_mode):
                before = file_identity(metadata)
                target = os.readlink(path)
                after = file_identity(path.lstat())
                if before != after or not target or "\x00" in target:
                    raise BuilderHandoffError("trusted source symlink is unstable")
                entries.append({"path": relative, "type": "symlink", "target": target})
                if len(entries) > 100_000:
                    raise BuilderHandoffError("trusted source has too many entries")
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise BuilderHandoffError("trusted source contains a special file")
            payload = read_stable_file(
                path,
                label=f"trusted source {relative}",
                max_bytes=MAX_FILE_BYTES,
            )
            if file_identity(metadata) != file_identity(path.lstat()):
                raise BuilderHandoffError("trusted source changed during inventory")
            total_size += len(payload)
            if total_size > MAX_TOTAL_BYTES:
                raise BuilderHandoffError("trusted source exceeds its size limit")
            entries.append(
                {
                    "path": relative,
                    "type": "file",
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "executable": bool(metadata.st_mode & stat.S_IXUSR),
                }
            )
            if len(entries) > 100_000:
                raise BuilderHandoffError("trusted source has too many entries")
    entries.sort(key=lambda entry: PurePosixPath(entry["path"]).parts)
    tree_sha256 = hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    inventory = {
        "schema_version": 1,
        "tree_sha256": tree_sha256,
        "entries": entries,
    }
    validate_source_inventory(inventory)
    return inventory


def observe_live_evidence_boundary(root: Path) -> dict[str, Any]:
    root_metadata = root.lstat()
    raw_root = root / "traces" / "raw"
    raw_metadata = raw_root.lstat()
    if (
        root_metadata.st_uid != 0
        or root_metadata.st_gid != 0
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
        or not stat.S_ISDIR(raw_metadata.st_mode)
        or stat.S_ISLNK(raw_metadata.st_mode)
        or raw_metadata.st_uid != 0
        or raw_metadata.st_gid != 0
        or stat.S_IMODE(raw_metadata.st_mode) != 0o700
    ):
        raise BuilderHandoffError("live evidence ownership boundary is not root-only")
    raw_files: list[dict[str, Any]] = []
    for path in sorted(raw_root.iterdir(), key=lambda item: item.name):
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            RAW_TRACE_NAME_PATTERN.fullmatch(path.name) is None
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or mode & 0o022
        ):
            raise BuilderHandoffError("live raw trace ownership is not protected")
        raw_files.append(
            {
                "path": f"traces/raw/{path.name}",
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "mode": f"{mode:04o}",
            }
        )
    if not raw_files:
        raise BuilderHandoffError("live evidence boundary has no raw traces")
    return {
        "evidence_root": {"uid": 0, "gid": 0, "mode": "0700"},
        "raw_trace_directory": {"uid": 0, "gid": 0, "mode": "0700"},
        "raw_trace_files": raw_files,
    }


def validate_trusted_source_binding(
    value: dict[str, Any],
    *,
    source_repository: str,
    source_commit: str,
    source_tree: str,
    source_inventory: dict[str, Any],
) -> None:
    if value != {
        "schema_version": 1,
        "source": {
            "repository": source_repository,
            "commit": source_commit,
            "tree": source_tree,
        },
        "inventory": source_inventory,
    }:
        raise BuilderHandoffError("trusted source binding is not exact")


def validate_handoff_seal(
    value: dict[str, Any],
    *,
    root: Path,
    source_repository: str,
    source_commit: str,
    source_tree: str,
    trusted_source_sha256: str,
) -> None:
    if set(value) != {
        "boundary",
        "claim_limit",
        "schema_version",
        "source",
        "status",
        "trusted_source",
    }:
        raise BuilderHandoffError("handoff seal fields are not exact")
    expected_source = {
        "repository": source_repository,
        "commit": source_commit,
        "tree": source_tree,
    }
    if (
        type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or value.get("status") != "validated"
        or value.get("source") != expected_source
        or value.get("trusted_source")
        != {
            "path": "reports/trusted-source-inventory.json",
            "sha256": trusted_source_sha256,
            "tree_sha256": read_json(root / "reports" / "source-inventory.json")[
                "tree_sha256"
            ],
        }
        or value.get("claim_limit")
        != (
            "This seal records a host-side source comparison and live ownership "
            "check before the evidence bundle was made read-only."
        )
    ):
        raise BuilderHandoffError("handoff seal identity is invalid")
    boundary = require_mapping(value.get("boundary"), "handoff seal boundary")
    if (
        set(boundary)
        != {
            "evidence_root",
            "raw_trace_directory",
            "raw_trace_files",
        }
        or boundary.get("evidence_root") != {"uid": 0, "gid": 0, "mode": "0700"}
        or (boundary.get("raw_trace_directory") != {"uid": 0, "gid": 0, "mode": "0700"})
    ):
        raise BuilderHandoffError("handoff seal root boundary is invalid")
    raw_files = boundary.get("raw_trace_files")
    expected_paths = [
        f"traces/raw/{path.name}"
        for path in sorted(
            (root / "traces" / "raw").iterdir(), key=lambda item: item.name
        )
    ]
    if (
        not isinstance(raw_files, list)
        or not all(isinstance(item, dict) for item in raw_files)
        or [item.get("path") for item in raw_files] != expected_paths
    ):
        raise BuilderHandoffError("handoff seal raw trace set is invalid")
    for item in raw_files:
        mode = item.get("mode")
        if (
            not isinstance(item, dict)
            or set(item) != {"gid", "mode", "path", "uid"}
            or item.get("uid") != 0
            or item.get("gid") != 0
            or not isinstance(mode, str)
            or re.fullmatch(r"0[0-7]{3}", mode) is None
            or int(mode, 8) & 0o022
        ):
            raise BuilderHandoffError("handoff seal raw trace boundary is invalid")


def validate_artifact_transforms(
    root: Path,
    value: dict[str, Any],
    *,
    expected_artifacts: list[dict[str, Any]],
    source_date_epoch: str,
) -> None:
    if set(value) != {"artifacts", "error", "policy", "schema_version", "status"}:
        raise BuilderHandoffError("artifact transform report fields are not exact")
    if (
        type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or value.get("status") != "succeeded"
        or value.get("error") is not None
        or value.get("policy") != expected_canonicalization_policy(source_date_epoch)
        or not isinstance(value.get("artifacts"), list)
    ):
        raise BuilderHandoffError("artifact transform report is invalid")

    raw_artifacts = artifact_entries_at(root, "raw-artifacts")
    raw_by_name = {
        entry["path"].removeprefix("raw-artifacts/"): entry for entry in raw_artifacts
    }
    final_by_name = {
        entry["path"].removeprefix("dist/"): entry for entry in expected_artifacts
    }
    if set(raw_by_name) != set(final_by_name):
        raise BuilderHandoffError("raw and canonical artifact namespaces differ")

    seen: set[str] = set()
    wheel_count = 0
    sdist_count = 0
    for item in value["artifacts"]:
        if not isinstance(item, dict) or set(item) != {
            "changed",
            "final",
            "format",
            "member_count",
            "original",
            "path",
            "payload_sha256",
            "payload_size",
            "sdist_layout",
        }:
            raise BuilderHandoffError("artifact transform entry fields are not exact")
        name = item.get("path")
        if (
            not isinstance(name, str)
            or name in seen
            or name not in raw_by_name
            or "/" in name
            or not SAFE_PATH_PATTERN.fullmatch(name)
        ):
            raise BuilderHandoffError("artifact transform path is invalid")
        seen.add(name)
        original = item.get("original")
        final = item.get("final")
        if original != raw_by_name[name] or final != final_by_name[name]:
            raise BuilderHandoffError(
                "artifact transform digests do not match retained files"
            )
        expected_changed = original["sha256"] != final["sha256"]
        if type(item.get("changed")) is not bool or item["changed"] != expected_changed:
            raise BuilderHandoffError("artifact transform changed flag is invalid")
        payload_size = item.get("payload_size")
        payload_sha256 = item.get("payload_sha256")
        if (
            type(payload_size) is not int
            or payload_size < 0
            or not isinstance(payload_sha256, str)
            or SHA256_PATTERN.fullmatch(payload_sha256) is None
        ):
            raise BuilderHandoffError("artifact transform payload identity is invalid")
        if name.endswith(".tar.gz"):
            sdist_count += 1
            if (
                item.get("format") != "python-sdist-tar-gzip"
                or type(item.get("member_count")) is not int
                or item["member_count"] <= 0
                or item.get("sdist_layout")
                not in {"legacy-setup-py", "modern-pyproject"}
            ):
                raise BuilderHandoffError("source distribution transform is invalid")
        elif name.endswith(".whl"):
            wheel_count += 1
            if (
                item.get("format") != "pass-through"
                or item.get("member_count") is not None
                or item.get("sdist_layout") is not None
                or payload_size != original["size"]
                or payload_sha256 != original["sha256"]
                or item["changed"] is not False
            ):
                raise BuilderHandoffError("wheel pass-through transform is invalid")
        else:
            raise BuilderHandoffError("v3 retained an unsupported release artifact")
    if seen != set(raw_by_name) or wheel_count == 0 or sdist_count == 0:
        raise BuilderHandoffError("artifact transform set is incomplete")
    expected_order = sorted(raw_by_name, key=lambda item: item.encode("utf-8"))
    if [item["path"] for item in value["artifacts"]] != expected_order:
        raise BuilderHandoffError("artifact transform order is not canonical")
    try:
        validate_archive_transforms(
            root,
            value,
            source_date_epoch=int(source_date_epoch),
        )
    except ArchiveValidationError as exc:
        raise BuilderHandoffError(str(exc)) from exc


def expected_canonicalization_policy(source_date_epoch: str) -> dict[str, Any]:
    return {
        "id": CANONICALIZATION_POLICY_ID,
        "source_date_epoch": source_date_epoch,
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
            "mtime": source_date_epoch,
            "file_modes": ["0644", "0755"],
            "directory_mode": "0755",
        },
        "gzip": {
            "compression_level": 9,
            "filename": "",
            "flags": 0,
            "mtime": source_date_epoch,
            "xfl": 2,
            "os": 255,
        },
        "limits": {
            "compressed_bytes": 536_870_912,
            "artifact_total_bytes": 1_073_741_824,
            "uncompressed_stream_bytes": 1_140_850_688,
            "payload_bytes": 1_073_741_824,
            "members": 100_000,
            "path_bytes": 4096,
            "path_segment_bytes": 255,
            "pax_headers_per_member": 16,
            "pax_bytes_per_member": 65_536,
            "source_date_epoch_min": MIN_SOURCE_DATE_EPOCH,
            "source_date_epoch_max": MAX_SOURCE_DATE_EPOCH,
        },
    }


def require_regular_root(root: Path) -> Path:
    absolute = Path(os.path.abspath(root.expanduser()))
    try:
        metadata = absolute.lstat()
    except OSError as exc:
        raise BuilderHandoffError("evidence root is missing") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise BuilderHandoffError("evidence root path is a symlink")
    if not stat.S_ISDIR(metadata.st_mode):
        raise BuilderHandoffError("evidence root must be a regular directory")
    resolved = absolute.resolve(strict=True)
    if not stat.S_ISDIR(resolved.lstat().st_mode):
        raise BuilderHandoffError("evidence root must be a regular directory")
    return resolved


def validate_regular_tree(root: Path) -> None:
    if not root.is_dir() or root.is_symlink():
        raise BuilderHandoffError("evidence root must be a regular directory")
    file_count = 0
    total_bytes = 0
    for directory, directory_names, file_names in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        directory_path = Path(directory)
        for name in sorted(directory_names):
            path = directory_path / name
            relative = path.relative_to(root).as_posix()
            if not SAFE_PATH_PATTERN.fullmatch(relative):
                raise BuilderHandoffError(f"unsafe evidence directory path: {relative}")
            if path.is_symlink() or not stat.S_ISDIR(path.lstat().st_mode):
                raise BuilderHandoffError(
                    f"evidence directory is not a regular directory: {relative}"
                )
        for name in sorted(file_names):
            path = directory_path / name
            relative = path.relative_to(root).as_posix()
            if not SAFE_PATH_PATTERN.fullmatch(relative):
                raise BuilderHandoffError(f"unsafe evidence file path: {relative}")
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
                raise BuilderHandoffError(
                    f"evidence entry is not a regular file: {relative}"
                )
            if metadata.st_nlink != 1:
                raise BuilderHandoffError(
                    f"hard-linked evidence is forbidden: {relative}"
                )
            if metadata.st_size > MAX_FILE_BYTES:
                raise BuilderHandoffError(
                    f"evidence file exceeds size limit: {relative}"
                )
            file_count += 1
            total_bytes += metadata.st_size
            if file_count > MAX_FILES or total_bytes > MAX_TOTAL_BYTES:
                raise BuilderHandoffError("evidence tree exceeds retention limits")


def validate_trace(trace: dict[str, Any]) -> None:
    collector = require_mapping(trace.get("collector"), "trace collector")
    coverage = require_mapping(trace.get("coverage"), "trace coverage")
    if (
        set(trace)
        != {
            "collector",
            "coverage",
            "coverage_basis",
            "events",
            "exit_line_count",
            "parsed_line_count",
            "raw_file_count",
            "schema_version",
            "signal_line_count",
            "syscall_line_count",
            "unparsed_line_count",
        }
        or type(trace.get("schema_version")) is not int
        or trace["schema_version"] != 1
        or set(collector) != {"mode", "name", "platform", "version"}
        or collector.get("name") != "strace"
        or collector.get("version") != "6.1"
        or collector.get("platform") != "linux"
        or collector.get("mode") != "follow-forks-full-syscall"
        or not isinstance(trace.get("events"), list)
        or not all(isinstance(event, dict) for event in trace["events"])
        or set(coverage) != {"file", "network", "process", "syscall"}
    ):
        raise BuilderHandoffError(
            "trace document does not match the collector contract"
        )
    values = [coverage.get(name) for name in ("process", "file", "network", "syscall")]
    if not all(isinstance(value, bool) for value in values):
        raise BuilderHandoffError("trace coverage values must be boolean")
    if not all(values):
        raise BuilderHandoffError(
            "python-wheel-v3 requires complete strace collector coverage"
        )
    positive_counts = ("parsed_line_count", "raw_file_count", "syscall_line_count")
    nonnegative_counts = ("exit_line_count", "signal_line_count")
    if (
        trace.get("coverage_basis") != "complete-parser-pass"
        or any(
            type(trace.get(field)) is not int or trace[field] <= 0
            for field in positive_counts
        )
        or any(
            type(trace.get(field)) is not int or trace[field] < 0
            for field in nonnegative_counts
        )
        or type(trace.get("unparsed_line_count")) is not int
        or trace["unparsed_line_count"] != 0
    ):
        raise BuilderHandoffError(
            "trace claims coverage without a complete parser pass"
        )
    validate_trace_events(trace["events"], trace=trace)


def validate_trace_events(
    events: list[dict[str, Any]], *, trace: dict[str, Any]
) -> None:
    keys: list[tuple[Any, ...]] = []
    syscall_count = 0
    signal_count = 0
    exit_count = 0
    for event in events:
        kind = event.get("kind")
        count = event.get("count")
        if type(count) is not int or count <= 0:
            raise BuilderHandoffError("trace event count is invalid")
        if kind == "syscall":
            if (
                set(event) != {"count", "kind", "name", "outcome"}
                or not isinstance(event.get("name"), str)
                or event.get("outcome") not in {"failed", "success"}
            ):
                raise BuilderHandoffError("syscall trace event is invalid")
            key = (kind, event["name"], event["outcome"])
            syscall_count += count
        elif kind == "signal":
            if (
                set(event) != {"count", "kind", "name"}
                or not isinstance(event.get("name"), str)
                or re.fullmatch(r"SIG[A-Z0-9]+", event["name"]) is None
            ):
                raise BuilderHandoffError("signal trace event is invalid")
            key = (kind, event["name"])
            signal_count += count
        elif kind == "process-exit":
            if set(event) != {"count", "kind", "status"} or not isinstance(
                event.get("status"), str
            ):
                raise BuilderHandoffError("process exit trace event is invalid")
            key = (kind, event["status"])
            exit_count += count
        elif kind == "process":
            if (
                set(event) != {"argv", "count", "exe", "kind", "outcome"}
                or not isinstance(event.get("exe"), str)
                or event.get("argv") != [event["exe"]]
                or event.get("outcome") not in {"failed", "success"}
            ):
                raise BuilderHandoffError("process trace event is invalid")
            key = (kind, event["exe"], event["outcome"])
        elif kind == "file":
            if (
                set(event) != {"count", "kind", "operation", "outcome", "path"}
                or event.get("operation")
                not in {"access", "create", "delete", "rename", "write"}
                or event.get("outcome") not in {"failed", "success"}
                or not isinstance(event.get("path"), str)
            ):
                raise BuilderHandoffError("file trace event is invalid")
            key = (kind, event["operation"], event["path"], event["outcome"])
        elif kind == "network":
            port = event.get("port")
            if (
                set(event)
                != {"count", "host", "kind", "operation", "outcome", "port", "protocol"}
                or not isinstance(event.get("operation"), str)
                or not isinstance(event.get("host"), str)
                or event.get("protocol") != "tcp"
                or event.get("outcome") not in {"failed", "success"}
                or not (port == "" or (type(port) is int and 0 <= port <= 65535))
            ):
                raise BuilderHandoffError("network trace event is invalid")
            key = (kind, event["operation"], event["host"], str(port), event["outcome"])
        else:
            raise BuilderHandoffError("trace event kind is unsupported")
        keys.append(key)
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise BuilderHandoffError("trace events are not canonical and unique")
    if (
        syscall_count != trace["syscall_line_count"]
        or signal_count != trace["signal_line_count"]
        or exit_count != trace["exit_line_count"]
    ):
        raise BuilderHandoffError("trace event counts do not match line counts")


def validate_raw_trace_files(root: Path, *, trace: dict[str, Any]) -> None:
    if not root.is_dir() or root.is_symlink():
        raise BuilderHandoffError("raw trace directory is invalid")
    paths = sorted(root.iterdir(), key=lambda path: path.name)
    if (
        not paths
        or len(paths) != trace["raw_file_count"]
        or any(RAW_TRACE_NAME_PATTERN.fullmatch(path.name) is None for path in paths)
    ):
        raise BuilderHandoffError("raw trace file set does not match its summary")
    counts = {"parsed": 0, "syscall": 0, "signal": 0, "exit": 0, "unparsed": 0}
    events: collections.Counter[tuple[str, ...]] = collections.Counter()
    total_bytes = 0
    for path in paths:
        payload = read_stable_file(
            path,
            label=f"raw trace {path.name}",
            max_bytes=64 * 1024 * 1024,
        )
        total_bytes += len(payload)
        if total_bytes > 256 * 1024 * 1024:
            raise BuilderHandoffError("raw trace set exceeds its total size limit")
        try:
            lines = payload.decode("utf-8", "strict").splitlines()
        except UnicodeDecodeError as exc:
            raise BuilderHandoffError("raw trace is not valid UTF-8") from exc
        if len(lines) > 10_000_000 or any(
            len(line.encode("utf-8")) > 1024 * 1024 for line in lines
        ):
            raise BuilderHandoffError("raw trace line limit exceeded")
        for line in lines:
            syscall = RAW_SYSCALL_PATTERN.fullmatch(line)
            if syscall is not None:
                counts["parsed"] += 1
                counts["syscall"] += 1
                name = syscall.group("name")
                arguments = syscall.group("args")
                outcome = (
                    "failed" if syscall.group("result").startswith("-1 ") else "success"
                )
                events[("syscall", name, outcome)] += 1
                for event in derived_trace_events(name, arguments, outcome):
                    events[event] += 1
                continue
            signal = RAW_SIGNAL_PATTERN.fullmatch(line)
            if signal is not None:
                counts["parsed"] += 1
                counts["signal"] += 1
                events[("signal", signal.group("name"))] += 1
                continue
            process_exit = RAW_EXIT_PATTERN.fullmatch(line)
            if process_exit is not None:
                counts["parsed"] += 1
                counts["exit"] += 1
                events[("process-exit", process_exit.group("status"))] += 1
                continue
            counts["unparsed"] += 1
    expected = {
        "parsed": trace["parsed_line_count"],
        "syscall": trace["syscall_line_count"],
        "signal": trace["signal_line_count"],
        "exit": trace["exit_line_count"],
        "unparsed": trace["unparsed_line_count"],
    }
    if counts != expected:
        raise BuilderHandoffError("raw trace counts do not match the trace summary")
    observed_events = [
        trace_event_from_key(key, count) for key, count in sorted(events.items())
    ]
    if trace["events"] != observed_events:
        raise BuilderHandoffError("raw trace events do not match the trace summary")


def derived_trace_events(
    name: str,
    arguments: str,
    outcome: str,
) -> list[tuple[str, ...]]:
    events: list[tuple[str, ...]] = []
    values = raw_quoted_values(arguments)
    if name in {"execve", "execveat"}:
        executable = values[0] if values else "unknown"
        events.append(("process", executable, outcome))
    operation = FILE_OPERATIONS.get(name)
    if operation is not None and values:
        if name in {"open", "openat", "openat2"} and any(
            flag in arguments for flag in WRITE_FLAGS
        ):
            operation = "write"
        events.append(("file", operation, values[0], outcome))
    if name in NETWORK_OPERATIONS and "AF_UNIX" not in arguments:
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
        events.append(("network", name, host, port, outcome))
    return events


def raw_quoted_values(value: str) -> list[str]:
    values: list[str] = []
    for match in RAW_QUOTED_PATTERN.finditer(value):
        encoded = f'"{match.group(1)}"'
        try:
            decoded = json.loads(encoded)
        except json.JSONDecodeError:
            decoded = match.group(1)
        values.append(decoded)
    return values


def trace_event_from_key(key: tuple[str, ...], count: int) -> dict[str, Any]:
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


def normalize_spdx(
    root: Path,
    *,
    source_repository: str,
    source_commit: str,
    source_tree: str,
    project_version: str,
    source_date_epoch: str,
) -> dict[str, Any]:
    root = require_regular_root(root)
    validate_regular_tree(root)
    validate_identity(source_repository, source_commit, source_tree)
    epoch = require_source_date_epoch(source_date_epoch)
    artifacts = artifact_entries(root)
    raw_path = root / "sbom" / "raw" / "syft.spdx.json"
    normalized_path = root / "sbom" / "sbom.spdx.json"
    report_path = root / "reports" / "spdx-normalization.json"
    raw_bytes = read_bounded_bytes(raw_path, label="raw Syft SPDX document")
    raw = decode_json_object(raw_bytes, label="raw Syft SPDX document")
    normalized, seed_sha256 = normalized_spdx_document(
        raw,
        artifacts=artifacts,
        source_repository=source_repository,
        source_commit=source_commit,
        source_tree=source_tree,
        project_version=project_version,
        source_date_epoch=source_date_epoch,
    )
    normalized_bytes = canonical_json_bytes(normalized)
    write_bytes_exclusive(normalized_path, normalized_bytes)
    report = {
        "schema_version": 1,
        "status": "succeeded",
        "policy_id": SPDX_NORMALIZATION_POLICY_ID,
        "source_date_epoch": source_date_epoch,
        "creation_time": format_spdx_time(epoch),
        "document_namespace": normalized["documentNamespace"],
        "namespace_seed_sha256": seed_sha256,
        "raw": {
            "path": "sbom/raw/syft.spdx.json",
            "size": len(raw_bytes),
            "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        },
        "normalized": {
            "path": "sbom/sbom.spdx.json",
            "size": len(normalized_bytes),
            "sha256": hashlib.sha256(normalized_bytes).hexdigest(),
        },
        "artifact_bindings": artifacts,
    }
    write_json(report_path, report)
    validate_regular_tree(root)
    validate_spdx_bundle(
        root,
        expected_artifacts=artifacts,
        source_repository=source_repository,
        source_commit=source_commit,
        source_tree=source_tree,
        project_version=project_version,
        source_date_epoch=source_date_epoch,
    )
    return {"document": normalized, "report": report}


def normalized_spdx_document(
    raw: dict[str, Any],
    *,
    artifacts: list[dict[str, Any]],
    source_repository: str,
    source_commit: str,
    source_tree: str,
    project_version: str,
    source_date_epoch: str,
) -> tuple[dict[str, Any], str]:
    allowed_top_level = {
        "SPDXID",
        "creationInfo",
        "dataLicense",
        "documentNamespace",
        "files",
        "name",
        "packages",
        "relationships",
        "spdxVersion",
    }
    required_top_level = allowed_top_level - {"files"}
    if not required_top_level.issubset(raw) or not set(raw).issubset(allowed_top_level):
        raise BuilderHandoffError("raw Syft SPDX fields are not supported")
    if (
        raw.get("spdxVersion") != "SPDX-2.3"
        or raw.get("dataLicense") != "CC0-1.0"
        or raw.get("SPDXID") != "SPDXRef-DOCUMENT"
        or not isinstance(raw.get("name"), str)
        or not raw["name"]
        or not isinstance(raw.get("documentNamespace"), str)
        or not raw["documentNamespace"]
    ):
        raise BuilderHandoffError("raw Syft SPDX document identity is invalid")
    creation = raw.get("creationInfo")
    if not isinstance(creation, dict) or set(creation) != {
        "created",
        "creators",
        "licenseListVersion",
    }:
        raise BuilderHandoffError("raw Syft SPDX creation info is not supported")
    creators = creation.get("creators")
    if (
        not isinstance(creators, list)
        or not creators
        or not all(isinstance(item, str) and item for item in creators)
        or len(set(creators)) != len(creators)
        or sorted(creators) != ["Organization: Anchore, Inc", "Tool: syft-1.42.3"]
        or creation.get("licenseListVersion") != "3.28"
        or not isinstance(creation.get("created"), str)
        or not creation["created"]
    ):
        raise BuilderHandoffError("raw Syft SPDX creators are invalid")
    packages = require_object_list(raw.get("packages"), label="SPDX packages")
    files = require_object_list(raw.get("files", []), label="SPDX files")
    relationships = require_object_list(
        raw.get("relationships"),
        label="SPDX relationships",
    )
    if len(packages) + len(files) + len(relationships) > MAX_SPDX_ITEMS:
        raise BuilderHandoffError("SPDX collection exceeds the item limit")

    document_name = f"{source_repository}@{source_commit}"
    old_ids: set[str] = {"SPDXRef-DOCUMENT"}
    id_map: dict[str, str] = {"SPDXRef-DOCUMENT": "SPDXRef-DOCUMENT"}
    normalized_packages: list[dict[str, Any]] = []
    normalized_files: list[dict[str, Any]] = []
    generated_ids: set[str] = {"SPDXRef-DOCUMENT"}
    for package in packages:
        candidate = dict(package)
        if candidate.get("name") == raw["name"]:
            candidate["name"] = document_name
        normalized_packages.append(
            normalize_spdx_element(
                candidate,
                prefix="Package",
                old_ids=old_ids,
                generated_ids=generated_ids,
                id_map=id_map,
            )
        )
    artifact_paths = {entry["path"].casefold() for entry in artifacts}
    raw_file_paths: set[str] = set()
    for file_entry in files:
        file_name = file_entry.get("fileName")
        if not isinstance(file_name, str):
            raise BuilderHandoffError("SPDX file name is invalid")
        safe_spdx_path(file_name)
        folded_file_name = file_name.casefold()
        if folded_file_name in artifact_paths or folded_file_name in raw_file_paths:
            raise BuilderHandoffError("raw SPDX file aliases a release artifact")
        raw_file_paths.add(folded_file_name)
        normalized_files.append(
            normalize_spdx_element(
                file_entry,
                prefix="File",
                old_ids=old_ids,
                generated_ids=generated_ids,
                id_map=id_map,
            )
        )

    normalized_relationships: list[dict[str, Any]] = []
    relationship_keys: set[bytes] = set()
    for relationship in relationships:
        if set(relationship) != {
            "relatedSpdxElement",
            "relationshipType",
            "spdxElementId",
        }:
            raise BuilderHandoffError("SPDX relationship fields are not supported")
        source_id = relationship.get("spdxElementId")
        target_id = relationship.get("relatedSpdxElement")
        relationship_type = relationship.get("relationshipType")
        if (
            source_id not in id_map
            or target_id not in id_map
            or not isinstance(relationship_type, str)
            or not relationship_type
        ):
            raise BuilderHandoffError("SPDX relationship has a dangling reference")
        normalized_relationship = {
            "spdxElementId": id_map[source_id],
            "relationshipType": relationship_type,
            "relatedSpdxElement": id_map[target_id],
        }
        key = canonical_json_bytes(normalized_relationship)
        if key in relationship_keys:
            raise BuilderHandoffError("SPDX relationship is duplicated")
        relationship_keys.add(key)
        normalized_relationships.append(normalized_relationship)

    for artifact in artifacts:
        identity = canonical_json_bytes(artifact)
        spdx_id = f"SPDXRef-Artifact-{hashlib.sha256(identity).hexdigest()}"
        if spdx_id in generated_ids:
            raise BuilderHandoffError("SPDX artifact identifier collision")
        generated_ids.add(spdx_id)
        normalized_files.append(
            {
                "SPDXID": spdx_id,
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": artifact["sha256"]}
                ],
                "copyrightText": "NOASSERTION",
                "fileName": artifact["path"],
                "licenseConcluded": "NOASSERTION",
            }
        )
        relationship = {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": spdx_id,
        }
        key = canonical_json_bytes(relationship)
        if key in relationship_keys:
            raise BuilderHandoffError("SPDX artifact relationship is duplicated")
        relationship_keys.add(key)
        normalized_relationships.append(relationship)

    normalized_packages.sort(key=lambda item: item["SPDXID"])
    normalized_files.sort(
        key=lambda item: (item["fileName"].encode("utf-8"), item["SPDXID"])
    )
    normalized_relationships.sort(
        key=lambda item: (
            item["spdxElementId"],
            item["relationshipType"],
            item["relatedSpdxElement"],
            canonical_json_bytes(item),
        )
    )
    normalized = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": format_spdx_time(require_source_date_epoch(source_date_epoch)),
            "creators": sorted(creators),
            "licenseListVersion": creation["licenseListVersion"],
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": "",
        "files": normalized_files,
        "name": document_name,
        "packages": normalized_packages,
        "relationships": normalized_relationships,
        "spdxVersion": "SPDX-2.3",
    }
    seed_document = dict(normalized)
    seed_document.pop("documentNamespace")
    seed_creation = dict(seed_document["creationInfo"])
    seed_creation.pop("created")
    seed_document["creationInfo"] = seed_creation
    seed = {
        "namespace_schema": 1,
        "profile": PROFILE_ID,
        "normalization_policy": SPDX_NORMALIZATION_POLICY_ID,
        "source": {
            "repository": source_repository,
            "commit": source_commit,
            "tree": source_tree,
            "project_version": project_version,
        },
        "source_date_epoch": source_date_epoch,
        "artifacts": artifacts,
        "document": seed_document,
    }
    seed_sha256 = hashlib.sha256(canonical_json_bytes(seed)).hexdigest()
    normalized["documentNamespace"] = (
        f"https://assured-downstream.dev/spdx/{PROFILE_ID}/{seed_sha256}"
    )
    return normalized, seed_sha256


def normalize_spdx_element(
    value: dict[str, Any],
    *,
    prefix: str,
    old_ids: set[str],
    generated_ids: set[str],
    id_map: dict[str, str],
) -> dict[str, Any]:
    old_id = value.get("SPDXID")
    if not isinstance(old_id, str) or not re.fullmatch(
        r"SPDXRef-[A-Za-z0-9.-]+", old_id
    ):
        raise BuilderHandoffError("SPDX element identifier is invalid")
    if old_id in old_ids:
        raise BuilderHandoffError("SPDX element identifier is duplicated")
    old_ids.add(old_id)
    body_value = {key: item for key, item in value.items() if key != "SPDXID"}
    if "checksums" in body_value:
        body_value["checksums"] = normalize_spdx_checksums(body_value["checksums"])
    if contains_inline_spdx_reference(body_value):
        raise BuilderHandoffError("SPDX inline identifier references are unsupported")
    body = {key: canonicalize_json(item) for key, item in body_value.items()}
    generated = (
        f"SPDXRef-{prefix}-{hashlib.sha256(canonical_json_bytes(body)).hexdigest()}"
    )
    if generated in generated_ids:
        raise BuilderHandoffError("SPDX normalized element is duplicated")
    generated_ids.add(generated)
    id_map[old_id] = generated
    return {"SPDXID": generated, **body}


def normalize_spdx_checksums(value: Any) -> list[dict[str, str]]:
    checksums = require_object_list(value, label="SPDX checksums")
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for checksum in checksums:
        if set(checksum) != {"algorithm", "checksumValue"}:
            raise BuilderHandoffError("SPDX checksum fields are not exact")
        algorithm = checksum.get("algorithm")
        digest = checksum.get("checksumValue")
        if not isinstance(algorithm, str) or not isinstance(digest, str):
            raise BuilderHandoffError("SPDX checksum is invalid")
        identity = (algorithm.upper(), digest.lower())
        if (
            identity in seen
            or not re.fullmatch(r"[A-Z0-9-]+", identity[0])
            or not re.fullmatch(r"[0-9a-f]+", identity[1])
        ):
            raise BuilderHandoffError("SPDX checksum is duplicated or malformed")
        seen.add(identity)
        normalized.append({"algorithm": identity[0], "checksumValue": identity[1]})
    return sorted(
        normalized,
        key=lambda item: (item["algorithm"], item["checksumValue"]),
    )


def contains_inline_spdx_reference(value: Any) -> bool:
    if isinstance(value, str):
        return (
            re.fullmatch(
                r"(?:DocumentRef-[A-Za-z0-9.-]+:)?SPDXRef-[A-Za-z0-9.-]+", value
            )
            is not None
        )
    if isinstance(value, dict):
        return any(contains_inline_spdx_reference(item) for item in value.values())
    if isinstance(value, list):
        return any(contains_inline_spdx_reference(item) for item in value)
    return False


def validate_spdx_bundle(
    root: Path,
    *,
    expected_artifacts: list[dict[str, Any]],
    source_repository: str,
    source_commit: str,
    source_tree: str,
    project_version: str,
    source_date_epoch: str,
) -> dict[str, Any]:
    raw_path = root / "sbom" / "raw" / "syft.spdx.json"
    normalized_path = root / "sbom" / "sbom.spdx.json"
    report_path = root / "reports" / "spdx-normalization.json"
    raw_bytes = read_bounded_bytes(raw_path, label="raw Syft SPDX document")
    normalized_bytes = read_bounded_bytes(
        normalized_path,
        label="normalized SPDX document",
    )
    raw = decode_json_object(raw_bytes, label="raw Syft SPDX document")
    expected_document, seed_sha256 = normalized_spdx_document(
        raw,
        artifacts=expected_artifacts,
        source_repository=source_repository,
        source_commit=source_commit,
        source_tree=source_tree,
        project_version=project_version,
        source_date_epoch=source_date_epoch,
    )
    if normalized_bytes != canonical_json_bytes(expected_document):
        raise BuilderHandoffError("normalized SPDX bytes are not canonical")
    report = read_json(report_path)
    expected_report = {
        "schema_version": 1,
        "status": "succeeded",
        "policy_id": SPDX_NORMALIZATION_POLICY_ID,
        "source_date_epoch": source_date_epoch,
        "creation_time": format_spdx_time(require_source_date_epoch(source_date_epoch)),
        "document_namespace": expected_document["documentNamespace"],
        "namespace_seed_sha256": seed_sha256,
        "raw": {
            "path": "sbom/raw/syft.spdx.json",
            "size": len(raw_bytes),
            "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        },
        "normalized": {
            "path": "sbom/sbom.spdx.json",
            "size": len(normalized_bytes),
            "sha256": hashlib.sha256(normalized_bytes).hexdigest(),
        },
        "artifact_bindings": expected_artifacts,
    }
    if report != expected_report:
        raise BuilderHandoffError("SPDX normalization report is invalid")
    validate_spdx_binding(expected_document, expected_artifacts=expected_artifacts)
    return report


def validate_spdx_binding(
    sbom: dict[str, Any],
    *,
    expected_artifacts: list[dict[str, Any]],
) -> None:
    files = sbom.get("files")
    relationships = sbom.get("relationships")
    if not isinstance(files, list) or not isinstance(relationships, list):
        raise BuilderHandoffError("SPDX artifact binding collections are invalid")
    described = {
        item["relatedSpdxElement"]
        for item in relationships
        if item.get("spdxElementId") == "SPDXRef-DOCUMENT"
        and item.get("relationshipType") == "DESCRIBES"
    }
    artifact_files = [
        item
        for item in files
        if isinstance(item, dict)
        and isinstance(item.get("SPDXID"), str)
        and item["SPDXID"].startswith("SPDXRef-Artifact-")
    ]
    bindings: list[dict[str, Any]] = []
    for item in artifact_files:
        checksums = item.get("checksums")
        if (
            item.get("SPDXID") not in described
            or set(item)
            != {
                "SPDXID",
                "checksums",
                "copyrightText",
                "fileName",
                "licenseConcluded",
            }
            or not isinstance(item.get("fileName"), str)
            or not isinstance(checksums, list)
            or len(checksums) != 1
            or not isinstance(checksums[0], dict)
            or set(checksums[0]) != {"algorithm", "checksumValue"}
            or checksums[0].get("algorithm") != "SHA256"
            or item.get("copyrightText") != "NOASSERTION"
            or item.get("licenseConcluded") != "NOASSERTION"
        ):
            raise BuilderHandoffError("SPDX artifact binding is malformed")
        digest = checksums[0]["checksumValue"]
        if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
            raise BuilderHandoffError("SPDX artifact checksum is invalid")
        bindings.append({"path": item["fileName"], "sha256": digest})
    expected = [
        {"path": item["path"], "sha256": item["sha256"]} for item in expected_artifacts
    ]
    if sorted(bindings, key=lambda item: item["path"].encode("utf-8")) != expected:
        raise BuilderHandoffError("SPDX artifact bindings are not exact")


def create_subject_checksums(
    root: Path,
    *,
    source_repository: str,
    source_commit: str,
    source_tree: str,
    project_version: str,
) -> dict[str, Any]:
    validated = validate_builder_output(
        root,
        source_repository=source_repository,
        source_commit=source_commit,
        source_tree=source_tree,
        project_version=project_version,
        require_sbom=True,
    )
    artifacts = validated["artifact_inventory"]["artifacts"]
    payload = "".join(
        f"{entry['sha256']}  {entry['path']}\n" for entry in artifacts
    ).encode("ascii")
    path = root / "reports" / "artifact-subjects.sha256"
    write_bytes_exclusive(path, payload)
    return {
        "path": "reports/artifact-subjects.sha256",
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def validate_subject_checksums(
    root: Path,
    *,
    expected_artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    expected = "".join(
        f"{entry['sha256']}  {entry['path']}\n" for entry in expected_artifacts
    ).encode("ascii")
    path = root / "reports" / "artifact-subjects.sha256"
    actual = read_bounded_bytes(path, label="artifact subject checksum manifest")
    if actual != expected:
        raise BuilderHandoffError("artifact subject checksum manifest is not exact")
    return {
        "path": "reports/artifact-subjects.sha256",
        "size": len(actual),
        "sha256": hashlib.sha256(actual).hexdigest(),
    }


def create_build_predicate(
    root: Path,
    *,
    source_repository: str,
    source_commit: str,
    source_tree: str,
    upstream_repository: str,
    upstream_commit: str,
    target_repository: str,
    project_version: str,
    release_tag: str,
    case_id: str,
    caller_repository: str,
    caller_commit: str,
    caller_workflow_ref: str,
    called_repository: str,
    called_workflow_ref: str,
    called_workflow_sha: str,
    handoff_commit: str,
    run_id: str,
    run_attempt: str,
    event_name: str,
    actor: str,
    triggering_actor: str,
    source_date_epoch: str,
) -> dict[str, Any]:
    root = require_regular_root(root)
    validate_identity(source_repository, source_commit, source_tree)
    validate_repository(upstream_repository, "upstream repository")
    validate_repository(target_repository, "target repository")
    require_sha(upstream_commit, "upstream commit")
    require_sha(caller_commit, "caller commit")
    require_sha(called_workflow_sha, "called workflow commit")
    require_sha(handoff_commit, "handoff verifier commit")
    validate_workflow_run_claims(
        caller_repository=caller_repository,
        caller_commit=caller_commit,
        caller_workflow_ref=caller_workflow_ref,
        called_repository=called_repository,
        called_workflow_ref=called_workflow_ref,
        called_workflow_sha=called_workflow_sha,
        run_id=run_id,
        run_attempt=run_attempt,
        event_name=event_name,
        actor=actor,
        triggering_actor=triggering_actor,
    )
    validated = validate_builder_output(
        root,
        source_repository=source_repository,
        source_commit=source_commit,
        source_tree=source_tree,
        project_version=project_version,
        require_sbom=True,
    )
    builder_source = validated["builder_report"]["source"]
    if builder_source["source_date_epoch"] != source_date_epoch:
        raise BuilderHandoffError("predicate source date does not match builder output")
    artifacts = validated["artifact_inventory"]["artifacts"]
    subject_manifest = validate_subject_checksums(
        root,
        expected_artifacts=artifacts,
    )
    spdx_report = validate_spdx_bundle(
        root,
        expected_artifacts=artifacts,
        source_repository=source_repository,
        source_commit=source_commit,
        source_tree=source_tree,
        project_version=project_version,
        source_date_epoch=source_date_epoch,
    )
    predicate = {
        "schemaVersion": 2,
        "predicateType": CUSTOM_PREDICATE_TYPE,
        "profile": PROFILE_ID,
        "builder": {
            "image": BUILDER_IMAGE,
            "imageDigest": BUILDER_DIGEST,
            "network": "none",
            "traceArgv": EXPECTED_TRACE_ARGV,
            "canonicalizationPolicy": CANONICALIZATION_POLICY_ID,
            "handoffVerifierCommit": handoff_commit,
            "identityBoundary": predicate_identity_boundary(
                validated["builder_report"]["execution"]["identity_boundary"]
            ),
        },
        "source": {
            "repository": source_repository,
            "commit": source_commit,
            "tree": source_tree,
            "filesystemSha256": builder_source["filesystem_sha256"],
            "upstreamRepository": upstream_repository,
            "upstreamCommit": upstream_commit,
            "projectVersion": project_version,
            "sourceDateEpoch": source_date_epoch,
        },
        "downstream": {
            "targetRepository": target_repository,
            "releaseTag": release_tag,
            "caseId": case_id,
        },
        "caller": {
            "repository": caller_repository,
            "workflowPath": CALLER_WORKFLOW_PATH,
            "workflowRef": caller_workflow_ref,
            "workflowSha": caller_commit,
        },
        "called": {
            "repository": called_repository,
            "workflowPath": CALLED_WORKFLOW_PATH,
            "workflowRef": called_workflow_ref,
            "workflowSha": called_workflow_sha,
        },
        "run": {
            "id": run_id,
            "attempt": run_attempt,
            "event": event_name,
            "actor": actor,
            "triggeringActor": triggering_actor,
            "runnerEnvironment": "github-hosted",
        },
        "materials": {
            "builderSources": [
                {"path": path, "sha256": digest}
                for path, digest in sorted(BUILDER_SOURCE_DIGESTS.items())
            ],
            "baseImageIndexDigest": "sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7",
            "actionPins": ACTION_PINS,
        },
        "artifacts": artifacts,
        "sbom": {
            "normalizationPolicy": SPDX_NORMALIZATION_POLICY_ID,
            "raw": spdx_report["raw"],
            "normalized": spdx_report["normalized"],
            "normalizationReport": {
                "path": "reports/spdx-normalization.json",
                "sha256": sha256_file(root / "reports" / "spdx-normalization.json"),
            },
            "documentNamespace": spdx_report["document_namespace"],
            "creationTime": spdx_report["creation_time"],
            "artifactBindings": [
                {"path": item["path"], "sha256": item["sha256"]} for item in artifacts
            ],
        },
        "evidence": {
            "artifactSubjectManifest": subject_manifest,
            "artifactInventorySha256": sha256_file(
                root / "reports" / "artifact-inventory.json"
            ),
            "artifactTransformSha256": sha256_file(
                root / "reports" / "artifact-transforms.json"
            ),
            "builderReportSha256": sha256_file(root / "reports" / "builder.json"),
            "sourceInventorySha256": sha256_file(
                root / "reports" / "source-inventory.json"
            ),
            "trustedSourceInventorySha256": sha256_file(
                root / "reports" / "trusted-source-inventory.json"
            ),
            "handoffSealSha256": sha256_file(root / "reports" / "handoff-seal.json"),
            "traceSha256": sha256_file(root / "traces" / "observed-trace.json"),
        },
        "claimLimit": (
            "The workflow signs these run, source, artifact, SBOM, and builder "
            "observations. Source ancestry, workflow implementation, builder "
            "containment, provider independence, and semantic safety require "
            "separate verification."
        ),
    }
    write_json(root / "predicates" / "build.json", predicate)
    return predicate


def validate_workflow_run_claims(
    *,
    caller_repository: str,
    caller_commit: str,
    caller_workflow_ref: str,
    called_repository: str,
    called_workflow_ref: str,
    called_workflow_sha: str,
    run_id: str,
    run_attempt: str,
    event_name: str,
    actor: str,
    triggering_actor: str,
) -> None:
    expected_caller_ref = f"{CONTROL_REPOSITORY}/{CALLER_WORKFLOW_PATH}@{REQUIRED_REF}"
    expected_called_ref = (
        f"{CONTROL_REPOSITORY}/{CALLED_WORKFLOW_PATH}@{called_workflow_sha}"
    )
    if (
        caller_repository != CONTROL_REPOSITORY
        or called_repository != CONTROL_REPOSITORY
        or caller_workflow_ref != expected_caller_ref
        or called_workflow_ref != expected_called_ref
        or event_name != REQUIRED_EVENT
        or actor != REQUIRED_ACTOR
        or triggering_actor != REQUIRED_ACTOR
        or not SHA_PATTERN.fullmatch(caller_commit)
    ):
        raise BuilderHandoffError("workflow run identity is outside the v3 boundary")
    for value, label in ((run_id, "run id"), (run_attempt, "run attempt")):
        if (
            not isinstance(value, str)
            or not value.isdigit()
            or len(value) > 20
            or str(int(value)) != value
            or int(value) <= 0
        ):
            raise BuilderHandoffError(f"workflow {label} is invalid")


def predicate_identity_boundary(boundary: dict[str, Any]) -> dict[str, Any]:
    return {
        "collectorUid": boundary["collector_uid"],
        "collectorGid": boundary["collector_gid"],
        "buildUid": boundary["build_uid"],
        "buildGid": boundary["build_gid"],
        "evidenceUid": boundary["evidence_uid"],
        "evidenceGid": boundary["evidence_gid"],
        "evidenceMode": boundary["evidence_mode"],
        "separateCollectorIdentity": boundary["separate_collector_identity"],
        "collectorOutputWritableByBuild": boundary[
            "collector_output_writable_by_build"
        ],
        "quiescenceBarrier": boundary["quiescence_barrier"],
        "killedProcessCount": boundary["killed_process_count"],
        "remainingProcessCount": boundary["remaining_process_count"],
    }


def assemble_evidence(
    root: Path,
    *,
    source_repository: str,
    source_commit: str,
    source_tree: str,
    upstream_repository: str,
    upstream_commit: str,
    target_repository: str,
    project_version: str,
    release_tag: str,
) -> dict[str, Any]:
    root = require_regular_root(root)
    validate_builder_output(
        root,
        source_repository=source_repository,
        source_commit=source_commit,
        source_tree=source_tree,
        project_version=project_version,
        require_sbom=True,
        require_attestations=True,
    )
    artifacts = [
        root / entry["path"]
        for entry in read_json(root / "reports" / "artifact-inventory.json")[
            "artifacts"
        ]
    ]
    validate_subject_checksums(
        root,
        expected_artifacts=artifact_entries(root),
    )
    raw_artifacts = sorted((root / "raw-artifacts").glob("*"))
    sboms = [
        root / "sbom" / "raw" / "syft.spdx.json",
        root / "sbom" / "sbom.spdx.json",
    ]
    attestations = sorted((root / "attestations").glob("*.sigstore.json"))
    traces = [root / "traces" / "observed-trace.json"]
    reports = sorted(
        [
            *(root / "reports").glob("*.json"),
            root / "reports" / "artifact-subjects.sha256",
            *(root / "traces" / "raw").glob("*"),
            root / "predicates" / "build.json",
        ],
        key=lambda path: path.relative_to(root).as_posix().encode("utf-8"),
    )
    manifest = create_evidence_manifest(
        project=upstream_repository,
        target_repo=target_repository,
        upstream_ref=upstream_commit,
        overlay_ref=source_commit,
        release_tag=release_tag,
        assurance="Evidence-candidate",
        files={
            "artifacts": artifacts,
            "raw_artifacts": raw_artifacts,
            "sboms": sboms,
            "attestations": attestations,
            "traces": traces,
            "reports": reports,
        },
        root=root,
    )
    manifest["schema_version"] = 2
    for role, entries in manifest["evidence"].items():
        for entry in entries:
            if entry.get("role") != role or not isinstance(entry.get("path"), str):
                raise BuilderHandoffError("assembled evidence entry is invalid")
            entry["logical_path"] = entry["path"]
    write_json(root / "evidence.json", manifest)
    verification = verify_evidence_manifest(manifest, base_dir=root)
    if not verification["ok"]:
        raise BuilderHandoffError("assembled evidence manifest does not verify")
    build_result = {
        "schema_version": 1,
        "status": "succeeded",
        "project": {
            "source_full_name": upstream_repository,
            "target_full_name": target_repository,
            "upstream_ref": upstream_commit,
            "overlay_ref": source_commit,
            "release_tag": release_tag,
        },
        "builder": {
            "mode": "external-isolated",
            "builder_id": f"{BUILDER_IMAGE}@{BUILDER_DIGEST}",
            "isolated": True,
            "secrets_exposed": False,
            "network_policy": "deny",
            "workspace_root": "/workspace",
        },
        "evidence": {
            "artifacts": [path.relative_to(root).as_posix() for path in artifacts],
            "raw_artifacts": [
                path.relative_to(root).as_posix() for path in raw_artifacts
            ],
            "sboms": [path.relative_to(root).as_posix() for path in sboms],
            "attestations": [
                path.relative_to(root).as_posix() for path in attestations
            ],
            "raw_traces": [path.relative_to(root).as_posix() for path in traces],
            "reports": [path.relative_to(root).as_posix() for path in reports],
        },
    }
    write_json(root / "build-result.json", build_result)
    validate_regular_tree(root)
    return {"manifest": manifest, "build_result": build_result}


def artifact_entries(root: Path) -> list[dict[str, Any]]:
    return artifact_entries_at(root, "dist")


def artifact_entries_at(root: Path, directory: str) -> list[dict[str, Any]]:
    base = root / directory
    if not base.is_dir() or base.is_symlink():
        raise BuilderHandoffError(
            f"evidence bundle has no regular {directory} directory"
        )
    paths = list(base.iterdir())
    if any(path.is_dir() for path in paths):
        raise BuilderHandoffError(f"{directory} artifact namespace is not flat")
    entries: list[dict[str, Any]] = []
    folded_names: set[str] = set()
    total_bytes = 0
    for path in sorted(paths, key=lambda item: item.name.encode("utf-8")):
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or path.is_symlink()
            or metadata.st_nlink != 1
        ):
            raise BuilderHandoffError(
                "release artifact is not a standalone regular file"
            )
        safe_spdx_path(path.relative_to(root).as_posix())
        folded = path.name.casefold()
        if folded in folded_names:
            raise BuilderHandoffError("release artifact name has a case-fold alias")
        folded_names.add(folded)
        total_bytes += metadata.st_size
        if (
            len(entries) >= 128
            or metadata.st_size > 536_870_912
            or total_bytes > 1_073_741_824
        ):
            raise BuilderHandoffError("release artifact set exceeds v3 limits")
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "size": metadata.st_size,
                "sha256": sha256_file(path),
            }
        )
    if not entries:
        raise BuilderHandoffError(f"evidence bundle has no {directory} artifacts")
    return entries


def validate_identity(repository: str, commit: str, tree: str) -> None:
    validate_repository(repository, "source repository")
    require_sha(commit, "source commit")
    require_sha(tree, "source tree")


def validate_repository(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or not REPOSITORY_PATTERN.fullmatch(value)
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        raise BuilderHandoffError(f"{label} is invalid")


def require_sha(value: str, label: str) -> None:
    if not isinstance(value, str) or not SHA_PATTERN.fullmatch(value):
        raise BuilderHandoffError(f"{label} is not a lowercase 40-character SHA")


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BuilderHandoffError(f"{label} must be an object")
    return value


def require_object_list(value: Any, *, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise BuilderHandoffError(f"{label} must be a list of objects")
    return value


def require_source_date_epoch(value: str) -> int:
    if (
        not isinstance(value, str)
        or not value.isdigit()
        or len(value) > 10
        or str(int(value)) != value
        or not MIN_SOURCE_DATE_EPOCH <= int(value) <= MAX_SOURCE_DATE_EPOCH
    ):
        raise BuilderHandoffError("SOURCE_DATE_EPOCH is outside the v3 range")
    return int(value)


def format_spdx_time(value: int) -> str:
    return datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_spdx_path(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
        or unicodedata.normalize("NFC", value) != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise BuilderHandoffError("SPDX path is invalid")
    parts = value.split("/")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in parts)
        or len(value.encode("utf-8")) > 4096
        or any(len(part.encode("utf-8")) > 255 for part in parts)
    ):
        raise BuilderHandoffError("SPDX path is not canonical")
    return value


def canonicalize_json(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool)):
        return value
    if type(value) is int:
        return value
    if isinstance(value, float):
        raise BuilderHandoffError("floating-point SPDX values are unsupported")
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise BuilderHandoffError("SPDX object key is invalid")
        return {key: canonicalize_json(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        items = [canonicalize_json(item) for item in value]
        items.sort(key=canonical_json_bytes)
        if any(items[index] == items[index - 1] for index in range(1, len(items))):
            raise BuilderHandoffError("SPDX collection contains a duplicate")
        return items
    raise BuilderHandoffError("SPDX value type is unsupported")


def canonical_json_bytes(value: Any) -> bytes:
    try:
        payload = json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise BuilderHandoffError("value cannot be serialized canonically") from exc
    return (payload + "\n").encode("utf-8")


def duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise BuilderHandoffError(f"JSON object contains duplicate key: {key}")
        value[key] = item
    return value


def decode_json_object(payload: bytes, *, label: str) -> dict[str, Any]:
    if payload.startswith(b"\xef\xbb\xbf"):
        raise BuilderHandoffError(f"{label} has a UTF-8 BOM")
    try:
        text = payload.decode("utf-8", "strict")
        value = json.loads(
            text,
            object_pairs_hook=duplicate_rejecting_object,
            parse_constant=lambda constant: reject_json_constant(constant, label=label),
            parse_int=bounded_json_integer,
            parse_float=bounded_json_float,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise BuilderHandoffError(f"could not parse {label}") from exc
    if not isinstance(value, dict):
        raise BuilderHandoffError(f"{label} must contain an object")
    validate_json_shape(value)
    return value


def reject_json_constant(value: str, *, label: str) -> None:
    raise BuilderHandoffError(f"{label} contains {value}")


def bounded_json_integer(value: str) -> int:
    if len(value) > 128:
        raise ValueError("JSON integer is oversized")
    return int(value)


def bounded_json_float(value: str) -> float:
    if len(value) > 128:
        raise ValueError("JSON float is oversized")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("JSON float is not finite")
    return result


def validate_json_shape(value: Any, *, depth: int = 0) -> int:
    if depth > 128:
        raise BuilderHandoffError("JSON nesting exceeds its limit")
    count = 1
    if isinstance(value, dict):
        for item in value.values():
            count += validate_json_shape(item, depth=depth + 1)
    elif isinstance(value, list):
        for item in value:
            count += validate_json_shape(item, depth=depth + 1)
    if count > 1_000_000:
        raise BuilderHandoffError("JSON value count exceeds its limit")
    return count


def read_bounded_bytes(path: Path, *, label: str) -> bytes:
    return read_stable_file(path, label=label, max_bytes=MAX_JSON_BYTES)


def read_stable_file(path: Path, *, label: str, max_bytes: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BuilderHandoffError(f"could not open {label}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > max_bytes
        ):
            raise BuilderHandoffError(f"{label} is not a bounded standalone file")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, min(1024 * 1024, max_bytes - total + 1)):
            total += len(chunk)
            if total > max_bytes:
                raise BuilderHandoffError(f"{label} exceeds its size limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if file_identity(before) != file_identity(after) or total != before.st_size:
            raise BuilderHandoffError(f"{label} changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def sha256_file(path: Path) -> str:
    return hashlib.sha256(
        read_stable_file(path, label=f"file {path}", max_bytes=MAX_FILE_BYTES)
    ).hexdigest()


def write_bytes_exclusive(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o444)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise BuilderHandoffError("canonical output write stalled")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_json_exclusive(path: Path, value: dict[str, Any]) -> None:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    write_bytes_exclusive(path, payload)


def read_json(path: Path) -> dict[str, Any]:
    return decode_json_object(
        read_bounded_bytes(path, label=f"JSON input {path}"),
        label=f"JSON input {path}",
    )


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise BuilderHandoffError("JSON output write stalled")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="builder-handoff-v3")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in (
        "seal",
        "validate",
        "normalize-sbom",
        "subject-checksums",
        "predicate",
        "assemble",
    ):
        command = subparsers.add_parser(name)
        command.add_argument("--root", required=True, type=Path)
        add_source_arguments(command)
    validate = subparsers.choices["validate"]
    validate.add_argument("--require-sbom", action="store_true")
    validate.add_argument("--require-attestations", action="store_true")
    seal = subparsers.choices["seal"]
    seal.add_argument("--source-root", required=True, type=Path)
    predicate = subparsers.choices["predicate"]
    add_project_arguments(predicate)
    predicate.add_argument("--case-id", required=True)
    predicate.add_argument("--caller-repository", required=True)
    predicate.add_argument("--caller-commit", required=True)
    predicate.add_argument("--caller-workflow-ref", required=True)
    predicate.add_argument("--called-repository", required=True)
    predicate.add_argument("--called-workflow-ref", required=True)
    predicate.add_argument("--called-workflow-sha", required=True)
    predicate.add_argument("--handoff-commit", required=True)
    predicate.add_argument("--run-id", required=True)
    predicate.add_argument("--run-attempt", required=True)
    predicate.add_argument("--event-name", required=True)
    predicate.add_argument("--actor", required=True)
    predicate.add_argument("--triggering-actor", required=True)
    predicate.add_argument("--source-date-epoch", required=True)
    normalize = subparsers.choices["normalize-sbom"]
    normalize.add_argument("--source-date-epoch", required=True)
    assemble = subparsers.choices["assemble"]
    add_project_arguments(assemble)
    return parser


def add_source_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--project-version", required=True)


def add_project_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--upstream-repository", required=True)
    parser.add_argument("--upstream-commit", required=True)
    parser.add_argument("--target-repository", required=True)
    parser.add_argument("--release-tag", required=True)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "seal":
        seal_builder_output(
            args.root,
            source_root=args.source_root,
            source_repository=args.source_repository,
            source_commit=args.source_commit,
            source_tree=args.source_tree,
            project_version=args.project_version,
        )
    elif args.command == "normalize-sbom":
        normalize_spdx(
            args.root,
            source_repository=args.source_repository,
            source_commit=args.source_commit,
            source_tree=args.source_tree,
            project_version=args.project_version,
            source_date_epoch=args.source_date_epoch,
        )
    elif args.command == "subject-checksums":
        create_subject_checksums(
            args.root,
            source_repository=args.source_repository,
            source_commit=args.source_commit,
            source_tree=args.source_tree,
            project_version=args.project_version,
        )
    elif args.command == "validate":
        validate_builder_output(
            args.root,
            source_repository=args.source_repository,
            source_commit=args.source_commit,
            source_tree=args.source_tree,
            project_version=args.project_version,
            require_sbom=args.require_sbom,
            require_attestations=args.require_attestations,
        )
    elif args.command == "predicate":
        create_build_predicate(
            args.root,
            source_repository=args.source_repository,
            source_commit=args.source_commit,
            source_tree=args.source_tree,
            upstream_repository=args.upstream_repository,
            upstream_commit=args.upstream_commit,
            target_repository=args.target_repository,
            project_version=args.project_version,
            release_tag=args.release_tag,
            case_id=args.case_id,
            caller_repository=args.caller_repository,
            caller_commit=args.caller_commit,
            caller_workflow_ref=args.caller_workflow_ref,
            called_repository=args.called_repository,
            called_workflow_ref=args.called_workflow_ref,
            called_workflow_sha=args.called_workflow_sha,
            handoff_commit=args.handoff_commit,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            event_name=args.event_name,
            actor=args.actor,
            triggering_actor=args.triggering_actor,
            source_date_epoch=args.source_date_epoch,
        )
    else:
        assemble_evidence(
            args.root,
            source_repository=args.source_repository,
            source_commit=args.source_commit,
            source_tree=args.source_tree,
            upstream_repository=args.upstream_repository,
            upstream_commit=args.upstream_commit,
            target_repository=args.target_repository,
            project_version=args.project_version,
            release_tag=args.release_tag,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuilderHandoffError as error:
        print(f"builder handoff rejected: {error}", file=os.sys.stderr)
        raise SystemExit(2) from error
