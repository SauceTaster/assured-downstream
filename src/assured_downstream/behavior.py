from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from assured_downstream.catalog import utc_now


def normalize_trace(
    trace: dict[str, Any],
    *,
    workspace_root: Path | None = None,
) -> dict[str, Any]:
    events = trace.get("events", [])
    normalized = {
        "processes": sorted(set(normalize_process(event, workspace_root) for event in events if event_kind(event) == "process")),
        "files": sorted(set(normalize_file(event, workspace_root) for event in events if event_kind(event) == "file")),
        "network": sorted(set(normalize_network(event) for event in events if event_kind(event) == "network")),
        "syscalls": sorted(set(normalize_syscall(event) for event in events if event_kind(event) == "syscall")),
    }
    digest = digest_normalized(normalized)
    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "digest": digest,
        "summary": {
            "processes": len(normalized["processes"]),
            "files": len(normalized["files"]),
            "network": len(normalized["network"]),
            "syscalls": len(normalized["syscalls"]),
        },
        "normalized": normalized,
    }


def compare_behavior_reports(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    left_normalized = left.get("normalized", {})
    right_normalized = right.get("normalized", {})
    differences = {}

    for category in ["processes", "files", "network", "syscalls"]:
        left_values = set(left_normalized.get(category, []))
        right_values = set(right_normalized.get(category, []))
        only_left = sorted(left_values - right_values)
        only_right = sorted(right_values - left_values)
        if only_left or only_right:
            differences[category] = {
                "only_left": only_left,
                "only_right": only_right,
            }

    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "ok": not differences and left.get("digest") == right.get("digest"),
        "left_digest": left.get("digest"),
        "right_digest": right.get("digest"),
        "differences": differences,
    }


def event_kind(event: dict[str, Any]) -> str | None:
    return event.get("kind") or event.get("type") or event.get("event_type")


def normalize_process(event: dict[str, Any], workspace_root: Path | None) -> str:
    exe = normalize_path(event.get("exe") or event.get("executable") or event.get("process") or "unknown", workspace_root)
    parent = normalize_path(event.get("parent_exe") or event.get("parent") or "unknown", workspace_root)
    argv = event.get("argv") or []
    argv_head = argv[0] if argv else ""
    return f"{parent} -> {exe} argv0={argv_head}"


def normalize_file(event: dict[str, Any], workspace_root: Path | None) -> str:
    operation = event.get("op") or event.get("operation") or "access"
    path = normalize_path(event.get("path") or event.get("file") or "unknown", workspace_root)
    boundary = file_boundary(path)
    return f"{operation}:{boundary}:{path}"


def normalize_network(event: dict[str, Any]) -> str:
    host = event.get("host") or event.get("hostname") or event.get("destination") or "unknown"
    port = event.get("port") or event.get("destination_port") or ""
    protocol = event.get("protocol") or "tcp"
    return f"{protocol}:{host}:{port}"


def normalize_syscall(event: dict[str, Any]) -> str:
    name = event.get("name") or event.get("syscall") or "unknown"
    category = event.get("category") or syscall_category(name)
    return f"{category}:{name}"


def normalize_path(value: str, workspace_root: Path | None) -> str:
    path = str(value)
    if workspace_root is None:
        return path
    root = str(workspace_root.resolve())
    if path.startswith(root):
        return "$WORKSPACE" + path[len(root):]
    return path


def file_boundary(path: str) -> str:
    if path.startswith("$WORKSPACE"):
        return "workspace"
    if path.startswith("/tmp") or path.startswith("/var/tmp"):
        return "temp"
    if path.startswith("/etc") or path.startswith("/root") or path.startswith("/home"):
        return "host-sensitive"
    return "system"


def syscall_category(name: str) -> str:
    privileged = {
        "bpf",
        "capset",
        "clone3",
        "init_module",
        "kexec_load",
        "mount",
        "ptrace",
        "setns",
        "swapon",
        "unshare",
    }
    network = {"accept", "bind", "connect", "listen", "recvfrom", "sendto", "socket"}
    filesystem = {"chmod", "chown", "creat", "mkdir", "open", "openat", "rename", "unlink"}
    if name in privileged:
        return "privileged"
    if name in network:
        return "network"
    if name in filesystem:
        return "filesystem"
    return "other"


def digest_normalized(normalized: dict[str, Any]) -> str:
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

