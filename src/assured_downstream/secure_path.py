from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any


def require_secure_descriptor_traversal() -> None:
    if (
        not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or os.open not in os.supports_dir_fd
    ):
        raise OSError(
            "Secure directory traversal requires openat, O_DIRECTORY, and O_NOFOLLOW"
        )


def directory_identity(metadata: os.stat_result) -> tuple[int, int]:
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("path is not a directory")
    return metadata.st_dev, metadata.st_ino


def directory_identity_record(identity: tuple[int, int]) -> dict[str, int]:
    return {"device": identity[0], "inode": identity[1]}


def require_directory_identity(value: Any) -> tuple[int, int]:
    if (
        not isinstance(value, dict)
        or set(value) != {"device", "inode"}
        or type(value.get("device")) is not int
        or type(value.get("inode")) is not int
        or value["device"] < 0
        or value["inode"] <= 0
    ):
        raise ValueError("run root identity is invalid")
    return value["device"], value["inode"]


def open_absolute_directory_without_symlinks(
    path: Path,
    *,
    expected_identity: tuple[int, int] | None = None,
) -> int:
    require_secure_descriptor_traversal()
    path = Path(os.path.abspath(path.expanduser()))
    if not path.is_absolute() or not path.anchor:
        raise ValueError("secure directory root must be absolute")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
    )
    current = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            next_directory = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = next_directory
        actual_identity = directory_identity(os.fstat(current))
        if expected_identity is not None and actual_identity != expected_identity:
            raise ValueError("secure directory root identity changed")
        return current
    except Exception:
        os.close(current)
        raise


def secure_directory_identity(path: Path) -> tuple[int, int]:
    descriptor = open_absolute_directory_without_symlinks(path)
    try:
        return directory_identity(os.fstat(descriptor))
    finally:
        os.close(descriptor)


def open_directory_beneath(root_descriptor: int, relative: Path) -> int:
    if relative.is_absolute() or any(
        part in {"", ".", ".."} for part in relative.parts
    ):
        raise ValueError("relative directory path is invalid")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
    )
    current = os.dup(root_descriptor)
    try:
        for part in relative.parts:
            next_directory = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = next_directory
        return current
    except Exception:
        os.close(current)
        raise
