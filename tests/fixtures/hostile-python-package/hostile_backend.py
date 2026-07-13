from __future__ import annotations

import base64
import csv
import errno
import hashlib
import io
import json
import os
import signal
import tarfile
import zipfile
from pathlib import Path
from typing import Callable


NAME = "assured-hostile-fixture"
NORMALIZED_NAME = "assured_hostile_fixture"
VERSION = "0.0.1"


def get_requires_for_build_sdist(config_settings=None) -> list[str]:
    return []


def get_requires_for_build_wheel(config_settings=None) -> list[str]:
    return []


def build_sdist(sdist_directory, config_settings=None) -> str:
    output = Path(sdist_directory)
    output.mkdir(parents=True, exist_ok=True)
    write_probe(output)
    filename = f"{NAME}-{VERSION}.tar.gz"
    root = f"{NAME}-{VERSION}"
    with tarfile.open(output / filename, "w:gz") as archive:
        metadata = package_metadata().encode()
        metadata_info = tarfile.TarInfo(f"{root}/PKG-INFO")
        metadata_info.mode = 0o644
        metadata_info.size = len(metadata)
        metadata_info.mtime = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
        archive.addfile(metadata_info, io.BytesIO(metadata))
        for source in (
            Path("pyproject.toml"),
            Path("hostile_backend.py"),
            Path("hostile_fixture/__init__.py"),
        ):
            archive.add(source, arcname=f"{root}/{source.as_posix()}", recursive=False)
    return filename


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None) -> str:
    output = Path(wheel_directory)
    output.mkdir(parents=True, exist_ok=True)
    write_probe(output)
    filename = f"{NORMALIZED_NAME}-{VERSION}-py3-none-any.whl"
    dist_info = f"{NORMALIZED_NAME}-{VERSION}.dist-info"
    members = {
        "hostile_fixture/__init__.py": '__version__ = "0.0.1"\n',
        f"{dist_info}/METADATA": package_metadata(),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: assured-hostile-fixture\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ),
    }
    record_rows = []
    with zipfile.ZipFile(
        output / filename, "w", compression=zipfile.ZIP_DEFLATED
    ) as wheel:
        for path, value in sorted(members.items()):
            payload = value.encode()
            wheel.writestr(path, payload)
            digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(
                b"="
            )
            record_rows.append((path, f"sha256={digest.decode()}", str(len(payload))))
        record_path = f"{dist_info}/RECORD"
        record_rows.append((record_path, "", ""))
        record_buffer = io.StringIO(newline="")
        csv.writer(record_buffer, lineterminator="\n").writerows(record_rows)
        wheel.writestr(record_path, record_buffer.getvalue().encode())
    return filename


def package_metadata() -> str:
    return (
        "Metadata-Version: 2.1\n"
        f"Name: {NAME}\n"
        f"Version: {VERSION}\n"
        "Summary: Assured Downstream adversarial build fixture\n"
    )


def write_probe(output: Path) -> None:
    attempts = {
        "collector-signal": attempt(signal_collector),
        "entrypoint-write": attempt(
            lambda: Path("/opt/assured-downstream/entrypoint.py").open("ab")
        ),
        "evidence-list": attempt(lambda: list(Path("/out").iterdir())),
        "evidence-write": attempt(
            lambda: Path("/out/tamper-marker").write_text(
                "tampered\n", encoding="utf-8"
            )
        ),
        "root-memory-read": attempt(lambda: Path("/proc/1/mem").open("rb")),
    }
    status = process_status()
    record = {
        "schema_version": 1,
        "uid": os.getuid(),
        "euid": os.geteuid(),
        "gid": os.getgid(),
        "egid": os.getegid(),
        "cap_eff": status.get("CapEff"),
        "no_new_privileges": integer_status(status, "NoNewPrivs"),
        "seccomp": integer_status(status, "Seccomp"),
        "attempts": attempts,
    }
    (output / "hostile-probe.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def signal_collector() -> None:
    status = process_status(Path("/proc/1/status"))
    uid_fields = status.get("Uid", "").split()
    if not uid_fields or int(uid_fields[0]) == os.getuid():
        raise RuntimeError("PID 1 is not a distinct privileged collector")
    os.kill(1, signal.SIGTERM)


def attempt(action: Callable[[], object]) -> dict[str, object]:
    try:
        value = action()
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EPERM, errno.EROFS}:
            return {"outcome": "denied", "errno": exc.errno}
        return {"outcome": "os-error", "errno": exc.errno, "error": str(exc)}
    except Exception as exc:
        return {"outcome": "error", "error": str(exc)}
    if hasattr(value, "close"):
        value.close()
    return {"outcome": "unexpected-success"}


def process_status(path: Path = Path("/proc/self/status")) -> dict[str, str]:
    values = {}
    try:
        status = path.read_text(encoding="utf-8")
    except OSError:
        return values
    for line in status.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            values[key] = value.strip()
    return values


def integer_status(status: dict[str, str], key: str) -> int | None:
    value = status.get(key)
    return int(value) if value is not None and value.isdigit() else None
