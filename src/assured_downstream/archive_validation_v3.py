from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import io
import json
import math
import os
import re
import stat
import tarfile
import unicodedata
import zipfile
from contextlib import contextmanager
from email import policy as email_policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Mapping


MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_TAR_STREAM_BYTES = MAX_TOTAL_BYTES + 64 * 1024 * 1024
MAX_MEMBERS = 100_000
MAX_PATH_BYTES = 4096
MAX_SEGMENT_BYTES = 255
MAX_PAX_BYTES = 64 * 1024
MAX_PAX_HEADERS = 16
COPY_CHUNK_SIZE = 1024 * 1024
MAX_WHEEL_METADATA_BYTES = 8 * 1024 * 1024
WHEEL_FILENAME_PATTERN = re.compile(
    r"^(?P<distribution>[A-Za-z0-9_.]+)-"
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9_.!+]*)-"
    r"(?P<python>[A-Za-z0-9_.]+)-"
    r"(?P<abi>[A-Za-z0-9_.]+)-"
    r"(?P<platform>[A-Za-z0-9_.]+)\.whl$"
)


class ArchiveValidationError(RuntimeError):
    pass


class BoundedReader:
    def __init__(self, handle: BinaryIO, *, limit: int) -> None:
        self.handle = handle
        self.limit = limit
        self.total = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self.limit - self.total
        requested = remaining + 1 if size < 0 else min(size, remaining + 1)
        payload = self.handle.read(requested)
        self.total += len(payload)
        if self.total > self.limit:
            raise ArchiveValidationError("archive exceeds its expanded size limit")
        return payload


def validate_artifact_transforms(
    root: Path,
    report: dict[str, Any],
    *,
    source_date_epoch: int,
    paths_by_logical_name: Mapping[str, Path] | None = None,
) -> None:
    for item in report.get("artifacts", []):
        name = item["path"]
        raw_logical_path = item["original"]["path"]
        final_logical_path = item["final"]["path"]
        try:
            raw_path = (
                root / raw_logical_path
                if paths_by_logical_name is None
                else paths_by_logical_name[raw_logical_path]
            )
            final_path = (
                root / final_logical_path
                if paths_by_logical_name is None
                else paths_by_logical_name[final_logical_path]
            )
        except KeyError as exc:
            raise ArchiveValidationError(
                "archive storage map is missing a logical artifact"
            ) from exc
        if name.endswith(".tar.gz"):
            raw = inspect_sdist(raw_path, require_canonical=False)
            final = inspect_sdist(
                final_path,
                source_date_epoch=source_date_epoch,
                require_canonical=True,
            )
            expected = {
                "member_count": item["member_count"],
                "payload_size": item["payload_size"],
                "payload_sha256": item["payload_sha256"],
                "sdist_layout": item["sdist_layout"],
            }
            observed_raw = {field: raw[field] for field in expected}
            observed_final = {field: final[field] for field in expected}
            if observed_raw != expected or observed_final != expected:
                raise ArchiveValidationError(
                    "sdist transform report does not match archive semantics"
                )
            expected_root = name.removesuffix(".tar.gz")
            if raw["root"] != expected_root or final["root"] != expected_root:
                raise ArchiveValidationError(
                    "sdist root directory does not match its filename"
                )
        elif name.endswith(".whl"):
            validate_wheel(final_path)
        else:
            raise ArchiveValidationError("unsupported Python release artifact")


def inspect_sdist(
    path: Path,
    *,
    source_date_epoch: int | None = None,
    require_canonical: bool,
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    observed_order: list[str] = []
    all_paths: set[str] = set()
    folded_paths: set[str] = set()
    file_paths: set[str] = set()
    folded_file_paths: set[str] = set()
    parent_paths: set[str] = set()
    folded_parent_paths: set[str] = set()
    prefix_aliases: dict[str, str] = {}
    payload_size = 0
    pending_pax: dict[str, str] | None = None
    end_marker_seen = False
    trailing_size = 0
    gzip_header: dict[str, int]
    try:
        with stable_binary_file(
            path,
            label="sdist",
            max_bytes=MAX_ARTIFACT_BYTES,
        ) as raw_handle:
            gzip_header = read_gzip_header(raw_handle)
            raw_handle.seek(0)
            with gzip.GzipFile(fileobj=raw_handle, mode="rb") as gzip_handle:
                stream = BoundedReader(gzip_handle, limit=MAX_TAR_STREAM_BYTES)
                while True:
                    header = read_exact(stream, tarfile.BLOCKSIZE)
                    if not any(header):
                        if pending_pax is not None:
                            raise ArchiveValidationError(
                                "sdist PAX header has no following member"
                            )
                        second = read_exact(stream, tarfile.BLOCKSIZE)
                        if any(second):
                            raise ArchiveValidationError(
                                "sdist is missing its second zero end marker"
                            )
                        end_marker_seen = True
                        while trailing := stream.read(COPY_CHUNK_SIZE):
                            if any(trailing):
                                raise ArchiveValidationError(
                                    "sdist has nonzero trailing tar data"
                                )
                            trailing_size += len(trailing)
                        break
                    try:
                        member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
                    except (tarfile.HeaderError, UnicodeError, ValueError) as exc:
                        raise ArchiveValidationError(
                            "sdist tar header is invalid"
                        ) from exc
                    if member.type == tarfile.XHDTYPE:
                        if require_canonical:
                            raise ArchiveValidationError(
                                "canonical sdist contains a PAX extension"
                            )
                        if pending_pax is not None:
                            raise ArchiveValidationError("sdist chains PAX headers")
                        if member.size <= 0 or member.size > MAX_PAX_BYTES:
                            raise ArchiveValidationError("sdist PAX body is oversized")
                        body = read_exact(stream, member.size)
                        require_zero_padding(stream, member.size)
                        pending_pax = parse_pax_records(body)
                        continue
                    if member.type in {
                        tarfile.GNUTYPE_LONGNAME,
                        tarfile.GNUTYPE_LONGLINK,
                        tarfile.GNUTYPE_SPARSE,
                        tarfile.XGLTYPE,
                        tarfile.SOLARIS_XHDTYPE,
                    }:
                        raise ArchiveValidationError(
                            "sdist contains a forbidden tar extension"
                        )
                    if pending_pax is not None:
                        if "path" in pending_pax:
                            member.name = pending_pax["path"]
                        if "mtime" in pending_pax:
                            member.mtime = parse_pax_mtime(pending_pax["mtime"])
                        member.pax_headers = pending_pax
                        pending_pax = None
                    if not (member.isfile() or member.isdir()):
                        raise ArchiveValidationError(
                            "sdist links and special members are forbidden"
                        )
                    name = safe_member_name(member.name, is_directory=member.isdir())
                    register_member_path(
                        name,
                        is_file=member.isfile(),
                        all_paths=all_paths,
                        folded_paths=folded_paths,
                        file_paths=file_paths,
                        folded_file_paths=folded_file_paths,
                        parent_paths=parent_paths,
                        folded_parent_paths=folded_parent_paths,
                        prefix_aliases=prefix_aliases,
                    )
                    observed_order.append(name)
                    if len(observed_order) > MAX_MEMBERS:
                        raise ArchiveValidationError("sdist has too many members")
                    size = member.size
                    if size < 0 or size > MAX_ARTIFACT_BYTES:
                        raise ArchiveValidationError("sdist member size is invalid")
                    if member.isdir() and size != 0:
                        raise ArchiveValidationError("sdist directory has data")
                    payload_size += size
                    if payload_size > MAX_TOTAL_BYTES:
                        raise ArchiveValidationError("sdist payload exceeds its limit")
                    content_sha256 = None
                    if member.isfile():
                        content_sha256 = digest_exact(stream, size)
                        require_zero_padding(stream, size)
                    mode = canonical_member_mode(member)
                    record = {
                        "name": name,
                        "type": "file" if member.isfile() else "directory",
                        "mode": mode,
                        "size": size,
                        "sha256": content_sha256,
                    }
                    records.append(record)
                    if require_canonical:
                        validate_canonical_member(
                            member,
                            header=header,
                            mode=mode,
                            source_date_epoch=source_date_epoch,
                        )
    except (EOFError, gzip.BadGzipFile, OSError, OverflowError) as exc:
        raise ArchiveValidationError("sdist gzip or tar stream is malformed") from exc
    if not end_marker_seen or not records:
        raise ArchiveValidationError("sdist is empty or lacks an end marker")
    if require_canonical and (
        stream.total % tarfile.RECORDSIZE != 0 or trailing_size >= tarfile.RECORDSIZE
    ):
        raise ArchiveValidationError("canonical sdist record padding is invalid")
    sorted_records = sorted(records, key=lambda item: item["name"].encode("utf-8"))
    if require_canonical and observed_order != [
        item["name"] for item in sorted_records
    ]:
        raise ArchiveValidationError("canonical sdist member order is invalid")
    roots = {item["name"].split("/", 1)[0] for item in sorted_records}
    if len(roots) != 1:
        raise ArchiveValidationError("sdist must contain one top-level directory")
    root = next(iter(roots))
    files = {item["name"] for item in sorted_records if item["type"] == "file"}
    if f"{root}/PKG-INFO" not in files:
        raise ArchiveValidationError("sdist has no PKG-INFO")
    if f"{root}/pyproject.toml" in files:
        layout = "modern-pyproject"
    elif f"{root}/setup.py" in files:
        layout = "legacy-setup-py"
    else:
        raise ArchiveValidationError("sdist has no supported build layout")
    identities = [
        {
            "name": item["name"],
            "type": item["type"],
            "mode": item["mode"],
            "size": item["size"],
            "sha256": item["sha256"],
        }
        for item in sorted_records
    ]
    if require_canonical and gzip_header != {
        "flags": 0,
        "mtime": source_date_epoch,
        "xfl": 2,
        "os": 255,
    }:
        raise ArchiveValidationError("canonical sdist gzip header is invalid")
    return {
        "root": root,
        "sdist_layout": layout,
        "member_count": len(sorted_records),
        "payload_size": payload_size,
        "payload_sha256": hashlib.sha256(
            json.dumps(identities, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def validate_wheel(path: Path) -> None:
    filename_match = WHEEL_FILENAME_PATTERN.fullmatch(path.name)
    if filename_match is None:
        raise ArchiveValidationError("wheel filename identity is unsupported")
    filename_identity = filename_match.groupdict()
    dist_info = (
        f"{filename_identity['distribution']}-{filename_identity['version']}.dist-info"
    )
    metadata_path = f"{dist_info}/METADATA"
    record_path = f"{dist_info}/RECORD"
    wheel_path = f"{dist_info}/WHEEL"
    names: set[str] = set()
    folded_names: set[str] = set()
    file_paths: set[str] = set()
    folded_file_paths: set[str] = set()
    parent_paths: set[str] = set()
    folded_parent_paths: set[str] = set()
    prefix_aliases: dict[str, str] = {}
    total = 0
    file_identities: dict[str, tuple[int, str]] = {}
    metadata_payloads: dict[str, bytes] = {}
    try:
        with stable_binary_file(
            path,
            label="wheel",
            max_bytes=MAX_ARTIFACT_BYTES,
        ) as wheel_handle:
            with zipfile.ZipFile(wheel_handle) as archive:
                infos = archive.infolist()
                if not infos or len(infos) > MAX_MEMBERS:
                    raise ArchiveValidationError("wheel member count is invalid")
                for info in infos:
                    if info.flag_bits & 0x1:
                        raise ArchiveValidationError(
                            "encrypted wheel members are forbidden"
                        )
                    if info.compress_type not in {
                        zipfile.ZIP_STORED,
                        zipfile.ZIP_DEFLATED,
                    }:
                        raise ArchiveValidationError(
                            "wheel compression method is unsupported"
                        )
                    is_directory = info.is_dir()
                    name = safe_member_name(info.filename, is_directory=is_directory)
                    register_member_path(
                        name,
                        is_file=not is_directory,
                        all_paths=names,
                        folded_paths=folded_names,
                        file_paths=file_paths,
                        folded_file_paths=folded_file_paths,
                        parent_paths=parent_paths,
                        folded_parent_paths=folded_parent_paths,
                        prefix_aliases=prefix_aliases,
                    )
                    unix_mode = (info.external_attr >> 16) & 0xFFFF
                    if unix_mode and not (
                        stat.S_ISREG(unix_mode) or stat.S_ISDIR(unix_mode)
                    ):
                        raise ArchiveValidationError(
                            "wheel special members are forbidden"
                        )
                    if info.file_size < 0 or info.file_size > MAX_ARTIFACT_BYTES:
                        raise ArchiveValidationError("wheel member size is invalid")
                    total += info.file_size
                    if total > MAX_TOTAL_BYTES:
                        raise ArchiveValidationError("wheel payload exceeds its limit")
                    if not is_directory:
                        with archive.open(info) as member:
                            copied = 0
                            digest = hashlib.sha256()
                            retained = bytearray()
                            while chunk := member.read(COPY_CHUNK_SIZE):
                                copied += len(chunk)
                                if copied > info.file_size:
                                    raise ArchiveValidationError(
                                        "wheel member exceeds its declared size"
                                    )
                                digest.update(chunk)
                                if name in {metadata_path, record_path, wheel_path}:
                                    retained.extend(chunk)
                                    if len(retained) > MAX_WHEEL_METADATA_BYTES:
                                        raise ArchiveValidationError(
                                            "wheel metadata exceeds its size limit"
                                        )
                            if copied != info.file_size:
                                raise ArchiveValidationError(
                                    "wheel member is shorter than declared"
                                )
                        file_identities[name] = (copied, digest.hexdigest())
                        if name in {metadata_path, record_path, wheel_path}:
                            metadata_payloads[name] = bytes(retained)
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise ArchiveValidationError("wheel ZIP structure is malformed") from exc
    if set(metadata_payloads) != {metadata_path, record_path, wheel_path}:
        raise ArchiveValidationError("wheel metadata set is incomplete")
    dist_info_directories = {
        name.split("/", 1)[0] for name in names if ".dist-info/" in f"{name}/"
    }
    if dist_info_directories != {dist_info}:
        raise ArchiveValidationError("wheel dist-info identity is ambiguous")
    validate_wheel_metadata(
        metadata_payloads[metadata_path],
        filename_identity=filename_identity,
    )
    validate_wheel_descriptor(
        metadata_payloads[wheel_path],
        filename_identity=filename_identity,
    )
    validate_wheel_record(
        metadata_payloads[record_path],
        record_path=record_path,
        file_identities=file_identities,
    )


def validate_wheel_metadata(
    payload: bytes,
    *,
    filename_identity: dict[str, str],
) -> None:
    try:
        message = BytesParser(policy=email_policy.default).parsebytes(payload)
    except (TypeError, ValueError) as exc:
        raise ArchiveValidationError("wheel METADATA is malformed") from exc
    names = message.get_all("Name", [])
    versions = message.get_all("Version", [])
    expected_name = re.sub(r"[-_.]+", "-", filename_identity["distribution"]).lower()
    observed_name = (
        re.sub(r"[-_.]+", "-", names[0]).lower() if len(names) == 1 else None
    )
    if (
        message.defects
        or observed_name != expected_name
        or versions != [filename_identity["version"]]
    ):
        raise ArchiveValidationError("wheel METADATA does not match its filename")


def validate_wheel_descriptor(
    payload: bytes,
    *,
    filename_identity: dict[str, str],
) -> None:
    try:
        message = BytesParser(policy=email_policy.default).parsebytes(payload)
    except (TypeError, ValueError) as exc:
        raise ArchiveValidationError("wheel WHEEL descriptor is malformed") from exc
    expected_tags = {
        f"{python_tag}-{abi_tag}-{platform_tag}"
        for python_tag in filename_identity["python"].split(".")
        for abi_tag in filename_identity["abi"].split(".")
        for platform_tag in filename_identity["platform"].split(".")
    }
    if (
        message.defects
        or message.get_all("Wheel-Version", []) != ["1.0"]
        or set(message.get_all("Tag", [])) != expected_tags
    ):
        raise ArchiveValidationError(
            "wheel WHEEL descriptor does not match its filename"
        )


def validate_wheel_record(
    payload: bytes,
    *,
    record_path: str,
    file_identities: dict[str, tuple[int, str]],
) -> None:
    try:
        text = payload.decode("utf-8", "strict")
        rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise ArchiveValidationError("wheel RECORD is malformed") from exc
    recorded: set[str] = set()
    for row in rows:
        if len(row) != 3:
            raise ArchiveValidationError("wheel RECORD row is malformed")
        name = safe_member_name(row[0], is_directory=False)
        if name in recorded or name not in file_identities:
            raise ArchiveValidationError("wheel RECORD path is duplicated or unknown")
        recorded.add(name)
        digest_field, size_field = row[1:]
        if name == record_path:
            if digest_field or size_field:
                raise ArchiveValidationError("wheel RECORD self-entry is not empty")
            continue
        size, digest = file_identities[name]
        encoded_digest = base64.urlsafe_b64encode(bytes.fromhex(digest)).rstrip(b"=")
        if (
            digest_field != f"sha256={encoded_digest.decode('ascii')}"
            or size_field != str(size)
        ):
            raise ArchiveValidationError("wheel RECORD digest or size is invalid")
    if recorded != set(file_identities):
        raise ArchiveValidationError("wheel RECORD does not cover every file")


@contextmanager
def stable_binary_file(
    path: Path,
    *,
    label: str,
    max_bytes: int,
) -> Any:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ArchiveValidationError(f"{label} could not be opened") from exc
    handle = os.fdopen(descriptor, "rb", closefd=True)
    try:
        before = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > max_bytes
        ):
            raise ArchiveValidationError(
                f"{label} is not a bounded standalone regular file"
            )
        yield handle
        after = os.fstat(handle.fileno())
        if file_identity(before) != file_identity(after):
            raise ArchiveValidationError(f"{label} changed during validation")
    finally:
        handle.close()


def file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def read_gzip_header(handle: BinaryIO) -> dict[str, int]:
    header = handle.read(10)
    if len(header) != 10 or header[:3] != b"\x1f\x8b\x08":
        raise ArchiveValidationError("sdist gzip header is invalid")
    if header[3] & 0xE0:
        raise ArchiveValidationError("sdist gzip header uses reserved flags")
    return {
        "flags": header[3],
        "mtime": int.from_bytes(header[4:8], "little"),
        "xfl": header[8],
        "os": header[9],
    }


def read_exact(handle: Any, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = handle.read(min(remaining, COPY_CHUNK_SIZE))
        if not chunk:
            raise ArchiveValidationError("archive body is truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def digest_exact(handle: Any, size: int) -> str:
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        chunk = handle.read(min(remaining, COPY_CHUNK_SIZE))
        if not chunk:
            raise ArchiveValidationError("archive member is truncated")
        digest.update(chunk)
        remaining -= len(chunk)
    return digest.hexdigest()


def require_zero_padding(handle: Any, size: int) -> None:
    padding = -size % tarfile.BLOCKSIZE
    if padding and any(read_exact(handle, padding)):
        raise ArchiveValidationError("archive member padding is not zero-filled")


def parse_pax_records(payload: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    position = 0
    while position < len(payload):
        space = payload.find(b" ", position, min(len(payload), position + 24))
        if space < 0:
            raise ArchiveValidationError("PAX record length is invalid")
        length_text = payload[position:space]
        if (
            not length_text
            or not length_text.isascii()
            or not length_text.isdigit()
            or (len(length_text) > 1 and length_text.startswith(b"0"))
        ):
            raise ArchiveValidationError("PAX record length is invalid")
        length = int(length_text)
        end = position + length
        if length < 5 or end > len(payload):
            raise ArchiveValidationError("PAX record framing is invalid")
        record = payload[space + 1 : end]
        if not record.endswith(b"\n"):
            raise ArchiveValidationError("PAX record terminator is invalid")
        key_bytes, separator, value_bytes = record[:-1].partition(b"=")
        if not key_bytes or not separator or b"\x00" in record:
            raise ArchiveValidationError("PAX key/value framing is invalid")
        try:
            key = key_bytes.decode("utf-8", "strict")
            value = value_bytes.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise ArchiveValidationError("PAX key/value is not UTF-8") from exc
        if key not in {"path", "mtime"} or key in headers:
            raise ArchiveValidationError("PAX header is unsupported or duplicated")
        headers[key] = value
        if len(headers) > MAX_PAX_HEADERS:
            raise ArchiveValidationError("PAX header count exceeds its limit")
        position = end
    if not headers:
        raise ArchiveValidationError("PAX body is empty")
    return headers


def parse_pax_mtime(value: str) -> int:
    if (
        len(value.encode("utf-8")) > 64
        or re.fullmatch(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", value) is None
    ):
        raise ArchiveValidationError("PAX mtime is invalid")
    return int(value.partition(".")[0])


def safe_member_name(value: str, *, is_directory: bool) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ArchiveValidationError("archive member path is invalid")
    candidate = value[:-1] if is_directory and value.endswith("/") else value
    if (
        not candidate
        or candidate.endswith("/")
        or unicodedata.normalize("NFC", candidate) != candidate
        or any(ord(character) < 32 or ord(character) == 127 for character in candidate)
    ):
        raise ArchiveValidationError("archive member path is not canonical")
    components = candidate.split("/")
    path = PurePosixPath(candidate)
    if (
        path.is_absolute()
        or path.as_posix() != candidate
        or any(component in {"", ".", ".."} for component in components)
        or len(candidate.encode("utf-8")) > MAX_PATH_BYTES
        or any(
            len(component.encode("utf-8")) > MAX_SEGMENT_BYTES
            for component in components
        )
    ):
        raise ArchiveValidationError("archive member path is unsafe")
    return candidate


def register_member_path(
    name: str,
    *,
    is_file: bool,
    all_paths: set[str],
    folded_paths: set[str],
    file_paths: set[str],
    folded_file_paths: set[str],
    parent_paths: set[str],
    folded_parent_paths: set[str],
    prefix_aliases: dict[str, str],
) -> None:
    folded = name.casefold()
    if name in all_paths or folded in folded_paths:
        raise ArchiveValidationError("archive contains a duplicate or aliased path")
    components = name.split("/")
    prefixes = ["/".join(components[:index]) for index in range(1, len(components))]
    folded_prefixes = {prefix.casefold() for prefix in prefixes}
    for prefix in prefixes:
        prior = prefix_aliases.get(prefix.casefold())
        if prior is not None and prior != prefix:
            raise ArchiveValidationError("archive contains a directory case-fold alias")
        prefix_aliases[prefix.casefold()] = prefix
    if (
        set(prefixes) & file_paths
        or folded_prefixes & folded_file_paths
        or (is_file and (name in parent_paths or folded in folded_parent_paths))
    ):
        raise ArchiveValidationError("archive contains a file/directory collision")
    all_paths.add(name)
    folded_paths.add(folded)
    parent_paths.update(prefixes)
    folded_parent_paths.update(folded_prefixes)
    if is_file:
        file_paths.add(name)
        folded_file_paths.add(folded)


def canonical_member_mode(member: tarfile.TarInfo) -> int:
    if member.mode < 0 or member.mode & ~0o777:
        raise ArchiveValidationError("archive member mode contains special bits")
    if member.isdir():
        return 0o755
    return 0o755 if member.mode & 0o111 else 0o644


def validate_canonical_member(
    member: tarfile.TarInfo,
    *,
    header: bytes,
    mode: int,
    source_date_epoch: int | None,
) -> None:
    mtime = member.mtime
    if isinstance(mtime, bool) or not isinstance(mtime, (int, float)):
        raise ArchiveValidationError("canonical member mtime is invalid")
    if isinstance(mtime, float) and not math.isfinite(mtime):
        raise ArchiveValidationError("canonical member mtime is not finite")
    if (
        source_date_epoch is None
        or int(mtime) != source_date_epoch
        or mtime != int(mtime)
        or member.uid != 0
        or member.gid != 0
        or member.uname != ""
        or member.gname != ""
        or member.mode != mode
    ):
        raise ArchiveValidationError("canonical member metadata is not exact")
    try:
        expected_header = member.tobuf(
            format=tarfile.PAX_FORMAT,
            encoding="utf-8",
            errors="strict",
        )
    except (UnicodeError, ValueError) as exc:
        raise ArchiveValidationError(
            "canonical member header cannot be rebuilt"
        ) from exc
    if len(expected_header) != tarfile.BLOCKSIZE or header != expected_header:
        raise ArchiveValidationError("canonical member tar header is not exact")
