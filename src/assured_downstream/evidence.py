from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from assured_downstream.catalog import utc_now


CHUNK_SIZE = 1024 * 1024


def create_evidence_manifest(
    *,
    project: str,
    target_repo: str,
    upstream_ref: str,
    overlay_ref: str,
    release_tag: str,
    assurance: str,
    files: dict[str, list[Path]],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "project": {
            "source_full_name": project,
            "target_full_name": target_repo,
            "upstream_ref": upstream_ref,
            "overlay_ref": overlay_ref,
            "release_tag": release_tag,
            "assurance": assurance,
        },
        "evidence": {
            role: [file_entry(path, role=role) for path in paths]
            for role, paths in files.items()
        },
    }


def verify_evidence_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    failures = []
    for role, entries in manifest.get("evidence", {}).items():
        for entry in entries:
            path = Path(entry["path"])
            if not path.exists():
                failures.append(f"{role}: missing {path}")
                continue
            actual = sha256_file(path)
            expected = entry.get("sha256")
            if actual != expected:
                failures.append(f"{role}: sha256 mismatch for {path}")
            size = path.stat().st_size
            if size != entry.get("size"):
                failures.append(f"{role}: size mismatch for {path}")
    return {
        "ok": not failures,
        "failures": failures,
    }


def file_entry(path: Path, *, role: str) -> dict[str, Any]:
    resolved = path.resolve()
    if not resolved.exists():
        raise FileNotFoundError(resolved)
    if not resolved.is_file():
        raise ValueError(f"Evidence path is not a file: {resolved}")
    return {
        "role": role,
        "path": str(resolved),
        "name": resolved.name,
        "size": resolved.stat().st_size,
        "sha256": sha256_file(resolved),
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()

