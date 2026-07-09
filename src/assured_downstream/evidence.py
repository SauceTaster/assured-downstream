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


def compare_evidence_manifests(
    left: dict[str, Any],
    right: dict[str, Any],
) -> dict[str, Any]:
    failures = []
    warnings = []
    matches = []

    left_project = left.get("project", {})
    right_project = right.get("project", {})
    for field in ["source_full_name", "upstream_ref", "release_tag"]:
        if left_project.get(field) != right_project.get(field):
            failures.append(
                f"project {field} differs: {left_project.get(field)!r} != {right_project.get(field)!r}"
            )

    left_index = evidence_index(left)
    right_index = evidence_index(right)
    all_keys = sorted(set(left_index) | set(right_index))

    for key in all_keys:
        left_entry = left_index.get(key)
        right_entry = right_index.get(key)
        role, name = key
        if left_entry is None:
            failures.append(f"{role}: {name} missing from left manifest")
            continue
        if right_entry is None:
            failures.append(f"{role}: {name} missing from right manifest")
            continue
        if left_entry.get("sha256") != right_entry.get("sha256"):
            failures.append(f"{role}: {name} sha256 differs")
            continue
        if left_entry.get("size") != right_entry.get("size"):
            warnings.append(f"{role}: {name} size differs despite matching sha256")
        matches.append({"role": role, "name": name, "sha256": left_entry.get("sha256")})

    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "ok": not failures,
        "summary": {
            "matches": len(matches),
            "failures": len(failures),
            "warnings": len(warnings),
        },
        "matches": matches,
        "failures": failures,
        "warnings": warnings,
    }


def evidence_index(manifest: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    index = {}
    for role, entries in manifest.get("evidence", {}).items():
        for entry in entries:
            index[(role, entry["name"])] = entry
    return index


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
