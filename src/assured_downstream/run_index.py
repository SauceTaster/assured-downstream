from __future__ import annotations

import json
from dataclasses import dataclass
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from assured_downstream.catalog import utc_now


SCHEMA_VERSION = 1


@dataclass
class RunIndexLoadResult:
    data: dict[str, Any]
    recovered_from: str | None = None


def empty_run_index() -> dict[str, Any]:
    now = utc_now()
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now,
        "updated_at": now,
        "runs": [],
    }


def load_run_index(path: Path) -> dict[str, Any]:
    return load_run_index_for_update(path).data


def load_run_index_for_update(path: Path) -> RunIndexLoadResult:
    if not path.exists():
        return RunIndexLoadResult(empty_run_index())

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except JSONDecodeError:
        backup_path = backup_malformed_index(path)
        return RunIndexLoadResult(empty_run_index(), recovered_from=str(backup_path))

    if not isinstance(data, dict):
        backup_path = backup_malformed_index(path)
        return RunIndexLoadResult(empty_run_index(), recovered_from=str(backup_path))

    if data.get("schema_version") != SCHEMA_VERSION:
        version = data.get("schema_version")
        raise ValueError(f"Unsupported run index schema_version: {version!r}")

    runs = data.setdefault("runs", [])
    if not isinstance(runs, list):
        backup_path = backup_malformed_index(path)
        return RunIndexLoadResult(empty_run_index(), recovered_from=str(backup_path))

    data.setdefault("generated_at", utc_now())
    data.setdefault("updated_at", utc_now())
    return RunIndexLoadResult(data)


def append_run_record(path: Path, record: dict[str, Any]) -> dict[str, Any]:
    load_result = load_run_index_for_update(path)
    index = load_result.data

    entry = dict(record)
    entry.setdefault("recorded_at", utc_now())
    if load_result.recovered_from:
        entry.setdefault("warnings", []).append(
            {
                "code": "run_index_recovered",
                "message": "Existing run index was malformed and was preserved before writing a new index.",
                "recovered_from": load_result.recovered_from,
            }
        )

    index.setdefault("runs", []).append(entry)
    index["updated_at"] = utc_now()
    atomic_write_json(path, index)
    return entry


def create_pilot_run_record(
    *,
    run_id: str,
    started_at: str,
    seed_refs: list[str],
    org: str,
    run_dir: Path,
    output_paths: dict[str, str | None],
    counts: dict[str, int],
    status: str,
    failures: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "started_at": started_at,
        "recorded_at": utc_now(),
        "kind": "pilot",
        "status": status,
        "seed_refs": seed_refs,
        "org": org,
        "run_dir": str(run_dir),
        "output_paths": output_paths,
        "counts": counts,
        "failures": failures or [],
    }


def backup_malformed_index(path: Path) -> Path:
    timestamp = utc_now().replace(":", "").replace("+", "")
    backup_path = path.with_name(f"{path.name}.corrupt-{timestamp}")
    counter = 1
    while backup_path.exists():
        counter += 1
        backup_path = path.with_name(f"{path.name}.corrupt-{timestamp}-{counter}")
    path.replace(backup_path)
    return backup_path


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    with tmp_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    tmp_path.replace(path)
