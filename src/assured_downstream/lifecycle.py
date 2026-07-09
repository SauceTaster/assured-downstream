from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from assured_downstream.catalog import utc_now


SCHEMA_VERSION = 1


@dataclass
class StateStore:
    data: dict[str, Any]

    @classmethod
    def empty(cls) -> "StateStore":
        now = utc_now()
        return cls(
            {
                "schema_version": SCHEMA_VERSION,
                "generated_at": now,
                "updated_at": now,
                "repositories": {},
            }
        )

    @classmethod
    def load(cls, path: Path) -> "StateStore":
        if not path.exists():
            return cls.empty()
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if data.get("schema_version") != SCHEMA_VERSION:
            version = data.get("schema_version")
            raise ValueError(f"Unsupported lifecycle schema_version: {version!r}")
        data.setdefault("repositories", {})
        return cls(data)

    def save(self, path: Path) -> None:
        self.data["updated_at"] = utc_now()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(self.data, handle, indent=2, sort_keys=True)
            handle.write("\n")

    def record(
        self,
        *,
        source_full_name: str,
        target_full_name: str,
        event: str,
        status: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        repositories = self.data.setdefault("repositories", {})
        repo = repositories.setdefault(
            source_full_name,
            {
                "source_full_name": source_full_name,
                "target_full_name": target_full_name,
                "current_state": "Seeded",
                "events": [],
            },
        )
        repo["target_full_name"] = target_full_name
        repo["current_state"] = event if status == "ok" else "Blocked"
        repo.setdefault("events", []).append(
            {
                "at": utc_now(),
                "event": event,
                "status": status,
                "detail": detail or {},
            }
        )

