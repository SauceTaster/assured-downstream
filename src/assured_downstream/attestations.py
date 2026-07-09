from __future__ import annotations

from pathlib import Path
from typing import Any

from assured_downstream.evidence import sha256_file


INTOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"


def create_intoto_statement(
    *,
    subjects: list[Path],
    predicate_type: str,
    predicate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not predicate_type:
        raise ValueError("predicate_type is required")
    return {
        "_type": INTOTO_STATEMENT_V1,
        "subject": [subject_entry(path) for path in subjects],
        "predicateType": predicate_type,
        "predicate": predicate or {},
    }


def subject_entry(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    if not resolved.exists():
        raise FileNotFoundError(resolved)
    if not resolved.is_file():
        raise ValueError(f"Subject is not a file: {resolved}")
    return {
        "name": resolved.name,
        "digest": {
            "sha256": sha256_file(resolved),
        },
    }

