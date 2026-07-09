from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from assured_downstream.seed import SeedFinding


SCHEMA_VERSION = 1


@dataclass
class SeedReference:
    source: str
    line_number: int
    line: str


@dataclass
class RepositoryCandidate:
    owner: str
    name: str
    html_url: str
    status: str = "Candidate"
    seeds: list[SeedReference] = field(default_factory=list)
    score: int = 0
    score_breakdown: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"


def empty_catalog() -> dict[str, Any]:
    now = utc_now()
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now,
        "updated_at": now,
        "repositories": [],
    }


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def load_catalog(path: Path) -> dict[str, Any]:
    if not path.exists():
        return empty_catalog()

    with path.open("r", encoding="utf-8") as handle:
        catalog = json.load(handle)

    if catalog.get("schema_version") != SCHEMA_VERSION:
        version = catalog.get("schema_version")
        raise ValueError(f"Unsupported catalog schema_version: {version!r}")

    catalog.setdefault("repositories", [])
    return catalog


def save_catalog(path: Path, catalog: dict[str, Any]) -> None:
    catalog["updated_at"] = utc_now()
    catalog["repositories"] = sorted(
        catalog.get("repositories", []),
        key=lambda repo: (repo["owner"].lower(), repo["name"].lower()),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(catalog, handle, indent=2, sort_keys=True)
        handle.write("\n")


def upsert_findings(
    catalog: dict[str, Any],
    findings: list[SeedFinding],
) -> tuple[int, int]:
    repositories = catalog.setdefault("repositories", [])
    by_key = {
        repo_key(repo["owner"], repo["name"]): repo
        for repo in repositories
    }

    added_repositories = 0
    added_seed_refs = 0

    for finding in findings:
        key = repo_key(finding.owner, finding.name)
        repo = by_key.get(key)
        if repo is None:
            candidate = RepositoryCandidate(
                owner=finding.owner,
                name=finding.name,
                html_url=finding.html_url,
                seeds=[],
            )
            repo = asdict(candidate)
            repositories.append(repo)
            by_key[key] = repo
            added_repositories += 1

        seed_ref = SeedReference(
            source=finding.source,
            line_number=finding.line_number,
            line=finding.line.strip(),
        )
        if add_seed_ref(repo, seed_ref):
            added_seed_refs += 1

    return added_repositories, added_seed_refs


def add_seed_ref(repo: dict[str, Any], seed_ref: SeedReference) -> bool:
    seeds = repo.setdefault("seeds", [])
    candidate = asdict(seed_ref)
    for existing in seeds:
        if (
            existing.get("source") == candidate["source"]
            and existing.get("line_number") == candidate["line_number"]
        ):
            return False
    seeds.append(candidate)
    return True


def repo_key(owner: str, name: str) -> str:
    return f"{owner.lower()}/{name.lower()}"

