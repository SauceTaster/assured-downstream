from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


GITHUB_PATTERNS = [
    re.compile(
        r"(?:https?://)?github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)"
    ),
    re.compile(
        r"git@github\.com:(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)"
    ),
]

INVALID_OWNERS = {
    "about",
    "apps",
    "collections",
    "enterprise",
    "events",
    "features",
    "github",
    "login",
    "marketplace",
    "new",
    "notifications",
    "orgs",
    "pricing",
    "settings",
    "sponsors",
    "topics",
    "users",
}


@dataclass(frozen=True)
class SeedFinding:
    owner: str
    name: str
    html_url: str
    source: str
    line_number: int
    line: str


def parse_seed_file(path: Path) -> list[SeedFinding]:
    with path.open("r", encoding="utf-8") as handle:
        return parse_seed_text(handle.read(), source=str(path))


def parse_seed_text(text: str, *, source: str) -> list[SeedFinding]:
    findings: list[SeedFinding] = []
    seen: set[tuple[str, str, int]] = set()

    for line_number, line in enumerate(text.splitlines(), start=1):
        for pattern in GITHUB_PATTERNS:
            for match in pattern.finditer(line):
                owner = clean_segment(match.group("owner"))
                name = clean_segment(match.group("repo"))
                if not is_valid_repo(owner, name):
                    continue

                key = (owner.lower(), name.lower(), line_number)
                if key in seen:
                    continue
                seen.add(key)

                findings.append(
                    SeedFinding(
                        owner=owner,
                        name=name,
                        html_url=f"https://github.com/{owner}/{name}",
                        source=source,
                        line_number=line_number,
                        line=line,
                    )
                )

    return findings


def clean_segment(value: str) -> str:
    value = value.strip()
    value = value.rstrip(".,;:)]}'\"")
    if value.endswith(".git"):
        value = value[:-4]
    return value


def is_valid_repo(owner: str, name: str) -> bool:
    if not owner or not name:
        return False
    if owner.lower() in INVALID_OWNERS:
        return False
    if name in {".", ".."}:
        return False
    if len(owner) > 39:
        return False
    return True

