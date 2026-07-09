from __future__ import annotations

from typing import Any


SECURITY_TERMS = {
    "auth",
    "crypto",
    "cve",
    "detect",
    "dfir",
    "exploit",
    "forensic",
    "fuzz",
    "hardening",
    "malware",
    "pentest",
    "policy",
    "provenance",
    "re",
    "reverse",
    "sandbox",
    "scanner",
    "security",
    "sigstore",
    "slsa",
    "supply-chain",
    "threat",
    "vuln",
    "yara",
}

TOOLING_TERMS = {
    "build",
    "cli",
    "compiler",
    "container",
    "debugger",
    "dnspy",
    "package",
    "release",
    "runner",
    "sbom",
    "trace",
}


def score_catalog(catalog: dict[str, Any]) -> int:
    scored = 0
    for repo in catalog.get("repositories", []):
        score, breakdown, notes = score_repository(repo)
        repo["score"] = score
        repo["score_breakdown"] = breakdown
        existing_notes = [note for note in repo.get("notes", []) if not note.startswith("score:")]
        repo["notes"] = existing_notes + notes
        scored += 1
    return scored


def score_repository(repo: dict[str, Any]) -> tuple[int, dict[str, int], list[str]]:
    text = candidate_text(repo)
    breakdown: dict[str, int] = {}
    notes: list[str] = []

    seed_count = len(repo.get("seeds", []))
    breakdown["seed_references"] = min(seed_count * 2, 10)

    security_hits = sorted(term for term in SECURITY_TERMS if term in text)
    if security_hits:
        breakdown["security_terms"] = min(len(security_hits) * 8, 32)
        notes.append(f"score: security terms: {', '.join(security_hits[:8])}")

    tooling_hits = sorted(term for term in TOOLING_TERMS if term in text)
    if tooling_hits:
        breakdown["tooling_terms"] = min(len(tooling_hits) * 4, 16)
        notes.append(f"score: tooling terms: {', '.join(tooling_hits[:8])}")

    name = repo["name"].lower()
    if name.startswith("awesome") or "-awesome" in name:
        breakdown["awesome_list_penalty"] = -12
        notes.append("score: likely a list rather than a target project")

    if repo["owner"].lower() in {"github", "actions", "marketplace"}:
        breakdown["platform_repo_penalty"] = -10
        notes.append("score: likely platform-owned infrastructure")

    score = sum(breakdown.values())
    return max(score, 0), breakdown, notes


def candidate_text(repo: dict[str, Any]) -> str:
    parts = [repo["owner"], repo["name"]]
    for seed in repo.get("seeds", []):
        parts.append(seed.get("line", ""))
        parts.append(seed.get("source", ""))
    return " ".join(parts).lower()

