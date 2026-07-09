from __future__ import annotations

import math
from datetime import UTC, datetime
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

    add_github_metadata_score(repo, breakdown, notes)
    repo["recommended_mode"] = recommend_mode(repo)

    score = sum(breakdown.values())
    return max(score, 0), breakdown, notes


def candidate_text(repo: dict[str, Any]) -> str:
    parts = [repo["owner"], repo["name"]]
    for seed in repo.get("seeds", []):
        parts.append(seed.get("line", ""))
        parts.append(seed.get("source", ""))
    github = repo.get("github") or {}
    parts.append(github.get("description") or "")
    parts.extend(github.get("topics") or [])
    parts.extend((github.get("languages") or {}).keys())
    return " ".join(parts).lower()


def add_github_metadata_score(
    repo: dict[str, Any],
    breakdown: dict[str, int],
    notes: list[str],
) -> None:
    github = repo.get("github") or {}
    if not github:
        return

    stars = int(github.get("stargazers_count") or 0)
    forks = int(github.get("forks_count") or 0)
    if stars:
        breakdown["github_stars"] = min(int(math.log10(stars + 1) * 6), 24)
    if forks:
        breakdown["github_forks"] = min(int(math.log10(forks + 1) * 4), 16)

    if github.get("has_releases"):
        breakdown["has_releases"] = 12
        notes.append("score: has GitHub releases")

    license_id = github.get("license_spdx_id")
    if license_id and license_id not in {"NOASSERTION", "NONE"}:
        breakdown["license_detected"] = 6
    else:
        breakdown["license_unknown_penalty"] = -8
        notes.append("score: missing or ambiguous GitHub license metadata")

    language_names = {language.lower() for language in (github.get("languages") or {})}
    first_lane_languages = {"go", "rust", "python", "c#", "c++", "c"}
    language_hits = sorted(language_names & first_lane_languages)
    if language_hits:
        breakdown["first_lane_language"] = min(len(language_hits) * 6, 18)
        notes.append(f"score: first-lane language: {', '.join(language_hits)}")

    age = pushed_age_days(github.get("pushed_at"))
    if age is not None:
        if age <= 180:
            breakdown["recent_activity"] = 12
        elif age <= 730:
            breakdown["moderate_activity"] = 5
        else:
            breakdown["stewardship_opportunity"] = 10
            notes.append("score: stale upstream activity, possible custodian review")

    if github.get("archived"):
        breakdown["archived_custodian_signal"] = 14
        notes.append("score: archived upstream, possible custodian review")

    if github.get("disabled") or github.get("private"):
        breakdown["unavailable_penalty"] = -40
        notes.append("score: repository unavailable for public downstream automation")


def recommend_mode(repo: dict[str, Any]) -> str:
    github = repo.get("github") or {}
    if github.get("archived"):
        return "CustodianReview"
    age = pushed_age_days(github.get("pushed_at"))
    if age is not None and age > 730:
        return "CustodianReview"
    return "DownstreamAssured"


def pushed_age_days(value: str | None) -> int | None:
    if not value:
        return None
    try:
        pushed_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(UTC) - pushed_at).days
