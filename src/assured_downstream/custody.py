from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from assured_downstream.catalog import utc_now
from assured_downstream.scoring import pushed_age_days


def create_custodian_review(
    catalog: dict[str, Any],
    *,
    min_score: int = 0,
) -> dict[str, Any]:
    candidates = []
    for repo in catalog.get("repositories", []):
        if repo.get("score", 0) < min_score:
            continue
        if repo.get("recommended_mode") != "CustodianReview" and not custody_signal(repo):
            continue
        candidates.append(custodian_candidate(repo))

    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": "human-review-required",
        "note": "This packet does not claim project ownership. It collects evidence for possible custodian review.",
        "candidates": candidates,
    }


def custody_signal(repo: dict[str, Any]) -> bool:
    github = repo.get("github") or {}
    if github.get("archived"):
        return True
    age = pushed_age_days(github.get("pushed_at"))
    return age is not None and age > 730


def custodian_candidate(repo: dict[str, Any]) -> dict[str, Any]:
    github = repo.get("github") or {}
    age = pushed_age_days(github.get("pushed_at"))
    criteria = {
        "archived": bool(github.get("archived")),
        "stale_activity": age is not None and age > 730,
        "pushed_at": github.get("pushed_at"),
        "activity_age_days": age,
        "license_spdx_id": github.get("license_spdx_id"),
        "license_review_required": not bool(github.get("license_spdx_id")),
        "has_releases": bool(github.get("has_releases")),
        "stars": int(github.get("stargazers_count") or 0),
        "forks": int(github.get("forks_count") or 0),
    }
    return {
        "source_full_name": f"{repo['owner']}/{repo['name']}",
        "html_url": repo.get("html_url"),
        "score": repo.get("score", 0),
        "recommended_mode": "CustodianReview",
        "criteria": criteria,
        "required_human_review": required_human_review(criteria),
        "suggested_language": suggested_language(repo),
    }


def required_human_review(criteria: dict[str, Any]) -> list[str]:
    required = [
        "confirm maintainer contact attempts",
        "confirm naming and trademark risk",
        "confirm community demand",
        "confirm continuation fork language",
    ]
    if criteria["license_review_required"]:
        required.append("confirm license compatibility")
    return required


def suggested_language(repo: dict[str, Any]) -> str:
    github = repo.get("github") or {}
    pushed_at = github.get("pushed_at") or "unknown"
    archived = "archived" if github.get("archived") else "inactive"
    checked_at = datetime.now(UTC).date().isoformat()
    return (
        f"{repo['owner']}/{repo['name']} appears {archived} based on public repository "
        f"metadata checked on {checked_at}. Last pushed at: {pushed_at}. "
        "SauceTotal should not claim official ownership without maintainer opt-in; "
        "this packet supports human review for a clearly labeled custodian fork."
    )

