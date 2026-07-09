from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from assured_downstream.catalog import utc_now
from assured_downstream.scoring import pushed_age_days


def create_custodian_review(
    catalog: dict[str, Any],
    *,
    min_score: int = 0,
    maintainer_contacts: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    maintainer_contacts = maintainer_contacts or {}
    candidates = []
    for repo in catalog.get("repositories", []):
        if repo.get("score", 0) < min_score:
            continue
        if repo.get("recommended_mode") != "CustodianReview" and not custody_signal(repo):
            continue
        full_name = f"{repo['owner']}/{repo['name']}"
        candidates.append(
            custodian_candidate(
                repo,
                maintainer_contact=contact_evidence_for_repo(
                    maintainer_contacts,
                    full_name,
                ),
            )
        )

    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": "human-review-required",
        "note": (
            "This packet does not transfer project authority. It collects "
            "evidence for possible custodian review."
        ),
        "candidates": candidates,
    }


def custody_signal(repo: dict[str, Any]) -> bool:
    github = repo.get("github") or {}
    if github.get("archived"):
        return True
    age = pushed_age_days(github.get("pushed_at"))
    return age is not None and age > 730


def custodian_candidate(
    repo: dict[str, Any],
    *,
    maintainer_contact: Any | None = None,
) -> dict[str, Any]:
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
        "maintainer_contact": maintainer_contact_review(maintainer_contact),
        "naming_trademark_review": naming_trademark_review(repo),
        "custodian_claim_gate": custodian_claim_gate(),
        "required_human_review": required_human_review(criteria),
        "suggested_language": suggested_language(repo),
    }


def required_human_review(criteria: dict[str, Any]) -> list[str]:
    required = [
        "confirm maintainer contact attempts",
        "confirm naming and trademark risk",
        "confirm community demand",
        "confirm continuation fork language",
        "confirm custodian claim gate approval",
    ]
    if criteria["license_review_required"]:
        required.append("confirm license compatibility")
    return required


def contact_evidence_for_repo(
    maintainer_contacts: Mapping[str, Any],
    full_name: str,
) -> Any | None:
    direct = maintainer_contacts.get(full_name)
    if direct is not None:
        return direct

    normalized = full_name.lower()
    for key, value in maintainer_contacts.items():
        if isinstance(key, str) and key.lower() == normalized:
            return value
    return None


def maintainer_contact_review(evidence: Any | None) -> dict[str, Any]:
    attempts: list[Any] = []
    preference = None
    last_contacted_at = None
    notes: list[str] = []

    if isinstance(evidence, Mapping):
        attempts = list(evidence.get("attempts") or [])
        preference = evidence.get("maintainer_preference") or evidence.get("preference")
        last_contacted_at = evidence.get("last_contacted_at")
        notes = list(evidence.get("notes") or [])

    return {
        "status": "human-review-required",
        "attempts": attempts,
        "last_contacted_at": last_contacted_at,
        "maintainer_preference": preference,
        "notes": notes,
        "required_before": "any public custodian claim",
        "next_step": (
            "Record good-faith maintainer contact attempts and any no-outreach "
            "preference before using public custodian language."
        ),
    }


def naming_trademark_review(repo: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "human-review-required",
        "project_name": repo.get("name"),
        "required_before": "public custodian naming or announcement",
        "suggested_boundary": (
            "Use clearly labeled continuation fork language; upstream remains "
            "authoritative while maintainers are active."
        ),
        "checklist": [
            {
                "item": "name distinction",
                "status": "pending",
                "description": (
                    "Confirm the downstream name is clearly distinguishable "
                    "unless maintainers explicitly opt in."
                ),
            },
            {
                "item": "trademark search",
                "status": "pending",
                "description": "Check project, foundation, and package registry naming rules.",
            },
            {
                "item": "endorsement risk",
                "status": "pending",
                "description": "Avoid wording that suggests maintainer endorsement.",
            },
        ],
    }


def custodian_claim_gate() -> dict[str, Any]:
    return {
        "status": "human-approval-required",
        "claim_allowed": False,
        "required_approvals": [
            "maintainer contact review",
            "naming and trademark review",
            "license compatibility review",
            "community demand review",
        ],
        "blocked_claims": [
            "project transfer",
            "upstream successor status",
            "maintainer endorsement",
        ],
    }


def suggested_language(repo: dict[str, Any]) -> str:
    github = repo.get("github") or {}
    pushed_at = github.get("pushed_at") or "unknown"
    archived = "archived" if github.get("archived") else "inactive"
    checked_at = datetime.now(UTC).date().isoformat()
    return (
        f"{repo['owner']}/{repo['name']} appears {archived} based on public repository "
        f"metadata checked on {checked_at}. Last pushed at: {pushed_at}. "
        "Assured Downstream should not present this as maintainer-endorsed or "
        "as a transfer of project authority without explicit opt-in; this packet "
        "supports human review for a clearly labeled continuation fork."
    )
