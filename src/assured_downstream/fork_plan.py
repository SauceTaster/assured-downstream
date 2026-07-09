from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

from assured_downstream.selection import (
    CandidateSelectionPolicy,
    repo_full_name,
    selection_reason_for_repo,
)


def create_fork_plan(
    catalog: dict[str, Any],
    *,
    org: str,
    min_score: int | None = None,
    limit: int | None = None,
    selection_policy: CandidateSelectionPolicy | None = None,
) -> dict[str, Any]:
    selected, selection_reasons = select_repositories_with_reasons(
        catalog,
        min_score=min_score,
        limit=limit,
        selection_policy=selection_policy,
    )
    target_names = choose_target_names(selected)
    reasons_by_repo = {
        reason["source_full_name"].lower(): reason
        for reason in selection_reasons
    }

    forks = []
    for repo in selected:
        source_full_name = f"{repo['owner']}/{repo['name']}"
        target_name = target_names[source_full_name]
        target_full_name = f"{org}/{target_name}"
        forks.append(
            {
                "source_full_name": source_full_name,
                "source_url": repo["html_url"],
                "target_full_name": target_full_name,
                "target_repo_name": target_name,
                "score": repo.get("score", 0),
                "recommended_mode": repo.get("recommended_mode", "DownstreamAssured"),
                "selection_reason": reasons_by_repo[source_full_name.lower()],
                "status": "dry_run",
                "dry_run_command": (
                    f"gh repo fork {source_full_name} "
                    f"--org {org} --clone=false"
                ),
                "metadata": fork_metadata_summary(repo),
                "branch_model": {
                    "upstream_default": "upstream/<default>",
                    "secure_default": "secure/<default>",
                    "proposal_prefix": "proposal/",
                    "secure_release_prefix": "secure/release/",
                },
            }
        )

    return {
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "org": org,
        "mode": "dry_run",
        "selection_counts": selection_counts(selection_reasons),
        "selection_reasons": selection_reasons,
        "forks": forks,
    }


def select_repositories(
    catalog: dict[str, Any],
    *,
    min_score: int | None,
    limit: int | None,
    selection_policy: CandidateSelectionPolicy | None = None,
) -> list[dict[str, Any]]:
    selected, _selection_reasons = select_repositories_with_reasons(
        catalog,
        min_score=min_score,
        limit=limit,
        selection_policy=selection_policy,
    )
    return selected


def select_repositories_with_reasons(
    catalog: dict[str, Any],
    *,
    min_score: int | None,
    limit: int | None,
    selection_policy: CandidateSelectionPolicy | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    policy = selection_policy or CandidateSelectionPolicy.empty()
    repositories = [
        repo
        for repo in catalog.get("repositories", [])
    ]
    repositories.sort(
        key=lambda repo: (
            -repo.get("score", 0),
            repo["owner"].lower(),
            repo["name"].lower(),
        )
    )

    eligible = []
    ineligible_reasons = []
    for repo in repositories:
        full_name = repo_full_name(repo)
        if policy.suppression_entry(full_name):
            ineligible_reasons.append(
                selection_reason_for_repo(
                    repo,
                    selected=False,
                    decision="suppressed",
                    min_score=min_score,
                    policy=policy,
                )
            )
            continue
        if policy.allow_entry(full_name) or min_score is None or repo.get("score", 0) >= min_score:
            eligible.append(repo)
            continue
        ineligible_reasons.append(
            selection_reason_for_repo(
                repo,
                selected=False,
                decision="below_min_score",
                min_score=min_score,
                policy=policy,
            )
        )

    eligible.sort(
        key=lambda repo: (
            0 if policy.allow_entry(repo_full_name(repo)) else 1,
            -repo.get("score", 0),
            repo["owner"].lower(),
            repo["name"].lower(),
        )
    )
    selected = eligible if limit is None else eligible[:limit]
    limited_out = [] if limit is None else eligible[limit:]

    selection_reasons = []
    for repo in selected:
        selection_reasons.append(
            selection_reason_for_repo(
                repo,
                selected=True,
                decision="selected",
                min_score=min_score,
                policy=policy,
            )
        )
    for repo in limited_out:
        selection_reasons.append(
            selection_reason_for_repo(
                repo,
                selected=False,
                decision="limit_excluded",
                min_score=min_score,
                policy=policy,
                limited_out=True,
            )
        )

    selection_reasons.extend(ineligible_reasons)
    selection_reasons.sort(key=lambda reason: reason["source_full_name"].lower())
    return selected, selection_reasons


def selection_counts(selection_reasons: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "candidates": len(selection_reasons),
        "selected": sum(1 for reason in selection_reasons if reason.get("selected")),
        "suppressed": sum(1 for reason in selection_reasons if reason.get("decision") == "suppressed"),
        "allowlisted": sum(
            1
            for reason in selection_reasons
            if any(item.get("code") == "allowlisted" for item in reason.get("reasons", []))
        ),
        "limit_excluded": sum(
            1 for reason in selection_reasons if reason.get("decision") == "limit_excluded"
        ),
    }


def choose_target_names(repositories: list[dict[str, Any]]) -> dict[str, str]:
    repo_name_counts = Counter(repo["name"].lower() for repo in repositories)
    target_names = {}

    for repo in repositories:
        source_full_name = f"{repo['owner']}/{repo['name']}"
        if repo_name_counts[repo["name"].lower()] > 1:
            target_names[source_full_name] = f"{repo['owner']}-{repo['name']}"
        else:
            target_names[source_full_name] = repo["name"]

    return target_names


def fork_metadata_summary(repo: dict[str, Any]) -> dict[str, Any]:
    github = repo.get("github") or {}
    return {
        "default_branch": github.get("default_branch"),
        "archived": github.get("archived"),
        "pushed_at": github.get("pushed_at"),
        "license_spdx_id": github.get("license_spdx_id"),
        "has_releases": github.get("has_releases"),
        "languages": sorted((github.get("languages") or {}).keys()),
    }
