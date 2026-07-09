from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any


def create_fork_plan(
    catalog: dict[str, Any],
    *,
    org: str,
    min_score: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    selected = select_repositories(catalog, min_score=min_score, limit=limit)
    target_names = choose_target_names(selected)

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
        "forks": forks,
    }


def select_repositories(
    catalog: dict[str, Any],
    *,
    min_score: int | None,
    limit: int | None,
) -> list[dict[str, Any]]:
    repositories = [
        repo
        for repo in catalog.get("repositories", [])
        if min_score is None or repo.get("score", 0) >= min_score
    ]
    repositories.sort(
        key=lambda repo: (
            -repo.get("score", 0),
            repo["owner"].lower(),
            repo["name"].lower(),
        )
    )
    if limit is not None:
        return repositories[:limit]
    return repositories


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
