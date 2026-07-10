from __future__ import annotations

import re
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from assured_downstream.command_runner import display_command
from assured_downstream.selection import (
    CandidateSelectionPolicy,
    repo_full_name,
    selection_reason_for_repo,
)


FORK_PLAN_SCHEMA_VERSION = 2
TARGET_OWNER_TYPES = {"organization", "user"}
GITHUB_NAME_PATTERN = re.compile(r"[A-Za-z0-9._-]+")
GITHUB_OWNER_PATTERN = re.compile(r"[A-Za-z0-9-]+")


def create_fork_plan(
    catalog: dict[str, Any],
    *,
    org: str | None = None,
    target_owner: str | None = None,
    target_owner_type: str | None = None,
    name_prefix: str = "",
    min_score: int | None = None,
    limit: int | None = None,
    selection_policy: CandidateSelectionPolicy | None = None,
) -> dict[str, Any]:
    target = resolve_fork_target(
        org=org,
        target_owner=target_owner,
        target_owner_type=target_owner_type,
        name_prefix=name_prefix,
    )
    selected, selection_reasons = select_repositories_with_reasons(
        catalog,
        min_score=min_score,
        limit=limit,
        selection_policy=selection_policy,
    )
    target_names = choose_target_names(selected, name_prefix=target["name_prefix"])
    reasons_by_repo = {
        reason["source_full_name"].lower(): reason
        for reason in selection_reasons
    }

    forks = []
    for repo in selected:
        source_full_name = f"{repo['owner']}/{repo['name']}"
        target_name = target_names[source_full_name]
        target_full_name = f"{target['owner']}/{target_name}"
        command = fork_command(
            source_full_name,
            target_owner=target["owner"],
            target_owner_type=target["owner_type"],
            target_repo_name=target_name,
        )
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
                "dry_run_command": display_command(command),
                "metadata": fork_metadata_summary(repo),
                "branch_model": {
                    "default_branch": (repo.get("github") or {}).get("default_branch") or "main",
                    "upstream_default": "upstream/<default>",
                    "secure_default": "secure/<default>",
                },
            }
        )

    return {
        "schema_version": FORK_PLAN_SCHEMA_VERSION,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "org": target["owner"] if target["owner_type"] == "organization" else None,
        "target": target,
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


def choose_target_names(
    repositories: list[dict[str, Any]],
    *,
    name_prefix: str = "",
) -> dict[str, str]:
    validate_name_prefix(name_prefix)
    repo_name_counts = Counter(repo["name"].lower() for repo in repositories)
    target_names = {}

    for repo in repositories:
        source_full_name = f"{repo['owner']}/{repo['name']}"
        if repo_name_counts[repo["name"].lower()] > 1:
            base_name = f"{repo['owner']}-{repo['name']}"
        else:
            base_name = repo["name"]
        target_name = f"{name_prefix}{base_name}"
        validate_github_name(target_name, field="target repository name")
        target_names[source_full_name] = target_name

    return target_names


def resolve_fork_target(
    *,
    org: str | None = None,
    target_owner: str | None = None,
    target_owner_type: str | None = None,
    name_prefix: str = "",
) -> dict[str, str]:
    if org and target_owner and org.casefold() != target_owner.casefold():
        raise ValueError("org and target_owner must identify the same GitHub owner")

    owner = (target_owner or org or "").strip()
    if not owner:
        raise ValueError("A target GitHub owner is required")
    if GITHUB_OWNER_PATTERN.fullmatch(owner) is None:
        raise ValueError(
            "Invalid target GitHub owner: use only ASCII letters, digits, and '-'"
        )

    owner_type = target_owner_type or "organization"
    if owner_type not in TARGET_OWNER_TYPES:
        raise ValueError(f"Unsupported target owner type: {owner_type!r}")
    if org and owner_type != "organization" and target_owner is None:
        raise ValueError("The legacy org argument can only target an organization")

    validate_name_prefix(name_prefix)
    return {
        "owner": owner,
        "owner_type": owner_type,
        "name_prefix": name_prefix,
    }


def fork_target_from_plan(plan: dict[str, Any]) -> dict[str, str]:
    target = plan.get("target")
    if isinstance(target, dict):
        return resolve_fork_target(
            target_owner=target.get("owner"),
            target_owner_type=target.get("owner_type"),
            name_prefix=target.get("name_prefix", ""),
        )
    return resolve_fork_target(org=plan.get("org"), name_prefix=plan.get("name_prefix", ""))


def fork_command(
    source_full_name: str,
    *,
    target_owner: str,
    target_owner_type: str,
    target_repo_name: str,
) -> list[str]:
    target = resolve_fork_target(
        target_owner=target_owner,
        target_owner_type=target_owner_type,
    )
    validate_github_name(target_repo_name, field="target repository name")

    command = ["gh", "repo", "fork", source_full_name]
    if target["owner_type"] == "organization":
        command.extend(["--org", target["owner"]])
    command.extend(["--fork-name", target_repo_name, "--clone=false"])
    return command


def validate_name_prefix(name_prefix: str) -> None:
    if not isinstance(name_prefix, str):
        raise ValueError("Repository name prefix must be a string")
    if name_prefix:
        validate_github_name(name_prefix, field="repository name prefix")


def validate_github_name(value: str, *, field: str) -> None:
    if value in {"", ".", ".."} or GITHUB_NAME_PATTERN.fullmatch(value) is None:
        raise ValueError(
            f"Invalid {field}: use only ASCII letters, digits, '.', '-', and '_'"
        )


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
