from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

from assured_downstream.catalog import utc_now


SCHEMA_VERSION = 1


def create_project_packet(
    fork_plan_entry: dict[str, Any],
    *,
    checkout_analysis: dict[str, Any] | None = None,
    overlay_plan: dict[str, Any] | None = None,
    render_result: Any | None = None,
    release_profile: dict[str, Any] | None = None,
    maintainer_preferences: Mapping[str, Any] | None = None,
    suppression_state: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    # Preference inputs are accepted for compatibility but outbound contact is
    # disabled globally, so they cannot change publication behavior.
    del maintainer_preferences, suppression_state

    source_full_name = str(fork_plan_entry["source_full_name"])
    target_full_name = str(fork_plan_entry["target_full_name"])
    summary = proposal_summary(
        checkout_analysis=checkout_analysis,
        overlay_plan=overlay_plan,
        render_result=render_result,
        release_profile=release_profile,
    )
    fetch = build_fetch_instructions(fork_plan_entry)

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "status": "passive-publication-ready",
        "source_full_name": source_full_name,
        "target_full_name": target_full_name,
        "publication": {
            "mode": "passive",
            "discoverability": "github-fork-network",
            "outbound_contact": False,
        },
        "mutation_policy": {
            "network_mutation": False,
            "automatic_pr_creation": False,
            "outbound_contact": False,
        },
        "source_analysis": source_analysis_summary(checkout_analysis),
        "proposal_summary": summary,
        "proposal_summary_markdown": render_proposal_summary(summary),
        "fetch_instructions": fetch,
        "fetch_instructions_markdown": render_fetch_instructions(fetch),
    }


def proposal_summary(
    *,
    checkout_analysis: dict[str, Any] | None,
    overlay_plan: dict[str, Any] | None,
    render_result: Any | None,
    release_profile: dict[str, Any] | None,
) -> dict[str, Any]:
    rendered = normalize_render_result(render_result)
    return {
        "affected_paths": collect_affected_paths(
            overlay_plan=overlay_plan,
            render_result=rendered,
            release_profile=release_profile,
        ),
        "rationale": collect_rationale(overlay_plan),
        "skipped_items": collect_skipped_items(rendered),
        "human_review_required": collect_human_review_notes(
            overlay_plan=overlay_plan,
            release_profile=release_profile,
            checkout_analysis=checkout_analysis,
        ),
    }


def normalize_render_result(render_result: Any | None) -> dict[str, list[Any]]:
    if render_result is None:
        return {"written": [], "skipped": []}
    if isinstance(render_result, Mapping):
        return {
            "written": list(render_result.get("written") or []),
            "skipped": list(render_result.get("skipped") or []),
        }
    return {
        "written": list(getattr(render_result, "written", []) or []),
        "skipped": list(getattr(render_result, "skipped", []) or []),
    }


def collect_affected_paths(
    *,
    overlay_plan: dict[str, Any] | None,
    render_result: dict[str, list[Any]],
    release_profile: dict[str, Any] | None,
) -> list[str]:
    paths: set[str] = set()
    if isinstance(overlay_plan, Mapping):
        for change in overlay_plan.get("proposed_changes", []):
            if isinstance(change, Mapping):
                paths.update(str(path) for path in change.get("paths", []))

    for written in render_result["written"]:
        if isinstance(written, Mapping) and written.get("path"):
            paths.add(str(written["path"]))

    release = (
        release_profile.get("release")
        if isinstance(release_profile, Mapping)
        else None
    )
    if isinstance(release, Mapping) and release.get("workflow_path"):
        paths.add(str(release["workflow_path"]))
    return sorted(paths)


def collect_rationale(overlay_plan: dict[str, Any] | None) -> list[str]:
    rationales = []
    if isinstance(overlay_plan, Mapping):
        for change in overlay_plan.get("proposed_changes", []):
            if not isinstance(change, Mapping):
                continue
            rationale = change.get("rationale")
            if isinstance(rationale, str) and rationale:
                rationales.append(f"{change.get('id', 'change')}: {rationale}")
    return rationales or [
        "No overlay rationale was recorded; review is required before publication."
    ]


def collect_skipped_items(render_result: dict[str, list[Any]]) -> list[dict[str, str]]:
    skipped = []
    for item in render_result["skipped"]:
        if isinstance(item, Mapping):
            skipped.append(
                {
                    "id": str(item.get("id", "unknown")),
                    "reason": str(item.get("reason", "requires human review")),
                }
            )
        else:
            skipped.append({"id": "unknown", "reason": str(item)})
    return skipped


def collect_human_review_notes(
    *,
    overlay_plan: dict[str, Any] | None,
    release_profile: dict[str, Any] | None,
    checkout_analysis: dict[str, Any] | None,
) -> list[str]:
    notes = []
    if isinstance(overlay_plan, Mapping):
        for change in overlay_plan.get("proposed_changes", []):
            if isinstance(change, Mapping) and change.get("human_review_required"):
                notes.append(
                    f"{change.get('id', 'change')}: "
                    f"{change.get('rationale', 'review required')}"
                )
    if isinstance(release_profile, Mapping):
        notes.extend(str(note) for note in release_profile.get("review_notes", []))
    if isinstance(checkout_analysis, Mapping):
        for risk in checkout_analysis.get("risk_signals", []):
            if isinstance(risk, Mapping) and risk.get("signal") and risk.get("path"):
                notes.append(f"{risk['path']}: {risk['signal']}")
    return notes or ["Review the downstream publication packet before release."]


def source_analysis_summary(checkout_analysis: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(checkout_analysis, Mapping):
        return {}
    package_managers = []
    for entry in checkout_analysis.get("package_managers", []):
        if isinstance(entry, Mapping) and entry.get("name"):
            package_managers.append(str(entry["name"]))
        elif isinstance(entry, str):
            package_managers.append(entry)
    return {
        "path": checkout_analysis.get("path"),
        "generated_at": checkout_analysis.get("generated_at"),
        "languages": checkout_analysis.get("languages", {}),
        "package_managers": sorted(set(package_managers)),
    }


def build_fetch_instructions(fork_plan_entry: dict[str, Any]) -> dict[str, Any]:
    remote_name = str(fork_plan_entry.get("review_remote") or "assured-downstream")
    target_full_name = str(fork_plan_entry["target_full_name"])
    publication_branch = choose_publication_branch(fork_plan_entry)
    local_review_branch = fork_plan_entry.get("local_review_branch") or (
        f"review/{safe_branch_segment(target_full_name)}"
    )
    remote_url = fork_plan_entry.get("target_clone_url") or fork_plan_entry.get(
        "target_url"
    )
    if not remote_url:
        remote_url = f"https://github.com/{target_full_name}.git"
    commands = [
        f"git remote add {remote_name} {remote_url}",
        f"git fetch {remote_name} {publication_branch}",
        f"git switch -c {local_review_branch} {remote_name}/{publication_branch}",
    ]
    return {
        "remote_name": remote_name,
        "remote_url": remote_url,
        "publication_branch": publication_branch,
        "local_review_branch": local_review_branch,
        "commands": commands,
    }


def choose_publication_branch(fork_plan_entry: dict[str, Any]) -> str:
    explicit = fork_plan_entry.get("publication_branch") or fork_plan_entry.get(
        "proposal_branch"
    )
    if explicit:
        return str(explicit)
    metadata = fork_plan_entry.get("metadata") or {}
    default_branch = str(
        fork_plan_entry.get("default_branch")
        or metadata.get("default_branch")
        or "main"
    )
    return f"secure/{default_branch}"


def safe_branch_segment(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-").lower()
    return cleaned or "assured-downstream"


def render_fetch_instructions(fetch: dict[str, Any]) -> str:
    commands = "\n".join(fetch["commands"])
    return f"""## Optional Fork Fetch Instructions

The downstream fork is public and upstream remains authoritative. These optional
commands create a local review branch without changing the upstream repository.

```sh
{commands}
```
"""


def render_proposal_summary(summary: dict[str, Any]) -> str:
    lines = ["## Downstream Summary", "", "Affected paths:"]
    lines.extend(markdown_items(summary["affected_paths"]))
    lines.extend(["", "Rationale:"])
    lines.extend(markdown_items(summary["rationale"]))
    lines.extend(["", "Skipped items:"])
    lines.extend(
        markdown_items(
            [
                f"{item['id']}: {item['reason']}"
                for item in summary["skipped_items"]
            ]
        )
    )
    lines.extend(["", "Human-review-required notes:"])
    lines.extend(markdown_items(summary["human_review_required"]))
    lines.append("")
    return "\n".join(lines)


def markdown_items(items: list[Any]) -> list[str]:
    return [f"- {item}" for item in items] if items else ["- None recorded."]
