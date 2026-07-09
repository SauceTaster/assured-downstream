from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

from assured_downstream.catalog import utc_now


SCHEMA_VERSION = 1
SUPPRESS_OUTREACH_VALUES = {
    "disabled",
    "do-not-contact",
    "no",
    "no-outreach",
    "none",
    "pause",
    "paused",
    "suppress",
    "suppressed",
}


def create_liaison_packet(
    fork_plan_entry: dict[str, Any],
    *,
    checkout_analysis: dict[str, Any] | None = None,
    overlay_plan: dict[str, Any] | None = None,
    render_result: Any | None = None,
    release_profile: dict[str, Any] | None = None,
    maintainer_preferences: Mapping[str, Any] | None = None,
    suppression_state: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    source_full_name = str(fork_plan_entry["source_full_name"])
    target_full_name = str(fork_plan_entry["target_full_name"])
    suppression = outreach_suppression(
        source_full_name,
        fork_plan_entry=fork_plan_entry,
        maintainer_preferences=maintainer_preferences,
        suppression_state=suppression_state,
    )
    summary = proposal_summary(
        checkout_analysis=checkout_analysis,
        overlay_plan=overlay_plan,
        render_result=render_result,
        release_profile=release_profile,
    )

    packet: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "status": "outreach-suppressed" if suppression["suppressed"] else "draft-local-only",
        "source_full_name": source_full_name,
        "target_full_name": target_full_name,
        "mutation_policy": {
            "network_mutation": False,
            "automatic_pr_creation": False,
        },
        "outreach": suppression,
        "preference_controls": preference_controls(source_full_name),
        "source_analysis": source_analysis_summary(checkout_analysis),
        "proposal_summary": summary,
        "proposal_summary_markdown": render_proposal_summary(summary),
        "fetch_instructions": None,
        "fetch_instructions_markdown": None,
        "pr_description_draft": None,
    }

    if suppression["suppressed"]:
        return packet

    fetch = build_fetch_instructions(fork_plan_entry)
    fetch_markdown = render_fetch_instructions(fetch)
    summary_markdown = packet["proposal_summary_markdown"]
    packet["fetch_instructions"] = fetch
    packet["fetch_instructions_markdown"] = fetch_markdown
    packet["pr_description_draft"] = render_pr_description(
        source_full_name=source_full_name,
        fetch_markdown=fetch_markdown,
        summary_markdown=summary_markdown,
    )
    return packet


def outreach_suppression(
    source_full_name: str,
    *,
    fork_plan_entry: Mapping[str, Any],
    maintainer_preferences: Mapping[str, Any] | None,
    suppression_state: Mapping[str, Any] | None,
) -> dict[str, Any]:
    checks: list[tuple[str, Any | None]] = [
        ("fork_plan_entry", fork_plan_entry),
        ("suppression_state", find_repo_record(suppression_state, source_full_name)),
        ("maintainer_preferences", find_repo_record(maintainer_preferences, source_full_name)),
    ]
    for source, record in checks:
        if record_suppresses_outreach(record):
            return {
                "status": "suppressed",
                "suppressed": True,
                "reason": record_reason(record),
                "preference_source": source,
                "suppression_key": source_full_name.lower(),
            }

    return {
        "status": "draft-ready",
        "suppressed": False,
        "reason": None,
        "preference_source": None,
        "suppression_key": source_full_name.lower(),
    }


def find_repo_record(container: Mapping[str, Any] | None, source_full_name: str) -> Any | None:
    if not isinstance(container, Mapping):
        return None

    direct = direct_mapping_record(container, source_full_name)
    if direct is not None:
        return direct

    for key in ("suppressed_repos", "suppressions"):
        record = find_in_collection(container.get(key), source_full_name)
        if record is not None:
            if isinstance(record, str):
                return {
                    "outreach": "suppress",
                    "reason": f"listed in {key}",
                }
            return record

    for key in ("repositories", "repos", "projects", "preferences"):
        record = find_in_collection(container.get(key), source_full_name)
        if record is not None:
            return record

    if repo_record_matches(container, source_full_name):
        return container
    return None


def direct_mapping_record(container: Mapping[str, Any], source_full_name: str) -> Any | None:
    normalized = source_full_name.lower()
    for key, value in container.items():
        if isinstance(key, str) and key.lower() == normalized:
            return value
    return None


def find_in_collection(records: Any, source_full_name: str) -> Any | None:
    if isinstance(records, Mapping):
        direct = direct_mapping_record(records, source_full_name)
        if direct is not None:
            return direct
        if repo_record_matches(records, source_full_name):
            return records
        return None

    if isinstance(records, (list, tuple)):
        normalized = source_full_name.lower()
        for record in records:
            if isinstance(record, str) and record.lower() == normalized:
                return record
            if isinstance(record, Mapping) and repo_record_matches(record, source_full_name):
                return record
    return None


def repo_record_matches(record: Mapping[str, Any], source_full_name: str) -> bool:
    normalized = source_full_name.lower()
    for key in ("source_full_name", "full_name", "repository", "repo"):
        value = record.get(key)
        if isinstance(value, str) and value.lower() == normalized:
            return True

    owner = record.get("owner")
    name = record.get("name")
    if isinstance(owner, str) and isinstance(name, str):
        return f"{owner}/{name}".lower() == normalized
    return False


def record_suppresses_outreach(record: Any | None) -> bool:
    if isinstance(record, bool):
        return record
    if isinstance(record, str):
        return record.strip().lower() in SUPPRESS_OUTREACH_VALUES
    if not isinstance(record, Mapping):
        return False

    for key in ("suppressed", "suppress_outreach", "outreach_suppressed", "do_not_contact"):
        if record.get(key) is True:
            return True

    outreach = record.get("outreach")
    if outreach is False:
        return True

    for key in ("outreach", "status", "preference", "maintainer_preference"):
        value = record.get(key)
        if isinstance(value, str) and value.strip().lower() in SUPPRESS_OUTREACH_VALUES:
            return True
    return False


def record_reason(record: Any | None) -> str | None:
    if isinstance(record, Mapping):
        for key in ("reason", "suppression_reason", "note"):
            value = record.get(key)
            if isinstance(value, str) and value:
                return value
        notes = record.get("notes")
        if isinstance(notes, list) and notes:
            return "; ".join(str(note) for note in notes)
    if isinstance(record, str):
        return f"preference={record}"
    return None


def preference_controls(source_full_name: str) -> dict[str, Any]:
    return {
        "suppression_key": source_full_name.lower(),
        "inputs": ["maintainer_preferences", "suppression_state"],
        "supported_suppression_values": sorted(SUPPRESS_OUTREACH_VALUES),
        "default": "draft outreach unless a suppression or no-outreach preference matches",
    }


def proposal_summary(
    *,
    checkout_analysis: dict[str, Any] | None,
    overlay_plan: dict[str, Any] | None,
    render_result: Any | None,
    release_profile: dict[str, Any] | None,
) -> dict[str, Any]:
    rendered = normalize_render_result(render_result)
    affected_paths = collect_affected_paths(
        overlay_plan=overlay_plan,
        render_result=rendered,
        release_profile=release_profile,
    )
    return {
        "affected_paths": affected_paths,
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

    release = release_profile.get("release") if isinstance(release_profile, Mapping) else None
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

    if not rationales:
        rationales.append("No rationale recorded; human review is required before outreach.")
    return rationales


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
                notes.append(f"{change.get('id', 'change')}: {change.get('rationale', 'review required')}")

    if isinstance(release_profile, Mapping):
        notes.extend(str(note) for note in release_profile.get("review_notes", []))

    if isinstance(checkout_analysis, Mapping):
        for risk in checkout_analysis.get("risk_signals", []):
            if isinstance(risk, Mapping):
                signal = risk.get("signal")
                path = risk.get("path")
                if signal and path:
                    notes.append(f"{path}: {signal}")

    if not notes:
        notes.append("Review the downstream proposal before contacting maintainers.")
    return notes


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
    proposal_branch = choose_proposal_branch(fork_plan_entry)
    local_review_branch = fork_plan_entry.get("local_review_branch") or (
        f"review/{safe_branch_segment(target_full_name)}"
    )
    remote_url = fork_plan_entry.get("target_clone_url") or fork_plan_entry.get("target_url")
    if not remote_url:
        remote_url = f"https://github.com/{target_full_name}.git"

    commands = [
        f"git remote add {remote_name} {remote_url}",
        f"git fetch {remote_name} {proposal_branch}",
        f"git switch -c {local_review_branch} {remote_name}/{proposal_branch}",
    ]
    return {
        "remote_name": remote_name,
        "remote_url": remote_url,
        "proposal_branch": proposal_branch,
        "local_review_branch": local_review_branch,
        "commands": commands,
    }


def choose_proposal_branch(fork_plan_entry: dict[str, Any]) -> str:
    if fork_plan_entry.get("proposal_branch"):
        return str(fork_plan_entry["proposal_branch"])

    metadata = fork_plan_entry.get("metadata") or {}
    default_branch = str(
        fork_plan_entry.get("default_branch") or metadata.get("default_branch") or "main"
    )
    branch_model = fork_plan_entry.get("branch_model") or {}
    proposal_prefix = str(branch_model.get("proposal_prefix") or "proposal/")
    if proposal_prefix.endswith("/"):
        return f"{proposal_prefix}{default_branch}"
    return str(proposal_prefix)


def safe_branch_segment(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-").lower()
    return cleaned or "assured-downstream"


def render_fetch_instructions(fetch: dict[str, Any]) -> str:
    commands = "\n".join(fetch["commands"])
    return f"""## Maintainer Fetch Instructions

Upstream remains authoritative. This optional downstream branch is offered so maintainers can fetch, inspect, and adopt only the parts they choose.

```sh
{commands}
```

These commands create a local review branch and do not grant write access or change upstream release authority.
"""


def render_proposal_summary(summary: dict[str, Any]) -> str:
    lines = ["## Proposal Summary", "", "Affected paths:"]
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
    if not items:
        return ["- None recorded."]
    return [f"- {item}" for item in items]


def render_pr_description(
    *,
    source_full_name: str,
    fetch_markdown: str,
    summary_markdown: str,
) -> str:
    return f"""## Summary

This is an optional Assured Downstream proposal for `{source_full_name}`. Upstream remains authoritative; this branch does not change maintainer authority, release authority, or project direction.

Maintainers are welcome to ignore it, fetch it for local inspection, adapt individual changes, or tell us that future outreach should be suppressed.

{fetch_markdown}

{summary_markdown}
"""
