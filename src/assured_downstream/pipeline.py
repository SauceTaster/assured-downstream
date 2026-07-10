from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from assured_downstream.catalog import empty_catalog, save_catalog, upsert_findings, utc_now
from assured_downstream.enrichment import enrich_catalog
from assured_downstream.evidence import sha256_file
from assured_downstream.fork_apply import apply_fork_plan
from assured_downstream.fork_plan import create_fork_plan, resolve_fork_target
from assured_downstream.lifecycle import StateStore
from assured_downstream.pin_resolver import resolve_tooling_pins
from assured_downstream.run_index import append_run_record, create_pilot_run_record
from assured_downstream.scoring import score_catalog
from assured_downstream.seed import parse_seed_source
from assured_downstream.selection import CandidateSelectionPolicy, load_candidate_policy
from assured_downstream.sync_plan import create_sync_plan


def run_pilot_pipeline(
    *,
    seed_paths: list[Path | str],
    run_dir: Path,
    client: Any,
    org: str | None = None,
    target_owner: str | None = None,
    target_owner_type: str | None = None,
    name_prefix: str = "",
    limit: int | None = None,
    enrich: bool = False,
    resolve_pins: bool = False,
    tooling_path: Path | None = None,
    run_index_path: Path | None = None,
    run_id: str | None = None,
    selection_policy: CandidateSelectionPolicy | None = None,
    allowlist_path: Path | None = None,
    suppression_path: Path | None = None,
) -> dict[str, Any]:
    target = resolve_fork_target(
        org=org,
        target_owner=target_owner,
        target_owner_type=target_owner_type,
        name_prefix=name_prefix,
    )
    run_dir.mkdir(parents=True, exist_ok=True)
    catalog_path = run_dir / "catalog.json"
    fork_plan_path = run_dir / "fork-plan.json"
    state_path = run_dir / "state.json"
    sync_plan_path = run_dir / "sync-plan.json"
    selection_reasons_path = run_dir / "selection-reasons.json"
    summary_path = run_dir / "RUN_SUMMARY.md"
    pins_path = run_dir / "pins.json" if resolve_pins else None
    index_path = run_index_path or run_dir.parent / "index.json"
    effective_run_id = run_id or run_dir.name
    started_at = utc_now()
    seed_refs = [str(seed_path) for seed_path in seed_paths]

    output_paths = {
        "summary": str(summary_path),
        "catalog": str(catalog_path),
        "fork_plan": str(fork_plan_path),
        "selection_reasons": str(selection_reasons_path),
        "state": str(state_path),
        "sync_plan": str(sync_plan_path),
        "pins": str(pins_path) if pins_path else None,
    }
    counts = {
        "seed_findings": 0,
        "repositories": 0,
        "added_repositories": 0,
        "added_seed_refs": 0,
        "fork_plan_entries": 0,
        "selected": 0,
        "suppressed": 0,
        "allowlisted": 0,
    }

    try:
        effective_policy = selection_policy
        if effective_policy is None:
            effective_policy = load_candidate_policy(
                allowlist_path=allowlist_path,
                suppression_path=suppression_path,
            )

        catalog = empty_catalog()
        findings = []
        for seed_source in seed_paths:
            findings.extend(parse_seed_source(seed_source))
        added_repositories, added_seed_refs = upsert_findings(catalog, findings)
        counts.update(
            {
                "seed_findings": len(findings),
                "added_repositories": added_repositories,
                "added_seed_refs": added_seed_refs,
            }
        )

        enrichment_result = None
        if enrich:
            enrichment_result = enrich_catalog(catalog, client=client)

        score_catalog(catalog)

        save_catalog(catalog_path, catalog)
        counts["repositories"] = len(catalog.get("repositories", []))

        fork_plan = create_fork_plan(
            catalog,
            target_owner=target["owner"],
            target_owner_type=target["owner_type"],
            name_prefix=target["name_prefix"],
            limit=limit,
            selection_policy=effective_policy,
        )
        write_json(fork_plan_path, fork_plan)
        write_json(
            selection_reasons_path,
            {
                "created_at": fork_plan["created_at"],
                "counts": fork_plan["selection_counts"],
                "selection_reasons": fork_plan["selection_reasons"],
            },
        )
        counts.update(
            {
                "fork_plan_entries": len(fork_plan.get("forks", [])),
                "selected": fork_plan["selection_counts"]["selected"],
                "suppressed": fork_plan["selection_counts"]["suppressed"],
                "allowlisted": fork_plan["selection_counts"]["allowlisted"],
            }
        )

        state = StateStore.empty()
        fork_apply_result = apply_fork_plan(fork_plan, state=state, execute=False)
        state.save(state_path)

        sync_plan = create_sync_plan(fork_plan, workspace=run_dir / "worktrees")
        write_json(sync_plan_path, sync_plan)

        if resolve_pins:
            if tooling_path is None:
                raise ValueError("tooling_path is required when resolve_pins is true")
            if pins_path is None:
                raise ValueError("pins_path could not be prepared")
            with tooling_path.open("r", encoding="utf-8") as handle:
                tooling_policy = json.load(handle)
            pins = resolve_tooling_pins(
                tooling_policy,
                client=client,
                source_policy_sha256=sha256_file(tooling_path),
            )
            write_json(pins_path, pins)

        summary = {
            "run_id": effective_run_id,
            "run_index_path": str(index_path),
            "run_dir": str(run_dir),
            "summary_path": str(summary_path),
            "catalog_path": str(catalog_path),
            "fork_plan_path": str(fork_plan_path),
            "selection_reasons_path": str(selection_reasons_path),
            "state_path": str(state_path),
            "sync_plan_path": str(sync_plan_path),
            "pins_path": str(pins_path) if pins_path else None,
            "repositories": counts["repositories"],
            "seed_findings": counts["seed_findings"],
            "added_repositories": added_repositories,
            "added_seed_refs": added_seed_refs,
            "selection_counts": fork_plan["selection_counts"],
            "target": target,
            "enrichment": enrichment_result.__dict__ if enrichment_result else None,
            "fork_apply": fork_apply_result.__dict__,
        }
        write_summary(summary_path, summary, catalog)
        append_run_record(
            index_path,
            create_pilot_run_record(
                run_id=effective_run_id,
                started_at=started_at,
                seed_refs=seed_refs,
                org=(target["owner"] if target["owner_type"] == "organization" else None),
                run_dir=run_dir,
                output_paths=output_paths,
                counts=counts,
                status="succeeded",
                failures=[],
                target=target,
            ),
        )
        return summary
    except Exception as exc:
        append_run_record(
            index_path,
            create_pilot_run_record(
                run_id=effective_run_id,
                started_at=started_at,
                seed_refs=seed_refs,
                org=(target["owner"] if target["owner_type"] == "organization" else None),
                run_dir=run_dir,
                output_paths=output_paths,
                counts=counts,
                status="failed",
                failures=[
                    {
                        "type": exc.__class__.__name__,
                        "message": str(exc),
                    }
                ],
                target=target,
            ),
        )
        raise


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_summary(path: Path, summary: dict[str, Any], catalog: dict[str, Any]) -> None:
    top_repos = sorted(
        catalog.get("repositories", []),
        key=lambda repo: (-repo.get("score", 0), repo["owner"].lower(), repo["name"].lower()),
    )[:10]
    lines = [
        "# Assured Downstream Pilot Run",
        "",
        "Status: observe-first dev/idea-stage run. No forks or clones are executed by this pipeline.",
        "",
        "## Outputs",
        "",
        f"- catalog: `{summary['catalog_path']}`",
        f"- fork plan: `{summary['fork_plan_path']}`",
        f"- selection reasons: `{summary['selection_reasons_path']}`",
        f"- lifecycle state: `{summary['state_path']}`",
        f"- sync plan: `{summary['sync_plan_path']}`",
        f"- run index: `{summary['run_index_path']}`",
    ]
    if summary.get("pins_path"):
        lines.append(f"- pins: `{summary['pins_path']}`")

    lines.extend(
        [
            "",
            "## Counts",
            "",
            f"- seed findings: {summary['seed_findings']}",
            f"- repositories: {summary['repositories']}",
            f"- dry-run fork plan entries: {summary['fork_apply']['succeeded']}",
            f"- suppressed candidates: {summary['selection_counts']['suppressed']}",
            f"- allowlisted candidates: {summary['selection_counts']['allowlisted']}",
            "",
            "## Top Candidates",
            "",
        ]
    )
    if not top_repos:
        lines.append("- none")
    for repo in top_repos:
        lines.append(
            f"- `{repo['owner']}/{repo['name']}` score={repo.get('score', 0)} "
            f"mode={repo.get('recommended_mode', 'DownstreamAssured')}"
        )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
