from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from assured_downstream.catalog import empty_catalog, save_catalog, upsert_findings
from assured_downstream.enrichment import enrich_catalog
from assured_downstream.fork_apply import apply_fork_plan
from assured_downstream.fork_plan import create_fork_plan
from assured_downstream.lifecycle import StateStore
from assured_downstream.pin_resolver import resolve_tooling_pins
from assured_downstream.scoring import score_catalog
from assured_downstream.seed import parse_seed_source
from assured_downstream.sync_plan import create_sync_plan


def run_pilot_pipeline(
    *,
    seed_paths: list[Path | str],
    org: str,
    run_dir: Path,
    client: Any,
    limit: int | None = None,
    enrich: bool = False,
    resolve_pins: bool = False,
    tooling_path: Path | None = None,
) -> dict[str, Any]:
    run_dir.mkdir(parents=True, exist_ok=True)

    catalog = empty_catalog()
    findings = []
    for seed_source in seed_paths:
        findings.extend(parse_seed_source(seed_source))
    added_repositories, added_seed_refs = upsert_findings(catalog, findings)

    enrichment_result = None
    if enrich:
        enrichment_result = enrich_catalog(catalog, client=client)

    score_catalog(catalog)

    catalog_path = run_dir / "catalog.json"
    save_catalog(catalog_path, catalog)

    fork_plan = create_fork_plan(catalog, org=org, limit=limit)
    fork_plan_path = run_dir / "fork-plan.json"
    write_json(fork_plan_path, fork_plan)

    state = StateStore.empty()
    fork_apply_result = apply_fork_plan(fork_plan, state=state, execute=False)
    state_path = run_dir / "state.json"
    state.save(state_path)

    sync_plan = create_sync_plan(fork_plan, workspace=run_dir / "worktrees")
    sync_plan_path = run_dir / "sync-plan.json"
    write_json(sync_plan_path, sync_plan)

    pins_path = None
    if resolve_pins:
        if tooling_path is None:
            raise ValueError("tooling_path is required when resolve_pins is true")
        with tooling_path.open("r", encoding="utf-8") as handle:
            tooling_policy = json.load(handle)
        pins = resolve_tooling_pins(tooling_policy, client=client)
        pins_path = run_dir / "pins.json"
        write_json(pins_path, pins)

    summary = {
        "run_dir": str(run_dir),
        "summary_path": str(run_dir / "RUN_SUMMARY.md"),
        "catalog_path": str(catalog_path),
        "fork_plan_path": str(fork_plan_path),
        "state_path": str(state_path),
        "sync_plan_path": str(sync_plan_path),
        "pins_path": str(pins_path) if pins_path else None,
        "repositories": len(catalog.get("repositories", [])),
        "seed_findings": len(findings),
        "added_repositories": added_repositories,
        "added_seed_refs": added_seed_refs,
        "enrichment": enrichment_result.__dict__ if enrichment_result else None,
        "fork_apply": fork_apply_result.__dict__,
    }
    write_summary(run_dir / "RUN_SUMMARY.md", summary, catalog)
    return summary


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
        f"- lifecycle state: `{summary['state_path']}`",
        f"- sync plan: `{summary['sync_plan_path']}`",
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
