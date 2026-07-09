from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from assured_downstream.overlay import plan_overlay
from assured_downstream.overlay_render import RenderResult, render_overlay
from assured_downstream.recon import inspect_repository


def run_checkout_analysis(
    *,
    checkout_path: Path,
    run_dir: Path,
    target: str,
    pins: dict[str, str] | None = None,
    render: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    run_dir.mkdir(parents=True, exist_ok=True)

    recon = inspect_repository(checkout_path)
    recon_path = run_dir / "recon.json"
    write_json(recon_path, recon)

    overlay = plan_overlay(recon, target=target)
    overlay_path = run_dir / "overlay-plan.json"
    write_json(overlay_path, overlay)

    render_result = render_overlay(
        overlay,
        root=checkout_path,
        pins=pins or {},
        execute=render,
        force=force,
    )
    render_path = run_dir / "render-result.json"
    write_json(render_path, render_result_payload(render_result, executed=render))

    summary = {
        "checkout_path": str(checkout_path.resolve()),
        "run_dir": str(run_dir),
        "summary_path": str(run_dir / "CHECKOUT_SUMMARY.md"),
        "recon_path": str(recon_path),
        "overlay_path": str(overlay_path),
        "render_path": str(render_path),
        "target": target,
        "overlay_changes": len(overlay.get("proposed_changes", [])),
        "planned_writable_files": len(render_result.written),
        "rendered_files": len(render_result.written) if render else 0,
        "skipped_changes": len(render_result.skipped),
        "render_executed": render,
    }
    write_checkout_summary(run_dir / "CHECKOUT_SUMMARY.md", summary, overlay, render_result)
    return summary


def render_result_payload(result: RenderResult, *, executed: bool) -> dict[str, Any]:
    return {
        "executed": executed,
        "written": result.written,
        "skipped": result.skipped,
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_checkout_summary(
    path: Path,
    summary: dict[str, Any],
    overlay: dict[str, Any],
    render_result: RenderResult,
) -> None:
    lines = [
        "# SauceTotal Checkout Analysis",
        "",
        "Status: dev/idea-stage local checkout analysis.",
        "",
        "## Outputs",
        "",
        f"- recon: `{summary['recon_path']}`",
        f"- overlay plan: `{summary['overlay_path']}`",
        f"- render result: `{summary['render_path']}`",
        "",
        "## Overlay",
        "",
        f"- target: {summary['target']}",
        f"- proposed changes: {summary['overlay_changes']}",
        f"- planned writable files: {summary['planned_writable_files']}",
        f"- rendered files: {summary['rendered_files']}",
        f"- skipped changes: {summary['skipped_changes']}",
        f"- render executed: {summary['render_executed']}",
        "",
        "## Proposed Changes",
        "",
    ]
    for change in overlay.get("proposed_changes", []):
        lines.append(f"- `{change['id']}` stage={change['stage']} action={change['action']}")
    if not overlay.get("proposed_changes"):
        lines.append("- none")

    lines.extend(["", "## Writable Files", ""])
    for item in render_result.written:
        lines.append(f"- `{item['path']}`")
    if not render_result.written:
        lines.append("- none")

    lines.extend(["", "## Skipped Changes", ""])
    for item in render_result.skipped:
        lines.append(f"- `{item['id']}`: {item['reason']}")
    if not render_result.skipped:
        lines.append("- none")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
