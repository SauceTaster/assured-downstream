from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


PIN_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


@dataclass(frozen=True)
class RenderResult:
    written: list[dict[str, str]]
    skipped: list[dict[str, str]]


def render_overlay(
    overlay: dict[str, Any],
    *,
    root: Path,
    pins: dict[str, str] | None = None,
    execute: bool = False,
    force: bool = False,
) -> RenderResult:
    pins = normalize_pin_map(pins or {})
    root = root.resolve()
    if not root.exists():
        raise FileNotFoundError(root)
    if not root.is_dir():
        raise NotADirectoryError(root)

    writable: list[tuple[str, str, str]] = []
    skipped: list[dict[str, str]] = []

    for change in overlay.get("proposed_changes", []):
        rendered = render_change(change, overlay=overlay, pins=pins)
        if rendered is None:
            skipped.append(
                {
                    "id": change["id"],
                    "reason": skip_reason(change),
                }
            )
            continue
        path, content = rendered
        writable.append((change["id"], path, content))

    written = []
    for change_id, relative_path, content in writable:
        target = root / relative_path
        if target.exists() and not force:
            skipped.append(
                {
                    "id": change_id,
                    "reason": f"{relative_path} already exists; pass --force to overwrite",
                }
            )
            continue
        if execute:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        written.append({"id": change_id, "path": relative_path})

    return RenderResult(written=written, skipped=skipped)


def render_change(
    change: dict[str, Any],
    *,
    overlay: dict[str, Any],
    pins: dict[str, str],
) -> tuple[str, str] | None:
    change_id = change["id"]
    if change_id == "gha-bootstrap":
        required = require_pins(pins, ["actions/checkout"])
        if required is None:
            return None
        return (
            ".github/workflows/assured-downstream-ci.yml",
            bootstrap_workflow(required["actions/checkout"]),
        )
    if change_id == "dependabot-baseline":
        return (".github/dependabot.yml", dependabot_config())
    if change_id == "dependency-review":
        required = require_pins(
            pins,
            ["actions/checkout", "actions/dependency-review-action"],
        )
        if required is None:
            return None
        return (
            ".github/workflows/assured-downstream-dependency-review.yml",
            dependency_review_workflow(
                checkout_sha=required["actions/checkout"],
                dependency_review_sha=required["actions/dependency-review-action"],
            ),
        )
    if change_id == "scorecard-evidence":
        required = require_pins(pins, ["ossf/scorecard-action"])
        if required is None:
            return None
        return (
            ".github/workflows/assured-downstream-scorecard.yml",
            scorecard_workflow(required["ossf/scorecard-action"]),
        )
    if change_id == "in-toto-evidence":
        return (
            "evidence/assured-downstream/README.md",
            evidence_readme(overlay),
        )
    return None


def skip_reason(change: dict[str, Any]) -> str:
    change_id = change["id"]
    if change_id in {"gha-bootstrap", "dependency-review", "scorecard-evidence"}:
        return "workflow rendering requires full SHA pins in --pins"
    return "change requires repository-specific patch logic or human review"


def require_pins(pins: dict[str, str], names: list[str]) -> dict[str, str] | None:
    resolved = {}
    for name in names:
        value = pins.get(name)
        if not value or not PIN_PATTERN.fullmatch(value):
            return None
        resolved[name] = value
    return resolved


def normalize_pin_map(pins: dict[str, Any]) -> dict[str, str]:
    if isinstance(pins.get("entries"), dict):
        return normalize_pin_lock(pins)
    if isinstance(pins.get("pins"), dict):
        pins = pins["pins"]

    normalized = {}
    for name, value in pins.items():
        if isinstance(value, str):
            normalized[name] = value
        elif isinstance(value, dict) and isinstance(value.get("sha"), str):
            normalized[name] = value["sha"]
    return normalized


def normalize_pin_lock(lock: dict[str, Any]) -> dict[str, str]:
    normalized = {}
    for name, entry in lock.get("entries", {}).items():
        if not isinstance(entry, dict):
            continue
        if not pin_entry_is_current(entry):
            continue
        sha = entry.get("sha")
        if isinstance(sha, str):
            normalized[name] = sha
    return normalized


def pin_entry_is_current(entry: dict[str, Any]) -> bool:
    if entry.get("status") != "resolved":
        return False
    if entry.get("refresh_status", "current") != "current":
        return False
    expires_at = entry.get("expires_at")
    if isinstance(expires_at, str):
        try:
            parsed = datetime.fromisoformat(expires_at)
        except ValueError:
            return False
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        if parsed <= datetime.now(UTC):
            return False
    return True


def dependabot_config() -> str:
    return """# Generated by Assured Downstream. Review before merging upstream.
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
"""


def bootstrap_workflow(checkout_sha: str) -> str:
    return f"""# Generated by Assured Downstream. Review before merging upstream.
name: Assured Downstream CI

on:
  pull_request:
  push:
    branches:
      - main

permissions:
  contents: read

jobs:
  baseline:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{checkout_sha}
"""


def dependency_review_workflow(
    *,
    checkout_sha: str,
    dependency_review_sha: str,
) -> str:
    return f"""# Generated by Assured Downstream. Review before merging upstream.
name: Assured Downstream Dependency Review

on:
  pull_request:

permissions:
  contents: read
  pull-requests: read

jobs:
  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{checkout_sha}
      - uses: actions/dependency-review-action@{dependency_review_sha}
"""


def scorecard_workflow(scorecard_sha: str) -> str:
    return f"""# Generated by Assured Downstream. Review before merging upstream.
name: Assured Downstream Scorecard

on:
  branch_protection_rule:
  schedule:
    - cron: "17 3 * * 2"
  workflow_dispatch:

permissions:
  contents: read
  security-events: write
  id-token: write

jobs:
  scorecard:
    runs-on: ubuntu-latest
    steps:
      - uses: ossf/scorecard-action@{scorecard_sha}
        with:
          results_file: scorecard.sarif
          results_format: sarif
          publish_results: true
"""


def evidence_readme(overlay: dict[str, Any]) -> str:
    target = overlay.get("target", "Hardened")
    generated_at = overlay.get("generated_at", "unknown")
    return f"""# Assured Downstream Evidence

This directory is reserved for Assured Downstream evidence artifacts.

Status: early idea/dev stage.

- overlay target: {target}
- overlay generated at: {generated_at}

Expected future contents include SBOMs, SLSA provenance, in-toto statements,
runtime trace summaries, rebuild comparison reports, and validation summaries.
"""
