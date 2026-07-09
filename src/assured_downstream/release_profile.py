from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from assured_downstream.catalog import utc_now


REQUIRED_RELEASE_ACTIONS = [
    "actions/checkout",
    "actions/attest",
    "actions/upload-artifact",
    "anchore/sbom-action",
]


def plan_release_profile(recon_report: dict[str, Any]) -> dict[str, Any]:
    root = Path(recon_report.get("path") or ".")
    package_managers = {entry["name"] for entry in recon_report.get("package_managers", [])}
    languages = recon_report.get("languages", {})
    project_name = detect_project_name(root, package_managers)
    build = choose_build(root, package_managers, languages, project_name)
    artifact_candidates = normalize_artifact_candidates(recon_report.get("artifact_candidates", []))

    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": "draft-human-review-required",
        "human_review_required": True,
        "review": {
            "status": "human-review-required",
            "release_workflow_confirmed": False,
            "artifact_paths_confirmed": False,
            "confirmed_by": None,
            "confirmed_at": None,
        },
        "source_recon": {
            "path": recon_report.get("path"),
            "generated_at": recon_report.get("generated_at"),
        },
        "project": {
            "name": project_name,
            "language_family": build["language_family"],
            "package_managers": sorted(package_managers),
        },
        "release": {
            "workflow_path": ".github/workflows/assured-downstream-attested-release.yml",
            "trigger": "workflow_dispatch until release workflow and artifact paths are confirmed",
            "confirmed_tag_pattern": "secure-v*",
            "runs_on": "ubuntu-latest",
            "build_commands": build["commands"],
            "artifact_paths": build["artifact_paths"],
            "artifact_candidates": artifact_candidates,
            "sbom_path": "dist/assured-downstream-sbom.spdx.json",
            "sbom_format": "spdx-json",
            "required_actions": REQUIRED_RELEASE_ACTIONS,
        },
        "review_notes": build["review_notes"] + artifact_candidate_notes(artifact_candidates) + [
            "Confirm artifact globs match the actual release outputs.",
            "Confirm generated SBOM scope is appropriate for this project.",
            "Confirm this downstream workflow does not replace upstream release authority.",
        ],
    }


def choose_build(
    root: Path,
    package_managers: set[str],
    languages: dict[str, int],
    project_name: str,
) -> dict[str, Any]:
    if "go" in package_managers or "Go" in languages:
        return {
            "language_family": "go",
            "commands": [
                "mkdir -p dist",
                f"go build -trimpath -buildvcs=true -o dist/{shell_name(project_name)} .",
            ],
            "artifact_paths": ["dist/*"],
            "review_notes": [
                "Review whether the Go project builds from repository root or needs package-specific commands.",
            ],
        }
    if "cargo" in package_managers or "Rust" in languages:
        return {
            "language_family": "rust",
            "commands": [
                "mkdir -p dist",
                "cargo build --locked --release",
                "find target/release -maxdepth 1 -type f -perm -111 -exec cp {} dist/ \\;",
            ],
            "artifact_paths": ["dist/*"],
            "review_notes": [
                "Review copied Rust release binaries; examples, test helpers, or build-script outputs may need filtering.",
            ],
        }
    if "python" in package_managers or "pip" in package_managers or "Python" in languages:
        return {
            "language_family": "python",
            "commands": [
                "python -m pip install --upgrade build",
                "python -m build --outdir dist",
            ],
            "artifact_paths": ["dist/*.whl", "dist/*.tar.gz"],
            "review_notes": [
                "Review whether the Python project needs extra build dependencies or isolated build settings.",
            ],
        }
    return {
        "language_family": "unknown",
        "commands": [
            "mkdir -p dist",
            "echo 'TODO: add reviewed build command' >&2",
            "exit 1",
        ],
        "artifact_paths": ["dist/*"],
        "review_notes": [
            "No first-lane build profile matched; provide a reviewed build command before enabling this workflow.",
        ],
    }


def normalize_artifact_candidates(raw_candidates: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_candidates, list):
        return []

    candidates = []
    for candidate in raw_candidates:
        if not isinstance(candidate, dict):
            continue
        paths = candidate.get("paths") or []
        if not isinstance(paths, list):
            paths = [paths]
        candidates.append(
            {
                "workflow": candidate.get("workflow"),
                "job_id": candidate.get("job_id"),
                "step_name": candidate.get("step_name"),
                "source": candidate.get("source"),
                "artifact_name": candidate.get("artifact_name"),
                "paths": [str(path) for path in paths if path],
            }
        )
    return candidates


def artifact_candidate_notes(candidates: list[dict[str, Any]]) -> list[str]:
    if not candidates:
        return []
    return [
        (
            "Review recon artifact candidates before confirming release paths: "
            + ", ".join(sorted({path for candidate in candidates for path in candidate["paths"]}))
        )
    ]


def detect_project_name(root: Path, package_managers: set[str]) -> str:
    if "python" in package_managers and (root / "pyproject.toml").exists():
        name = read_toml_name(root / "pyproject.toml", "project")
        if name:
            return name
    if "cargo" in package_managers and (root / "Cargo.toml").exists():
        name = read_toml_name(root / "Cargo.toml", "package")
        if name:
            return name
    if "go" in package_managers and (root / "go.mod").exists():
        module_name = read_go_module(root / "go.mod")
        if module_name:
            return module_name.rsplit("/", 1)[-1]
    return root.name


def read_toml_name(path: Path, section: str) -> str | None:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        return None
    value = data.get(section, {}).get("name")
    return value if isinstance(value, str) else None


def read_go_module(path: Path) -> str | None:
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith("module "):
            return stripped.split(None, 1)[1]
    return None


def shell_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")
    return cleaned or "artifact"
