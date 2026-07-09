from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

from assured_downstream.catalog import utc_now


IGNORED_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "vendor",
}

EXTENSION_LANGUAGES = {
    ".c": "C",
    ".cc": "C++",
    ".cs": "C#",
    ".cpp": "C++",
    ".fs": "F#",
    ".go": "Go",
    ".java": "Java",
    ".js": "JavaScript",
    ".kt": "Kotlin",
    ".m": "Objective-C",
    ".mm": "Objective-C++",
    ".php": "PHP",
    ".ps1": "PowerShell",
    ".py": "Python",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".sh": "Shell",
    ".swift": "Swift",
    ".ts": "TypeScript",
}

PACKAGE_MANAGER_FILES = {
    "Cargo.lock": "cargo",
    "Cargo.toml": "cargo",
    "Gemfile": "bundler",
    "Gemfile.lock": "bundler",
    "go.mod": "go",
    "go.sum": "go",
    "gradle.properties": "gradle",
    "package-lock.json": "npm",
    "package.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "poetry.lock": "poetry",
    "pom.xml": "maven",
    "pyproject.toml": "python",
    "requirements.txt": "pip",
    "setup.cfg": "python",
    "setup.py": "python",
    "yarn.lock": "yarn",
}

BUILD_SYSTEM_FILES = {
    "CMakeLists.txt": "cmake",
    "Dockerfile": "docker",
    "Justfile": "just",
    "Makefile": "make",
    "Taskfile.yml": "task",
    "Taskfile.yaml": "task",
    "docker-compose.yml": "docker-compose",
    "docker-compose.yaml": "docker-compose",
    "goreleaser.yml": "goreleaser",
    "goreleaser.yaml": "goreleaser",
}

ACTION_USES_PATTERN = re.compile(
    r"^\s*(?:-\s*)?uses:\s*([^@\s]+)(?:@([^\s#]+))?",
    re.MULTILINE,
)


def inspect_repository(path: Path) -> dict[str, Any]:
    root = path.resolve()
    if not root.exists():
        raise FileNotFoundError(root)
    if not root.is_dir():
        raise NotADirectoryError(root)

    files = list(walk_files(root))
    workflow_files = [
        file for file in files
        if ".github/workflows/" in file.relative_to(root).as_posix()
        and file.suffix.lower() in {".yml", ".yaml"}
    ]

    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "path": str(root),
        "file_count": len(files),
        "languages": detect_languages(files),
        "package_managers": detect_named_files(files, PACKAGE_MANAGER_FILES),
        "build_systems": detect_build_systems(files),
        "ci": inspect_ci_workflows(root, workflow_files),
        "security_controls": detect_security_controls(files, workflow_files),
        "release_signals": detect_release_signals(files, workflow_files),
        "risk_signals": detect_risk_signals(root, workflow_files),
    }


def walk_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if any(part in IGNORED_DIRS for part in path.relative_to(root).parts):
            continue
        if path.is_file():
            files.append(path)
    return files


def detect_languages(files: list[Path]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for file in files:
        language = EXTENSION_LANGUAGES.get(file.suffix.lower())
        if language:
            counts[language] += 1
    return dict(counts.most_common())


def detect_named_files(files: list[Path], mapping: dict[str, str]) -> list[dict[str, str]]:
    matches = []
    for file in files:
        name = mapping.get(file.name)
        if name:
            matches.append({"name": name, "path": file.name})
    return sorted(matches, key=lambda entry: (entry["name"], entry["path"]))


def detect_build_systems(files: list[Path]) -> list[dict[str, str]]:
    matches = detect_named_files(files, BUILD_SYSTEM_FILES)
    for file in files:
        if file.suffix.lower() in {".csproj", ".fsproj", ".sln"}:
            matches.append({"name": "dotnet", "path": file.name})
    return sorted(matches, key=lambda entry: (entry["name"], entry["path"]))


def inspect_ci_workflows(root: Path, workflow_files: list[Path]) -> dict[str, Any]:
    workflows = []
    for workflow in sorted(workflow_files):
        text = read_text(workflow)
        actions = [
            {"name": match.group(1), "ref": match.group(2)}
            for match in ACTION_USES_PATTERN.finditer(text)
        ]
        workflows.append(
            {
                "path": workflow.relative_to(root).as_posix(),
                "has_permissions_block": "permissions:" in text,
                "uses_pull_request_target": "pull_request_target" in text,
                "uses_workflow_dispatch": "workflow_dispatch" in text,
                "uses_release_trigger": "release:" in text or "published:" in text,
                "actions": actions,
            }
        )

    return {
        "provider": "github-actions" if workflows else None,
        "workflow_count": len(workflows),
        "workflows": workflows,
    }


def detect_security_controls(files: list[Path], workflow_files: list[Path]) -> dict[str, bool]:
    combined_text = "\n".join(read_text(file).lower() for file in workflow_files)
    file_names = {file.name.lower() for file in files}

    return {
        "has_security_policy": "security.md" in file_names,
        "has_dependabot": any(".github/dependabot.yml" in file.as_posix() for file in files),
        "mentions_sigstore": "sigstore" in combined_text or "cosign" in combined_text,
        "mentions_slsa": "slsa" in combined_text,
        "mentions_sbom": "sbom" in combined_text or "cyclonedx" in combined_text or "syft" in combined_text,
        "mentions_scorecard": "scorecard" in combined_text,
        "mentions_harden_runner": "harden-runner" in combined_text,
        "mentions_falco": "falco" in combined_text,
    }


def detect_release_signals(files: list[Path], workflow_files: list[Path]) -> dict[str, bool]:
    combined_text = "\n".join(read_text(file).lower() for file in workflow_files)
    file_names = {file.name.lower() for file in files}

    return {
        "has_goreleaser": "goreleaser.yml" in file_names or "goreleaser.yaml" in file_names,
        "uploads_github_release": "softprops/action-gh-release" in combined_text
        or "gh release" in combined_text,
        "publishes_container": "docker/build-push-action" in combined_text,
        "publishes_npm": "npm publish" in combined_text,
        "publishes_pypi": "pypa/gh-action-pypi-publish" in combined_text
        or "twine upload" in combined_text,
        "publishes_crate": "cargo publish" in combined_text,
    }


def detect_risk_signals(root: Path, workflow_files: list[Path]) -> list[dict[str, str]]:
    risks = []
    for workflow in sorted(workflow_files):
        text = read_text(workflow)
        relative = workflow.relative_to(root).as_posix()
        if "pull_request_target" in text:
            risks.append(
                {
                    "severity": "high",
                    "path": relative,
                    "signal": "workflow uses pull_request_target",
                }
            )
        if re.search(r"permissions:\s+write-all", text):
            risks.append(
                {
                    "severity": "high",
                    "path": relative,
                    "signal": "workflow grants write-all permissions",
                }
            )
        if re.search(r"curl\s+[^|\n]+\|\s*(sh|bash)", text):
            risks.append(
                {
                    "severity": "medium",
                    "path": relative,
                    "signal": "workflow pipes curl to shell",
                }
            )
        for action, ref in ACTION_USES_PATTERN.findall(text):
            if ref and not looks_pinned(ref):
                risks.append(
                    {
                        "severity": "medium",
                        "path": relative,
                        "signal": f"action {action}@{ref} is not pinned to a full commit SHA",
                    }
                )
    return risks


def looks_pinned(ref: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}", ref))


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")
