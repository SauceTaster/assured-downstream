from __future__ import annotations

import re
import shlex
from collections import Counter
from pathlib import Path
from typing import Any

from assured_downstream.catalog import utc_now
from assured_downstream.workflow_yaml import WorkflowYamlError, parse_workflow_yaml


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
    ".vb": "Visual Basic",
}

PACKAGE_MANAGER_FILES = {
    "Cargo.lock": "cargo",
    "Cargo.toml": "cargo",
    "Gemfile": "bundler",
    "Gemfile.lock": "bundler",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "Directory.Packages.props": "dotnet",
    "go.mod": "go",
    "go.sum": "go",
    "gradle.properties": "gradle",
    "gradle.lockfile": "gradle",
    "package-lock.json": "npm",
    "package.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "poetry.lock": "poetry",
    "pom.xml": "maven",
    "pyproject.toml": "python",
    "requirements.txt": "pip",
    "setup.cfg": "python",
    "setup.py": "python",
    "settings.gradle": "gradle",
    "settings.gradle.kts": "gradle",
    "packages.lock.json": "dotnet",
    "yarn.lock": "yarn",
}

BUILD_SYSTEM_FILES = {
    "CMakeLists.txt": "cmake",
    "Dockerfile": "docker",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "Justfile": "just",
    "Makefile": "make",
    "Taskfile.yml": "task",
    "Taskfile.yaml": "task",
    "docker-compose.yml": "docker-compose",
    "docker-compose.yaml": "docker-compose",
    "goreleaser.yml": "goreleaser",
    "goreleaser.yaml": "goreleaser",
    "pom.xml": "maven",
    "settings.gradle": "gradle",
    "settings.gradle.kts": "gradle",
}

ACTION_USES_PATTERN = re.compile(
    r"^\s*(?:-\s*)?uses:\s*([^@\s]+)(?:@([^\s#]+))?",
    re.MULTILINE,
)

ARTIFACT_UPLOAD_ACTIONS = {
    "actions/upload-artifact",
}

ARTIFACT_DOWNLOAD_ACTIONS = {
    "actions/download-artifact",
}

RELEASE_UPLOAD_ACTIONS = {
    "ncipollo/release-action",
    "softprops/action-gh-release",
    "svenstaro/upload-release-action",
}


def inspect_repository(
    path: Path,
    *,
    descriptor_relative: bool = False,
) -> dict[str, Any]:
    if descriptor_relative:
        if path != Path("."):
            raise ValueError("Descriptor-relative recon requires root '.'")
        root = Path(".")
    else:
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

    ci = inspect_ci_workflows(root, workflow_files)

    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "path": str(root),
        "file_count": len(files),
        "languages": detect_languages(files),
        "package_managers": detect_package_managers(files),
        "build_systems": detect_build_systems(files),
        "ci": ci,
        "security_controls": detect_security_controls(files, workflow_files),
        "release_signals": detect_release_signals(files, workflow_files, ci),
        "release_triggers": collect_release_triggers(ci),
        "artifact_candidates": collect_artifact_candidates(ci),
        "risk_signals": detect_risk_signals(ci),
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


def detect_package_managers(files: list[Path]) -> list[dict[str, str]]:
    matches = detect_named_files(files, PACKAGE_MANAGER_FILES)
    for file in files:
        if file.suffix.lower() in {".csproj", ".fsproj", ".vbproj", ".sln"}:
            matches.append({"name": "dotnet", "path": file.name})
    return sorted(matches, key=lambda entry: (entry["name"], entry["path"]))


def detect_build_systems(files: list[Path]) -> list[dict[str, str]]:
    matches = detect_named_files(files, BUILD_SYSTEM_FILES)
    for file in files:
        if file.suffix.lower() in {".csproj", ".fsproj", ".vbproj", ".sln"}:
            matches.append({"name": "dotnet", "path": file.name})
    return sorted(matches, key=lambda entry: (entry["name"], entry["path"]))


def inspect_ci_workflows(root: Path, workflow_files: list[Path]) -> dict[str, Any]:
    workflows = []
    for workflow in sorted(workflow_files):
        workflows.append(inspect_workflow(root, workflow))

    return {
        "provider": "github-actions" if workflows else None,
        "workflow_count": len(workflows),
        "workflows": workflows,
    }


def inspect_workflow(root: Path, workflow: Path) -> dict[str, Any]:
    text = read_text(workflow)
    relative = workflow.relative_to(root).as_posix()
    parse_error = None
    try:
        parsed = parse_workflow_yaml(text)
        parsed_ok = True
    except WorkflowYamlError as exc:
        parsed = {}
        parsed_ok = False
        parse_error = str(exc)

    triggers = normalize_triggers(parsed.get("on")) if parsed_ok else fallback_triggers(text)
    permissions = (
        normalize_permissions(parsed.get("permissions"))
        if "permissions" in parsed
        else fallback_permissions(text) if not parsed_ok else None
    )
    jobs = inspect_jobs(parsed.get("jobs")) if isinstance(parsed.get("jobs"), dict) else []
    actions = collect_workflow_actions(jobs) if parsed_ok else fallback_actions(text)
    artifact_steps = collect_workflow_artifact_steps(jobs)
    release_triggers = detect_workflow_release_triggers(triggers)

    return {
        "path": relative,
        "name": parsed.get("name") if isinstance(parsed.get("name"), str) else None,
        "parsed": parsed_ok,
        "parse_error": parse_error,
        "triggers": triggers,
        "release_triggers": release_triggers,
        "permissions": permissions,
        "has_permissions_block": permissions is not None if parsed_ok else "permissions:" in text,
        "uses_pull_request_target": has_trigger(triggers, "pull_request_target"),
        "uses_workflow_dispatch": has_trigger(triggers, "workflow_dispatch"),
        "uses_release_trigger": bool(release_triggers)
        or (not parsed_ok and ("release:" in text or "published:" in text)),
        "actions": actions,
        "artifact_steps": artifact_steps,
        "jobs": jobs,
    }


def normalize_triggers(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, str):
        return [{"event": value, "config": {}}]
    if isinstance(value, list):
        return [
            {"event": str(event), "config": {}}
            for event in value
            if event not in (None, "")
        ]
    if isinstance(value, dict):
        triggers = []
        for event, config in value.items():
            triggers.append(
                {
                    "event": str(event),
                    "config": normalize_trigger_config(config),
                }
            )
        return triggers
    return [{"event": str(value), "config": {}}]


def normalize_trigger_config(value: Any) -> Any:
    if value in (None, ""):
        return {}
    if isinstance(value, list):
        return {"types": normalize_json_value(value)}
    return normalize_json_value(value)


def fallback_triggers(text: str) -> list[dict[str, Any]]:
    triggers = []
    for event in ["pull_request_target", "workflow_dispatch", "release", "push", "pull_request"]:
        if re.search(rf"^\s*{re.escape(event)}\s*:", text, re.MULTILINE):
            triggers.append({"event": event, "config": {}})
    return triggers


def has_trigger(triggers: list[dict[str, Any]], event: str) -> bool:
    return any(trigger.get("event") == event for trigger in triggers)


def detect_workflow_release_triggers(triggers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    release_triggers = []
    for trigger in triggers:
        event = trigger.get("event")
        config = trigger.get("config")
        if event == "release":
            release_triggers.append(
                {
                    "event": "release",
                    "types": ensure_list(config.get("types")) if isinstance(config, dict) else [],
                    "config": normalize_json_value(config),
                }
            )
        elif event == "push" and isinstance(config, dict):
            tags = ensure_list(config.get("tags"))
            tags_ignore = ensure_list(config.get("tags-ignore"))
            if tags or tags_ignore:
                release_triggers.append(
                    {
                        "event": "push",
                        "tags": tags,
                        "tags_ignore": tags_ignore,
                        "config": normalize_json_value(config),
                    }
                )
    return release_triggers


def normalize_permissions(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return {"mode": value, "scopes": {}}
    if isinstance(value, dict):
        return {
            "mode": "scoped",
            "scopes": {
                str(scope): str(access)
                for scope, access in value.items()
            },
        }
    return {"mode": "unknown", "value": normalize_json_value(value), "scopes": {}}


def inspect_jobs(value: dict[Any, Any]) -> list[dict[str, Any]]:
    jobs = []
    for job_id, job_config in value.items():
        if not isinstance(job_config, dict):
            jobs.append({"id": str(job_id), "raw": normalize_json_value(job_config), "steps": []})
            continue

        steps = inspect_steps(str(job_id), job_config.get("steps"))
        job_uses = parse_uses(job_config.get("uses"))
        job = {
            "id": str(job_id),
            "name": job_config.get("name") if isinstance(job_config.get("name"), str) else None,
            "runs_on": normalize_json_value(job_config.get("runs-on")),
            "needs": normalize_json_value(job_config.get("needs")),
            "permissions": normalize_permissions(job_config.get("permissions"))
            if "permissions" in job_config else None,
            "uses": job_uses,
            "actions": collect_step_actions(steps),
            "artifact_steps": collect_step_artifacts(steps),
            "steps": steps,
        }
        jobs.append(job)
    return jobs


def inspect_steps(job_id: str, value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    steps = []
    for index, step_config in enumerate(value, start=1):
        if not isinstance(step_config, dict):
            steps.append(
                {
                    "index": index,
                    "job_id": job_id,
                    "raw": normalize_json_value(step_config),
                }
            )
            continue

        with_config = normalize_mapping(step_config.get("with"))
        uses = parse_uses(step_config.get("uses"))
        run = step_config.get("run") if isinstance(step_config.get("run"), str) else None
        step = {
            "index": index,
            "job_id": job_id,
            "id": step_config.get("id") if isinstance(step_config.get("id"), str) else None,
            "name": step_config.get("name") if isinstance(step_config.get("name"), str) else None,
            "uses": uses,
            "run": run,
            "with": with_config,
        }
        artifact = detect_artifact_step(step)
        if artifact:
            step["artifact"] = artifact
        steps.append(step)
    return steps


def parse_uses(value: Any) -> dict[str, str | None] | None:
    if not isinstance(value, str) or not value:
        return None
    if "@" in value:
        name, ref = value.rsplit("@", 1)
    else:
        name, ref = value, None
    return {"name": name, "ref": ref, "raw": value}


def detect_artifact_step(step: dict[str, Any]) -> dict[str, Any] | None:
    uses = step.get("uses")
    run = step.get("run")
    with_config = step.get("with") if isinstance(step.get("with"), dict) else {}

    if isinstance(uses, dict):
        action_name = str(uses.get("name", "")).lower()
        if action_name in ARTIFACT_UPLOAD_ACTIONS:
            return {
                "kind": "upload-artifact",
                "artifact_name": string_or_none(with_config.get("name")),
                "paths": extract_paths(with_config.get("path")),
            }
        if action_name in ARTIFACT_DOWNLOAD_ACTIONS:
            return {
                "kind": "download-artifact",
                "artifact_name": string_or_none(with_config.get("name")),
                "paths": extract_paths(with_config.get("path")),
            }
        if action_name in RELEASE_UPLOAD_ACTIONS:
            return {
                "kind": "release-upload",
                "artifact_name": string_or_none(with_config.get("name")),
                "paths": extract_paths(
                    first_present(with_config, ["files", "artifacts", "asset_path", "artifact"])
                ),
            }

    if isinstance(run, str) and "gh release upload" in run:
        return {
            "kind": "release-upload-command",
            "artifact_name": None,
            "paths": extract_gh_release_upload_paths(run),
        }
    return None


def collect_step_actions(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    actions = []
    for step in steps:
        uses = step.get("uses")
        if isinstance(uses, dict):
            actions.append(
                {
                    "name": uses.get("name"),
                    "ref": uses.get("ref"),
                    "raw": uses.get("raw"),
                    "job_id": step.get("job_id"),
                    "step_index": step.get("index"),
                    "step_name": step.get("name"),
                }
            )
    return actions


def collect_step_artifacts(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    artifacts = []
    for step in steps:
        artifact = step.get("artifact")
        if isinstance(artifact, dict):
            entry = {
                "job_id": step.get("job_id"),
                "step_index": step.get("index"),
                "step_name": step.get("name"),
            }
            entry.update(artifact)
            artifacts.append(entry)
    return artifacts


def collect_workflow_actions(jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    actions = []
    for job in jobs:
        actions.extend(job.get("actions", []))
    return actions


def collect_workflow_artifact_steps(jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    artifacts = []
    for job in jobs:
        artifacts.extend(job.get("artifact_steps", []))
    return artifacts


def collect_release_triggers(ci: dict[str, Any]) -> list[dict[str, Any]]:
    triggers = []
    for workflow in ci.get("workflows", []):
        for trigger in workflow.get("release_triggers", []):
            entry = {"workflow": workflow.get("path")}
            entry.update(trigger)
            triggers.append(entry)
    return triggers


def collect_artifact_candidates(ci: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = []
    for workflow in ci.get("workflows", []):
        for artifact in workflow.get("artifact_steps", []):
            paths = artifact.get("paths") or []
            if not paths or artifact.get("kind") == "download-artifact":
                continue
            candidates.append(
                {
                    "workflow": workflow.get("path"),
                    "job_id": artifact.get("job_id"),
                    "step_index": artifact.get("step_index"),
                    "step_name": artifact.get("step_name"),
                    "source": artifact.get("kind"),
                    "artifact_name": artifact.get("artifact_name"),
                    "paths": paths,
                }
            )
    return candidates


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


def detect_release_signals(
    files: list[Path],
    workflow_files: list[Path],
    ci: dict[str, Any],
) -> dict[str, bool]:
    combined_text = "\n".join(read_text(file).lower() for file in workflow_files)
    run_text = "\n".join(collect_run_commands(ci)).lower()
    action_names = {
        str(action.get("name", "")).lower()
        for workflow in ci.get("workflows", [])
        for action in workflow.get("actions", [])
    }
    file_names = {file.name.lower() for file in files}

    return {
        "has_goreleaser": "goreleaser.yml" in file_names or "goreleaser.yaml" in file_names,
        "uploads_github_release": bool(RELEASE_UPLOAD_ACTIONS & action_names)
        or "gh release" in run_text
        or "gh release" in combined_text,
        "publishes_container": "docker/build-push-action" in action_names
        or "docker/build-push-action" in combined_text,
        "publishes_npm": "npm publish" in run_text or "npm publish" in combined_text,
        "publishes_pypi": "pypa/gh-action-pypi-publish" in action_names
        or "twine upload" in run_text
        or "twine upload" in combined_text,
        "publishes_crate": "cargo publish" in run_text or "cargo publish" in combined_text,
        "publishes_maven": command_mentions_words(run_text, ["mvn", "deploy"])
        or command_mentions_words(run_text, ["gradle", "publish"])
        or "gradle publish" in combined_text,
        "publishes_nuget": "dotnet nuget push" in run_text
        or "nuget push" in run_text
        or "dotnet nuget push" in combined_text
        or "nuget push" in combined_text,
    }


def command_mentions_words(text: str, words: list[str]) -> bool:
    index = 0
    for word in words:
        match = re.search(rf"\b{re.escape(word)}\b", text[index:])
        if not match:
            return False
        index += match.end()
    return True


def detect_risk_signals(ci: dict[str, Any]) -> list[dict[str, str]]:
    risks = []
    for workflow in ci.get("workflows", []):
        path = workflow.get("path", "")
        if not workflow.get("parsed", True):
            risks.append(
                {
                    "severity": "medium",
                    "path": path,
                    "signal": f"workflow YAML could not be parsed structurally: {workflow.get('parse_error')}",
                }
            )
        if workflow.get("uses_pull_request_target"):
            risks.append(
                {
                    "severity": "high",
                    "path": path,
                    "signal": "workflow uses pull_request_target",
                }
            )
        if grants_write_all(workflow.get("permissions")):
            risks.append(
                {
                    "severity": "high",
                    "path": path,
                    "signal": "workflow grants write-all permissions",
                }
            )

        for job in workflow.get("jobs", []):
            if grants_write_all(job.get("permissions")):
                risks.append(
                    {
                        "severity": "high",
                        "path": path,
                        "signal": f"job {job.get('id')} grants write-all permissions",
                    }
                )
            for step in job.get("steps", []):
                run = step.get("run")
                if isinstance(run, str) and pipes_curl_to_shell(run):
                    risks.append(
                        {
                            "severity": "medium",
                            "path": path,
                            "signal": "workflow pipes curl to shell",
                        }
                    )
                uses = step.get("uses")
                if isinstance(uses, dict):
                    action = uses.get("name")
                    ref = uses.get("ref")
                    if is_local_uses(action):
                        continue
                    if ref and not looks_pinned(ref):
                        risks.append(
                            {
                                "severity": "medium",
                                "path": path,
                                "signal": (
                                    f"action {action}@{ref} is not pinned to a full commit SHA"
                                ),
                            }
                        )
                    elif ref is None:
                        risks.append(
                            {
                                "severity": "medium",
                                "path": path,
                                "signal": f"action {action} has no ref pin",
                            }
                        )
        if not workflow.get("jobs"):
            add_action_pin_risks(risks, path, workflow.get("actions", []))
    return risks


def fallback_actions(text: str) -> list[dict[str, str | None]]:
    return [
        {"name": match.group(1), "ref": match.group(2)}
        for match in ACTION_USES_PATTERN.finditer(text)
    ]


def fallback_permissions(text: str) -> dict[str, Any] | None:
    if re.search(r"^\s*permissions:\s+write-all\s*(?:#.*)?$", text, re.MULTILINE):
        return normalize_permissions("write-all")
    return None


def add_action_pin_risks(
    risks: list[dict[str, str]],
    path: str,
    actions: list[dict[str, Any]],
) -> None:
    for uses in actions:
        action = uses.get("name")
        ref = uses.get("ref")
        if is_local_uses(action):
            continue
        if ref and not looks_pinned(ref):
            risks.append(
                {
                    "severity": "medium",
                    "path": path,
                    "signal": f"action {action}@{ref} is not pinned to a full commit SHA",
                }
            )
        elif ref is None:
            risks.append(
                {
                    "severity": "medium",
                    "path": path,
                    "signal": f"action {action} has no ref pin",
                }
            )


def normalize_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key): normalize_json_value(item)
        for key, item in value.items()
    }


def normalize_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): normalize_json_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [normalize_json_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def ensure_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, "")]
    return [str(value)] if value != "" else []


def string_or_none(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def first_present(mapping: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, "", []):
            return value
    return None


def extract_paths(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if not isinstance(value, str):
        return [str(value)]

    paths = []
    for line in value.splitlines() or [value]:
        for part in line.split(","):
            cleaned = part.strip()
            if cleaned:
                paths.append(cleaned)
    return paths


def extract_gh_release_upload_paths(command: str) -> list[str]:
    paths = []
    for line in command.splitlines():
        if "gh release upload" not in line:
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            continue
        for index in range(len(tokens) - 3):
            if tokens[index:index + 3] == ["gh", "release", "upload"]:
                for token in tokens[index + 4:]:
                    if token.startswith("-"):
                        continue
                    paths.append(token)
                break
    return paths


def collect_run_commands(ci: dict[str, Any]) -> list[str]:
    commands = []
    for workflow in ci.get("workflows", []):
        for job in workflow.get("jobs", []):
            for step in job.get("steps", []):
                run = step.get("run")
                if isinstance(run, str):
                    commands.append(run)
    return commands


def grants_write_all(permissions: Any) -> bool:
    if not isinstance(permissions, dict):
        return False
    return str(permissions.get("mode", "")).lower() == "write-all"


def pipes_curl_to_shell(command: str) -> bool:
    return bool(re.search(r"curl\s+[^|\n]+\|\s*(sh|bash)", command))


def is_local_uses(action: Any) -> bool:
    if not isinstance(action, str):
        return False
    return action.startswith("./") or action.startswith("../")


def looks_pinned(ref: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}", ref))


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")
