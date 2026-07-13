from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import xml.etree.ElementTree as ET
from base64 import b64decode
from binascii import Error as Base64Error
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from assured_downstream.builder_handoff_v3 import (
    BuilderHandoffError,
    inventory_trusted_source,
)
from assured_downstream.catalog import utc_now


MAX_SOURCE_FILE_BYTES = 4 * 1024 * 1024
IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    "bin",
    "build",
    "dist",
    "node_modules",
    "obj",
    "target",
}
FULL_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
FULL_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SOURCE_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
DOTNET_CLI_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
MAVEN_ARTIFACT_OUTPUT_PARAMETERS = {
    "appendassemblyid",
    "attach",
    "classifier",
    "finalname",
    "jarname",
    "outputdirectory",
    "outputfile",
    "outputfilename",
    "primaryartifact",
    "replacemainartifact",
    "shadedartifactattached",
    "shadedclassifiername",
    "warname",
}


def default_ecosystem_policy_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "policies" / "ecosystems"


def ecosystem_policy_digests() -> dict[str, str]:
    return {
        policy_id: load_ecosystem_policy(policy_id)["_policy_sha256"]
        for policy_id in ("dotnet-v1", "java-maven-v1")
    }


def ecosystem_profiler_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def plan_ecosystem_build_profile(
    *,
    root: Path,
    source_repository: str | None = None,
    source_commit: str | None = None,
    source_git_tree: str | None = None,
    target: str | None = None,
    ecosystem: str | None = None,
    target_framework: str | None = None,
    runtime_identifier: str | None = None,
    self_contained: bool | None = None,
    operation: str | None = None,
    expected_artifacts: list[str] | None = None,
    include_analysis_path: bool = True,
    descriptor_relative: bool = False,
    source_identity_verified: bool = False,
    generated_at: str | None = None,
    policy_dir: Path | None = None,
) -> dict[str, Any]:
    if descriptor_relative:
        if root != Path(".") or include_analysis_path:
            raise ValueError(
                "Descriptor-relative profiling requires root '.' and no analysis path"
            )
        source_root = Path(".")
    else:
        source_root = Path(os.path.abspath(root.expanduser()))
    try:
        source_root_metadata = source_root.lstat()
    except OSError as exc:
        raise NotADirectoryError(source_root) from exc
    if stat.S_ISLNK(source_root_metadata.st_mode) or not stat.S_ISDIR(
        source_root_metadata.st_mode
    ):
        raise NotADirectoryError(source_root)

    findings: list[dict[str, Any]] = []
    if not source_repository or not SOURCE_REPOSITORY.fullmatch(source_repository):
        add_finding(
            findings,
            code="SOURCE_REPOSITORY_UNBOUND",
            severity="blocker",
            summary="The profile is not bound to a source repository identity.",
            owner="recon",
        )
    if not source_commit or not FULL_OBJECT_ID.fullmatch(source_commit):
        add_finding(
            findings,
            code="SOURCE_COMMIT_UNBOUND",
            severity="blocker",
            summary="The profile is not bound to a full Git commit object ID.",
            owner="source-reacquirer-v3",
        )
    if not source_git_tree or not FULL_OBJECT_ID.fullmatch(source_git_tree):
        add_finding(
            findings,
            code="SOURCE_GIT_TREE_UNBOUND",
            severity="blocker",
            summary="The profile is not bound to a full Git tree object ID.",
            owner="source-reacquirer-v3",
        )
    if not source_identity_verified:
        add_finding(
            findings,
            code="SOURCE_IDENTITY_HANDOFF_UNVERIFIED",
            severity="blocker",
            summary=(
                "The repository and commit are caller declarations, not a verified "
                "source handoff."
            ),
            owner="source-reacquirer-v3",
        )
    source_inventory = snapshot_source_inventory(
        source_root,
        findings,
        descriptor_relative=descriptor_relative,
    )

    profile_candidates = detected_profile_candidates(source_root)
    selected_profile = select_profile_candidate(
        profile_candidates,
        requested=ecosystem,
        findings=findings,
    )

    if selected_profile == "java-maven":
        body = plan_maven_profile(
            root=source_root,
            source_commit=source_commit,
            policy_dir=policy_dir,
            findings=findings,
        )
    elif selected_profile == "java-gradle":
        body = plan_unsupported_gradle_profile(
            root=source_root,
            findings=findings,
        )
    elif selected_profile == "dotnet":
        body = plan_dotnet_profile(
            root=source_root,
            source_commit=source_commit,
            target=target,
            target_framework=target_framework,
            runtime_identifier=runtime_identifier,
            self_contained=self_contained,
            operation=operation,
            expected_artifacts=expected_artifacts,
            policy_dir=policy_dir,
            findings=findings,
        )
    else:
        add_finding(
            findings,
            code="ECOSYSTEM_PROFILE_NOT_IMPLEMENTED",
            severity="blocker",
            summary="No Java Maven, Java Gradle, or .NET profile matched this source tree.",
            owner="ecosystem-profiler",
        )
        body = {
            "profile_id": None,
            "ecosystem": "unknown",
            "build_system": "unknown",
            "policy": None,
            "source_inputs": [],
            "signals": {},
            "build_plan": empty_build_plan(),
        }

    blockers = sorted(
        finding["code"] for finding in findings if finding["severity"] == "blocker"
    )
    reviews = sorted(
        finding["code"] for finding in findings if finding["severity"] == "review"
    )
    canary_requirements = sorted(
        finding["code"] for finding in findings if finding["severity"] == "canary"
    )
    canary_admission_candidate = not blockers and bool(
        (body.get("policy") or {}).get("canary_profile_approved")
    )
    status = (
        "ready-for-governor-admission"
        if canary_admission_candidate
        else "blocked"
    )
    execution_permitted = False

    return {
        "schema_version": 1,
        "generated_at": validate_generated_at(generated_at),
        "profile_id": body["profile_id"],
        "ecosystem": body["ecosystem"],
        "build_system": body["build_system"],
        "detected_profile_candidates": profile_candidates,
        "profiler": {
            "implementation_sha256": ecosystem_profiler_sha256(),
        },
        "status": status,
        "execution_permitted": execution_permitted,
        "canary_admission_candidate": canary_admission_candidate,
        "source": {
            "repository": source_repository,
            "commit": source_commit,
            "git_tree": source_git_tree,
            "analysis_path": str(source_root) if include_analysis_path else None,
            "identity_binding": (
                "verified-managed-handoff"
                if source_identity_verified
                else "caller-declared-unverified"
            ),
            "inventory": source_inventory,
        },
        "policy": body["policy"],
        "source_inputs": body["source_inputs"],
        "signals": body["signals"],
        "build_plan": body["build_plan"],
        "findings": findings,
        "decision": {
            "status": status,
            "execution_permitted": execution_permitted,
            "execution_scope": "none",
            "canary_admission_candidate": canary_admission_candidate,
            "required_authority": "separate-governor-canary-admission",
            "release_eligible": False,
            "blockers": blockers,
            "review_items": reviews,
            "canary_requirements": canary_requirements,
            "next_handoffs": finding_handoffs(findings, severity="blocker"),
            "canary_handoffs": finding_handoffs(findings, severity="canary"),
        },
        "claim_limit": (
            "This is a non-executing structural profile decision. It does not prove "
            "dependency closure, build isolation, artifact correctness, reproducibility, "
            "or source safety. Execution remains forbidden until every blocker is closed "
            "and a separate Governor admission authorizes one exact canary request."
        ),
    }


def validate_generated_at(value: str | None) -> str:
    if value is None:
        return utc_now()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError("generated_at must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("generated_at must include a timezone")
    return value


def detected_profile_candidates(root: Path) -> list[str]:
    candidates = []
    if (root / "pom.xml").exists():
        candidates.append("java-maven")
    if java_gradle_manifests(root):
        candidates.append("java-gradle")
    if dotnet_project_paths(root):
        candidates.append("dotnet")
    return candidates


def select_profile_candidate(
    candidates: list[str],
    *,
    requested: str | None,
    findings: list[dict[str, Any]],
) -> str | None:
    if requested:
        if requested not in candidates:
            add_finding(
                findings,
                code="BUILD_ECOSYSTEM_SELECTION_INVALID",
                severity="blocker",
                summary="The requested build ecosystem was not detected in the source tree.",
                evidence=[requested, *candidates],
                owner="ecosystem-profiler",
            )
            return None
        return requested
    if len(candidates) > 1:
        add_finding(
            findings,
            code="BUILD_ECOSYSTEM_SELECTION_REQUIRED",
            severity="blocker",
            summary="Multiple build ecosystems require an explicit profile selection.",
            evidence=candidates,
            owner="ecosystem-profiler",
        )
    return candidates[0] if candidates else None


def plan_maven_profile(
    *,
    root: Path,
    source_commit: str | None,
    policy_dir: Path | None,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    policy = load_ecosystem_policy("java-maven-v1", policy_dir)
    enforce_policy_gate(policy, findings)
    pom_path = root / "pom.xml"
    pom_text, pom_info = safe_read_source_text(root, pom_path)
    pom = parse_xml(pom_text, pom_path)

    artifact_id = child_text(pom, "artifactId")
    project_version = child_text(pom, "version")
    packaging = child_text(pom, "packaging") or "jar"
    build = direct_child(pom, "build")
    final_name = child_text(build, "finalName")
    build_directory = child_text(build, "directory")
    parent = maven_parent_signal(pom)
    modules = [text for text in descendant_texts(direct_child(pom, "modules"), "module")]
    properties = xml_properties(direct_child(pom, "properties"))
    dependencies = maven_coordinates(pom, "dependencies", "dependency")
    plugins = maven_plugins(pom)
    repositories = maven_repository_urls(pom)
    distribution_urls = maven_distribution_urls(pom)
    profiles = maven_profile_signals(pom)
    profile_output_overrides = maven_profile_output_overrides(pom)
    plugin_output_overrides = maven_plugin_output_overrides(pom)
    wrapper = maven_wrapper_signals(root)
    source_literals = find_source_literals(root, ["fuzz.seed"])
    release_scripts = source_release_script_signals(root)
    project_config = maven_project_config_signals(root)

    if modules:
        add_finding(
            findings,
            code="MAVEN_MULTI_MODULE_SELECTION_REQUIRED",
            severity="blocker",
            summary="A multi-module Maven reactor needs an explicit artifact and module policy.",
            evidence=modules,
            owner="ecosystem-profiler",
        )
    if repositories:
        add_finding(
            findings,
            code="MAVEN_CUSTOM_REPOSITORIES_RECORDED",
            severity="review",
            summary="Custom Maven repositories must be replaced by the material resolver.",
            evidence=repositories,
            owner="material-resolver",
        )
    insecure_repositories = [
        url for url in repositories if urlsplit(url).scheme.lower() == "http"
    ]
    if insecure_repositories:
        add_finding(
            findings,
            code="MAVEN_INSECURE_REPOSITORY",
            severity="blocker",
            summary="The POM declares a plaintext Maven repository.",
            evidence=insecure_repositories,
            owner="governor",
        )
    if distribution_urls:
        add_finding(
            findings,
            code="UPSTREAM_MAVEN_PUBLICATION_CONFIG_PRESENT",
            severity="review",
            summary="Distribution endpoints are source evidence only and must never receive credentials.",
            evidence=distribution_urls,
            owner="governor",
        )

    publishing_plugins = sorted(
        plugin["coordinate"]
        for plugin in plugins
        if any(
            token in plugin["artifact_id"].lower()
            for token in ("deploy", "gpg", "nexus", "release", "sign")
        )
        or plugin["extension"]
    )
    if publishing_plugins:
        add_finding(
            findings,
            code="MAVEN_RELEASE_OR_EXTENSION_PLUGINS_PRESENT",
            severity="review",
            summary="Release, signing, staging, or extension plugins are present in the build model.",
            evidence=publishing_plugins,
            owner="ecosystem-profiler",
        )
    extension_plugins = sorted(
        plugin["coordinate"] for plugin in plugins if plugin["extension"]
    )
    if extension_plugins:
        add_finding(
            findings,
            code="MAVEN_BUILD_EXTENSION_REQUIRES_CANARY",
            severity="canary",
            summary="Maven build extensions execute inside Maven and require an isolation canary.",
            evidence=extension_plugins,
            owner="build",
        )
    missing_versions = sorted(
        coordinate["coordinate"]
        for coordinate in [*dependencies, *plugins]
        if not coordinate.get("version")
    )
    if missing_versions:
        add_finding(
            findings,
            code="MAVEN_EFFECTIVE_MODEL_REQUIRED",
            severity="review",
            summary="Some dependency or plugin versions require effective-model resolution.",
            evidence=missing_versions,
            owner="material-resolver",
        )
    if project_version and project_version.endswith("-SNAPSHOT"):
        add_finding(
            findings,
            code="MAVEN_SNAPSHOT_PROJECT_VERSION",
            severity="review",
            summary="The upstream project version is a snapshot and needs downstream version policy.",
            evidence=[project_version],
            owner="release",
        )
    if not properties.get("project.build.outputTimestamp"):
        add_finding(
            findings,
            code="MAVEN_OUTPUT_TIMESTAMP_UNPINNED",
            severity="review",
            summary="The POM does not pin project.build.outputTimestamp.",
            owner="repro",
        )
    compiler_level = (
        properties.get("maven.compiler.release")
        or properties.get("maven.compiler.target")
        or properties.get("maven.compiler.source")
    )
    if compiler_level and legacy_java_level(compiler_level):
        add_finding(
            findings,
            code="LEGACY_JAVA_TARGET_REQUIRES_CANARY",
            severity="canary",
            summary="The requested Java bytecode level needs a pinned-JDK compatibility canary.",
            evidence=[compiler_level],
            owner="build",
        )
    if not wrapper["present"]:
        add_finding(
            findings,
            code="MAVEN_WRAPPER_ABSENT",
            severity="review",
            summary="Maven must come entirely from the digest-pinned builder image.",
            owner="tooling-curator",
        )
    if release_scripts:
        add_finding(
            findings,
            code="SOURCE_RELEASE_SCRIPTS_EXCLUDED",
            severity="review",
            summary="Repository release scripts are evidence only and are excluded from execution.",
            evidence=[item["path"] for item in release_scripts],
            owner="ecosystem-profiler",
        )
    if project_config:
        add_finding(
            findings,
            code="MAVEN_PROJECT_CONFIG_FORBIDDEN",
            severity="blocker",
            summary="Project-level Maven/JVM argument injection is not allowed by this profile.",
            evidence=[item["path"] for item in project_config],
            owner="ecosystem-profiler",
        )

    effective_output_model_unresolved = bool(
        parent or profile_output_overrides or plugin_output_overrides
    )
    if parent:
        add_finding(
            findings,
            code="MAVEN_PARENT_EFFECTIVE_MODEL_REQUIRED",
            severity="blocker",
            summary="A parent POM can alter inherited output naming and needs a resolved effective model.",
            evidence=[json.dumps(parent, sort_keys=True, separators=(",", ":"))],
            owner="material-resolver",
        )
    if profile_output_overrides:
        add_finding(
            findings,
            code="MAVEN_PROFILE_BUILD_OUTPUT_UNRESOLVED",
            severity="blocker",
            summary="A Maven profile can override the primary artifact name or build directory.",
            evidence=[
                json.dumps(value, sort_keys=True, separators=(",", ":"))
                for value in profile_output_overrides
            ],
            owner="material-resolver",
        )
    if plugin_output_overrides:
        add_finding(
            findings,
            code="MAVEN_PLUGIN_BUILD_OUTPUT_UNRESOLVED",
            severity="blocker",
            summary=(
                "Maven plugin configuration can alter or attach build outputs and "
                "needs a resolved effective model and collector contract."
            ),
            evidence=[
                json.dumps(value, sort_keys=True, separators=(",", ":"))
                for value in plugin_output_overrides
            ],
            owner="material-resolver",
        )

    artifact_root = None if effective_output_model_unresolved else "target"
    if build_directory and build_directory != "target":
        artifact_root = None
        add_finding(
            findings,
            code="MAVEN_CUSTOM_BUILD_DIRECTORY_UNSUPPORTED",
            severity="blocker",
            summary="A non-default Maven build directory needs an explicit collector policy.",
            evidence=[build_directory],
            owner="ecosystem-profiler",
        )

    declared_artifact = maven_exact_artifact_name(
        artifact_id=artifact_id,
        project_version=project_version,
        packaging=packaging,
        final_name=final_name,
    )
    exact_artifact = (
        None if effective_output_model_unresolved else declared_artifact
    )
    if packaging == "pom":
        add_finding(
            findings,
            code="MAVEN_PRIMARY_ARTIFACT_UNAVAILABLE",
            severity="blocker",
            summary="POM packaging has no primary JAR or WAR for this single-module profile.",
            owner="ecosystem-profiler",
        )
    elif declared_artifact is None:
        add_finding(
            findings,
            code="MAVEN_ARTIFACT_NAME_UNRESOLVED",
            severity="blocker",
            summary="The primary Maven artifact filename cannot be fixed structurally.",
            owner="ecosystem-profiler",
        )

    material_lock = assess_material_lock(
        root=root,
        policy=policy,
        source_commit=source_commit,
        findings=findings,
    )
    argv = [
        policy["builder"]["maven_executable"],
        "--batch-mode",
        "--no-transfer-progress",
        "--offline",
        "--strict-checksums",
        "--settings",
        "/policy/maven-settings.xml",
        "--global-settings",
        "/policy/maven-global-settings.xml",
        "--file",
        "pom.xml",
        "-Dmaven.repo.local=/workspace/m2",
        "-DperformRelease=false",
        "-DskipTests=false",
        "-Dmaven.test.skip=false",
        "-Dmaven.source.skip=true",
        "-Dmaven.javadoc.skip=true",
        "-Djacoco.skip=true",
    ]
    if source_literals.get("fuzz.seed"):
        argv.append("-Dfuzz.seed=0")
    argv.append("package")
    return {
        "profile_id": policy["policy_id"],
        "ecosystem": "java",
        "build_system": "maven",
        "policy": policy_summary(policy, material_lock),
        "source_inputs": [pom_info, *wrapper["inputs"]],
        "signals": {
            "manifest": "pom.xml",
            "packaging": packaging,
            "project_version": project_version,
            "final_name": final_name,
            "build_directory": build_directory or "target",
            "parent": parent,
            "modules": modules,
            "profiles": profiles,
            "profile_output_overrides": profile_output_overrides,
            "plugin_output_overrides": plugin_output_overrides,
            "compiler_level": compiler_level,
            "dependencies": dependencies,
            "plugins": plugins,
            "repositories": repositories,
            "distribution_urls": distribution_urls,
            "wrapper": wrapper["summary"],
            "source_literals": source_literals,
            "release_scripts": release_scripts,
            "project_config": project_config,
            "exact_primary_artifact": exact_artifact,
            "declared_primary_artifact": declared_artifact,
        },
        "build_plan": {
            "network": "none",
            "shell": False,
            "source_mount": "/src:ro",
            "material_mount": "/materials:ro",
            "workspace": "/workspace:tmpfs",
            "output": "/out:collector-only",
            "cwd": "/workspace/src",
            "trusted_preparation": trusted_preparation("maven"),
            "environment_allowlist": policy["environment_allowlist"],
            "steps": [{"name": "test-and-package", "argv": argv}],
            "artifact_selection": {
                "root": artifact_root,
                "include": [exact_artifact] if exact_artifact and artifact_root else [],
                "expected_count": 1 if exact_artifact and artifact_root else 0,
                "reject_unexpected_release_candidates": [
                    "*.jar",
                    "*.war",
                    "*.zip",
                    "*.asc",
                ],
                "exclude": [],
                "follow_symlinks": False,
            },
            "forbidden_goals": policy["forbidden_goals"],
            "evidence_required": policy["evidence_required"],
        },
    }


def plan_dotnet_profile(
    *,
    root: Path,
    source_commit: str | None,
    target: str | None,
    target_framework: str | None,
    runtime_identifier: str | None,
    self_contained: bool | None,
    operation: str | None,
    expected_artifacts: list[str] | None,
    policy_dir: Path | None,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    policy = load_ecosystem_policy("dotnet-v1", policy_dir)
    enforce_policy_gate(policy, findings)
    projects = dotnet_project_paths(root)
    pipeline_references, external_templates = dotnet_pipeline_signals(root)
    candidates = [dotnet_project_summary(root, path, pipeline_references) for path in projects]

    selected_path = select_dotnet_target(root, projects, target, findings)
    selected = (
        dotnet_project_summary(root, selected_path, pipeline_references)
        if selected_path is not None
        else None
    )
    source_inputs = [source_file_info(root, path) for path in projects]
    source_inputs.extend(dotnet_control_inputs(root))

    if external_templates:
        add_finding(
            findings,
            code="DOTNET_EXTERNAL_PIPELINE_LOGIC_PRESENT",
            severity="review",
            summary="Upstream release behavior depends on external pipeline templates.",
            evidence=external_templates,
            owner="recon",
        )

    global_json = read_optional_json(root, root / "global.json")
    sdk_version = None
    if global_json is None:
        add_finding(
            findings,
            code="DOTNET_GLOBAL_JSON_ABSENT",
            severity="review",
            summary="The source tree does not pin an exact .NET SDK; the builder policy must.",
            owner="tooling-curator",
        )
    else:
        sdk_version = (global_json.get("sdk") or {}).get("version")
        if not isinstance(sdk_version, str) or not re.fullmatch(
            r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", sdk_version
        ):
            add_finding(
                findings,
                code="DOTNET_SDK_VERSION_UNRESOLVED",
                severity="blocker",
                summary="global.json does not contain an exact SDK version.",
                owner="tooling-curator",
            )

    feeds = dotnet_package_sources(root)
    credential_configs = dotnet_nuget_credential_signals(root)
    if credential_configs:
        add_finding(
            findings,
            code="DOTNET_SOURCE_NUGET_CREDENTIALS_FORBIDDEN",
            severity="blocker",
            summary="Source-controlled NuGet credential sections may not enter the builder.",
            evidence=credential_configs,
            owner="governor",
        )
    non_public_feeds = [
        feed["value"]
        for feed in feeds
        if not canonical_nuget_org_url(feed["value"])
    ]
    if non_public_feeds:
        add_finding(
            findings,
            code="DOTNET_NON_PUBLIC_FEED_REQUIRES_CLOSURE",
            severity="blocker",
            summary="A non-nuget.org feed cannot be used by the isolated build.",
            evidence=non_public_feeds,
            owner="material-resolver",
        )

    selected_framework = None
    selected_rid = None
    referenced_projects: list[str] = []
    lock_files: list[dict[str, Any]] = []
    import_inputs: list[dict[str, Any]] = []
    resolved_imports: list[str] = []
    test_projects: list[str] = []
    selected_operation = None
    deployment_mode = None
    if selected_path is not None and selected is not None:
        selected_framework = select_dotnet_framework(
            selected,
            requested=target_framework,
            findings=findings,
        )
        selected_operation = select_dotnet_operation(
            selected,
            requested=operation,
            findings=findings,
        )
        selected_rid = select_dotnet_rid(
            selected,
            requested=runtime_identifier,
            operation=selected_operation,
            findings=findings,
        )
        referenced_paths = dotnet_project_closure(root, selected_path, findings)
        referenced_projects = [path.relative_to(root).as_posix() for path in referenced_paths]
        test_projects = dotnet_test_projects(root, projects, selected_path)
        option_like_tests = [
            path for path in test_projects if path.startswith(("-", "@"))
        ]
        if option_like_tests:
            add_finding(
                findings,
                code="DOTNET_TEST_PATH_OPTION_LIKE",
                severity="blocker",
                summary="A selected test project path could be parsed as a CLI option.",
                evidence=option_like_tests,
                owner="ecosystem-profiler",
            )
        lock_closure = set(referenced_paths)
        for test_project in test_projects:
            lock_closure.update(
                dotnet_project_closure(root, root / test_project, findings)
            )
        import_result = dotnet_import_closure(root, sorted(lock_closure))
        import_inputs = import_result["inputs"]
        resolved_imports = [item["path"] for item in import_inputs]
        if import_result["unresolved"]:
            add_finding(
                findings,
                code="DOTNET_IMPORT_CLOSURE_UNRESOLVED",
                severity="blocker",
                summary="Explicit MSBuild imports are missing, external, or dynamic.",
                evidence=import_result["unresolved"],
                owner="material-resolver",
            )
        conditional_critical_properties = sorted(
            {
                value
                for project_path in lock_closure
                for value in dotnet_project_summary(root, project_path, {})[
                    "conditional_critical_properties"
                ]
            }
        )
        if conditional_critical_properties:
            add_finding(
                findings,
                code="DOTNET_CONDITIONAL_TARGET_MODEL_UNRESOLVED",
                severity="blocker",
                summary=(
                    "Conditional target, framework, runtime, or package properties "
                    "cannot authorize a fixed build plan."
                ),
                evidence=conditional_critical_properties,
                owner="material-resolver",
            )
        sdk_references = sorted(
            {
                sdk
                for project_path in lock_closure
                for sdk in dotnet_project_summary(root, project_path, {})[
                    "sdk_references"
                ]
            }
        )
        custom_sdks = [
            sdk for sdk in sdk_references if not sdk.startswith("Microsoft.NET.Sdk")
        ]
        if custom_sdks:
            add_finding(
                findings,
                code="DOTNET_CUSTOM_SDK_REQUIRES_CLOSURE",
                severity="blocker",
                summary="Custom MSBuild SDK logic is outside the base builder closure.",
                evidence=custom_sdks,
                owner="material-resolver",
            )
        exec_sources = sorted(
            set(import_result["exec_task_sources"])
            | {
                source
                for project_path in lock_closure
                for source in dotnet_project_summary(root, project_path, {})[
                    "exec_task_sources"
                ]
            }
        )
        if exec_sources:
            add_finding(
                findings,
                code="DOTNET_MSBUILD_EXEC_REQUIRES_CANARY",
                severity="canary",
                summary="The selected MSBuild closure contains Exec tasks.",
                evidence=exec_sources,
                owner="build",
            )
        using_task_sources = sorted(
            set(import_result["using_task_sources"])
            | {
                source
                for project_path in lock_closure
                for source in dotnet_project_summary(root, project_path, {})[
                    "using_task_sources"
                ]
            }
        )
        if using_task_sources:
            add_finding(
                findings,
                code="DOTNET_USING_TASK_REQUIRES_CANARY",
                severity="canary",
                summary="The selected MSBuild closure registers custom build tasks.",
                evidence=using_task_sources,
                owner="build",
            )
        conditional_sources = sorted(
            set(import_result["conditional_element_sources"])
            | {
                source
                for project_path in lock_closure
                for source in dotnet_project_summary(root, project_path, {})[
                    "conditional_element_sources"
                ]
            }
        )
        if conditional_sources:
            add_finding(
                findings,
                code="DOTNET_CONDITIONAL_MODEL_REQUIRES_CANARY",
                severity="canary",
                summary="Conditional MSBuild elements require exact-SDK evaluation evidence.",
                evidence=conditional_sources,
                owner="build",
            )
        lock_files = dotnet_lock_signals(
            root,
            sorted(lock_closure),
            framework=selected_framework,
            findings=findings,
        )
        deployment_mode = select_dotnet_deployment_mode(
            operation=selected_operation,
            requested=self_contained,
            findings=findings,
        )
        if not test_projects:
            add_finding(
                findings,
                code="DOTNET_TEST_TARGET_NOT_DETECTED",
                severity="review",
                summary="No test project was structurally associated with the selected target.",
                owner="ecosystem-profiler",
            )

    response_files = dotnet_response_file_signals(root)
    if response_files:
        add_finding(
            findings,
            code="DOTNET_RESPONSE_FILE_FORBIDDEN",
            severity="blocker",
            summary="MSBuild response files can inject arguments outside the fixed argv contract.",
            evidence=[item["path"] for item in response_files],
            owner="ecosystem-profiler",
        )

    material_lock = assess_material_lock(
        root=root,
        policy=policy,
        source_commit=source_commit,
        findings=findings,
    )
    build_operation = selected_operation
    if selected_operation == "publish" and selected is not None and (
        (runtime_identifier is not None and selected_rid is None)
        or (selected["runtime_identifiers"] and selected_rid is None)
    ):
        build_operation = None
    steps = dotnet_steps(
        selected_path=selected_path,
        root=root,
        framework=selected_framework,
        runtime_identifier=selected_rid,
        operation=build_operation,
        self_contained=deployment_mode,
        test_projects=test_projects,
    )
    artifact_selection = dotnet_artifact_selection(
        build_operation,
        expected_artifacts=expected_artifacts,
        findings=findings,
    )
    return {
        "profile_id": policy["policy_id"],
        "ecosystem": "dotnet",
        "build_system": "dotnet-cli",
        "policy": policy_summary(policy, material_lock),
        "source_inputs": dedupe_inputs(source_inputs + lock_files + import_inputs),
        "signals": {
            "project_candidates": candidates,
            "selected_target": selected,
            "selected_framework": selected_framework,
            "selected_runtime_identifier": selected_rid,
            "operation": selected_operation,
            "self_contained": deployment_mode,
            "project_closure": referenced_projects,
            "resolved_imports": resolved_imports,
            "test_projects": test_projects,
            "sdk_version_from_source": sdk_version,
            "package_sources": feeds,
            "source_nuget_credential_configs": credential_configs,
            "external_pipeline_templates": external_templates,
            "response_files": response_files,
        },
        "build_plan": {
            "network": "none",
            "shell": False,
            "source_mount": "/src:ro",
            "material_mount": "/materials:ro",
            "workspace": "/workspace:tmpfs",
            "output": "/out:collector-only",
            "cwd": "/workspace/src",
            "trusted_preparation": trusted_preparation("dotnet"),
            "environment_allowlist": policy["environment_allowlist"],
            "steps": steps,
            "artifact_selection": artifact_selection,
            "forbidden_commands": policy["forbidden_commands"],
            "evidence_required": policy["evidence_required"],
        },
    }


def plan_unsupported_gradle_profile(
    *, root: Path, findings: list[dict[str, Any]]
) -> dict[str, Any]:
    manifests = java_gradle_manifests(root)
    inputs = [source_file_info(root, path) for path in manifests]
    text = "\n".join(safe_read_source_text(root, path)[0] for path in manifests)
    evidence = []
    if "sourceControl" in text or "gitRepository" in text:
        evidence.append("source-control dependency declaration")
    if not (root / "gradlew").is_file():
        evidence.append("Gradle wrapper absent")
    if not any(path.suffix == ".lockfile" for path in iter_source_files(root)):
        evidence.append("Gradle dependency locks absent")
    add_finding(
        findings,
        code="JAVA_GRADLE_PROFILE_NOT_IMPLEMENTED",
        severity="blocker",
        summary="The MVP Java execution profile supports Maven only.",
        evidence=evidence,
        owner="ecosystem-profiler",
    )
    return {
        "profile_id": "java-gradle-v1-planned",
        "ecosystem": "java",
        "build_system": "gradle",
        "policy": {
            "policy_id": "java-gradle-v1-planned",
            "status": "not-implemented",
            "canary_profile_approved": False,
        },
        "source_inputs": inputs,
        "signals": {"manifests": [item["path"] for item in inputs]},
        "build_plan": empty_build_plan(),
    }


def load_ecosystem_policy(
    policy_id: str, policy_dir: Path | None = None
) -> dict[str, Any]:
    root = (policy_dir or default_ecosystem_policy_dir()).expanduser().resolve()
    path = root / f"{policy_id}.json"
    policy_bytes = path.read_bytes()
    try:
        policy = strict_json_loads(
            policy_bytes.decode("utf-8"),
            label=f"ecosystem policy {path}",
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"Invalid ecosystem policy JSON: {path}") from exc
    if not isinstance(policy, dict):
        raise ValueError(f"Ecosystem policy must be an object: {path}")
    required = {
        "schema_version",
        "policy_id",
        "status",
        "ecosystem",
        "build_system",
        "canary_profile_approved",
        "builder",
        "material_lock_path",
        "evidence_required",
        "environment_allowlist",
    }
    missing = sorted(required - policy.keys())
    if missing:
        raise ValueError(f"Ecosystem policy is missing fields: {', '.join(missing)}")
    if policy["schema_version"] != 1 or policy["policy_id"] != policy_id:
        raise ValueError(f"Invalid ecosystem policy identity: {path}")
    expected_identity = {
        "dotnet-v1": ("dotnet", "dotnet-cli"),
        "java-maven-v1": ("java", "maven"),
    }[policy_id]
    if (policy.get("ecosystem"), policy.get("build_system")) != expected_identity:
        raise ValueError(f"Ecosystem policy family does not match its id: {path}")
    if not isinstance(policy["canary_profile_approved"], bool):
        raise ValueError(
            f"Ecosystem policy canary_profile_approved must be boolean: {path}"
        )
    builder = policy["builder"]
    if not isinstance(builder, dict) or builder.get("network") != "none":
        raise ValueError(f"Ecosystem policy must require a no-network builder: {path}")
    expected_builder_controls = {
        "read_only_root": True,
        "source_read_only": True,
        "materials_read_only": True,
        "workspace": "tmpfs",
        "capabilities": [],
        "no_new_privileges": True,
    }
    if any(builder.get(key) != value for key, value in expected_builder_controls.items()):
        raise ValueError(f"Ecosystem policy weakens required builder controls: {path}")
    executable_key = (
        "maven_executable" if policy["build_system"] == "maven" else "dotnet_executable"
    )
    executable = builder.get(executable_key)
    executable_path = PurePosixPath(str(executable))
    if (
        not isinstance(executable, str)
        or not executable_path.is_absolute()
        or any(part in {"", ".", ".."} for part in executable_path.parts)
    ):
        raise ValueError(f"Ecosystem policy must pin an absolute executable: {path}")
    lock_path = Path(str(policy["material_lock_path"]))
    if lock_path.is_absolute() or any(part in {"", ".", ".."} for part in lock_path.parts):
        raise ValueError(f"Ecosystem policy material lock path is unsafe: {path}")
    environment = policy["environment_allowlist"]
    allowed_environment_names = {
        "dotnet-v1": {
            "DOTNET_CLI_HOME",
            "DOTNET_NOLOGO",
            "DOTNET_SKIP_FIRST_TIME_EXPERIENCE",
            "HOME",
            "LANG",
            "LC_ALL",
            "NUGET_PACKAGES",
            "PATH",
            "TZ",
        },
        "java-maven-v1": {
            "HOME",
            "JAVA_HOME",
            "LANG",
            "LC_ALL",
            "PATH",
            "TZ",
        },
    }[policy_id]
    environment_names = [
        value.split("=", 1)[0]
        for value in environment
        if isinstance(value, str) and "=" in value
    ] if isinstance(environment, list) else []
    if (
        not isinstance(environment, list)
        or not environment
        or not all(isinstance(value, str) and "=" in value for value in environment)
        or len(environment) != len(set(environment))
        or len(environment_names) != len(set(environment_names))
        or set(environment_names) != allowed_environment_names
    ):
        raise ValueError(f"Ecosystem policy environment allowlist is invalid: {path}")
    policy["_policy_sha256"] = hashlib.sha256(policy_bytes).hexdigest()
    return policy


def enforce_policy_gate(policy: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    if not policy.get("canary_profile_approved"):
        add_finding(
            findings,
            code="ECOSYSTEM_POLICY_NOT_CANARY_APPROVED",
            severity="blocker",
            summary="The ecosystem policy is development-stage and cannot request admission.",
            evidence=[str(policy.get("status"))],
            owner="governor",
        )
    else:
        approval = policy.get("approval")
        approval_valid = (
            policy.get("status") == "approved-for-isolated-canary"
            and isinstance(approval, dict)
            and isinstance(approval.get("hostile_canary_sha256"), str)
            and bool(FULL_SHA256.fullmatch(approval["hostile_canary_sha256"]))
            and isinstance(approval.get("governor_policy_sha256"), str)
            and bool(FULL_SHA256.fullmatch(approval["governor_policy_sha256"]))
        )
        if not approval_valid:
            add_finding(
                findings,
                code="ECOSYSTEM_POLICY_APPROVAL_INVALID",
                severity="blocker",
                summary="Execution approval lacks code-anchored Governor and hostile-canary evidence.",
                owner="governor",
            )
    builder = policy.get("builder") or {}
    image_digest = builder.get("image_digest")
    if not isinstance(image_digest, str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", image_digest
    ):
        add_finding(
            findings,
            code="BUILDER_IMAGE_NOT_DIGEST_PINNED",
            severity="blocker",
            summary="No independently approved builder image digest is configured.",
            owner="tooling-curator",
        )


def assess_material_lock(
    *,
    root: Path,
    policy: dict[str, Any],
    source_commit: str | None,
    findings: list[dict[str, Any]],
) -> dict[str, Any] | None:
    relative = str(policy["material_lock_path"])
    lock_path = root / relative
    if not lock_path.exists():
        add_finding(
            findings,
            code="DEPENDENCY_MATERIAL_LOCK_MISSING",
            severity="blocker",
            summary="The source has no digest-bound dependency and build-plugin material lock.",
            evidence=[relative],
            owner="material-resolver",
        )
        return None
    lock_text, lock_info = safe_read_source_text(root, lock_path)
    try:
        lock = strict_json_loads(lock_text, label="dependency material lock")
    except ValueError as exc:
        add_finding(
            findings,
            code="DEPENDENCY_MATERIAL_LOCK_INVALID",
            severity="blocker",
            summary="The dependency material lock is not valid JSON.",
            evidence=[str(exc)],
            owner="material-resolver",
        )
        return lock_info
    materials = lock.get("materials") if isinstance(lock, dict) else None
    bundle = lock.get("bundle") if isinstance(lock, dict) else None
    valid = (
        isinstance(lock, dict)
        and lock.get("schema_version") == 1
        and lock.get("profile_id") == policy["policy_id"]
        and (source_commit is None or lock.get("source_commit") == source_commit)
        and isinstance(materials, list)
        and bool(materials)
        and all(valid_material_entry(item) for item in materials)
        and [item["bundle_path"] for item in materials]
        == sorted(item["bundle_path"] for item in materials)
        and len({item["name"] for item in materials}) == len(materials)
        and len({item["bundle_path"] for item in materials}) == len(materials)
        and sum(item["size"] for item in materials) <= 4 * 1024 * 1024 * 1024
        and isinstance(bundle, dict)
        and set(bundle) == {"sha256", "size"}
        and isinstance(bundle.get("sha256"), str)
        and bool(FULL_SHA256.fullmatch(bundle["sha256"]))
        and type(bundle.get("size")) is int
        and 0 < bundle["size"] <= 4 * 1024 * 1024 * 1024
    )
    if not valid:
        add_finding(
            findings,
            code="DEPENDENCY_MATERIAL_LOCK_INVALID",
            severity="blocker",
            summary="The material lock is not bound to this profile, source, and exact material set.",
            evidence=[relative],
            owner="material-resolver",
        )
    else:
        add_finding(
            findings,
            code="DEPENDENCY_MATERIAL_LOCK_UNVERIFIED",
            severity="blocker",
            summary=(
                "The source-declared material lock has no independently verified "
                "resolver handoff or bundle binding."
            ),
            evidence=[relative],
            owner="material-resolver",
        )
    return {
        **lock_info,
        "authority": "source-declared-unverified",
    }


def valid_material_entry(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "bundle_path",
        "kind",
        "name",
        "sha256",
        "size",
        "source_url",
    }:
        return False
    bundle_path = Path(str(value.get("bundle_path")))
    source_url = urlsplit(str(value.get("source_url")))
    return (
        isinstance(value.get("name"), str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+:/@-]{0,511}", value["name"])
        is not None
        and value.get("kind")
        in {
            "dotnet-runtime-pack",
            "dotnet-sdk-pack",
            "maven-artifact",
            "maven-metadata",
            "nuget-package",
        }
        and not bundle_path.is_absolute()
        and bool(bundle_path.parts)
        and all(part not in {"", ".", ".."} for part in bundle_path.parts)
        and "\\" not in str(value["bundle_path"])
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+@/-]{0,1023}", value["bundle_path"])
        is not None
        and isinstance(value.get("sha256"), str)
        and bool(FULL_SHA256.fullmatch(value["sha256"]))
        and type(value.get("size")) is int
        and 0 <= value["size"] <= 1024 * 1024 * 1024
        and source_url.scheme.lower() == "https"
        and source_url.hostname is not None
        and source_url.username is None
        and source_url.password is None
        and not source_url.fragment
    )


def policy_summary(
    policy: dict[str, Any], material_lock: dict[str, Any] | None
) -> dict[str, Any]:
    return {
        "policy_id": policy["policy_id"],
        "policy_sha256": policy["_policy_sha256"],
        "status": policy["status"],
        "canary_profile_approved": policy["canary_profile_approved"],
        "builder": policy["builder"],
        "material_lock_path": policy["material_lock_path"],
        "material_lock": material_lock,
    }


def finding_handoffs(
    findings: list[dict[str, Any]], *, severity: str
) -> list[dict[str, Any]]:
    by_owner: dict[str, list[str]] = {}
    for finding in findings:
        if finding["severity"] != severity:
            continue
        by_owner.setdefault(finding["owner"], []).append(finding["code"])
    return [
        {"agent_id": owner, "required_closures": sorted(codes)}
        for owner, codes in sorted(by_owner.items())
    ]


def add_finding(
    findings: list[dict[str, Any]],
    *,
    code: str,
    severity: str,
    summary: str,
    owner: str,
    evidence: list[str] | None = None,
) -> None:
    findings.append(
        {
            "code": code,
            "severity": severity,
            "summary": summary,
            "owner": owner,
            "evidence": sorted(set(evidence or [])),
        }
    )


def snapshot_source_inventory(
    root: Path,
    findings: list[dict[str, Any]],
    *,
    descriptor_relative: bool = False,
) -> dict[str, Any] | None:
    try:
        inventory = inventory_trusted_source(
            root,
            descriptor_relative=descriptor_relative,
        )
    except BuilderHandoffError as exc:
        add_finding(
            findings,
            code="SOURCE_INVENTORY_REJECTED",
            severity="blocker",
            summary="The complete source filesystem inventory could not be sealed.",
            evidence=[str(exc)],
            owner="source-reacquirer-v3",
        )
        return None
    unsafe_symlinks = [
        entry["path"]
        for entry in inventory["entries"]
        if entry["type"] == "symlink"
        and not root_confined_symlink(entry["path"], entry["target"])
    ]
    if unsafe_symlinks:
        add_finding(
            findings,
            code="SOURCE_SYMLINK_PREPARATION_UNSAFE",
            severity="blocker",
            summary="Source symlinks escape the trusted workspace-copy policy.",
            evidence=unsafe_symlinks,
            owner="build",
        )
    return {
        "schema_version": inventory["schema_version"],
        "tree_sha256": inventory["tree_sha256"],
        "entry_count": len(inventory["entries"]),
        "total_file_bytes": sum(
            entry["size"]
            for entry in inventory["entries"]
            if entry["type"] == "file"
        ),
        "symlink_count": sum(
            1 for entry in inventory["entries"] if entry["type"] == "symlink"
        ),
    }


def root_confined_symlink(path: str, target: str) -> bool:
    target_path = PurePosixPath(target)
    if target_path.is_absolute() or "\x00" in target:
        return False
    stack = list(PurePosixPath(path).parent.parts)
    for part in target_path.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not stack:
                return False
            stack.pop()
            continue
        if part.casefold() == ".git":
            return False
        stack.append(part)
    return bool(stack)


def safe_read_source_text(root: Path, path: Path) -> tuple[str, dict[str, Any]]:
    root = Path(".") if root == Path(".") else Path(os.path.abspath(root))
    path = path if path.is_absolute() else root / path
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Source profile input escapes the source root: {path}") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError(f"Source profile input path is invalid: {relative}")
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_descriptors: list[int] = []
    descriptor: int | None = None
    try:
        current_directory = os.open(root, directory_flags)
        directory_descriptors.append(current_directory)
        for part in relative.parts[:-1]:
            current_directory = os.open(
                part,
                directory_flags,
                dir_fd=current_directory,
            )
            directory_descriptors.append(current_directory)
        descriptor = os.open(
            relative.parts[-1],
            file_flags,
            dir_fd=current_directory,
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"Source profile input is not a regular file: {relative}")
        if before.st_size > MAX_SOURCE_FILE_BYTES:
            raise ValueError(f"Source profile input exceeds size limit: {relative}")
        chunks = []
        remaining = MAX_SOURCE_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise ValueError(
            f"Source profile input could not be opened without symlinks: {relative}"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for directory_descriptor in reversed(directory_descriptors):
            os.close(directory_descriptor)
    if len(data) > MAX_SOURCE_FILE_BYTES:
        raise ValueError(f"Source profile input exceeds size limit: {relative}")
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) or len(data) != before.st_size:
        raise ValueError(f"Source profile input changed while reading: {relative}")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Source profile input is not UTF-8: {relative}") from exc
    return text, {
        "path": relative.as_posix(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def source_file_info(root: Path, path: Path) -> dict[str, Any]:
    return safe_read_source_text(root, path)[1]


def iter_source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for directory, names, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        names[:] = sorted(
            name
            for name in names
            if name not in IGNORED_DIRECTORIES
            and not (directory_path / name).is_symlink()
        )
        for filename in sorted(filenames):
            path = directory_path / filename
            if not path.is_symlink() and path.is_file():
                files.append(path)
    return files


def java_gradle_manifests(root: Path) -> list[Path]:
    names = {
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
    }
    return [path for path in iter_source_files(root) if path.name in names]


def dotnet_project_paths(root: Path) -> list[Path]:
    return sorted(
        path
        for path in iter_source_files(root)
        if path.suffix.lower() in {".csproj", ".fsproj", ".vbproj"}
    )


def dotnet_control_inputs(root: Path) -> list[dict[str, Any]]:
    names = {
        "Directory.Build.props",
        "Directory.Build.targets",
        "Directory.Packages.props",
        "global.json",
        "nuget.config",
        "NuGet.Config",
        "version.json",
    }
    return [
        source_file_info(root, path)
        for path in iter_source_files(root)
        if path.name in names
    ]


def strict_json_loads(text: str, *, label: str) -> Any:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"{label} contains duplicate key {key!r}")
            value[key] = item
        return value

    try:
        return json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON") from exc


def parse_xml(text: str, path: Path) -> ET.Element:
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError(f"XML declarations with entities are forbidden: {path}")
    try:
        return ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML source profile input: {path}: {exc}") from exc


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def direct_child(root: ET.Element | None, name: str) -> ET.Element | None:
    if root is None:
        return None
    return next((child for child in root if local_name(child.tag) == name), None)


def child_text(root: ET.Element | None, name: str) -> str | None:
    child = direct_child(root, name)
    if child is None or child.text is None:
        return None
    value = child.text.strip()
    return value or None


def descendant_texts(root: ET.Element | None, name: str) -> list[str]:
    if root is None:
        return []
    return sorted(
        {
            child.text.strip()
            for child in root.iter()
            if local_name(child.tag) == name and child.text and child.text.strip()
        }
    )


def xml_properties(root: ET.Element | None) -> dict[str, str]:
    if root is None:
        return {}
    return {
        local_name(child.tag): child.text.strip()
        for child in root
        if child.text and child.text.strip()
    }


def maven_coordinates(
    root: ET.Element, container_name: str, item_name: str
) -> list[dict[str, Any]]:
    entries = []
    for container in root.iter():
        if local_name(container.tag) != container_name:
            continue
        for item in container:
            if local_name(item.tag) != item_name:
                continue
            group = child_text(item, "groupId") or ""
            artifact = child_text(item, "artifactId") or ""
            version = child_text(item, "version")
            if artifact:
                entries.append(
                    {
                        "coordinate": f"{group}:{artifact}" if group else artifact,
                        "group_id": group or None,
                        "artifact_id": artifact,
                        "version": version,
                    }
                )
    return sorted(entries, key=lambda item: item["coordinate"])


def maven_plugins(root: ET.Element) -> list[dict[str, Any]]:
    entries = maven_coordinates(root, "plugins", "plugin")
    for container in root.iter():
        if local_name(container.tag) != "plugins":
            continue
        for plugin in container:
            if local_name(plugin.tag) != "plugin":
                continue
            group = child_text(plugin, "groupId") or "org.apache.maven.plugins"
            artifact = child_text(plugin, "artifactId") or ""
            coordinate = f"{group}:{artifact}"
            matching = next(
                (
                    entry
                    for entry in entries
                    if entry["artifact_id"] == artifact
                    and entry.get("group_id") in {None, group}
                ),
                None,
            )
            if matching is not None:
                matching["coordinate"] = coordinate
                matching["group_id"] = group
                matching["extension"] = (
                    (child_text(plugin, "extensions") or "false").lower() == "true"
                )
    for entry in entries:
        entry.setdefault("extension", False)
    return entries


def maven_repository_urls(root: ET.Element) -> list[str]:
    urls = []
    for container_name in ("repositories", "pluginRepositories"):
        for container in root.iter():
            if local_name(container.tag) != container_name:
                continue
            for item in container:
                url = child_text(item, "url")
                if url:
                    urls.append(url)
    return sorted(set(urls))


def maven_distribution_urls(root: ET.Element) -> list[str]:
    distribution = direct_child(root, "distributionManagement")
    if distribution is None:
        return []
    return descendant_texts(distribution, "url")


def maven_wrapper_signals(root: Path) -> dict[str, Any]:
    candidates = [
        root / "mvnw",
        root / "mvnw.cmd",
        root / ".mvn" / "wrapper" / "maven-wrapper.properties",
    ]
    inputs = [source_file_info(root, path) for path in candidates if path.exists()]
    properties = root / ".mvn" / "wrapper" / "maven-wrapper.properties"
    distribution_url = None
    distribution_sha256 = None
    if properties.exists():
        text, _ = safe_read_source_text(root, properties)
        for line in text.splitlines():
            if line.startswith("distributionUrl="):
                distribution_url = line.split("=", 1)[1].strip()
            elif line.startswith("distributionSha256Sum="):
                distribution_sha256 = line.split("=", 1)[1].strip()
    return {
        "present": (root / "mvnw").is_file() and properties.is_file(),
        "inputs": inputs,
        "summary": {
            "script_present": (root / "mvnw").is_file(),
            "properties_present": properties.is_file(),
            "distribution_url": distribution_url,
            "distribution_sha256": distribution_sha256,
        },
    }


def legacy_java_level(value: str) -> bool:
    match = re.fullmatch(r"(?:1\.)?(\d+)", value.strip())
    return bool(match and int(match.group(1)) < 8)


def maven_profile_signals(root: ET.Element) -> list[dict[str, Any]]:
    profiles = direct_child(root, "profiles")
    if profiles is None:
        return []
    result = []
    for profile in profiles:
        if local_name(profile.tag) != "profile":
            continue
        activation = direct_child(profile, "activation")
        result.append(
            {
                "id": child_text(profile, "id"),
                "active_by_default": child_text(activation, "activeByDefault"),
                "jdk_activation": child_text(activation, "jdk"),
                "property_activation": xml_properties(
                    direct_child(activation, "property")
                ),
            }
        )
    return sorted(result, key=lambda item: str(item["id"]))


def maven_parent_signal(root: ET.Element) -> dict[str, Any] | None:
    parent = direct_child(root, "parent")
    if parent is None:
        return None
    return {
        "group_id": child_text(parent, "groupId"),
        "artifact_id": child_text(parent, "artifactId"),
        "version": child_text(parent, "version"),
        "relative_path": child_text(parent, "relativePath"),
    }


def maven_profile_output_overrides(root: ET.Element) -> list[dict[str, Any]]:
    profiles = direct_child(root, "profiles")
    if profiles is None:
        return []
    overrides = []
    for profile in profiles:
        if local_name(profile.tag) != "profile":
            continue
        build = direct_child(profile, "build")
        final_name = child_text(build, "finalName")
        directory = child_text(build, "directory")
        if final_name is not None or directory is not None:
            overrides.append(
                {
                    "profile_id": child_text(profile, "id"),
                    "final_name": final_name,
                    "directory": directory,
                }
            )
    return sorted(overrides, key=lambda item: str(item["profile_id"]))


def maven_plugin_output_overrides(root: ET.Element) -> list[dict[str, Any]]:
    overrides: list[dict[str, Any]] = []
    project_build = direct_child(root, "build")
    overrides.extend(
        maven_build_plugin_output_overrides(project_build, scope="project.build")
    )

    profiles = direct_child(root, "profiles")
    if profiles is not None:
        for profile in profiles:
            if local_name(profile.tag) != "profile":
                continue
            profile_id = child_text(profile, "id") or "<unnamed>"
            overrides.extend(
                maven_build_plugin_output_overrides(
                    direct_child(profile, "build"),
                    scope=f"profile:{profile_id}.build",
                )
            )
    return sorted(
        overrides,
        key=lambda item: (
            item["scope"],
            item["plugin"],
            item["parameter_path"],
            str(item["value"]),
        ),
    )


def maven_build_plugin_output_overrides(
    build: ET.Element | None,
    *,
    scope: str,
) -> list[dict[str, Any]]:
    if build is None:
        return []
    containers: list[tuple[str, ET.Element | None]] = [
        ("plugins", direct_child(build, "plugins")),
    ]
    plugin_management = direct_child(build, "pluginManagement")
    containers.append(
        (
            "pluginManagement.plugins",
            direct_child(plugin_management, "plugins"),
        )
    )

    overrides = []
    for container_name, container in containers:
        if container is None:
            continue
        for plugin in container:
            if local_name(plugin.tag) != "plugin":
                continue
            group_id = child_text(plugin, "groupId") or "org.apache.maven.plugins"
            artifact_id = child_text(plugin, "artifactId") or "<missing>"
            coordinate = f"{group_id}:{artifact_id}"
            for configuration in plugin.iter():
                if local_name(configuration.tag) != "configuration":
                    continue
                for parameter_path, value in maven_output_configuration_values(
                    configuration
                ):
                    overrides.append(
                        {
                            "scope": f"{scope}.{container_name}",
                            "plugin": coordinate,
                            "parameter_path": parameter_path,
                            "value": value,
                        }
                    )
    return overrides


def maven_output_configuration_values(
    configuration: ET.Element,
) -> list[tuple[str, str | None]]:
    values: list[tuple[str, str | None]] = []

    def visit(element: ET.Element, path: tuple[str, ...]) -> None:
        for child in element:
            name = local_name(child.tag)
            child_path = (*path, name)
            normalized_name = re.sub(r"[^a-z0-9]", "", name.lower())
            if normalized_name in MAVEN_ARTIFACT_OUTPUT_PARAMETERS:
                text = " ".join(part.strip() for part in child.itertext() if part.strip())
                values.append(("/".join(child_path), text or None))
            visit(child, child_path)

    visit(configuration, ("configuration",))
    return values


def find_source_literals(root: Path, literals: list[str]) -> dict[str, list[str]]:
    matches = {literal: [] for literal in literals}
    for path in iter_source_files(root):
        if path.suffix.lower() not in {".java", ".kt", ".groovy"}:
            continue
        text, _ = safe_read_source_text(root, path)
        for literal in literals:
            if literal in text:
                matches[literal].append(path.relative_to(root).as_posix())
    return {key: sorted(value) for key, value in matches.items() if value}


def source_release_script_signals(root: Path) -> list[dict[str, Any]]:
    command_pattern = re.compile(
        r"\b(?:curl|deploy|git\s+(?:clone|commit|push|tag)|gpg|mvn|nuget|rm\s+-rf|wget)\b",
        re.IGNORECASE,
    )
    scripts = []
    for path in iter_source_files(root):
        lowered = path.name.lower()
        if "release" not in lowered and "publish" not in lowered and "deploy" not in lowered:
            continue
        if path.suffix.lower() not in {"", ".bat", ".cmd", ".ps1", ".sh"}:
            continue
        text, info = safe_read_source_text(root, path)
        commands = sorted(set(command_pattern.findall(text)))
        scripts.append({**info, "hazard_tokens": commands})
    return scripts


def maven_exact_artifact_name(
    *,
    artifact_id: str | None,
    project_version: str | None,
    packaging: str,
    final_name: str | None,
) -> str | None:
    extension = {"jar": "jar", "war": "war"}.get(packaging)
    safe_component = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]*\Z")
    if not extension:
        return None
    if final_name is not None:
        base_name = final_name
    elif artifact_id and project_version:
        base_name = f"{artifact_id}-{project_version}"
    else:
        return None
    if "${" in base_name or safe_component.fullmatch(base_name) is None:
        return None
    return f"{base_name}.{extension}"


def maven_project_config_signals(root: Path) -> list[dict[str, Any]]:
    paths = [
        root / ".mvn" / "extensions.xml",
        root / ".mvn" / "jvm.config",
        root / ".mvn" / "maven.config",
    ]
    return [source_file_info(root, path) for path in paths if path.exists()]


def dotnet_project_summary(
    root: Path, path: Path, pipeline_references: dict[str, int]
) -> dict[str, Any]:
    source_documents = [
        *dotnet_inherited_documents(root, path),
        (path, parse_xml(safe_read_source_text(root, path)[0], path)),
    ]
    info = source_file_info(root, path)
    properties: dict[str, str] = {}
    critical_properties = {
        "AssemblyName",
        "OutputType",
        "PackageId",
        "PackAsTool",
        "RuntimeIdentifier",
        "RuntimeIdentifiers",
        "TargetFramework",
        "TargetFrameworks",
    }
    conditional_critical_properties = []
    for document_path, document in source_documents:
        for group in document:
            if local_name(group.tag) == "PropertyGroup":
                group_condition = group.attrib.get("Condition")
                for child in group:
                    property_name = local_name(child.tag)
                    if property_name in critical_properties and (
                        group_condition or child.attrib.get("Condition")
                    ):
                        conditional_critical_properties.append(
                            f"{document_path.relative_to(root).as_posix()}:{property_name}"
                        )
                properties.update(xml_properties(group))
    frameworks = split_msbuild_list(
        properties.get("TargetFrameworks") or properties.get("TargetFramework")
    )
    rids = split_msbuild_list(
        properties.get("RuntimeIdentifiers") or properties.get("RuntimeIdentifier")
    )
    relative = path.relative_to(root).as_posix()
    package_references = []
    project_references = []
    imports = []
    exec_task_sources = []
    using_task_sources = []
    conditional_element_sources = []
    sdk_references = []
    for document_path, document in source_documents:
        sdk_attribute = document.attrib.get("Sdk")
        if sdk_attribute:
            sdk_references.extend(
                value.strip() for value in sdk_attribute.split(";") if value.strip()
            )
        for element in document.iter():
            name = local_name(element.tag)
            if element.attrib.get("Condition"):
                conditional_element_sources.append(
                    document_path.relative_to(root).as_posix()
                )
            if name == "PackageReference":
                package_references.append(
                    {
                        "name": element.attrib.get("Include")
                        or element.attrib.get("Update"),
                        "version": element.attrib.get("Version")
                        or child_text(element, "Version"),
                    }
                )
            elif name == "ProjectReference" and element.attrib.get("Include"):
                project_references.append(element.attrib["Include"])
            elif name == "Import" and element.attrib.get("Project"):
                imports.append(element.attrib["Project"])
            elif name == "Exec":
                exec_task_sources.append(document_path.relative_to(root).as_posix())
            elif name == "UsingTask":
                using_task_sources.append(
                    document_path.relative_to(root).as_posix()
                )
            elif name == "Sdk" and element.attrib.get("Name"):
                value = element.attrib["Name"]
                if element.attrib.get("Version"):
                    value = f"{value}/{element.attrib['Version']}"
                sdk_references.append(value)
    return {
        **info,
        "target_frameworks": frameworks,
        "runtime_identifiers": rids,
        "output_type": properties.get("OutputType") or "Library",
        "package_id": properties.get("PackageId"),
        "assembly_name": properties.get("AssemblyName"),
        "pack_as_tool": properties.get("PackAsTool", "false").lower() == "true",
        "package_references": sorted(
            package_references, key=lambda item: (str(item["name"]), str(item["version"]))
        ),
        "project_references": sorted(project_references),
        "imports": sorted(imports),
        "exec_task_sources": sorted(set(exec_task_sources)),
        "using_task_sources": sorted(set(using_task_sources)),
        "sdk_references": sorted(set(sdk_references)),
        "conditional_element_sources": sorted(set(conditional_element_sources)),
        "conditional_critical_properties": sorted(
            set(conditional_critical_properties)
        ),
        "release_pipeline_references": pipeline_references.get(relative, 0),
    }


def dotnet_inherited_documents(
    root: Path, project: Path
) -> list[tuple[Path, ET.Element]]:
    documents = []
    for filename in ("Directory.Build.props", "Directory.Packages.props"):
        candidate = nearest_ancestor_file(root, project.parent, filename)
        if candidate is None:
            continue
        text, _ = safe_read_source_text(root, candidate)
        documents.append((candidate, parse_xml(text, candidate)))
    target = nearest_ancestor_file(root, project.parent, "Directory.Build.targets")
    if target is not None:
        text, _ = safe_read_source_text(root, target)
        documents.append((target, parse_xml(text, target)))
    return documents


def normalize_source_candidate(root: Path, candidate: Path) -> Path | None:
    if root == Path("."):
        normalized = Path(os.path.normpath(candidate))
        if normalized.is_absolute() or any(part == ".." for part in normalized.parts):
            return None
        return normalized
    return Path(os.path.abspath(candidate))


def source_candidate_is_within_root(root: Path, candidate: Path) -> bool:
    if root == Path("."):
        return not candidate.is_absolute() and all(
            part not in {"", ".."} for part in candidate.parts
        )
    return candidate.is_relative_to(root)


def nearest_ancestor_file(root: Path, start: Path, filename: str) -> Path | None:
    current = normalize_source_candidate(root, start)
    while current is not None and source_candidate_is_within_root(root, current):
        candidate = current / filename
        if candidate.exists():
            safe_read_source_text(root, candidate)
            return candidate
        if current == root:
            break
        current = current.parent
    return None


def dotnet_import_closure(root: Path, projects: list[Path]) -> dict[str, Any]:
    pending: list[Path] = []
    for project in projects:
        pending.append(project)
        pending.extend(path for path, _ in dotnet_inherited_documents(root, project))
    visited: set[Path] = set()
    inputs: list[dict[str, Any]] = []
    unresolved: set[str] = set()
    exec_sources: set[str] = set()
    using_task_sources: set[str] = set()
    conditional_sources: set[str] = set()
    while pending:
        path = pending.pop()
        if path in visited:
            continue
        visited.add(path)
        text, info = safe_read_source_text(root, path)
        document = parse_xml(text, path)
        inputs.append(info)
        relative = path.relative_to(root).as_posix()
        for element in document.iter():
            if element.attrib.get("Condition"):
                conditional_sources.add(relative)
            name = local_name(element.tag)
            if name == "Exec":
                exec_sources.add(relative)
            if name == "UsingTask":
                using_task_sources.add(relative)
            if name != "Import":
                continue
            import_value = element.attrib.get("Project")
            if not import_value:
                unresolved.add(f"{relative}:<missing Project>")
                continue
            normalized = import_value.replace("\\", "/")
            if (
                msbuild_expression(normalized)
                or any(character in normalized for character in ("*", "?", "["))
                or PurePosixPath(normalized).is_absolute()
            ):
                unresolved.add(f"{relative}:{import_value}")
                continue
            candidate = normalize_source_candidate(root, path.parent / normalized)
            if (
                candidate is None
                or not source_candidate_is_within_root(root, candidate)
                or not candidate.is_file()
                or candidate.is_symlink()
            ):
                unresolved.add(f"{relative}:{import_value}")
                continue
            pending.append(candidate)
    return {
        "inputs": dedupe_inputs(inputs),
        "unresolved": sorted(unresolved),
        "exec_task_sources": sorted(exec_sources),
        "using_task_sources": sorted(using_task_sources),
        "conditional_element_sources": sorted(conditional_sources),
    }


def select_dotnet_target(
    root: Path,
    projects: list[Path],
    requested: str | None,
    findings: list[dict[str, Any]],
) -> Path | None:
    by_relative = {path.relative_to(root).as_posix(): path for path in projects}
    if requested:
        normalized = Path(requested).as_posix()
        selected = by_relative.get(normalized)
        if selected is None:
            add_finding(
                findings,
                code="DOTNET_TARGET_INVALID",
                severity="blocker",
                summary="The requested .NET target is not a discovered project.",
                evidence=[normalized],
                owner="ecosystem-profiler",
            )
        if selected is not None and normalized.startswith(("-", "@")):
            add_finding(
                findings,
                code="DOTNET_TARGET_PATH_OPTION_LIKE",
                severity="blocker",
                summary="The selected project path could be parsed as a CLI option.",
                evidence=[normalized],
                owner="ecosystem-profiler",
            )
            return None
        return selected
    if len(projects) == 1:
        relative = projects[0].relative_to(root).as_posix()
        if relative.startswith(("-", "@")):
            add_finding(
                findings,
                code="DOTNET_TARGET_PATH_OPTION_LIKE",
                severity="blocker",
                summary="The selected project path could be parsed as a CLI option.",
                evidence=[relative],
                owner="ecosystem-profiler",
            )
            return None
        return projects[0]
    add_finding(
        findings,
        code="DOTNET_TARGET_SELECTION_REQUIRED",
        severity="blocker",
        summary="Multiple .NET projects require an explicit release target.",
        evidence=sorted(by_relative),
        owner="ecosystem-profiler",
    )
    return None


def select_dotnet_framework(
    selected: dict[str, Any],
    *,
    requested: str | None,
    findings: list[dict[str, Any]],
) -> str | None:
    frameworks = selected["target_frameworks"]
    invalid_tokens = sorted(
        {
            value
            for value in [*frameworks, requested]
            if value is not None and not safe_dotnet_cli_token(value)
        }
    )
    if invalid_tokens:
        add_finding(
            findings,
            code="DOTNET_TARGET_FRAMEWORK_TOKEN_INVALID",
            severity="blocker",
            summary="Target frameworks must be bounded literal .NET CLI tokens.",
            evidence=invalid_tokens,
            owner="ecosystem-profiler",
        )
        return None
    if requested:
        if requested not in frameworks:
            add_finding(
                findings,
                code="DOTNET_TARGET_FRAMEWORK_INVALID",
                severity="blocker",
                summary="The requested target framework is not declared by the project.",
                evidence=[requested, *frameworks],
                owner="ecosystem-profiler",
            )
            return None
        return requested
    if len(frameworks) == 1:
        return frameworks[0]
    add_finding(
        findings,
        code="DOTNET_TARGET_FRAMEWORK_SELECTION_REQUIRED",
        severity="blocker",
        summary="The target framework must be one exact, statically declared value.",
        evidence=frameworks,
        owner="ecosystem-profiler",
    )
    return None


def select_dotnet_rid(
    selected: dict[str, Any],
    *,
    requested: str | None,
    operation: str | None,
    findings: list[dict[str, Any]],
) -> str | None:
    rids = selected["runtime_identifiers"]
    invalid_tokens = sorted(
        {
            value
            for value in [*rids, requested]
            if value is not None and not safe_dotnet_cli_token(value)
        }
    )
    if invalid_tokens:
        add_finding(
            findings,
            code="DOTNET_RUNTIME_IDENTIFIER_TOKEN_INVALID",
            severity="blocker",
            summary="Runtime identifiers must be bounded literal .NET CLI tokens.",
            evidence=invalid_tokens,
            owner="ecosystem-profiler",
        )
        return None
    if operation != "publish":
        if requested:
            add_finding(
                findings,
                code="DOTNET_RUNTIME_IDENTIFIER_NOT_APPLICABLE",
                severity="blocker",
                summary="Runtime identifiers apply to publish, not this selected operation.",
                evidence=[requested, str(operation)],
                owner="ecosystem-profiler",
            )
        return None
    if requested:
        if rids and requested not in rids:
            add_finding(
                findings,
                code="DOTNET_RUNTIME_IDENTIFIER_INVALID",
                severity="blocker",
                summary="The requested runtime identifier is not declared by the project.",
                evidence=[requested, *rids],
                owner="ecosystem-profiler",
            )
            return None
        return requested
    if len(rids) <= 1:
        return rids[0] if rids else None
    add_finding(
        findings,
        code="DOTNET_RUNTIME_IDENTIFIER_SELECTION_REQUIRED",
        severity="blocker",
        summary="The release target declares multiple runtime identifiers.",
        evidence=rids,
        owner="ecosystem-profiler",
    )
    return None


def dotnet_project_closure(
    root: Path, selected: Path, findings: list[dict[str, Any]]
) -> list[Path]:
    visited: set[Path] = set()
    pending = [selected]
    while pending:
        path = pending.pop()
        if path in visited:
            continue
        visited.add(path)
        summary = dotnet_project_summary(root, path, {})
        for reference in summary["project_references"]:
            candidate = normalize_source_candidate(
                root,
                path.parent / reference.replace("\\", "/"),
            )
            if (
                candidate is None
                or not source_candidate_is_within_root(root, candidate)
                or not candidate.is_file()
            ):
                add_finding(
                    findings,
                    code="DOTNET_PROJECT_REFERENCE_INVALID",
                    severity="blocker",
                    summary="A project reference escapes the source tree or is missing.",
                    evidence=[reference],
                    owner="ecosystem-profiler",
                )
                continue
            pending.append(candidate)
    return sorted(visited)


def dotnet_lock_signals(
    root: Path,
    projects: list[Path],
    framework: str | None,
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    inputs = []
    missing = []
    invalid = []
    for project in projects:
        lock_path = project.parent / "packages.lock.json"
        if lock_path.is_file():
            inputs.append(source_file_info(root, lock_path))
            if not valid_dotnet_packages_lock(root, lock_path, framework):
                invalid.append(lock_path.relative_to(root).as_posix())
        else:
            missing.append(project.relative_to(root).as_posix())
    if missing:
        add_finding(
            findings,
            code="DOTNET_PACKAGES_LOCK_MISSING",
            severity="blocker",
            summary="Every project in the selected closure needs a packages.lock.json.",
            evidence=missing,
            owner="material-resolver",
        )
    if invalid:
        add_finding(
            findings,
            code="DOTNET_PACKAGES_LOCK_INVALID",
            severity="blocker",
            summary="A packages.lock.json lacks exact resolved package content hashes.",
            evidence=invalid,
            owner="material-resolver",
        )
    return inputs


def valid_dotnet_packages_lock(
    root: Path, path: Path, framework: str | None
) -> bool:
    text, _ = safe_read_source_text(root, path)
    try:
        lock = strict_json_loads(text, label="packages.lock.json")
    except ValueError:
        return False
    if not isinstance(lock, dict) or lock.get("version") not in {1, 2}:
        return False
    dependencies = lock.get("dependencies")
    if not isinstance(dependencies, dict) or not dependencies:
        return False
    if not framework:
        return False
    selected_frameworks = [
        framework_entries
        for key, framework_entries in dependencies.items()
        if key == framework or key.startswith(f"{framework}/")
    ]
    if not selected_frameworks:
        return False
    package_entries = [
        entry
        for framework_entries in selected_frameworks
        if isinstance(framework_entries, dict)
        for entry in framework_entries.values()
        if isinstance(entry, dict)
    ]
    if not package_entries:
        return False
    for entry in package_entries:
        content_hash = entry.get("contentHash")
        if (
            entry.get("type") not in {"Direct", "Transitive"}
            or not isinstance(entry.get("resolved"), str)
            or not entry["resolved"]
            or not isinstance(content_hash, str)
        ):
            return False
        try:
            decoded_hash = b64decode(content_hash, validate=True)
        except (Base64Error, ValueError):
            return False
        if len(decoded_hash) != 64:
            return False
    return True


def dotnet_test_projects(root: Path, projects: list[Path], selected: Path) -> list[str]:
    selected_relative = selected.relative_to(root).as_posix()
    tests = []
    for project in projects:
        relative = project.relative_to(root).as_posix()
        lowered = relative.lower()
        if "test" not in lowered:
            continue
        summary = dotnet_project_summary(root, project, {})
        references = set()
        for reference in summary["project_references"]:
            candidate = normalize_source_candidate(
                root,
                project.parent / reference.replace("\\", "/"),
            )
            if candidate is not None and source_candidate_is_within_root(
                root, candidate
            ):
                references.add(candidate.relative_to(root).as_posix())
        if selected_relative in references:
            tests.append(relative)
    return sorted(tests)


def select_dotnet_operation(
    selected: dict[str, Any],
    *,
    requested: str | None,
    findings: list[dict[str, Any]],
) -> str | None:
    output_is_executable = str(selected["output_type"]).lower() in {"exe", "winexe"}
    supported = {"publish"} if output_is_executable else {"pack"}
    if selected["pack_as_tool"]:
        supported.add("pack")
    if requested:
        if requested not in supported:
            add_finding(
                findings,
                code="DOTNET_OPERATION_INVALID",
                severity="blocker",
                summary="The requested operation is incompatible with the selected project.",
                evidence=[requested, *sorted(supported)],
                owner="ecosystem-profiler",
            )
            return None
        return requested
    if len(supported) == 1:
        return next(iter(supported))
    add_finding(
        findings,
        code="DOTNET_OPERATION_SELECTION_REQUIRED",
        severity="blocker",
        summary="The project can produce both package and published application artifacts.",
        evidence=sorted(supported),
        owner="ecosystem-profiler",
    )
    return None


def select_dotnet_deployment_mode(
    *,
    operation: str | None,
    requested: bool | None,
    findings: list[dict[str, Any]],
) -> bool | None:
    if operation != "publish":
        return None
    if requested is None:
        add_finding(
            findings,
            code="DOTNET_DEPLOYMENT_MODE_SELECTION_REQUIRED",
            severity="blocker",
            summary="Publish must explicitly select self-contained or framework-dependent output.",
            owner="ecosystem-profiler",
        )
        return None
    return requested


def dotnet_steps(
    *,
    selected_path: Path | None,
    root: Path,
    framework: str | None,
    runtime_identifier: str | None,
    operation: str | None,
    self_contained: bool | None,
    test_projects: list[str],
) -> list[dict[str, Any]]:
    if (
        selected_path is None
        or framework is None
        or not safe_dotnet_cli_token(framework)
        or operation is None
        or (
            runtime_identifier is not None
            and not safe_dotnet_cli_token(runtime_identifier)
        )
        or (operation == "publish" and self_contained is None)
    ):
        return []
    target = selected_path.relative_to(root).as_posix()
    common = [
        "--locked-mode",
        "--configfile",
        "/policy/offline.NuGet.Config",
        "--packages",
        "/workspace/.nuget/packages",
    ]
    steps = [
        {
            "name": "restore",
            "argv": [
                "/opt/dotnet/dotnet",
                "restore",
                target,
                *common,
                "--disable-parallel",
                "/p:RestoreIgnoreFailedSources=false",
            ],
        }
    ]
    for test_project in test_projects:
        steps.append(
            {
                "name": f"restore-test:{test_project}",
                "argv": [
                    "/opt/dotnet/dotnet",
                    "restore",
                    test_project,
                    *common,
                    "--disable-parallel",
                    "/p:RestoreIgnoreFailedSources=false",
                ],
            }
        )
        steps.append(
            {
                "name": f"test:{test_project}",
                "argv": [
                    "/opt/dotnet/dotnet",
                    "test",
                    test_project,
                    "--no-restore",
                    "--configuration",
                    "Release",
                    "--framework",
                    framework,
                    "--property:ContinuousIntegrationBuild=true",
                    "--property:Deterministic=true",
                    "--results-directory",
                    "/out/test-results",
                ],
            }
        )
    argv = [
        "/opt/dotnet/dotnet",
        operation,
        target,
        "--no-restore",
        "--configuration",
        "Release",
        "--framework",
        framework,
        "--output",
        "/out",
        "--property:ContinuousIntegrationBuild=true",
        "--property:Deterministic=true",
        "--property:PathMap=/workspace/src=/_/src",
    ]
    if runtime_identifier:
        argv.extend(["--runtime", runtime_identifier])
    if operation == "publish":
        argv.extend(
            ["--self-contained", "true" if self_contained else "false"]
        )
    steps.append({"name": operation, "argv": argv})
    return steps


def safe_dotnet_cli_token(value: str) -> bool:
    return (
        isinstance(value, str)
        and not msbuild_expression(value)
        and DOTNET_CLI_TOKEN.fullmatch(value) is not None
    )


def dotnet_artifact_selection(
    operation: str | None,
    *,
    expected_artifacts: list[str] | None,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    include = []
    for value in expected_artifacts or []:
        candidate = Path(value)
        if (
            candidate.is_absolute()
            or not candidate.parts
            or any(part in {"", ".", ".."} for part in candidate.parts)
            or "\\" in value
            or any(character in value for character in ("*", "?", "[", "]"))
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            add_finding(
                findings,
                code="DOTNET_ARTIFACT_PATH_INVALID",
                severity="blocker",
                summary="Expected artifact paths must be normalized and relative to /out.",
                evidence=[value],
                owner="ecosystem-profiler",
            )
            continue
        include.append(candidate.as_posix())
    include = sorted(set(include))
    if operation is not None and not include:
        add_finding(
            findings,
            code="DOTNET_ARTIFACT_MANIFEST_REQUIRES_CANARY",
            severity="canary",
            summary="A first isolated canary must produce the exact recursive artifact manifest.",
            owner="build",
        )
    return {
        "root": "/out",
        "include": include,
        "expected_count": len(include),
        "reject_unlisted": True,
        "exclude": [],
        "follow_symlinks": False,
    }


def dotnet_response_file_signals(root: Path) -> list[dict[str, Any]]:
    names = {"Directory.Build.rsp", "MSBuild.rsp"}
    return [
        source_file_info(root, path)
        for path in iter_source_files(root)
        if path.name in names
    ]


def dotnet_package_sources(root: Path) -> list[dict[str, str]]:
    candidates = [
        path
        for path in iter_source_files(root)
        if path.name.lower() == "nuget.config"
    ]
    if not candidates:
        return [
            {
                "key": "implicit-nuget.org",
                "value": "https://api.nuget.org/v3/index.json",
                "path": "<implicit>",
            }
        ]
    feeds = []
    for path in candidates:
        text, _ = safe_read_source_text(root, path)
        config = parse_xml(text, path)
        for element in config.iter():
            if local_name(element.tag) != "packageSources":
                continue
            for source in element:
                if local_name(source.tag) == "add" and source.attrib.get("value"):
                    feeds.append(
                        {
                            "key": source.attrib.get("key", ""),
                            "value": source.attrib["value"],
                            "path": path.relative_to(root).as_posix(),
                        }
                    )
    return sorted(feeds, key=lambda item: (item["path"], item["key"]))


def canonical_nuget_org_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme.lower() == "https"
        and parsed.hostname is not None
        and parsed.hostname.lower() == "api.nuget.org"
        and port in {None, 443}
        and parsed.username is None
        and parsed.password is None
        and parsed.path.rstrip("/") == "/v3/index.json"
        and not parsed.query
        and not parsed.fragment
    )


def dotnet_nuget_credential_signals(root: Path) -> list[str]:
    findings = []
    for path in iter_source_files(root):
        if path.name.lower() != "nuget.config":
            continue
        text, _ = safe_read_source_text(root, path)
        config = parse_xml(text, path)
        if any(
            local_name(element.tag) == "packageSourceCredentials"
            for element in config.iter()
        ):
            findings.append(path.relative_to(root).as_posix())
    return sorted(findings)


def trusted_preparation(ecosystem: str) -> dict[str, Any]:
    if ecosystem == "maven":
        material_source = "/materials/m2"
        material_destination = "/workspace/m2"
    else:
        material_source = "/materials/nuget-packages"
        material_destination = "/workspace/.nuget/packages"
    return {
        "performed_by": "trusted-builder-supervisor",
        "source": {
            "from": "/src",
            "to": "/workspace/src",
            "mode": "inventory-verified-copy",
            "symlink_policy": "root-confined-relative-only",
            "verify_before_and_after": True,
        },
        "materials": {
            "from": material_source,
            "to": material_destination,
            "mode": "digest-verified-copy",
            "verify_before_and_after": True,
        },
        "workspace_owner": "unprivileged-build-uid",
        "collector_output_not_writable_by_build": True,
    }


def dotnet_pipeline_signals(root: Path) -> tuple[dict[str, int], list[str]]:
    references: dict[str, int] = {}
    external_templates: set[str] = set()
    project_pattern = re.compile(r"[A-Za-z0-9_./\\ -]+\.(?:cs|fs|vb)proj")
    template_pattern = re.compile(r"(?:template|extends):\s*([^\s]+@[^\s]+)")
    for path in iter_source_files(root):
        if path.suffix.lower() not in {".yml", ".yaml"}:
            continue
        text, _ = safe_read_source_text(root, path)
        normalized_text = text.replace("\\", "/")
        for match in project_pattern.findall(normalized_text):
            candidate = match.strip(" '\"\r\n")
            if candidate:
                references[candidate] = references.get(candidate, 0) + 1
        for match in template_pattern.findall(normalized_text):
            external_templates.add(f"{path.relative_to(root).as_posix()}:{match}")
    return references, sorted(external_templates)


def read_optional_json(root: Path, path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    text, _ = safe_read_source_text(root, path)
    try:
        value = strict_json_loads(text, label=f"JSON source profile input {path}")
    except ValueError as exc:
        raise ValueError(f"Invalid JSON source profile input: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON source profile input must be an object: {path}")
    return value


def split_msbuild_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(";") if part.strip()]


def msbuild_expression(value: str) -> bool:
    return "$(" in value or "@(" in value or "%(" in value


def dedupe_inputs(inputs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        value
        for _, value in sorted(
            {value["path"]: value for value in inputs}.items(),
            key=lambda item: item[0],
        )
    ]


def empty_build_plan() -> dict[str, Any]:
    return {
        "network": "none",
        "shell": False,
        "steps": [],
        "artifact_selection": {
            "include": [],
            "exclude": [],
            "follow_symlinks": False,
        },
    }
