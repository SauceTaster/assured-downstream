from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
import stat
import threading
import uuid
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterator

from assured_downstream.agent_contracts import (
    AgentContext,
    AgentResult,
    ArtifactOutput,
    EventOutput,
    content_digest,
)
from assured_downstream.agent_runtime import AgentHandler, AgentRuntime
from assured_downstream.agent_store import AgentStore
from assured_downstream.builder_handoff_v3 import inventory_trusted_source
from assured_downstream.catalog import utc_now
from assured_downstream.command_runner import CommandRunner, display_command
from assured_downstream.ecosystem_profile import (
    ecosystem_policy_digests,
    ecosystem_profiler_sha256,
    plan_ecosystem_build_profile,
)
from assured_downstream.fork_plan import FORK_PLAN_SCHEMA_VERSION
from assured_downstream.evidence import sha256_file
from assured_downstream.lifecycle import StateStore
from assured_downstream.overlay import ASSURANCE_ORDER, plan_overlay
from assured_downstream.recon import inspect_repository
from assured_downstream.release_profile import plan_release_profile
from assured_downstream.secure_path import (
    directory_identity,
    open_absolute_directory_without_symlinks,
    open_directory_beneath,
    require_directory_identity,
    secure_directory_identity,
)
from assured_downstream.sync_apply import apply_sync_plan
from assured_downstream.sync_plan import create_sync_plan, safe_repo_dir


MANAGED_CHECKOUT_WORKFLOW = "managed-checkout-reconciliation"
VERIFIED_FORK_STATES = {"ForkVerified", "Forked"}
MAX_HANDOFF_JSON_BYTES = 64 * 1024 * 1024
PROCESS_DIRECTORY_LOCK = threading.RLock()


class ManagedForkSyncHandler:
    agent_id = "fork-sync"

    def __init__(self, *, allow_local_remotes: bool = False) -> None:
        self.allow_local_remotes = allow_local_remotes

    def handle(self, context: AgentContext) -> AgentResult:
        if context.event.event_type != "UpstreamChanged":
            raise ValueError("Managed fork reconciliation requires UpstreamChanged")
        attempt_output_root(context, expected_agent_id=self.agent_id)
        config = require_managed_config(context.event.payload)
        _fork_plan_path, fork_plan = read_verified_config_json(
            config,
            "fork_plan_path",
        )
        _state_path, source_state_payload = read_verified_config_json(
            config,
            "state_path",
        )
        if source_state_payload.get("schema_version") != 1:
            raise ValueError("Lifecycle state has an unsupported schema version")
        source_state_payload.setdefault("repositories", {})
        source_state = StateStore(source_state_payload)
        execute_sync = config["execute_sync"]

        checks = managed_sync_checks(
            fork_plan,
            source_state=source_state,
            execute_sync=execute_sync,
        )
        gate_passed = all(check["passed"] for check in checks)
        gate = {
            "schema_version": 1,
            "gate": "fork-to-managed-checkout",
            "passed": gate_passed,
            "checks": checks,
        }
        gate_path = write_attempt_json(
            context,
            Path("sync-gate-decision.json"),
            gate,
        )
        gate_artifact = ArtifactOutput(role="sync-gate-decision", path=gate_path)
        if not gate_passed:
            return AgentResult(
                status="blocked",
                summary="Managed checkout gate blocked before local Git mutation.",
                artifacts=[gate_artifact],
                human_review=["Review the failed managed checkout gate checks."],
            )

        sync_plan = create_sync_plan(
            fork_plan,
            workspace=Path(config["workspace"]),
            allow_local_remotes=self.allow_local_remotes,
        )
        sync_plan_path = write_attempt_json(
            context,
            Path("sync-plan.json"),
            sync_plan,
        )
        lifecycle_state = StateStore(copy.deepcopy(source_state.data))
        result = apply_sync_plan(
            sync_plan,
            state=lifecycle_state,
            execute=execute_sync,
            allow_local_remotes=self.allow_local_remotes,
        )
        lifecycle_state.data["updated_at"] = utc_now()
        lifecycle_path = write_attempt_json(
            context,
            Path("lifecycle-state.json"),
            lifecycle_state.data,
        )
        result_path = write_attempt_json(
            context,
            Path("sync-result.json"),
            {
                "schema_version": 1,
                "execute_sync": execute_sync,
                **asdict(result),
            },
        )
        artifacts = [
            gate_artifact,
            ArtifactOutput(role="sync-plan", path=sync_plan_path),
            ArtifactOutput(role="lifecycle-state", path=lifecycle_path),
            ArtifactOutput(role="sync-result", path=result_path),
        ]

        if result.failed:
            return AgentResult(
                status="blocked",
                summary=f"Managed checkout reconciliation failed for {result.failed} repositories.",
                artifacts=artifacts,
                human_review=["Review SyncConflict or SyncFailed lifecycle events."],
            )
        if result.review_required:
            return AgentResult(
                status="needs_human_review",
                summary=(
                    "Managed mirrors were updated, but secure branch divergence "
                    f"requires review for {result.review_required} repositories."
                ),
                artifacts=artifacts,
                human_review=["Review secure branch divergence before overlay replay."],
            )
        if not execute_sync:
            return AgentResult(
                status="succeeded",
                summary=f"Prepared {result.succeeded} guarded managed checkout plans.",
                artifacts=artifacts,
            )

        payload = {
            "config": config,
            "sync_plan": artifact_reference(sync_plan_path, context=context),
            "lifecycle_state": artifact_reference(lifecycle_path, context=context),
            "sync_result": artifact_reference(result_path, context=context),
        }
        return AgentResult(
            status="succeeded",
            summary=f"Reconciled {result.succeeded} managed checkouts.",
            events=[
                EventOutput(
                    event_type="SyncReady",
                    payload=payload,
                    dedupe_key=content_digest(payload),
                )
            ],
            artifacts=artifacts,
        )


class ManagedReconHandler:
    agent_id = "recon"

    def handle(self, context: AgentContext) -> AgentResult:
        require_producer(context, "fork-sync")
        if context.event.event_type != "SyncReady":
            raise ValueError("Managed recon requires SyncReady")
        attempt_output_root(context, expected_agent_id=self.agent_id)
        config = require_managed_config(context.event.payload)
        _sync_plan_path, sync_plan = read_verified_attempt_json(
            context,
            context.event.payload["sync_plan"],
            expected_agent_id="fork-sync",
            label="sync plan",
        )
        _lifecycle_path, lifecycle_payload = read_verified_attempt_json(
            context,
            context.event.payload["lifecycle_state"],
            expected_agent_id="fork-sync",
            label="lifecycle state",
        )
        if lifecycle_payload.get("schema_version") != 1:
            raise ValueError("Lifecycle state has an unsupported schema version")
        lifecycle_payload.setdefault("repositories", {})
        lifecycle_state = StateStore(lifecycle_payload)

        index_entries = []
        artifacts = []
        for repo in sync_plan.get("repositories", []):
            local_path = Path(repo["local_path"])
            if not local_path.is_dir():
                raise ValueError(f"Managed checkout is missing: {local_path}")
            lifecycle_repo = lifecycle_state.data.get("repositories", {}).get(
                repo["source_full_name"],
                {},
            )
            last_event = (lifecycle_repo.get("events") or [{}])[-1]
            sync_detail = last_event.get("detail") or {}
            analysis_sha = require_commit_sha(
                sync_detail.get("upstream_default_sha"),
                label=f"{repo['source_full_name']} synchronized upstream commit",
            )
            snapshot_root = ensure_attempt_directory(context, Path("snapshots"))
            snapshot_name = safe_repo_dir(repo["target_full_name"])
            snapshot_path = snapshot_root / snapshot_name
            with pinned_attempt_directory(
                context,
                snapshot_root,
                expected_agent_id=self.agent_id,
                expected_attempt_id=require_current_attempt_id(context),
                label="analysis snapshot root",
            ) as snapshot_root_descriptor:
                prepare_analysis_worktree(
                    checkout_path=local_path,
                    snapshot_root_descriptor=snapshot_root_descriptor,
                    snapshot_name=snapshot_name,
                    commit_sha=analysis_sha,
                )
            with pinned_attempt_directory(
                context,
                snapshot_path,
                expected_agent_id=self.agent_id,
                expected_attempt_id=require_current_attempt_id(context),
                label="analysis snapshot",
            ) as analysis_descriptor:
                verify_analysis_snapshot(
                    directory_descriptor=analysis_descriptor,
                    expected_commit=analysis_sha,
                    expected_tree=None,
                )
                analysis_git_tree = require_git_object_id(
                    run_git_in_directory(
                        analysis_descriptor,
                        ["git", "rev-parse", "HEAD^{tree}"],
                    ),
                    label=f"{repo['source_full_name']} synchronized Git tree",
                )
                with current_directory_from_descriptor(analysis_descriptor):
                    recon = inspect_repository(
                        Path("."),
                        descriptor_relative=True,
                    )
                recon["path"] = str(snapshot_path)
                verify_analysis_snapshot(
                    directory_descriptor=analysis_descriptor,
                    expected_commit=analysis_sha,
                    expected_tree=analysis_git_tree,
                )
            recon_path = write_attempt_json(
                context,
                Path("repositories")
                / safe_repo_dir(repo["target_full_name"])
                / "recon.json",
                recon,
            )
            artifacts.append(ArtifactOutput(role="repository-recon", path=recon_path))

            index_entries.append(
                {
                    "source_full_name": repo["source_full_name"],
                    "target_full_name": repo["target_full_name"],
                    "local_path": str(local_path.resolve()),
                    "analysis_path": str(snapshot_path),
                    "analysis_ref": f"upstream/{repo['default_branch']}",
                    "analysis_sha": analysis_sha,
                    "analysis_git_tree": analysis_git_tree,
                    "recon_path": str(recon_path.resolve()),
                    "recon_sha256": attempt_file_sha256(context, recon_path),
                    "recon_attempt_id": require_current_attempt_id(context),
                    "default_branch": repo["default_branch"],
                    "upstream_default_sha": sync_detail.get("upstream_default_sha"),
                    "secure_branch_sha": sync_detail.get("secure_branch_sha"),
                    "languages": sorted((recon.get("languages") or {}).keys()),
                    "workflow_count": len((recon.get("ci") or {}).get("workflows", [])),
                    "risk_count": len(recon.get("risk_signals", [])),
                }
            )

        index = {
            "schema_version": 1,
            "repository_count": len(index_entries),
            "repositories": index_entries,
        }
        index_path = write_attempt_json(context, Path("recon-index.json"), index)
        artifacts.append(ArtifactOutput(role="recon-index", path=index_path))
        payload = {
            "config": config,
            "recon_index": artifact_reference(index_path, context=context),
            "lifecycle_state": context.event.payload["lifecycle_state"],
        }
        return AgentResult(
            status="succeeded",
            summary=f"Structurally analyzed {len(index_entries)} managed checkouts.",
            events=[
                EventOutput(
                    event_type="CheckoutAnalyzed",
                    payload=payload,
                    dedupe_key=content_digest(payload),
                )
            ],
            artifacts=artifacts,
        )


class EcosystemProfilerHandler:
    agent_id = "ecosystem-profiler"

    def handle(self, context: AgentContext) -> AgentResult:
        require_producer(context, "recon")
        if context.event.event_type != "CheckoutAnalyzed":
            raise ValueError("Ecosystem profiling requires CheckoutAnalyzed")
        config = require_managed_config(context.event.payload)
        _recon_index_path, recon_index = read_verified_attempt_json(
            context,
            context.event.payload["recon_index"],
            expected_agent_id="recon",
            label="recon index",
        )
        attempt_output_root(context, expected_agent_id=self.agent_id)

        entries = []
        artifacts = []
        review_items = []
        for repo in recon_index.get("repositories", []):
            analysis_path = Path(repo["analysis_path"])
            with pinned_attempt_directory(
                context,
                analysis_path,
                expected_agent_id="recon",
                expected_attempt_id=repo.get("recon_attempt_id"),
                label="analysis snapshot",
            ) as analysis_descriptor:
                verify_analysis_snapshot(
                    directory_descriptor=analysis_descriptor,
                    expected_commit=repo["analysis_sha"],
                    expected_tree=repo["analysis_git_tree"],
                )
                with current_directory_from_descriptor(analysis_descriptor):
                    profile = plan_ecosystem_build_profile(
                        root=Path("."),
                        source_repository=repo["source_full_name"],
                        source_commit=repo["analysis_sha"],
                        source_git_tree=repo["analysis_git_tree"],
                        include_analysis_path=False,
                        descriptor_relative=True,
                        source_identity_verified=True,
                        generated_at=context.event.created_at,
                    )
                    final_inventory = inventory_trusted_source(
                        Path("."),
                        descriptor_relative=True,
                    )
                verify_analysis_snapshot(
                    directory_descriptor=analysis_descriptor,
                    expected_commit=repo["analysis_sha"],
                    expected_tree=repo["analysis_git_tree"],
                )
            if final_inventory["tree_sha256"] != (
                profile.get("source", {}).get("inventory", {}).get("tree_sha256")
            ):
                raise ValueError("Analysis snapshot changed during ecosystem profiling")
            profile_policy = profile.get("policy") or {}
            if profile.get("profiler", {}).get("implementation_sha256") != config[
                "ecosystem_profiler_sha256"
            ]:
                raise ValueError("Ecosystem profiler changed after run creation")
            profile_id = profile.get("profile_id")
            expected_policy_digest = config["ecosystem_policy_digests"].get(profile_id)
            if expected_policy_digest is not None and (
                profile_policy.get("policy_sha256") != expected_policy_digest
            ):
                raise ValueError("Ecosystem policy changed after run creation")
            profile_path = write_attempt_json(
                context,
                Path("repositories")
                / safe_repo_dir(repo["target_full_name"])
                / "ecosystem-build-profile.json",
                profile,
            )
            artifacts.append(
                ArtifactOutput(
                    role="repository-ecosystem-build-profile",
                    path=profile_path,
                )
            )
            blockers = profile["decision"]["blockers"]
            if blockers:
                review_items.append(
                    f"{repo['target_full_name']}: build execution remains blocked by "
                    + ", ".join(blockers)
                )
            entries.append(
                {
                    **repo,
                    "ecosystem_profile_path": str(profile_path.resolve()),
                    "ecosystem_profile_sha256": attempt_file_sha256(
                        context, profile_path
                    ),
                    "ecosystem_profile_attempt_id": require_current_attempt_id(
                        context
                    ),
                    "ecosystem_profile_id": profile["profile_id"],
                    "ecosystem_profile_status": profile["status"],
                    "ecosystem_execution_permitted": profile["execution_permitted"],
                    "ecosystem_canary_admission_candidate": profile[
                        "canary_admission_candidate"
                    ],
                    "ecosystem_profile_blockers": blockers,
                }
            )

        profile_index = {
            "schema_version": 1,
            "repository_count": len(entries),
            "repositories": entries,
            "execution_permitted_count": sum(
                1 for entry in entries if entry["ecosystem_execution_permitted"]
            ),
            "canary_admission_candidate_count": sum(
                1
                for entry in entries
                if entry["ecosystem_canary_admission_candidate"]
            ),
            "claim_limit": (
                "Profiles are structural decisions only; blocked profiles may continue "
                "through overlay analysis but may not enter a builder."
            ),
        }
        index_path = write_attempt_json(
            context,
            Path("ecosystem-profile-index.json"),
            profile_index,
        )
        artifacts.append(ArtifactOutput(role="ecosystem-profile-index", path=index_path))
        payload = {
            "config": config,
            "ecosystem_profile_index": artifact_reference(index_path, context=context),
        }
        return AgentResult(
            status="succeeded",
            summary=(
                f"Planned {len(entries)} non-executing ecosystem build profiles; "
                f"{profile_index['canary_admission_candidate_count']} may request "
                "Governor canary admission."
            ),
            events=[
                EventOutput(
                    event_type="BuildProfilesPlanned",
                    payload=payload,
                    dedupe_key=content_digest(payload),
                )
            ],
            artifacts=artifacts,
            human_review=review_items,
        )


class ManagedOverlayPlannerHandler:
    agent_id = "overlay-planner"

    def handle(self, context: AgentContext) -> AgentResult:
        require_producer(context, "ecosystem-profiler")
        if context.event.event_type != "BuildProfilesPlanned":
            raise ValueError("Managed overlay planning requires BuildProfilesPlanned")
        attempt_output_root(context, expected_agent_id=self.agent_id)
        config = require_managed_config(context.event.payload)
        _profile_index_path, recon_index = read_verified_attempt_json(
            context,
            context.event.payload["ecosystem_profile_index"],
            expected_agent_id="ecosystem-profiler",
            label="ecosystem profile index",
        )
        assurance_target = config["assurance_target"]

        entries = []
        artifacts = []
        review_items = []
        for repo in recon_index.get("repositories", []):
            _recon_path, recon = read_verified_attempt_json_values(
                context,
                path_value=repo.get("recon_path"),
                digest_value=repo.get("recon_sha256"),
                expected_agent_id="recon",
                expected_attempt_id=repo.get("recon_attempt_id"),
                label="repository recon",
            )
            _ecosystem_profile_path, ecosystem_profile = (
                read_verified_attempt_json_values(
                    context,
                    path_value=repo.get("ecosystem_profile_path"),
                    digest_value=repo.get("ecosystem_profile_sha256"),
                    expected_agent_id="ecosystem-profiler",
                    expected_attempt_id=repo.get("ecosystem_profile_attempt_id"),
                    label="ecosystem build profile",
                )
            )
            profile_source = ecosystem_profile.get("source") or {}
            if (
                profile_source.get("repository") != repo["source_full_name"]
                or profile_source.get("commit") != repo["analysis_sha"]
                or profile_source.get("git_tree") != repo["analysis_git_tree"]
                or profile_source.get("identity_binding")
                != "verified-managed-handoff"
            ):
                raise ValueError(
                    "Ecosystem build profile source binding does not match recon"
                )
            overlay = plan_overlay(recon, target=assurance_target)
            release_profile = plan_release_profile(recon)
            release_profile["lineage"] = {
                "source_full_name": repo["source_full_name"],
                "upstream_ref": repo["analysis_sha"],
            }
            overlay_path = write_attempt_json(
                context,
                Path("repositories")
                / safe_repo_dir(repo["target_full_name"])
                / "overlay-plan.json",
                overlay,
            )
            release_path = write_attempt_json(
                context,
                Path("repositories")
                / safe_repo_dir(repo["target_full_name"])
                / "release-profile.json",
                release_profile,
            )
            artifacts.extend(
                [
                    ArtifactOutput(role="repository-overlay-plan", path=overlay_path),
                    ArtifactOutput(role="repository-release-profile", path=release_path),
                ]
            )
            if overlay.get("summary", {}).get("human_review_required"):
                review_items.append(
                    f"{repo['target_full_name']}: overlay contains review-required changes"
                )
            review_items.append(
                f"{repo['target_full_name']}: release profile confirmation remains required"
            )
            entries.append(
                {
                    **repo,
                    "overlay_plan_path": str(overlay_path.resolve()),
                    "overlay_plan_sha256": attempt_file_sha256(
                        context, overlay_path
                    ),
                    "release_profile_path": str(release_path.resolve()),
                    "release_profile_sha256": attempt_file_sha256(
                        context, release_path
                    ),
                    "overlay_summary": overlay.get("summary", {}),
                    "release_language_family": release_profile.get("project", {}).get(
                        "language_family"
                    ),
                    "release_human_review_required": release_profile.get(
                        "human_review_required",
                        True,
                    ),
                    "ecosystem_profile_id": ecosystem_profile.get("profile_id"),
                    "ecosystem_profile_status": ecosystem_profile.get("status"),
                    "ecosystem_execution_permitted": ecosystem_profile.get(
                        "execution_permitted", False
                    ),
                    "ecosystem_canary_admission_candidate": ecosystem_profile.get(
                        "canary_admission_candidate", False
                    ),
                    "ecosystem_profile_blockers": ecosystem_profile.get(
                        "decision", {}
                    ).get("blockers", []),
                }
            )

        analysis_index = {
            "schema_version": 1,
            "assurance_target": assurance_target,
            "repository_count": len(entries),
            "repositories": entries,
            "next_gate": "human release-profile and repository-specific overlay review",
        }
        index_path = write_attempt_json(context, Path("analysis-index.json"), analysis_index)
        artifacts.append(ArtifactOutput(role="analysis-index", path=index_path))
        payload = {
            "config": config,
            "analysis_index": artifact_reference(index_path, context=context),
        }
        return AgentResult(
            status="succeeded",
            summary=(
                f"Prepared {len(entries)} {assurance_target} overlay plans and "
                "draft release profiles."
            ),
            events=[
                EventOutput(
                    event_type="AnalysisBundleReady",
                    payload=payload,
                    dedupe_key=content_digest(payload),
                )
            ],
            artifacts=artifacts,
            human_review=review_items,
        )


def managed_checkout_handlers(
    *,
    allow_local_test_remotes: bool = False,
) -> list[AgentHandler]:
    return [
        ManagedForkSyncHandler(allow_local_remotes=allow_local_test_remotes),
        ManagedReconHandler(),
        EcosystemProfilerHandler(),
        ManagedOverlayPlannerHandler(),
    ]


def run_managed_checkout_agent_system(
    *,
    fork_plan_path: Path,
    state_path: Path,
    workspace: Path,
    run_dir: Path,
    assurance_target: str = "Attested",
    execute_sync: bool = False,
    database_path: Path | None = None,
    run_id: str | None = None,
    worker_id: str | None = None,
    max_items: int = 100,
    enqueue_only: bool = False,
    allow_local_test_remotes: bool = False,
) -> dict[str, Any]:
    if assurance_target not in ASSURANCE_ORDER:
        raise ValueError(f"Unsupported assurance target: {assurance_target}")
    if max_items < 1:
        raise ValueError("max_items must be at least 1")

    run_dir = run_dir.expanduser().resolve()
    fork_plan_path = fork_plan_path.expanduser().resolve()
    state_path = state_path.expanduser().resolve()
    workspace = workspace.expanduser().resolve()
    if not fork_plan_path.is_file():
        raise FileNotFoundError(fork_plan_path)
    if not state_path.is_file():
        raise FileNotFoundError(state_path)
    effective_run_id = run_id or f"checkout-{uuid.uuid4().hex[:12]}"
    database_path = (
        database_path or run_dir / "agent-control-plane.sqlite3"
    ).expanduser().resolve()
    config = {
        "fork_plan_path": str(fork_plan_path),
        "fork_plan_path_sha256": sha256_file(fork_plan_path),
        "state_path": str(state_path),
        "state_path_sha256": sha256_file(state_path),
        "workspace": str(workspace),
        "assurance_target": assurance_target,
        "execute_sync": execute_sync,
        "ecosystem_policy_digests": ecosystem_policy_digests(),
        "ecosystem_profiler_sha256": ecosystem_profiler_sha256(),
    }
    store = AgentStore(database_path)
    runtime = AgentRuntime(
        backend=store,
        handlers=managed_checkout_handlers(
            allow_local_test_remotes=allow_local_test_remotes
        ),
        worker_id=worker_id or f"local-{os.getpid()}",
    )
    created = ensure_managed_run(
        store,
        runtime=runtime,
        run_id=effective_run_id,
        run_dir=run_dir,
        database_path=database_path,
        config=config,
    )
    if created:
        runtime.publish_external(
            run_id=effective_run_id,
            event_type="UpstreamChanged",
            payload={"config": config},
            dedupe_key="initial-managed-checkout-request",
        )
    if enqueue_only:
        persisted_status = store.get_run(effective_run_id)["status"]
        result = {
            "run_id": effective_run_id,
            "status": persisted_status,
            "processed": [],
            "processed_count": 0,
            "pending_count": store.pending_count(effective_run_id),
            "artifact_verification": store.verify_artifacts(effective_run_id),
            "summary": store.run_summary(effective_run_id),
        }
    else:
        result = runtime.drain(run_id=effective_run_id, max_items=max_items)
    result["database_path"] = str(database_path)
    result["run_dir"] = str(run_dir)
    summary_path = run_dir / "managed-checkout-summary.json"
    write_json_atomic(summary_path, result)
    result["summary_path"] = str(summary_path)
    return result


def managed_sync_checks(
    fork_plan: dict[str, Any],
    *,
    source_state: StateStore,
    execute_sync: bool,
) -> list[dict[str, Any]]:
    forks = fork_plan.get("forks", [])
    checks = [
        {
            "check": "fork-plan-schema",
            "passed": fork_plan.get("schema_version") == FORK_PLAN_SCHEMA_VERSION,
            "detail": str(fork_plan.get("schema_version")),
        },
        {
            "check": "forks-selected",
            "passed": isinstance(forks, list) and bool(forks),
            "detail": f"selected={len(forks) if isinstance(forks, list) else 0}",
        },
        {
            "check": "explicit-sync-execution",
            "passed": isinstance(execute_sync, bool),
            "detail": f"execute_sync={execute_sync}",
        },
    ]
    if execute_sync and isinstance(forks, list):
        repositories = source_state.data.get("repositories", {})
        unverified = []
        target_mismatches = []
        for entry in forks:
            source = entry.get("source_full_name")
            target = entry.get("target_full_name")
            lifecycle = repositories.get(source, {})
            if lifecycle.get("current_state") not in VERIFIED_FORK_STATES:
                unverified.append(source)
            if lifecycle.get("target_full_name") != target:
                target_mismatches.append(source)
        checks.extend(
            [
                {
                    "check": "fork-lineage-state",
                    "passed": not unverified,
                    "detail": "verified" if not unverified else ", ".join(unverified),
                },
                {
                    "check": "fork-target-state",
                    "passed": not target_mismatches,
                    "detail": (
                        "matched"
                        if not target_mismatches
                        else ", ".join(target_mismatches)
                    ),
                },
            ]
        )
    return checks


def require_managed_config(payload: dict[str, Any]) -> dict[str, Any]:
    config = payload.get("config")
    if not isinstance(config, dict):
        raise ValueError("Managed checkout event is missing config")
    for key in ("fork_plan_path", "state_path", "workspace"):
        value = config.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"Managed checkout config has invalid {key}")
    for key in ("fork_plan_path_sha256", "state_path_sha256"):
        value = config.get(key)
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError(f"Managed checkout config has invalid {key}")
    target = config.get("assurance_target")
    if target not in ASSURANCE_ORDER:
        raise ValueError(f"Managed checkout config has invalid assurance target: {target!r}")
    if not isinstance(config.get("execute_sync"), bool):
        raise ValueError("Managed checkout config has invalid execute_sync")
    policy_digests = config.get("ecosystem_policy_digests")
    if (
        not isinstance(policy_digests, dict)
        or set(policy_digests) != {"dotnet-v1", "java-maven-v1"}
        or any(
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in policy_digests.values()
        )
    ):
        raise ValueError("Managed checkout config has invalid ecosystem policy digests")
    profiler_digest = config.get("ecosystem_profiler_sha256")
    if (
        not isinstance(profiler_digest, str)
        or len(profiler_digest) != 64
        or any(character not in "0123456789abcdef" for character in profiler_digest)
    ):
        raise ValueError("Managed checkout config has invalid ecosystem profiler digest")
    return config


def require_producer(context: AgentContext, expected_agent_id: str) -> None:
    if context.event.producer_agent_id != expected_agent_id:
        raise ValueError(
            f"Event {context.event.event_type} must be produced by "
            f"{expected_agent_id}, not {context.event.producer_agent_id!r}"
        )


def attempt_output_root(
    context: AgentContext,
    *,
    expected_agent_id: str,
) -> Path:
    attempt_id = context.work.current_attempt_id
    if not isinstance(attempt_id, str) or re.fullmatch(r"[0-9a-f]{32}", attempt_id) is None:
        raise ValueError("Managed agent work has no valid current attempt id")
    if context.work.agent_id != expected_agent_id:
        raise ValueError(
            f"Work is assigned to {context.work.agent_id!r}, not {expected_agent_id!r}"
        )
    return context.run_dir / "attempts" / attempt_id / expected_agent_id


def ensure_managed_run(
    store: AgentStore,
    *,
    runtime: AgentRuntime,
    run_id: str,
    run_dir: Path,
    database_path: Path,
    config: dict[str, Any],
) -> bool:
    try:
        existing = store.get_run(run_id)
    except KeyError:
        runtime.create_run(
            run_id=run_id,
            run_dir=run_dir,
            metadata={
                "workflow": MANAGED_CHECKOUT_WORKFLOW,
                "database_path": str(database_path),
                "config": config,
                "artifact_scope": "attempt-scoped-v1",
            },
        )
        return True

    metadata = existing.get("metadata") or {}
    if metadata.get("workflow") != MANAGED_CHECKOUT_WORKFLOW:
        raise ValueError(f"Run {run_id!r} belongs to a different workflow")
    if metadata.get("config") != config:
        raise ValueError(f"Run {run_id!r} cannot resume with different configuration")
    if metadata.get("artifact_scope") != "attempt-scoped-v1":
        raise ValueError(f"Run {run_id!r} has an incompatible artifact scope")
    if Path(str(metadata.get("run_dir"))).resolve() != run_dir:
        raise ValueError(f"Run {run_id!r} cannot resume in a different run directory")
    if require_directory_identity(metadata.get("run_root_identity")) != (
        secure_directory_identity(run_dir)
    ):
        raise ValueError(f"Run {run_id!r} run directory identity changed")
    return False


def artifact_reference(
    path: Path,
    *,
    context: AgentContext | None = None,
) -> dict[str, str]:
    if context is not None:
        attempt_id = require_current_attempt_id(context)
        validate_attempt_path(
            context,
            path,
            expected_agent_id=context.work.agent_id,
            expected_attempt_id=attempt_id,
            label="produced artifact",
        )
        return {
            "path": str(Path(os.path.abspath(path))),
            "sha256": attempt_file_sha256(context, path),
            "producer_agent_id": context.work.agent_id,
            "producer_attempt_id": attempt_id,
        }
    resolved = path.resolve()
    return {
        "path": str(resolved),
        "sha256": sha256_file(resolved),
    }


def read_verified_attempt_json(
    context: AgentContext,
    value: Any,
    *,
    expected_agent_id: str,
    label: str,
) -> tuple[Path, dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != {
        "path",
        "producer_agent_id",
        "producer_attempt_id",
        "sha256",
    }:
        raise ValueError(f"{label} reference fields are invalid")
    if value.get("producer_agent_id") != expected_agent_id:
        raise ValueError(f"{label} producer identity is invalid")
    if context.event.producer_agent_id != expected_agent_id:
        raise ValueError(f"{label} producing event identity is invalid")
    event_attempt_id = context.event.producer_attempt_id
    if (
        not isinstance(event_attempt_id, str)
        or re.fullmatch(r"[0-9a-f]{32}", event_attempt_id) is None
        or value.get("producer_attempt_id") != event_attempt_id
    ):
        raise ValueError(f"{label} attempt does not match its producing event")
    return read_verified_attempt_json_values(
        context,
        path_value=value.get("path"),
        digest_value=value.get("sha256"),
        expected_agent_id=expected_agent_id,
        expected_attempt_id=value.get("producer_attempt_id"),
        label=label,
    )


def read_verified_attempt_json_values(
    context: AgentContext,
    *,
    path_value: Any,
    digest_value: Any,
    expected_agent_id: str,
    expected_attempt_id: Any,
    label: str,
) -> tuple[Path, dict[str, Any]]:
    expected_digest = require_sha256(digest_value, label=f"{label} digest")
    path = validate_attempt_path(
        context,
        path_value,
        expected_agent_id=expected_agent_id,
        expected_attempt_id=expected_attempt_id,
        label=label,
    )
    payload_bytes = read_attempt_file_bytes(
        context,
        path,
        expected_agent_id=expected_agent_id,
        expected_attempt_id=expected_attempt_id,
        label=label,
    )
    actual_digest = hashlib.sha256(payload_bytes).hexdigest()
    if not hmac.compare_digest(actual_digest, expected_digest):
        raise ValueError(f"{label} digest verification failed: {path}")
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    return path, payload


def require_current_attempt_id(context: AgentContext) -> str:
    attempt_id = context.work.current_attempt_id
    if not isinstance(attempt_id, str) or re.fullmatch(r"[0-9a-f]{32}", attempt_id) is None:
        raise ValueError("Managed agent work has no valid current attempt id")
    return attempt_id


def managed_run_root_identity(context: AgentContext) -> tuple[int, int]:
    metadata_run_dir = context.run_metadata.get("run_dir")
    if not isinstance(metadata_run_dir, str) or Path(
        os.path.abspath(metadata_run_dir)
    ) != Path(os.path.abspath(context.run_dir)):
        raise ValueError("Managed run context has a mismatched run directory")
    return require_directory_identity(
        context.run_metadata.get("run_root_identity")
    )


@contextmanager
def pinned_attempt_directory(
    context: AgentContext,
    path_value: Any,
    *,
    expected_agent_id: str,
    expected_attempt_id: Any,
    label: str,
) -> Iterator[int]:
    path = validate_attempt_path(
        context,
        path_value,
        expected_agent_id=expected_agent_id,
        expected_attempt_id=expected_attempt_id,
        label=label,
    )
    run_root = Path(os.path.abspath(context.run_dir))
    relative = path.relative_to(run_root)
    root_descriptor = open_absolute_directory_without_symlinks(
        run_root,
        expected_identity=managed_run_root_identity(context),
    )
    directory_descriptor: int | None = None
    try:
        try:
            directory_descriptor = open_directory_beneath(root_descriptor, relative)
        except OSError as exc:
            raise ValueError(f"{label} traverses an unsafe directory path") from exc
        pinned_identity = directory_identity(os.fstat(directory_descriptor))
        try:
            yield directory_descriptor
        finally:
            try:
                reopened = open_directory_beneath(root_descriptor, relative)
            except OSError as exc:
                raise ValueError(f"{label} directory path changed") from exc
            try:
                if directory_identity(os.fstat(reopened)) != pinned_identity:
                    raise ValueError(f"{label} directory identity changed")
            finally:
                os.close(reopened)
    finally:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        os.close(root_descriptor)


@contextmanager
def current_directory_from_descriptor(
    directory_descriptor: int,
) -> Iterator[None]:
    if not hasattr(os, "fchdir"):
        raise OSError("Descriptor-rooted analysis requires fchdir")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    with PROCESS_DIRECTORY_LOCK:
        previous_directory = os.open(".", flags)
        try:
            os.fchdir(directory_descriptor)
            yield
        finally:
            os.fchdir(previous_directory)
            os.close(previous_directory)


def run_git_in_directory(directory_descriptor: int, command: list[str]) -> str:
    with current_directory_from_descriptor(directory_descriptor):
        return run_git_required(CommandRunner(execute=True), command)


def validate_attempt_path(
    context: AgentContext,
    path_value: Any,
    *,
    expected_agent_id: str,
    expected_attempt_id: Any,
    label: str,
) -> Path:
    if (
        not isinstance(expected_attempt_id, str)
        or re.fullmatch(r"[0-9a-f]{32}", expected_attempt_id) is None
    ):
        raise ValueError(f"{label} producer attempt identity is invalid")
    if not isinstance(path_value, (str, os.PathLike)):
        raise ValueError(f"{label} path is invalid")
    path = Path(path_value)
    if not path.is_absolute():
        raise ValueError(f"{label} path must be absolute")
    lexical_path = Path(os.path.abspath(path))
    run_root = Path(os.path.abspath(context.run_dir))
    try:
        relative = lexical_path.relative_to(run_root)
    except ValueError as exc:
        raise ValueError(f"{label} path escapes the managed run directory") from exc
    expected_prefix = ("attempts", expected_attempt_id, expected_agent_id)
    if (
        len(relative.parts) <= len(expected_prefix)
        or relative.parts[: len(expected_prefix)] != expected_prefix
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError(f"{label} path is not bound to its producer attempt")
    return lexical_path


def read_attempt_file_bytes(
    context: AgentContext,
    path: Path,
    *,
    expected_agent_id: str,
    expected_attempt_id: Any,
    label: str,
) -> bytes:
    validated = validate_attempt_path(
        context,
        path,
        expected_agent_id=expected_agent_id,
        expected_attempt_id=expected_attempt_id,
        label=label,
    )
    run_root = Path(os.path.abspath(context.run_dir))
    relative = validated.relative_to(run_root)
    return read_regular_file_beneath(
        run_root,
        relative,
        label=label,
        root_identity=managed_run_root_identity(context),
    )


def attempt_file_sha256(context: AgentContext, path: Path) -> str:
    attempt_id = require_current_attempt_id(context)
    payload = read_attempt_file_bytes(
        context,
        path,
        expected_agent_id=context.work.agent_id,
        expected_attempt_id=attempt_id,
        label="produced artifact",
    )
    return hashlib.sha256(payload).hexdigest()


def read_regular_file_beneath(
    root: Path,
    relative: Path,
    *,
    label: str,
    root_identity: tuple[int, int] | None = None,
) -> bytes:
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError(f"{label} path is invalid")
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    root_descriptor: int | None = None
    parent_descriptor: int | None = None
    descriptor: int | None = None
    try:
        root_descriptor = open_absolute_directory_without_symlinks(
            root,
            expected_identity=root_identity,
        )
        parent_descriptor = open_directory_beneath(
            root_descriptor,
            Path(*relative.parts[:-1]),
        )
        descriptor = os.open(
            relative.parts[-1],
            file_flags,
            dir_fd=parent_descriptor,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > MAX_HANDOFF_JSON_BYTES
        ):
            raise ValueError(f"{label} is not a bounded standalone file")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(
            descriptor,
            min(1024 * 1024, MAX_HANDOFF_JSON_BYTES - total + 1),
        ):
            total += len(chunk)
            if total > MAX_HANDOFF_JSON_BYTES:
                raise ValueError(f"{label} exceeds its size limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if file_identity(before) != file_identity(after) or total != before.st_size:
            raise ValueError(f"{label} changed while it was read")
        return b"".join(chunks)
    except OSError as exc:
        raise ValueError(f"{label} traverses a symlink or unreadable path") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        if root_descriptor is not None:
            os.close(root_descriptor)


def ensure_attempt_directory(context: AgentContext, relative: Path) -> Path:
    attempt_root = attempt_output_root(
        context,
        expected_agent_id=context.work.agent_id,
    )
    validate_safe_relative_path(relative, label="attempt output directory")
    run_root = Path(os.path.abspath(context.run_dir))
    target_relative = (attempt_root / relative).relative_to(run_root)
    ensure_directory_beneath(
        run_root,
        target_relative,
        root_identity=managed_run_root_identity(context),
    )
    return run_root / target_relative


def write_attempt_json(
    context: AgentContext,
    relative: Path,
    payload: dict[str, Any],
) -> Path:
    validate_safe_relative_path(relative, label="attempt output")
    attempt_root = attempt_output_root(
        context,
        expected_agent_id=context.work.agent_id,
    )
    run_root = Path(os.path.abspath(context.run_dir))
    target_relative = (attempt_root / relative).relative_to(run_root)
    encoded = (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    write_bytes_beneath(
        run_root,
        target_relative,
        encoded,
        root_identity=managed_run_root_identity(context),
    )
    return run_root / target_relative


def validate_safe_relative_path(path: Path, *, label: str) -> None:
    if path.is_absolute() or not path.parts or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise ValueError(f"{label} path is invalid")


def ensure_directory_beneath(
    root: Path,
    relative: Path,
    *,
    root_identity: tuple[int, int] | None = None,
) -> None:
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptors: list[int] = []
    try:
        current = open_absolute_directory_without_symlinks(
            root,
            expected_identity=root_identity,
        )
        descriptors.append(current)
        for part in relative.parts:
            try:
                os.mkdir(part, mode=0o700, dir_fd=current)
            except FileExistsError:
                pass
            current = os.open(part, directory_flags, dir_fd=current)
            descriptors.append(current)
    except OSError as exc:
        raise ValueError("Attempt output directory traverses an unsafe path") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def write_bytes_beneath(
    root: Path,
    relative: Path,
    payload: bytes,
    *,
    root_identity: tuple[int, int] | None = None,
) -> None:
    validate_safe_relative_path(relative, label="attempt output")
    ensure_directory_beneath(
        root,
        Path(*relative.parts[:-1]),
        root_identity=root_identity,
    )
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptors: list[int] = []
    temporary_name = f".{relative.name}.{uuid.uuid4().hex}.tmp"
    file_descriptor: int | None = None
    try:
        current = open_absolute_directory_without_symlinks(
            root,
            expected_identity=root_identity,
        )
        descriptors.append(current)
        for part in relative.parts[:-1]:
            current = os.open(part, directory_flags, dir_fd=current)
            descriptors.append(current)
        file_descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=current,
        )
        view = memoryview(payload)
        while view:
            written = os.write(file_descriptor, view)
            if written <= 0:
                raise OSError("Attempt output write made no progress")
            view = view[written:]
        os.fsync(file_descriptor)
        os.close(file_descriptor)
        file_descriptor = None
        os.replace(
            temporary_name,
            relative.name,
            src_dir_fd=current,
            dst_dir_fd=current,
        )
        os.fsync(current)
    except OSError as exc:
        raise ValueError("Attempt output could not be written safely") from exc
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if descriptors:
            try:
                os.unlink(temporary_name, dir_fd=descriptors[-1])
            except FileNotFoundError:
                pass
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def require_sha256(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} is invalid")
    return value


def read_verified_config_json(
    config: dict[str, Any],
    key: str,
) -> tuple[Path, dict[str, Any]]:
    path_value = config.get(key)
    if not isinstance(path_value, str) or not path_value:
        raise ValueError(f"{key} path is invalid")
    path = Path(path_value)
    if not path.is_absolute():
        raise ValueError(f"{key} path must be absolute")
    expected_digest = require_sha256(
        config.get(f"{key}_sha256"),
        label=f"{key} digest",
    )
    payload_bytes = read_regular_file_beneath(
        path.parent,
        Path(path.name),
        label=key,
    )
    actual_digest = hashlib.sha256(payload_bytes).hexdigest()
    if not hmac.compare_digest(actual_digest, expected_digest):
        raise ValueError(f"{key} digest verification failed: {path}")
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{key} is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{key} must be a JSON object")
    return path, payload


def require_commit_sha(value: Any, *, label: str) -> str:
    return require_git_object_id(value, label=label)


def require_git_object_id(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} is not a full Git object ID")
    return value


def prepare_analysis_worktree(
    *,
    checkout_path: Path,
    snapshot_root_descriptor: int,
    snapshot_name: str,
    commit_sha: str,
) -> None:
    checkout_path = checkout_path.resolve()
    if (
        not snapshot_name
        or Path(snapshot_name).name != snapshot_name
        or snapshot_name in {".", ".."}
    ):
        raise ValueError("Analysis snapshot name is invalid")
    runner = CommandRunner(execute=True)

    checkout_root = run_git_required(
        runner,
        ["git", "-C", str(checkout_path), "rev-parse", "--show-toplevel"],
    )
    if Path(checkout_root).resolve() != checkout_path:
        raise ValueError(f"Managed checkout is not a Git worktree root: {checkout_path}")

    run_git_required(
        runner,
        ["git", "-C", str(checkout_path), "cat-file", "-e", f"{commit_sha}^{{commit}}"],
    )
    git_directory = run_git_required(
        runner,
        ["git", "-C", str(checkout_path), "rev-parse", "--absolute-git-dir"],
    )
    snapshot_descriptor: int | None = None
    try:
        try:
            snapshot_descriptor = open_directory_beneath(
                snapshot_root_descriptor,
                Path(snapshot_name),
            )
        except FileNotFoundError:
            with current_directory_from_descriptor(snapshot_root_descriptor):
                run_git_required(
                    runner,
                    [
                        "git",
                        f"--git-dir={git_directory}",
                        "worktree",
                        "add",
                        "--detach",
                        "--force",
                        snapshot_name,
                        commit_sha,
                    ],
                )
            snapshot_descriptor = open_directory_beneath(
                snapshot_root_descriptor,
                Path(snapshot_name),
            )
        actual_sha = run_git_in_directory(
            snapshot_descriptor,
            ["git", "rev-parse", "HEAD"],
        )
        if actual_sha != commit_sha:
            raise ValueError(
                f"Analysis snapshot points to {actual_sha}, expected {commit_sha}"
            )
    finally:
        if snapshot_descriptor is not None:
            os.close(snapshot_descriptor)


def verify_analysis_snapshot(
    *,
    directory_descriptor: int,
    expected_commit: str,
    expected_tree: str | None,
) -> None:
    actual_commit = run_git_in_directory(
        directory_descriptor,
        ["git", "rev-parse", "HEAD"],
    )
    if actual_commit != expected_commit:
        raise ValueError(
            f"Analysis snapshot points to {actual_commit}, expected {expected_commit}"
        )
    if expected_tree is not None:
        actual_tree = run_git_in_directory(
            directory_descriptor,
            ["git", "rev-parse", "HEAD^{tree}"],
        )
        if actual_tree != expected_tree:
            raise ValueError(
                f"Analysis snapshot tree is {actual_tree}, expected {expected_tree}"
            )
    status = run_git_in_directory(
        directory_descriptor,
        [
            "git",
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
        ],
    )
    if status:
        raise ValueError("Analysis snapshot changed after recon")


def run_git_required(runner: CommandRunner, command: list[str]) -> str:
    result = runner.run(command)
    if not result.ok:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown Git error"
        raise ValueError(f"Git command failed: {display_command(command)}: {detail}")
    return result.stdout.strip()


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
