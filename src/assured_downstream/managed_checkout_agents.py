from __future__ import annotations

import copy
import hmac
import json
import os
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from assured_downstream.agent_contracts import (
    AgentContext,
    AgentResult,
    ArtifactOutput,
    EventOutput,
    content_digest,
)
from assured_downstream.agent_runtime import AgentHandler, AgentRuntime
from assured_downstream.agent_store import AgentStore
from assured_downstream.command_runner import CommandRunner, display_command
from assured_downstream.fork_plan import FORK_PLAN_SCHEMA_VERSION
from assured_downstream.evidence import sha256_file
from assured_downstream.lifecycle import StateStore
from assured_downstream.overlay import ASSURANCE_ORDER, plan_overlay
from assured_downstream.recon import inspect_repository
from assured_downstream.release_profile import plan_release_profile
from assured_downstream.sync_apply import apply_sync_plan
from assured_downstream.sync_plan import create_sync_plan, safe_repo_dir


MANAGED_CHECKOUT_WORKFLOW = "managed-checkout-reconciliation"
VERIFIED_FORK_STATES = {"ForkVerified", "Forked"}


class ManagedForkSyncHandler:
    agent_id = "fork-sync"

    def __init__(self, *, allow_local_remotes: bool = False) -> None:
        self.allow_local_remotes = allow_local_remotes

    def handle(self, context: AgentContext) -> AgentResult:
        if context.event.event_type != "UpstreamChanged":
            raise ValueError("Managed fork reconciliation requires UpstreamChanged")
        config = require_managed_config(context.event.payload)
        fork_plan_path = verified_config_path(config, "fork_plan_path")
        state_path = verified_config_path(config, "state_path")
        fork_plan = read_json(fork_plan_path)
        source_state = StateStore.load(state_path)
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
        gate_path = context.run_dir / "sync-gate-decision.json"
        write_json_atomic(gate_path, gate)
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
        sync_plan_path = context.run_dir / "sync-plan.json"
        write_json_atomic(sync_plan_path, sync_plan)
        lifecycle_state = StateStore(copy.deepcopy(source_state.data))
        result = apply_sync_plan(
            sync_plan,
            state=lifecycle_state,
            execute=execute_sync,
            allow_local_remotes=self.allow_local_remotes,
        )
        lifecycle_path = context.run_dir / "lifecycle-state.json"
        lifecycle_state.save(lifecycle_path)
        result_path = context.run_dir / "sync-result.json"
        write_json_atomic(
            result_path,
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
            "sync_plan": artifact_reference(sync_plan_path),
            "lifecycle_state": artifact_reference(lifecycle_path),
            "sync_result": artifact_reference(result_path),
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
        config = require_managed_config(context.event.payload)
        sync_plan = read_json(verified_artifact_path(context.event.payload["sync_plan"]))
        lifecycle_state = StateStore.load(
            verified_artifact_path(context.event.payload["lifecycle_state"])
        )

        index_entries = []
        artifacts = []
        for repo in sync_plan.get("repositories", []):
            local_path = Path(repo["local_path"])
            if not local_path.is_dir():
                raise ValueError(f"Managed checkout is missing: {local_path}")
            repository_dir = context.run_dir / "repositories" / safe_repo_dir(
                repo["target_full_name"]
            )
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
            snapshot_path = context.run_dir / "snapshots" / safe_repo_dir(
                repo["target_full_name"]
            )
            prepare_analysis_worktree(
                checkout_path=local_path,
                snapshot_path=snapshot_path,
                commit_sha=analysis_sha,
            )
            recon = inspect_repository(snapshot_path)
            recon_path = repository_dir / "recon.json"
            write_json_atomic(recon_path, recon)
            artifacts.append(ArtifactOutput(role="repository-recon", path=recon_path))

            index_entries.append(
                {
                    "source_full_name": repo["source_full_name"],
                    "target_full_name": repo["target_full_name"],
                    "local_path": str(local_path.resolve()),
                    "analysis_path": str(snapshot_path.resolve()),
                    "analysis_ref": f"upstream/{repo['default_branch']}",
                    "analysis_sha": analysis_sha,
                    "recon_path": str(recon_path.resolve()),
                    "recon_sha256": sha256_file(recon_path),
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
        index_path = context.run_dir / "recon-index.json"
        write_json_atomic(index_path, index)
        artifacts.append(ArtifactOutput(role="recon-index", path=index_path))
        payload = {
            "config": config,
            "recon_index": artifact_reference(index_path),
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


class ManagedOverlayPlannerHandler:
    agent_id = "overlay-planner"

    def handle(self, context: AgentContext) -> AgentResult:
        require_producer(context, "recon")
        if context.event.event_type != "CheckoutAnalyzed":
            raise ValueError("Managed overlay planning requires CheckoutAnalyzed")
        config = require_managed_config(context.event.payload)
        recon_index = read_json(
            verified_artifact_path(context.event.payload["recon_index"])
        )
        assurance_target = config["assurance_target"]

        entries = []
        artifacts = []
        review_items = []
        for repo in recon_index.get("repositories", []):
            recon_path = verified_path_and_digest(
                path_value=repo.get("recon_path"),
                digest_value=repo.get("recon_sha256"),
                label="repository recon",
            )
            recon = read_json(recon_path)
            overlay = plan_overlay(recon, target=assurance_target)
            release_profile = plan_release_profile(recon)
            release_profile["lineage"] = {
                "source_full_name": repo["source_full_name"],
                "upstream_ref": repo["analysis_sha"],
            }
            repository_dir = context.run_dir / "repositories" / safe_repo_dir(
                repo["target_full_name"]
            )
            overlay_path = repository_dir / "overlay-plan.json"
            release_path = repository_dir / "release-profile.json"
            write_json_atomic(overlay_path, overlay)
            write_json_atomic(release_path, release_profile)
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
                    "overlay_plan_sha256": sha256_file(overlay_path),
                    "release_profile_path": str(release_path.resolve()),
                    "release_profile_sha256": sha256_file(release_path),
                    "overlay_summary": overlay.get("summary", {}),
                    "release_language_family": release_profile.get("project", {}).get(
                        "language_family"
                    ),
                    "release_human_review_required": release_profile.get(
                        "human_review_required",
                        True,
                    ),
                }
            )

        analysis_index = {
            "schema_version": 1,
            "assurance_target": assurance_target,
            "repository_count": len(entries),
            "repositories": entries,
            "next_gate": "human release-profile and repository-specific overlay review",
        }
        index_path = context.run_dir / "analysis-index.json"
        write_json_atomic(index_path, analysis_index)
        artifacts.append(ArtifactOutput(role="analysis-index", path=index_path))
        payload = {
            "config": config,
            "analysis_index": artifact_reference(index_path),
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
    return config


def require_producer(context: AgentContext, expected_agent_id: str) -> None:
    if context.event.producer_agent_id != expected_agent_id:
        raise ValueError(
            f"Event {context.event.event_type} must be produced by "
            f"{expected_agent_id}, not {context.event.producer_agent_id!r}"
        )


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Expected a JSON object: {path}")
    return payload


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
            },
        )
        return True

    metadata = existing.get("metadata") or {}
    if metadata.get("workflow") != MANAGED_CHECKOUT_WORKFLOW:
        raise ValueError(f"Run {run_id!r} belongs to a different workflow")
    if metadata.get("config") != config:
        raise ValueError(f"Run {run_id!r} cannot resume with different configuration")
    if Path(str(metadata.get("run_dir"))).resolve() != run_dir:
        raise ValueError(f"Run {run_id!r} cannot resume in a different run directory")
    return False


def artifact_reference(path: Path) -> dict[str, str]:
    resolved = path.resolve()
    return {
        "path": str(resolved),
        "sha256": sha256_file(resolved),
    }


def verified_artifact_path(value: Any) -> Path:
    if not isinstance(value, dict):
        raise ValueError("Agent handoff artifact reference must be an object")
    return verified_path_and_digest(
        path_value=value.get("path"),
        digest_value=value.get("sha256"),
        label="agent handoff artifact",
    )


def verified_config_path(config: dict[str, Any], key: str) -> Path:
    return verified_path_and_digest(
        path_value=config.get(key),
        digest_value=config.get(f"{key}_sha256"),
        label=key,
    )


def verified_path_and_digest(
    *,
    path_value: Any,
    digest_value: Any,
    label: str,
) -> Path:
    if not isinstance(path_value, str) or not path_value:
        raise ValueError(f"{label} path is invalid")
    if not isinstance(digest_value, str) or len(digest_value) != 64:
        raise ValueError(f"{label} digest is invalid")
    path = Path(path_value).resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    actual = sha256_file(path)
    if not hmac.compare_digest(actual, digest_value):
        raise ValueError(f"{label} digest verification failed: {path}")
    return path


def require_commit_sha(value: Any, *, label: str) -> str:
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
    snapshot_path: Path,
    commit_sha: str,
) -> Path:
    checkout_path = checkout_path.resolve()
    snapshot_path = snapshot_path.resolve()
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
    if snapshot_path.exists():
        if not snapshot_path.is_dir():
            raise ValueError(f"Analysis snapshot is not a directory: {snapshot_path}")
        snapshot_root = run_git_required(
            runner,
            ["git", "-C", str(snapshot_path), "rev-parse", "--show-toplevel"],
        )
        if Path(snapshot_root).resolve() != snapshot_path:
            raise ValueError(
                f"Analysis snapshot is not its Git worktree root: {snapshot_path}"
            )
    else:
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        run_git_required(
            runner,
            [
                "git",
                "-C",
                str(checkout_path),
                "worktree",
                "add",
                "--detach",
                "--force",
                str(snapshot_path),
                commit_sha,
            ],
        )

    actual_sha = run_git_required(
        runner,
        ["git", "-C", str(snapshot_path), "rev-parse", "HEAD"],
    )
    if actual_sha != commit_sha:
        raise ValueError(
            f"Analysis snapshot points to {actual_sha}, expected {commit_sha}: "
            f"{snapshot_path}"
        )
    return snapshot_path


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
