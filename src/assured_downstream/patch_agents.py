from __future__ import annotations

import os
import uuid
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
from assured_downstream.evidence import sha256_file
from assured_downstream.managed_checkout_agents import (
    artifact_reference,
    read_json,
    verified_config_path,
    write_json_atomic,
)
from assured_downstream.patch_approval import (
    PatchApprovalError,
    validate_patch_approval,
)
from assured_downstream.secure_patch import (
    SecurePatchError,
    apply_secure_patch,
    build_rendered_patch,
    rendered_patch_manifest,
)
from assured_downstream.secure_publish import SecurePublishError, publish_secure_branch


PATCH_PUBLICATION_WORKFLOW = "governed-patch-publication"


class PatchHandler:
    agent_id = "patch"

    def __init__(self, *, allow_local_remotes: bool = False) -> None:
        self.allow_local_remotes = allow_local_remotes

    def handle(self, context: AgentContext) -> AgentResult:
        if context.event.event_type != "PatchApprovalRecorded":
            raise ValueError("Patch Agent requires PatchApprovalRecorded")
        if context.event.producer_agent_id is not None:
            raise ValueError("PatchApprovalRecorded must be an external event")
        config = require_patch_config(context.event.payload)
        analysis_path = verified_config_path(config, "analysis_index_path")
        pin_lock_path = verified_config_path(config, "pin_lock_path")
        tooling_policy_path = verified_config_path(config, "tooling_policy_path")
        approval_path = verified_config_path(config, "approval_path")
        analysis = read_json(analysis_path)
        pin_lock = read_json(pin_lock_path)
        tooling_policy = read_json(tooling_policy_path)
        approval = read_json(approval_path)
        gate_path = context.run_dir / "patch-gate-decision.json"

        try:
            repository, overlay = validate_patch_approval(
                approval,
                analysis_index=analysis,
                analysis_index_sha256=config["analysis_index_path_sha256"],
                pin_lock=pin_lock,
                pin_lock_sha256=config["pin_lock_path_sha256"],
                tooling_policy=tooling_policy,
                tooling_policy_sha256=config["tooling_policy_path_sha256"],
            )
            checkout_path = guarded_checkout_path(
                repository.get("local_path"),
                workspace=Path(config["workspace"]),
            )
            approved_ids = approval["repository"]["approved_change_ids"]
            rendered_patch = build_rendered_patch(
                overlay,
                pins=pin_lock,
                approved_change_ids=approved_ids,
            )
            gate = {
                "schema_version": 1,
                "gate": "analysis-to-secure-patch",
                "passed": True,
                "target_full_name": repository["target_full_name"],
                "approval_type": approval["approval_type"],
                "approved_by": approval["approved_by"],
                "approved_change_ids": sorted(approved_ids),
                "execute_patch": config["execute_patch"],
            }
        except (PatchApprovalError, SecurePatchError, ValueError) as exc:
            gate = {
                "schema_version": 1,
                "gate": "analysis-to-secure-patch",
                "passed": False,
                "reason": str(exc),
            }
            write_json_atomic(gate_path, gate)
            return AgentResult(
                status="blocked",
                summary="Patch approval gate blocked before Git object mutation.",
                artifacts=[ArtifactOutput(role="patch-gate-decision", path=gate_path)],
                human_review=[str(exc)],
            )

        write_json_atomic(gate_path, gate)
        patch_plan_path = context.run_dir / "rendered-patch-plan.json"
        write_json_atomic(patch_plan_path, rendered_patch_manifest(rendered_patch))
        try:
            patch_result = apply_secure_patch(
                checkout_path=checkout_path,
                target_full_name=repository["target_full_name"],
                secure_branch=f"secure/{repository['default_branch']}",
                expected_secure_sha=repository["secure_branch_sha"],
                required_upstream_sha=repository["analysis_sha"],
                rendered_patch=rendered_patch,
                approval_sha256=config["approval_path_sha256"],
                approved_at=approval["approved_at"],
                run_dir=context.run_dir,
                execute=config["execute_patch"],
                allow_local_remotes=self.allow_local_remotes,
            )
        except SecurePatchError as exc:
            result_path = context.run_dir / "patch-result.json"
            write_json_atomic(
                result_path,
                {
                    "schema_version": 1,
                    "status": "blocked",
                    "reason": str(exc),
                    "remote_pushes_executed": False,
                },
            )
            return AgentResult(
                status="blocked",
                summary="Secure branch patch application was blocked.",
                artifacts=[
                    ArtifactOutput(role="patch-gate-decision", path=gate_path),
                    ArtifactOutput(role="rendered-patch-plan", path=patch_plan_path),
                    ArtifactOutput(role="patch-result", path=result_path),
                ],
                human_review=[str(exc)],
            )

        patch_result_path = context.run_dir / "patch-result.json"
        write_json_atomic(
            patch_result_path,
            {
                **patch_result,
                "source_full_name": repository["source_full_name"],
                "target_full_name": repository["target_full_name"],
                "checkout_path": str(checkout_path),
                "approval_sha256": config["approval_path_sha256"],
            },
        )
        artifacts = [
            ArtifactOutput(role="patch-gate-decision", path=gate_path),
            ArtifactOutput(role="rendered-patch-plan", path=patch_plan_path),
            ArtifactOutput(role="patch-result", path=patch_result_path),
        ]
        payload = {
            "config": config,
            "patch_result": artifact_reference(patch_result_path),
            "rendered_patch_plan": artifact_reference(patch_plan_path),
        }
        return AgentResult(
            status="succeeded",
            summary=(
                f"{patch_result['action']} secure overlay for "
                f"{repository['target_full_name']}."
            ),
            events=[
                EventOutput(
                    event_type="PatchReady",
                    payload=payload,
                    source_repository=repository["source_full_name"],
                    dedupe_key=content_digest(payload),
                )
            ],
            artifacts=artifacts,
        )


class SecureBranchPublisherHandler:
    agent_id = "secure-branch-publisher"

    def __init__(
        self,
        *,
        allow_local_remotes: bool = False,
    ) -> None:
        self.allow_local_remotes = allow_local_remotes

    def handle(self, context: AgentContext) -> AgentResult:
        if context.event.event_type != "PatchReady":
            raise ValueError("Secure Branch Publisher requires PatchReady")
        if context.event.producer_agent_id != "patch":
            raise ValueError("PatchReady must be produced by the Patch Agent")
        config = require_patch_config(context.event.payload)
        patch_result = read_json(
            verified_handoff_path(context.event.payload.get("patch_result"))
        )
        analysis_path = verified_config_path(config, "analysis_index_path")
        pin_lock_path = verified_config_path(config, "pin_lock_path")
        tooling_policy_path = verified_config_path(config, "tooling_policy_path")
        approval_path = verified_config_path(config, "approval_path")
        approval = read_json(approval_path)
        result_path = context.run_dir / "secure-branch-publication.json"
        try:
            _repository, _overlay = validate_patch_approval(
                approval,
                analysis_index=read_json(analysis_path),
                analysis_index_sha256=config["analysis_index_path_sha256"],
                pin_lock=read_json(pin_lock_path),
                pin_lock_sha256=config["pin_lock_path_sha256"],
                tooling_policy=read_json(tooling_policy_path),
                tooling_policy_sha256=config["tooling_policy_path_sha256"],
            )
        except (PatchApprovalError, SecurePatchError, ValueError) as exc:
            write_json_atomic(
                result_path,
                {
                    "schema_version": 1,
                    "status": "blocked",
                    "reason": str(exc),
                    "executed": False,
                },
            )
            return AgentResult(
                status="blocked",
                summary="Publication approval revalidation failed.",
                artifacts=[
                    ArtifactOutput(role="secure-branch-publication", path=result_path)
                ],
                human_review=[str(exc)],
            )
        approval_repo = approval["repository"]
        expected_branch = f"secure/{approval_repo['default_branch']}"
        if (
            patch_result.get("target_full_name") != approval_repo["target_full_name"]
            or patch_result.get("source_full_name") != approval_repo["source_full_name"]
            or patch_result.get("secure_branch") != expected_branch
            or patch_result.get("approval_sha256") != config["approval_path_sha256"]
        ):
            raise ValueError("Patch result scope does not match the approved publication")
        publication_requested = approval_repo["publish_secure_branch"]
        execute_publish = config["execute_publish"]

        if execute_publish and not publication_requested:
            write_json_atomic(
                result_path,
                {
                    "schema_version": 1,
                    "status": "blocked",
                    "reason": "Approval does not authorize secure branch publication",
                    "executed": False,
                },
            )
            return AgentResult(
                status="blocked",
                summary="Secure branch publication was not authorized.",
                artifacts=[
                    ArtifactOutput(role="secure-branch-publication", path=result_path)
                ],
                human_review=["Record a human publication approval with an expected remote SHA."],
            )

        if execute_publish:
            write_json_atomic(
                result_path,
                {
                    "schema_version": 1,
                    "status": "blocked",
                    "reason": (
                        "Executed publication is disabled until an authenticated "
                        "approval backend is available"
                    ),
                    "executed": False,
                },
            )
            return AgentResult(
                status="blocked",
                summary="Secure branch publication execution is disabled.",
                artifacts=[
                    ArtifactOutput(role="secure-branch-publication", path=result_path)
                ],
                human_review=[
                    "Configure authenticated publication approval before remote mutation."
                ],
            )

        patch_sha = patch_result.get("patch_sha")
        if patch_sha is None:
            publication = {
                "schema_version": 1,
                "status": "awaiting-local-patch",
                "executed": False,
                "publication_requested": publication_requested,
                "target_full_name": approval_repo["target_full_name"],
                "secure_branch": f"secure/{approval_repo['default_branch']}",
            }
        elif not publication_requested:
            publication = {
                "schema_version": 1,
                "status": "not-authorized",
                "executed": False,
                "publication_requested": False,
                "target_full_name": approval_repo["target_full_name"],
                "secure_branch": f"secure/{approval_repo['default_branch']}",
                "patch_sha": patch_sha,
            }
        else:
            try:
                publication = publish_secure_branch(
                    checkout_path=Path(patch_result["checkout_path"]),
                    target_full_name=approval_repo["target_full_name"],
                    secure_branch=f"secure/{approval_repo['default_branch']}",
                    patch_sha=patch_sha,
                    expected_remote_sha=approval_repo.get("expected_remote_sha"),
                    execute=execute_publish,
                    allow_local_remotes=self.allow_local_remotes,
                )
            except SecurePublishError as exc:
                write_json_atomic(
                    result_path,
                    {
                        "schema_version": 1,
                        "status": "blocked",
                        "reason": str(exc),
                        "executed": False,
                    },
                )
                return AgentResult(
                    status="blocked",
                    summary="Secure branch publication was blocked.",
                    artifacts=[
                        ArtifactOutput(
                            role="secure-branch-publication",
                            path=result_path,
                        )
                    ],
                    human_review=[str(exc)],
                )

        write_json_atomic(result_path, publication)
        event_type = (
            "SecureBranchPublished"
            if publication.get("status") in {"published", "already-published"}
            else "SecureBranchPublicationPlanned"
        )
        payload = {"publication": artifact_reference(result_path)}
        return AgentResult(
            status="succeeded",
            summary=(
                f"Secure branch publication status: {publication['status']} for "
                f"{approval_repo['target_full_name']}."
            ),
            events=[
                EventOutput(
                    event_type=event_type,
                    payload=payload,
                    source_repository=approval_repo["source_full_name"],
                    dedupe_key=content_digest(payload),
                )
            ],
            artifacts=[
                ArtifactOutput(role="secure-branch-publication", path=result_path)
            ],
        )


def patch_publication_handlers(
    *,
    allow_local_test_remotes: bool = False,
) -> list[AgentHandler]:
    return [
        PatchHandler(allow_local_remotes=allow_local_test_remotes),
        SecureBranchPublisherHandler(
            allow_local_remotes=allow_local_test_remotes,
        ),
    ]


def run_patch_publication_agent_system(
    *,
    analysis_index_path: Path,
    pin_lock_path: Path,
    tooling_policy_path: Path,
    approval_path: Path,
    workspace: Path,
    run_dir: Path,
    execute_patch: bool = False,
    execute_publish: bool = False,
    database_path: Path | None = None,
    run_id: str | None = None,
    worker_id: str | None = None,
    max_items: int = 100,
    enqueue_only: bool = False,
    allow_local_test_remotes: bool = False,
) -> dict[str, Any]:
    if execute_publish and not execute_patch:
        raise ValueError("Remote publication requires --execute-patch")
    if max_items < 1:
        raise ValueError("max_items must be at least 1")
    analysis_index_path = analysis_index_path.expanduser().resolve()
    pin_lock_path = pin_lock_path.expanduser().resolve()
    tooling_policy_path = tooling_policy_path.expanduser().resolve()
    approval_path = approval_path.expanduser().resolve()
    workspace = workspace.expanduser().resolve()
    run_dir = run_dir.expanduser().resolve()
    for path in (
        analysis_index_path,
        pin_lock_path,
        tooling_policy_path,
        approval_path,
    ):
        if not path.is_file():
            raise FileNotFoundError(path)
    effective_run_id = run_id or f"patch-{uuid.uuid4().hex[:12]}"
    database_path = (
        database_path or run_dir / "agent-control-plane.sqlite3"
    ).expanduser().resolve()
    config = {
        "analysis_index_path": str(analysis_index_path),
        "analysis_index_path_sha256": sha256_file(analysis_index_path),
        "pin_lock_path": str(pin_lock_path),
        "pin_lock_path_sha256": sha256_file(pin_lock_path),
        "tooling_policy_path": str(tooling_policy_path),
        "tooling_policy_path_sha256": sha256_file(tooling_policy_path),
        "approval_path": str(approval_path),
        "approval_path_sha256": sha256_file(approval_path),
        "workspace": str(workspace),
        "execute_patch": execute_patch,
        "execute_publish": execute_publish,
    }
    store = AgentStore(database_path)
    runtime = AgentRuntime(
        backend=store,
        handlers=patch_publication_handlers(
            allow_local_test_remotes=allow_local_test_remotes,
        ),
        worker_id=worker_id or f"local-{os.getpid()}",
    )
    created = ensure_patch_run(
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
            event_type="PatchApprovalRecorded",
            payload={"config": config},
            dedupe_key="initial-patch-approval",
        )
    if enqueue_only:
        result = {
            "run_id": effective_run_id,
            "status": store.get_run(effective_run_id)["status"],
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
    summary_path = run_dir / "patch-publication-summary.json"
    write_json_atomic(summary_path, result)
    result["summary_path"] = str(summary_path)
    return result


def ensure_patch_run(
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
                "workflow": PATCH_PUBLICATION_WORKFLOW,
                "database_path": str(database_path),
                "config": config,
            },
        )
        return True
    metadata = existing.get("metadata") or {}
    if metadata.get("workflow") != PATCH_PUBLICATION_WORKFLOW:
        raise ValueError(f"Run {run_id!r} belongs to a different workflow")
    if metadata.get("config") != config:
        raise ValueError(f"Run {run_id!r} cannot resume with different configuration")
    if Path(str(metadata.get("run_dir"))).resolve() != run_dir:
        raise ValueError(f"Run {run_id!r} cannot resume in a different run directory")
    return False


def require_patch_config(payload: dict[str, Any]) -> dict[str, Any]:
    config = payload.get("config")
    if not isinstance(config, dict):
        raise ValueError("Patch event is missing config")
    for key in (
        "analysis_index_path",
        "pin_lock_path",
        "tooling_policy_path",
        "approval_path",
        "workspace",
    ):
        if not isinstance(config.get(key), str) or not config[key]:
            raise ValueError(f"Patch config has invalid {key}")
    for key in (
        "analysis_index_path_sha256",
        "pin_lock_path_sha256",
        "tooling_policy_path_sha256",
        "approval_path_sha256",
    ):
        value = config.get(key)
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError(f"Patch config has invalid {key}")
    if not isinstance(config.get("execute_patch"), bool):
        raise ValueError("Patch config has invalid execute_patch")
    if not isinstance(config.get("execute_publish"), bool):
        raise ValueError("Patch config has invalid execute_publish")
    return config


def guarded_checkout_path(value: Any, *, workspace: Path) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("Analysis entry has no managed checkout path")
    workspace = workspace.expanduser().resolve()
    path = Path(value).expanduser().resolve()
    if path == workspace or not path.is_relative_to(workspace):
        raise ValueError("Managed checkout path escapes the configured workspace")
    if not path.is_dir():
        raise ValueError(f"Managed checkout is missing: {path}")
    return path


def verified_handoff_path(value: Any) -> Path:
    if not isinstance(value, dict):
        raise ValueError("Patch handoff artifact reference must be an object")
    path = value.get("path")
    digest = value.get("sha256")
    if not isinstance(path, str) or not isinstance(digest, str):
        raise ValueError("Patch handoff artifact reference is invalid")
    resolved = Path(path).resolve()
    if not resolved.is_file() or sha256_file(resolved) != digest:
        raise ValueError("Patch handoff artifact digest verification failed")
    return resolved
