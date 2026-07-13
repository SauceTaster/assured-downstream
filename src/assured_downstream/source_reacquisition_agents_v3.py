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
from assured_downstream.evidence_agents import (
    EvidenceLaneError,
    artifact_reference,
    snapshot_regular_file,
    verified_artifact_path,
    write_json_atomic,
)
from assured_downstream.source_reacquisition_v3 import (
    MAX_ACQUISITION_SECONDS,
    SourceReacquisitionError,
    canonical_github_url,
    hash_executable,
    load_trusted_source_report,
    reacquire_source,
    require_regular_executable,
    require_sha256,
    validate_source_ref,
)


SOURCE_REACQUISITION_V3_WORKFLOW = "source-reacquisition-v3"
SOURCE_REACQUISITION_V3_EVENT = "SourceReacquisitionV3Requested"
SOURCE_REACQUISITION_V3_MATCHED_EVENT = "SourceReacquiredV3Compared"
SOURCE_REACQUISITION_V3_MISMATCH_EVENT = "SourceReacquisitionV3Mismatch"
SOURCE_REACQUISITION_V3_REJECTED_EVENT = "SourceReacquisitionV3Rejected"
SOURCE_REACQUISITION_V3_LEASE_SECONDS = int(MAX_ACQUISITION_SECONDS) + 120


class SourceReacquisitionV3Handler:
    agent_id = "source-reacquirer-v3"

    def __init__(
        self,
        *,
        remote_url: str | None = None,
        allow_local_remote: bool = False,
    ) -> None:
        self.remote_url = remote_url
        self.allow_local_remote = allow_local_remote

    def handle(self, context: AgentContext) -> AgentResult:
        if context.event.event_type != SOURCE_REACQUISITION_V3_EVENT:
            raise ValueError(
                "Source Reacquirer v3 Agent requires SourceReacquisitionV3Requested"
            )
        if context.event.producer_agent_id is not None:
            raise ValueError("SourceReacquisitionV3Requested must be external")
        if content_digest(context.event.payload) != context.event.payload_sha256:
            raise ValueError("Source reacquisition event payload digest is invalid")
        inputs = context.event.payload.get("inputs")
        request = context.event.payload.get("request")
        if (
            not isinstance(inputs, dict)
            or set(inputs) != {"trusted_source_inventory"}
            or not isinstance(request, dict)
            or set(request)
            != {
                "git_executable",
                "git_https_helper",
                "git_https_helper_sha256",
                "git_sha256",
                "object_format",
                "source_ref",
            }
        ):
            raise ValueError("Source reacquisition request is invalid")
        if context.work.current_attempt_id is None:
            raise ValueError("Source reacquisition work has no fenced attempt identity")
        attempt_dir = context.run_dir / "attempts" / context.work.current_attempt_id
        attempt_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        report_path = attempt_dir / "source-reacquisition-v3.json"
        acquired_path = attempt_dir / "acquired-source-inventory-v3.json"
        try:
            trusted_path = verified_artifact_path(
                inputs["trusted_source_inventory"],
                label="trusted source inventory",
            )
            validate_source_ref(request["source_ref"])
            result = reacquire_source(
                trusted_inventory_path=trusted_path,
                source_ref=request["source_ref"],
                object_format=request["object_format"],
                expected_trusted_inventory_sha256=inputs["trusted_source_inventory"][
                    "sha256"
                ],
                git_path=Path(request["git_executable"]),
                expected_git_sha256=request["git_sha256"],
                https_helper_path=Path(request["git_https_helper"]),
                expected_https_helper_sha256=request["git_https_helper_sha256"],
                scratch_parent=attempt_dir / "scratch",
                remote_url=self.remote_url,
                allow_local_remote=self.allow_local_remote,
            )
        except (
            EvidenceLaneError,
            FileNotFoundError,
            KeyError,
            OSError,
            SourceReacquisitionError,
            TypeError,
            ValueError,
        ) as exc:
            rejection = {
                "schema_version": 1,
                "status": "rejected",
                "ok": False,
                "authority": "none",
                "error": str(exc),
                "claims": {
                    "source_reacquisition_match": False,
                    "upstream_lineage": False,
                    "host_independent": False,
                    "provider_independent": False,
                },
            }
            write_json_atomic(report_path, rejection)
            payload = {
                "report": artifact_reference(report_path),
                "inputs": inputs,
                "request": request,
            }
            return AgentResult(
                status="blocked",
                summary="Source reacquisition v3 was rejected before comparison.",
                events=[
                    EventOutput(
                        event_type=SOURCE_REACQUISITION_V3_REJECTED_EVENT,
                        payload=payload,
                        source_repository=context.event.source_repository,
                        dedupe_key=content_digest(payload),
                    )
                ],
                artifacts=[
                    ArtifactOutput(
                        role="source-reacquisition-v3-rejection", path=report_path
                    )
                ],
                human_review=[str(exc)],
            )

        write_json_atomic(acquired_path, result.inventory)
        write_json_atomic(report_path, result.report)
        payload = {
            "report": artifact_reference(report_path),
            "acquired_inventory": artifact_reference(acquired_path),
            "trusted_inventory": inputs["trusted_source_inventory"],
            "source_reacquisition_match": result.report["ok"] is True,
            "upstream_lineage": False,
            "host_independent": False,
            "provider_independent": False,
        }
        artifacts = [
            ArtifactOutput(role="acquired-source-inventory-v3", path=acquired_path),
            ArtifactOutput(role="source-reacquisition-v3-report", path=report_path),
        ]
        if result.report["ok"] is True:
            return AgentResult(
                status="succeeded",
                summary=(
                    "Reacquired source Git objects matched the retained v3 inventory; "
                    "no lineage or independence claim was granted."
                ),
                events=[
                    EventOutput(
                        event_type=SOURCE_REACQUISITION_V3_MATCHED_EVENT,
                        payload=payload,
                        source_repository=context.event.source_repository,
                        dedupe_key=content_digest(payload),
                    )
                ],
                artifacts=artifacts,
            )
        findings = result.report["comparison"]["findings"]
        return AgentResult(
            status="blocked",
            summary="Reacquired source Git objects did not match retained v3 inventory.",
            events=[
                EventOutput(
                    event_type=SOURCE_REACQUISITION_V3_MISMATCH_EVENT,
                    payload=payload,
                    source_repository=context.event.source_repository,
                    dedupe_key=content_digest(payload),
                )
            ],
            artifacts=artifacts,
            human_review=[
                f"{finding['code']}: {finding['path']}" for finding in findings
            ],
        )


def source_reacquisition_v3_handlers(
    *,
    remote_url: str | None = None,
    allow_local_remote: bool = False,
) -> list[AgentHandler]:
    return [
        SourceReacquisitionV3Handler(
            remote_url=remote_url,
            allow_local_remote=allow_local_remote,
        )
    ]


def source_reacquisition_v3_routes() -> dict[str, list[str]]:
    return {
        SOURCE_REACQUISITION_V3_EVENT: ["source-reacquirer-v3"],
        SOURCE_REACQUISITION_V3_MATCHED_EVENT: [],
        SOURCE_REACQUISITION_V3_MISMATCH_EVENT: [],
        SOURCE_REACQUISITION_V3_REJECTED_EVENT: [],
    }


def run_source_reacquisition_v3_agent_system(
    *,
    trusted_inventory_path: Path,
    source_ref: str,
    object_format: str,
    run_dir: Path,
    execute_reacquisition: bool,
    git_path: Path,
    expected_git_sha256: str,
    https_helper_path: Path,
    expected_https_helper_sha256: str,
    database_path: Path | None = None,
    run_id: str | None = None,
    worker_id: str | None = None,
    max_items: int = 20,
    enqueue_only: bool = False,
    test_remote_url: str | None = None,
    allow_test_local_remote: bool = False,
) -> dict[str, Any]:
    if not execute_reacquisition:
        raise ValueError("Source reacquisition requires --execute-reacquisition")
    if max_items < 1:
        raise ValueError("max_items must be at least 1")
    if (test_remote_url is None) != (not allow_test_local_remote):
        raise ValueError("Test local source transport must be explicitly paired")
    validate_source_ref(source_ref)
    require_sha256(expected_git_sha256, label="expected Git executable digest")
    effective_git_path = require_regular_executable(git_path)
    if hash_executable(effective_git_path) != expected_git_sha256:
        raise ValueError("Git executable digest does not match the run request")
    require_sha256(
        expected_https_helper_sha256,
        label="expected Git HTTPS helper digest",
    )
    effective_https_helper_path = require_regular_executable(https_helper_path)
    if hash_executable(effective_https_helper_path) != expected_https_helper_sha256:
        raise ValueError("Git HTTPS helper digest does not match the run request")
    run_dir = run_dir.expanduser().resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    trusted_snapshot = snapshot_regular_file(
        trusted_inventory_path,
        target_dir=run_dir / "inputs" / "source",
        label="trusted-source-inventory-v3.json",
    )
    trusted_report, _ = load_trusted_source_report(
        Path(trusted_snapshot["path"]),
        object_format=object_format,
        expected_sha256=trusted_snapshot["sha256"],
    )
    inputs = {"trusted_source_inventory": trusted_snapshot}
    request = {
        "source_ref": source_ref,
        "object_format": object_format,
        "git_executable": str(effective_git_path),
        "git_sha256": expected_git_sha256,
        "git_https_helper": str(effective_https_helper_path),
        "git_https_helper_sha256": expected_https_helper_sha256,
    }
    transport_url = (
        str(Path(test_remote_url).expanduser().resolve())
        if allow_test_local_remote and test_remote_url is not None
        else canonical_github_url(trusted_report["source"]["repository"])
    )
    config = {
        "inputs": inputs,
        "request": request,
        "execute_reacquisition": True,
        "transport": {
            "mode": (
                "test-local" if allow_test_local_remote else "canonical-github-https"
            ),
            "url": transport_url,
        },
    }
    effective_run_id = run_id or f"source-reacquire-v3-{uuid.uuid4().hex[:12]}"
    database_path = (
        (database_path or run_dir / "agent-control-plane.sqlite3")
        .expanduser()
        .resolve()
    )
    store = AgentStore(database_path)
    runtime = AgentRuntime(
        backend=store,
        handlers=[
            SourceReacquisitionV3Handler(
                remote_url=test_remote_url,
                allow_local_remote=allow_test_local_remote,
            )
        ],
        routes=source_reacquisition_v3_routes(),
        worker_id=worker_id or f"local-{os.getpid()}",
        lease_seconds=SOURCE_REACQUISITION_V3_LEASE_SECONDS,
    )
    ensure_source_reacquisition_v3_run(
        store,
        runtime=runtime,
        run_id=effective_run_id,
        run_dir=run_dir,
        config=config,
    )
    payload = {"inputs": inputs, "request": request}
    runtime.publish_external(
        run_id=effective_run_id,
        event_type=SOURCE_REACQUISITION_V3_EVENT,
        payload=payload,
        source_repository=trusted_report["source"]["repository"],
        dedupe_key=content_digest(payload),
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
    terminal_events = [
        event
        for event in store.list_events(effective_run_id)
        if event["event_type"]
        in {
            SOURCE_REACQUISITION_V3_MATCHED_EVENT,
            SOURCE_REACQUISITION_V3_MISMATCH_EVENT,
            SOURCE_REACQUISITION_V3_REJECTED_EVENT,
        }
    ]
    if terminal_events:
        result["terminal_event"] = terminal_events[-1]
        result["report"] = terminal_events[-1]["payload"]["report"]
        if "acquired_inventory" in terminal_events[-1]["payload"]:
            result["acquired_inventory"] = terminal_events[-1]["payload"][
                "acquired_inventory"
            ]
    result["database_path"] = str(database_path)
    result["run_dir"] = str(run_dir)
    summary_path = run_dir / "source-reacquisition-v3-summary.json"
    write_json_atomic(summary_path, result)
    result["summary_path"] = str(summary_path)
    return result


def ensure_source_reacquisition_v3_run(
    store: AgentStore,
    *,
    runtime: AgentRuntime,
    run_id: str,
    run_dir: Path,
    config: dict[str, Any],
) -> bool:
    try:
        existing = store.get_run(run_id)
    except KeyError:
        runtime.create_run(
            run_id=run_id,
            run_dir=run_dir,
            metadata={
                "workflow": SOURCE_REACQUISITION_V3_WORKFLOW,
                "config": config,
            },
        )
        return True
    metadata = existing.get("metadata") or {}
    if metadata.get("workflow") != SOURCE_REACQUISITION_V3_WORKFLOW:
        raise ValueError(f"Run {run_id!r} belongs to a different workflow")
    if metadata.get("config") != config:
        raise ValueError(f"Run {run_id!r} cannot resume with different configuration")
    if Path(str(metadata.get("run_dir"))).resolve() != run_dir:
        raise ValueError(f"Run {run_id!r} cannot resume in a different run directory")
    return False
