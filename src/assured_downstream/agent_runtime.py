from __future__ import annotations

import os
import re
import traceback
from pathlib import Path
from typing import Any, Protocol

from assured_downstream.agent_contracts import (
    AgentContext,
    AgentResult,
    EventOutput,
    EventRecord,
    WorkItem,
)
from assured_downstream.agent_registry import load_agent_registry
from assured_downstream.secure_path import (
    directory_identity_record,
    secure_directory_identity,
)


class AgentBackend(Protocol):
    """Storage boundary that a future Dapr backend can implement."""

    def create_run(self, run_id: str, metadata: dict[str, Any]) -> dict[str, Any]: ...

    def get_run(self, run_id: str) -> dict[str, Any]: ...

    def set_run_status(self, run_id: str, status: str) -> None: ...

    def publish_event(
        self,
        *,
        run_id: str,
        event_type: str,
        payload: dict[str, Any],
        agent_ids: list[str],
        source_repository: str | None = None,
        producer_agent_id: str | None = None,
        causation_id: str | None = None,
        correlation_id: str | None = None,
        dedupe_key: str | None = None,
        max_attempts: int = 3,
    ) -> EventRecord: ...

    def claim_work(
        self,
        *,
        worker_id: str,
        agent_ids: list[str] | None = None,
        run_id: str | None = None,
        lease_seconds: int = 120,
    ) -> WorkItem | None: ...

    def get_event(self, event_id: str) -> EventRecord: ...

    def complete_work(
        self,
        *,
        work: WorkItem,
        worker_id: str,
        result: AgentResult,
        routed_events: list[tuple[EventOutput, list[str]]],
    ) -> dict[str, Any]: ...

    def fail_work(
        self,
        *,
        work: WorkItem,
        worker_id: str,
        error: dict[str, Any],
        retry_delay_seconds: int = 0,
    ) -> str: ...

    def pending_count(self, run_id: str | None = None) -> int: ...

    def list_handoffs(self, run_id: str) -> list[dict[str, Any]]: ...

    def run_summary(self, run_id: str) -> dict[str, Any]: ...

    def verify_artifacts(self, run_id: str) -> dict[str, Any]: ...


class AgentHandler(Protocol):
    agent_id: str

    def handle(self, context: AgentContext) -> AgentResult: ...


def build_event_routes(
    registry: dict[str, Any] | None = None,
) -> dict[str, list[str]]:
    effective_registry = registry if registry is not None else load_agent_registry()
    routes: dict[str, list[str]] = {}
    for agent in effective_registry["agents"]:
        for event_type in agent["input_events"]:
            routes.setdefault(str(event_type), []).append(str(agent["id"]))
    return {
        event_type: sorted(set(agent_ids))
        for event_type, agent_ids in routes.items()
    }


class AgentRuntime:
    """Runs typed agents over a durable backend one leased handoff at a time."""

    def __init__(
        self,
        *,
        backend: AgentBackend,
        handlers: list[AgentHandler],
        routes: dict[str, list[str]] | None = None,
        worker_id: str = "local-worker",
        lease_seconds: int = 120,
    ) -> None:
        self.backend = backend
        if not handlers:
            raise ValueError("AgentRuntime requires at least one handler")
        self.handlers = {handler.agent_id: handler for handler in handlers}
        if len(self.handlers) != len(handlers):
            raise ValueError("Agent handler ids must be unique")
        self.routes = routes if routes is not None else build_event_routes()
        self.worker_id = worker_id
        self.lease_seconds = lease_seconds

    def create_run(
        self,
        *,
        run_id: str,
        run_dir: Path,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        run_dir = run_dir.resolve()
        run_dir.mkdir(parents=True, exist_ok=True)
        run_metadata = dict(metadata or {})
        run_metadata["run_dir"] = str(run_dir)
        if run_metadata.get("artifact_scope") == "attempt-scoped-v1":
            run_metadata["run_root_identity"] = directory_identity_record(
                secure_directory_identity(run_dir)
            )
        return self.backend.create_run(run_id, run_metadata)

    def publish_external(
        self,
        *,
        run_id: str,
        event_type: str,
        payload: dict[str, Any],
        source_repository: str | None = None,
        dedupe_key: str | None = None,
    ) -> EventRecord:
        return self.backend.publish_event(
            run_id=run_id,
            event_type=event_type,
            payload=payload,
            agent_ids=self.routes.get(event_type, []),
            source_repository=source_repository,
            dedupe_key=dedupe_key,
        )

    def run_once(self, *, run_id: str | None = None) -> dict[str, Any] | None:
        work = self.backend.claim_work(
            worker_id=self.worker_id,
            agent_ids=sorted(self.handlers),
            run_id=run_id,
            lease_seconds=self.lease_seconds,
        )
        if work is None:
            return None

        try:
            handler = self.handlers[work.agent_id]
            event = self.backend.get_event(work.event_id)
            run = self.backend.get_run(work.run_id)
            run_dir_value = run["metadata"].get("run_dir")
            if not run_dir_value:
                raise ValueError(f"Run {work.run_id} has no run_dir metadata")
            context = AgentContext(
                run_id=work.run_id,
                run_dir=Path(str(run_dir_value)),
                worker_id=self.worker_id,
                work=work,
                event=event,
                run_metadata=run["metadata"],
            )
            result = handler.handle(context)
            validate_result_artifact_scope(
                context,
                result,
                artifact_scope=run["metadata"].get("artifact_scope"),
            )
            routed_events = [
                (output, self.routes.get(output.event_type, []))
                for output in result.events
            ]
            completion = self.backend.complete_work(
                work=work,
                worker_id=self.worker_id,
                result=result,
                routed_events=routed_events,
            )
            return {
                "agent_id": work.agent_id,
                "work_id": work.work_id,
                "status": result.status,
                **completion,
            }
        except Exception as exc:
            try:
                failure_status = self.backend.fail_work(
                    work=work,
                    worker_id=self.worker_id,
                    error={
                        "type": exc.__class__.__name__,
                        "message": str(exc),
                        "traceback": traceback.format_exc(limit=12),
                    },
                )
            except Exception as persistence_exc:
                return {
                    "agent_id": work.agent_id,
                    "work_id": work.work_id,
                    "status": "lease_lost",
                    "error": str(exc),
                    "persistence_error": str(persistence_exc),
                }
            return {
                "agent_id": work.agent_id,
                "work_id": work.work_id,
                "status": failure_status,
                "error": str(exc),
            }
    def drain(self, *, run_id: str, max_items: int = 100) -> dict[str, Any]:
        processed = []
        for _ in range(max_items):
            outcome = self.run_once(run_id=run_id)
            if outcome is None:
                break
            processed.append(outcome)

        pending = self.backend.pending_count(run_id)
        handoffs = self.backend.list_handoffs(run_id)
        handoff_statuses = {handoff["status"] for handoff in handoffs}
        summary = self.backend.run_summary(run_id)
        dead_letters = summary["work"].get("dead_letter", 0)
        artifact_verification = self.backend.verify_artifacts(run_id)
        if not artifact_verification["ok"]:
            final_status = "failed"
        elif dead_letters:
            final_status = "failed"
        elif "blocked" in handoff_statuses:
            final_status = "blocked"
        elif "needs_human_review" in handoff_statuses:
            final_status = "needs_human_review"
        elif pending == 0:
            final_status = "succeeded"
        else:
            final_status = "running"
        self.backend.set_run_status(run_id, final_status)

        return {
            "run_id": run_id,
            "status": final_status,
            "processed": processed,
            "processed_count": len(processed),
            "pending_count": pending,
            "artifact_verification": artifact_verification,
            "summary": self.backend.run_summary(run_id),
        }


def validate_result_artifact_scope(
    context: AgentContext,
    result: AgentResult,
    *,
    artifact_scope: Any,
) -> None:
    if artifact_scope is None:
        return
    if artifact_scope != "attempt-scoped-v1":
        raise ValueError(f"Unsupported agent artifact scope: {artifact_scope!r}")
    attempt_id = context.work.current_attempt_id
    if (
        not isinstance(attempt_id, str)
        or re.fullmatch(r"[0-9a-f]{32}", attempt_id) is None
    ):
        raise ValueError("Attempt-scoped run has no valid current attempt id")
    run_root = Path(os.path.abspath(context.run_dir))
    expected_root = run_root / "attempts" / attempt_id / context.work.agent_id
    for artifact in result.artifacts:
        path = artifact.path
        if not path.is_absolute():
            raise ValueError(f"Agent artifact path must be absolute: {path}")
        lexical_path = Path(os.path.abspath(path))
        try:
            lexical_path.relative_to(expected_root)
        except ValueError as exc:
            raise ValueError(
                f"Agent artifact is outside its current attempt: {path}"
            ) from exc
        try:
            resolved_path = lexical_path.resolve(strict=True)
        except OSError as exc:
            raise ValueError(f"Agent artifact is unavailable: {path}") from exc
        if resolved_path != lexical_path or not resolved_path.is_file():
            raise ValueError(f"Agent artifact traverses a symlink: {path}")
