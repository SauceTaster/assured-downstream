from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


AGENT_RESULT_STATUSES = {"succeeded", "blocked", "needs_human_review"}


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def content_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EventRecord:
    event_id: str
    run_id: str
    event_type: str
    payload: dict[str, Any]
    payload_sha256: str
    created_at: str
    source_repository: str | None = None
    producer_agent_id: str | None = None
    producer_attempt_id: str | None = None
    causation_id: str | None = None
    correlation_id: str | None = None
    dedupe_key: str | None = None


@dataclass(frozen=True)
class WorkItem:
    work_id: str
    run_id: str
    event_id: str
    agent_id: str
    status: str
    attempts: int
    max_attempts: int
    lease_owner: str | None
    lease_expires_at: str | None
    current_attempt_id: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class ArtifactOutput:
    role: str
    path: Path
    media_type: str = "application/json"


@dataclass(frozen=True)
class EventOutput:
    event_type: str
    payload: dict[str, Any]
    source_repository: str | None = None
    dedupe_key: str | None = None


@dataclass(frozen=True)
class ModelExecution:
    driver: str
    profile: str
    model: str | None
    reasoning_effort: str | None
    sandbox: str
    codex_version: str | None
    duration_seconds: float
    result_path: str | None
    status: str
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "driver": self.driver,
            "profile": self.profile,
            "model": self.model,
            "reasoning_effort": self.reasoning_effort,
            "sandbox": self.sandbox,
            "codex_version": self.codex_version,
            "duration_seconds": self.duration_seconds,
            "result_path": self.result_path,
            "status": self.status,
            "error": self.error,
        }


@dataclass(frozen=True)
class AgentResult:
    status: str
    summary: str
    events: list[EventOutput] = field(default_factory=list)
    artifacts: list[ArtifactOutput] = field(default_factory=list)
    human_review: list[str] = field(default_factory=list)
    model_execution: ModelExecution | None = None

    def __post_init__(self) -> None:
        if self.status not in AGENT_RESULT_STATUSES:
            raise ValueError(f"Unsupported agent result status: {self.status}")


@dataclass(frozen=True)
class AgentContext:
    run_id: str
    run_dir: Path
    worker_id: str
    work: WorkItem
    event: EventRecord
    run_metadata: dict[str, Any] = field(default_factory=dict)
