from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import closing, contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

from assured_downstream.agent_contracts import (
    AgentResult,
    ArtifactOutput,
    EventOutput,
    EventRecord,
    WorkItem,
    canonical_json,
    content_digest,
)
from assured_downstream.evidence import sha256_file


SCHEMA_VERSION = 1


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def utc_after(seconds: int | float) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat(
        timespec="microseconds"
    )


class AgentStore:
    """Durable local event, work, attempt, artifact, and handoff store."""

    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with closing(self.connect()) as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                    event_type TEXT NOT NULL,
                    source_repository TEXT,
                    producer_agent_id TEXT,
                    causation_id TEXT REFERENCES events(event_id),
                    correlation_id TEXT NOT NULL,
                    dedupe_key TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(run_id, event_type, dedupe_key)
                );

                CREATE INDEX IF NOT EXISTS events_run_created_idx
                    ON events(run_id, created_at, event_id);

                CREATE TABLE IF NOT EXISTS work_items (
                    work_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                    event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
                    agent_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL,
                    available_at TEXT NOT NULL,
                    lease_owner TEXT,
                    lease_expires_at TEXT,
                    current_attempt_id TEXT,
                    last_error_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(event_id, agent_id)
                );

                CREATE INDEX IF NOT EXISTS work_claim_idx
                    ON work_items(status, available_at, created_at);

                CREATE TABLE IF NOT EXISTS attempts (
                    attempt_id TEXT PRIMARY KEY,
                    work_id TEXT NOT NULL REFERENCES work_items(work_id) ON DELETE CASCADE,
                    attempt_number INTEGER NOT NULL,
                    worker_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error_json TEXT,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    UNIQUE(work_id, attempt_number)
                );

                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                    work_id TEXT NOT NULL REFERENCES work_items(work_id) ON DELETE CASCADE,
                    role TEXT NOT NULL,
                    path TEXT NOT NULL,
                    media_type TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(work_id, role, path)
                );

                CREATE TABLE IF NOT EXISTS handoffs (
                    handoff_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                    work_id TEXT NOT NULL UNIQUE REFERENCES work_items(work_id) ON DELETE CASCADE,
                    agent_id TEXT NOT NULL,
                    input_event_id TEXT NOT NULL REFERENCES events(event_id),
                    output_event_ids_json TEXT NOT NULL,
                    artifact_ids_json TEXT NOT NULL,
                    input_digest TEXT NOT NULL,
                    output_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    human_review_json TEXT NOT NULL,
                    model_execution_json TEXT,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL
                );
                """
            )
            version_row = connection.execute(
                "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
            ).fetchone()
            if version_row is not None and version_row["value"] != str(SCHEMA_VERSION):
                raise RuntimeError(
                    "Unsupported agent database schema version: "
                    f"{version_row['value']}"
                )
            connection.execute(
                "INSERT OR IGNORE INTO schema_metadata(key, value) VALUES (?, ?)",
                ("schema_version", str(SCHEMA_VERSION)),
            )

    def create_run(self, run_id: str, metadata: dict[str, Any]) -> dict[str, Any]:
        now = utc_now()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO runs(run_id, status, metadata_json, created_at, updated_at)
                VALUES (?, 'running', ?, ?, ?)
                """,
                (run_id, canonical_json(metadata), now, now),
            )
        return self.get_run(run_id)

    def get_run(self, run_id: str) -> dict[str, Any]:
        with closing(self.connect()) as connection:
            row = connection.execute(
                "SELECT * FROM runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Unknown agent run: {run_id}")
        return run_from_row(row)

    def latest_run_id(self) -> str | None:
        with closing(self.connect()) as connection:
            row = connection.execute(
                "SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
        return None if row is None else str(row["run_id"])

    def set_run_status(self, run_id: str, status: str) -> None:
        with self.transaction() as connection:
            connection.execute(
                "UPDATE runs SET status = ?, updated_at = ? WHERE run_id = ?",
                (status, utc_now(), run_id),
            )

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
    ) -> EventRecord:
        with self.transaction() as connection:
            return self._publish_event(
                connection,
                run_id=run_id,
                event_type=event_type,
                payload=payload,
                agent_ids=agent_ids,
                source_repository=source_repository,
                producer_agent_id=producer_agent_id,
                causation_id=causation_id,
                correlation_id=correlation_id,
                dedupe_key=dedupe_key,
                max_attempts=max_attempts,
            )

    def _publish_event(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        event_type: str,
        payload: dict[str, Any],
        agent_ids: list[str],
        source_repository: str | None,
        producer_agent_id: str | None,
        causation_id: str | None,
        correlation_id: str | None,
        dedupe_key: str | None,
        max_attempts: int,
    ) -> EventRecord:
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        event_id = uuid.uuid4().hex
        effective_dedupe_key = dedupe_key or event_id
        payload_json = canonical_json(payload)
        payload_sha256 = content_digest(payload)
        now = utc_now()
        connection.execute(
            """
            INSERT OR IGNORE INTO events(
                event_id, run_id, event_type, source_repository,
                producer_agent_id, causation_id, correlation_id, dedupe_key,
                payload_json, payload_sha256, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                run_id,
                event_type,
                source_repository,
                producer_agent_id,
                causation_id,
                correlation_id or run_id,
                effective_dedupe_key,
                payload_json,
                payload_sha256,
                now,
            ),
        )
        row = connection.execute(
            """
            SELECT * FROM events
            WHERE run_id = ? AND event_type = ? AND dedupe_key = ?
            """,
            (run_id, event_type, effective_dedupe_key),
        ).fetchone()
        if row is None:
            raise RuntimeError("Failed to persist agent event")
        event = event_from_row(row)
        if event.payload_sha256 != payload_sha256:
            raise ValueError(
                "Event idempotency collision for "
                f"{run_id}/{event_type}/{effective_dedupe_key}"
            )

        for agent_id in sorted(set(agent_ids)):
            work_id = content_digest(
                {"event_id": event.event_id, "agent_id": agent_id}
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO work_items(
                    work_id, run_id, event_id, agent_id, status, attempts,
                    max_attempts, available_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'queued', 0, ?, ?, ?, ?)
                """,
                (
                    work_id,
                    run_id,
                    event.event_id,
                    agent_id,
                    max_attempts,
                    now,
                    now,
                    now,
                ),
            )
        return event

    def claim_work(
        self,
        *,
        worker_id: str,
        agent_ids: list[str] | None = None,
        run_id: str | None = None,
        lease_seconds: int = 120,
    ) -> WorkItem | None:
        now = utc_now()
        with self.transaction() as connection:
            self._recover_expired_leases(
                connection,
                now,
                run_id=run_id,
                agent_ids=agent_ids,
            )
            parameters: list[Any] = [now]
            agent_filter = ""
            run_filter = ""
            if run_id is not None:
                run_filter = " AND run_id = ?"
                parameters.append(run_id)
            if agent_ids:
                placeholders = ",".join("?" for _ in agent_ids)
                agent_filter = f" AND agent_id IN ({placeholders})"
                parameters.extend(sorted(set(agent_ids)))
            row = connection.execute(
                f"""
                SELECT * FROM work_items
                WHERE status = 'queued' AND available_at <= ?
                    {run_filter} {agent_filter}
                ORDER BY created_at, work_id
                LIMIT 1
                """,
                parameters,
            ).fetchone()
            if row is None:
                return None

            attempt_number = int(row["attempts"]) + 1
            attempt_id = uuid.uuid4().hex
            lease_expires_at = utc_after(lease_seconds)
            connection.execute(
                """
                UPDATE work_items
                SET status = 'running', attempts = ?, lease_owner = ?,
                    lease_expires_at = ?, current_attempt_id = ?, updated_at = ?
                WHERE work_id = ? AND status = 'queued'
                """,
                (
                    attempt_number,
                    worker_id,
                    lease_expires_at,
                    attempt_id,
                    now,
                    row["work_id"],
                ),
            )
            connection.execute(
                """
                INSERT INTO attempts(
                    attempt_id, work_id, attempt_number, worker_id,
                    status, started_at
                ) VALUES (?, ?, ?, ?, 'running', ?)
                """,
                (attempt_id, row["work_id"], attempt_number, worker_id, now),
            )
            claimed = connection.execute(
                "SELECT * FROM work_items WHERE work_id = ?",
                (row["work_id"],),
            ).fetchone()
        return None if claimed is None else work_from_row(claimed)

    def _recover_expired_leases(
        self,
        connection: sqlite3.Connection,
        now: str,
        *,
        run_id: str | None,
        agent_ids: list[str] | None,
    ) -> None:
        query = """
            SELECT work_id, attempts, max_attempts, current_attempt_id
            FROM work_items
            WHERE status = 'running' AND lease_expires_at <= ?
        """
        parameters: list[Any] = [now]
        if run_id is not None:
            query += " AND run_id = ?"
            parameters.append(run_id)
        if agent_ids:
            placeholders = ",".join("?" for _ in agent_ids)
            query += f" AND agent_id IN ({placeholders})"
            parameters.extend(sorted(set(agent_ids)))
        expired = connection.execute(query, parameters).fetchall()
        for row in expired:
            if row["current_attempt_id"]:
                connection.execute(
                    """
                    UPDATE attempts
                    SET status = 'lease_expired', completed_at = ?
                    WHERE attempt_id = ? AND status = 'running'
                    """,
                    (now, row["current_attempt_id"]),
                )
            next_status = (
                "queued"
                if int(row["attempts"]) < int(row["max_attempts"])
                else "dead_letter"
            )
            connection.execute(
                """
                UPDATE work_items
                SET status = ?, lease_owner = NULL, lease_expires_at = NULL,
                    current_attempt_id = NULL, available_at = ?, updated_at = ?
                WHERE work_id = ?
                """,
                (next_status, now, now, row["work_id"]),
            )
            if next_status == "dead_letter":
                connection.execute(
                    """
                    UPDATE runs SET status = 'failed', updated_at = ?
                    WHERE run_id = (
                        SELECT run_id FROM work_items WHERE work_id = ?
                    )
                    """,
                    (now, row["work_id"]),
                )

    def complete_work(
        self,
        *,
        work: WorkItem,
        worker_id: str,
        result: AgentResult,
        routed_events: list[tuple[EventOutput, list[str]]],
    ) -> dict[str, Any]:
        artifact_records = [prepare_artifact(work, artifact) for artifact in result.artifacts]
        now = utc_now()
        with self.transaction() as connection:
            current = self._require_active_lease(
                connection,
                work_id=work.work_id,
                worker_id=worker_id,
            )
            input_event_row = connection.execute(
                "SELECT * FROM events WHERE event_id = ?",
                (work.event_id,),
            ).fetchone()
            if input_event_row is None:
                raise RuntimeError(f"Missing input event: {work.event_id}")
            input_event = event_from_row(input_event_row)

            output_events = []
            for output, agent_ids in routed_events:
                output_events.append(
                    self._publish_event(
                        connection,
                        run_id=work.run_id,
                        event_type=output.event_type,
                        payload=output.payload,
                        agent_ids=agent_ids,
                        source_repository=output.source_repository,
                        producer_agent_id=work.agent_id,
                        causation_id=work.event_id,
                        correlation_id=input_event.correlation_id or work.run_id,
                        dedupe_key=output.dedupe_key,
                        max_attempts=work.max_attempts,
                    )
                )

            artifact_ids = []
            for artifact in artifact_records:
                artifact_ids.append(artifact["artifact_id"])
                connection.execute(
                    """
                    INSERT OR REPLACE INTO artifacts(
                        artifact_id, run_id, work_id, role, path, media_type,
                        sha256, size, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        artifact["artifact_id"],
                        work.run_id,
                        work.work_id,
                        artifact["role"],
                        artifact["path"],
                        artifact["media_type"],
                        artifact["sha256"],
                        artifact["size"],
                        now,
                    ),
                )

            output_event_ids = [event.event_id for event in output_events]
            output_digest = content_digest(
                {
                    "events": [
                        {
                            "event_id": event.event_id,
                            "event_type": event.event_type,
                            "payload_sha256": event.payload_sha256,
                        }
                        for event in output_events
                    ],
                    "artifacts": artifact_records,
                    "status": result.status,
                }
            )
            handoff_id = content_digest(
                {"run_id": work.run_id, "work_id": work.work_id}
            )
            model_json = (
                None
                if result.model_execution is None
                else canonical_json(result.model_execution.as_dict())
            )
            attempt_id = current["current_attempt_id"]
            connection.execute(
                """
                INSERT INTO handoffs(
                    handoff_id, run_id, work_id, agent_id, input_event_id,
                    output_event_ids_json, artifact_ids_json, input_digest,
                    output_digest, status, summary, human_review_json,
                    model_execution_json, started_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    handoff_id,
                    work.run_id,
                    work.work_id,
                    work.agent_id,
                    work.event_id,
                    canonical_json(output_event_ids),
                    canonical_json(artifact_ids),
                    input_event.payload_sha256,
                    output_digest,
                    result.status,
                    result.summary,
                    canonical_json(result.human_review),
                    model_json,
                    self._attempt_started_at(connection, attempt_id),
                    now,
                ),
            )
            connection.execute(
                """
                UPDATE attempts
                SET status = 'succeeded', completed_at = ?
                WHERE attempt_id = ?
                """,
                (now, attempt_id),
            )
            connection.execute(
                """
                UPDATE work_items
                SET status = 'succeeded', lease_owner = NULL,
                    lease_expires_at = NULL, current_attempt_id = NULL,
                    updated_at = ?
                WHERE work_id = ?
                """,
                (now, work.work_id),
            )
            connection.execute(
                "UPDATE runs SET updated_at = ? WHERE run_id = ?",
                (now, work.run_id),
            )
        return {
            "handoff_id": handoff_id,
            "output_event_ids": output_event_ids,
            "artifact_ids": artifact_ids,
        }

    def fail_work(
        self,
        *,
        work: WorkItem,
        worker_id: str,
        error: dict[str, Any],
        retry_delay_seconds: int = 0,
    ) -> str:
        now = utc_now()
        with self.transaction() as connection:
            current = self._require_active_lease(
                connection,
                work_id=work.work_id,
                worker_id=worker_id,
            )
            status = (
                "queued"
                if int(current["attempts"]) < int(current["max_attempts"])
                else "dead_letter"
            )
            attempt_status = "retryable_failure" if status == "queued" else "failed"
            error_json = canonical_json(error)
            connection.execute(
                """
                UPDATE attempts
                SET status = ?, error_json = ?, completed_at = ?
                WHERE attempt_id = ?
                """,
                (attempt_status, error_json, now, current["current_attempt_id"]),
            )
            connection.execute(
                """
                UPDATE work_items
                SET status = ?, available_at = ?, lease_owner = NULL,
                    lease_expires_at = NULL, current_attempt_id = NULL,
                    last_error_json = ?, updated_at = ?
                WHERE work_id = ?
                """,
                (
                    status,
                    utc_after(retry_delay_seconds),
                    error_json,
                    now,
                    work.work_id,
                ),
            )
            if status == "dead_letter":
                connection.execute(
                    "UPDATE runs SET status = 'failed', updated_at = ? WHERE run_id = ?",
                    (now, work.run_id),
                )
        return status

    def _require_active_lease(
        self,
        connection: sqlite3.Connection,
        *,
        work_id: str,
        worker_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM work_items WHERE work_id = ?",
            (work_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"Unknown work item: {work_id}")
        if row["status"] != "running" or row["lease_owner"] != worker_id:
            raise RuntimeError(
                f"Worker {worker_id} does not hold the active lease for {work_id}"
            )
        return row

    def _attempt_started_at(
        self,
        connection: sqlite3.Connection,
        attempt_id: str,
    ) -> str:
        row = connection.execute(
            "SELECT started_at FROM attempts WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        if row is None:
            raise RuntimeError(f"Missing work attempt: {attempt_id}")
        return str(row["started_at"])

    def get_event(self, event_id: str) -> EventRecord:
        with closing(self.connect()) as connection:
            row = connection.execute(
                "SELECT * FROM events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Unknown agent event: {event_id}")
        return event_from_row(row)

    def list_events(self, run_id: str) -> list[dict[str, Any]]:
        with closing(self.connect()) as connection:
            rows = connection.execute(
                """
                SELECT * FROM events
                WHERE run_id = ?
                ORDER BY created_at, event_id
                """,
                (run_id,),
            ).fetchall()
        return [event_dict(event_from_row(row)) for row in rows]

    def list_handoffs(self, run_id: str) -> list[dict[str, Any]]:
        with closing(self.connect()) as connection:
            rows = connection.execute(
                """
                SELECT * FROM handoffs
                WHERE run_id = ?
                ORDER BY completed_at, handoff_id
                """,
                (run_id,),
            ).fetchall()
        return [handoff_from_row(row) for row in rows]

    def work_status_counts(self, run_id: str) -> dict[str, int]:
        with closing(self.connect()) as connection:
            rows = connection.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM work_items WHERE run_id = ? GROUP BY status
                """,
                (run_id,),
            ).fetchall()
        return {str(row["status"]): int(row["count"]) for row in rows}

    def pending_count(self, run_id: str | None = None) -> int:
        query = "SELECT COUNT(*) AS count FROM work_items WHERE status IN ('queued', 'running')"
        parameters: tuple[Any, ...] = ()
        if run_id is not None:
            query += " AND run_id = ?"
            parameters = (run_id,)
        with closing(self.connect()) as connection:
            row = connection.execute(query, parameters).fetchone()
        return 0 if row is None else int(row["count"])

    def run_summary(self, run_id: str) -> dict[str, Any]:
        run = self.get_run(run_id)
        events = self.list_events(run_id)
        handoffs = self.list_handoffs(run_id)
        with closing(self.connect()) as connection:
            artifact_count_row = connection.execute(
                "SELECT COUNT(*) AS count FROM artifacts WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        return {
            "schema_version": 1,
            "run": run,
            "event_count": len(events),
            "event_types": [event["event_type"] for event in events],
            "work": self.work_status_counts(run_id),
            "handoff_count": len(handoffs),
            "handoff_agents": [handoff["agent_id"] for handoff in handoffs],
            "artifact_count": (
                0 if artifact_count_row is None else int(artifact_count_row["count"])
            ),
        }

    def verify_artifacts(self, run_id: str) -> dict[str, Any]:
        with closing(self.connect()) as connection:
            rows = connection.execute(
                """
                SELECT artifact_id, role, path, sha256, size
                FROM artifacts WHERE run_id = ?
                ORDER BY created_at, artifact_id
                """,
                (run_id,),
            ).fetchall()

        failures = []
        for row in rows:
            path = Path(str(row["path"]))
            if not path.exists() or not path.is_file():
                failures.append(
                    {
                        "artifact_id": str(row["artifact_id"]),
                        "role": str(row["role"]),
                        "path": str(path),
                        "reason": "missing",
                    }
                )
                continue
            actual_size = path.stat().st_size
            actual_sha256 = sha256_file(path)
            if actual_size != int(row["size"]) or actual_sha256 != row["sha256"]:
                failures.append(
                    {
                        "artifact_id": str(row["artifact_id"]),
                        "role": str(row["role"]),
                        "path": str(path),
                        "reason": "digest_mismatch",
                        "expected_sha256": str(row["sha256"]),
                        "actual_sha256": actual_sha256,
                        "expected_size": int(row["size"]),
                        "actual_size": actual_size,
                    }
                )
        return {
            "ok": not failures,
            "checked": len(rows),
            "failures": failures,
        }


def prepare_artifact(work: WorkItem, artifact: ArtifactOutput) -> dict[str, Any]:
    path = artifact.path.resolve()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Agent artifact is not a file: {path}")
    digest = sha256_file(path)
    record = {
        "role": artifact.role,
        "path": str(path),
        "media_type": artifact.media_type,
        "sha256": digest,
        "size": path.stat().st_size,
    }
    record["artifact_id"] = content_digest(
        {
            "work_id": work.work_id,
            "role": artifact.role,
            "path": str(path),
            "sha256": digest,
        }
    )
    return record


def event_from_row(row: sqlite3.Row) -> EventRecord:
    return EventRecord(
        event_id=str(row["event_id"]),
        run_id=str(row["run_id"]),
        event_type=str(row["event_type"]),
        payload=json.loads(row["payload_json"]),
        payload_sha256=str(row["payload_sha256"]),
        created_at=str(row["created_at"]),
        source_repository=row["source_repository"],
        producer_agent_id=row["producer_agent_id"],
        causation_id=row["causation_id"],
        correlation_id=row["correlation_id"],
        dedupe_key=row["dedupe_key"],
    )


def event_dict(event: EventRecord) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "run_id": event.run_id,
        "event_type": event.event_type,
        "source_repository": event.source_repository,
        "producer_agent_id": event.producer_agent_id,
        "causation_id": event.causation_id,
        "correlation_id": event.correlation_id,
        "dedupe_key": event.dedupe_key,
        "payload": event.payload,
        "payload_sha256": event.payload_sha256,
        "created_at": event.created_at,
    }


def work_from_row(row: sqlite3.Row) -> WorkItem:
    return WorkItem(
        work_id=str(row["work_id"]),
        run_id=str(row["run_id"]),
        event_id=str(row["event_id"]),
        agent_id=str(row["agent_id"]),
        status=str(row["status"]),
        attempts=int(row["attempts"]),
        max_attempts=int(row["max_attempts"]),
        lease_owner=row["lease_owner"],
        lease_expires_at=row["lease_expires_at"],
        current_attempt_id=row["current_attempt_id"],
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def run_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "run_id": str(row["run_id"]),
        "status": str(row["status"]),
        "metadata": json.loads(row["metadata_json"]),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }


def handoff_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "handoff_id": str(row["handoff_id"]),
        "run_id": str(row["run_id"]),
        "work_id": str(row["work_id"]),
        "agent_id": str(row["agent_id"]),
        "input_event_id": str(row["input_event_id"]),
        "output_event_ids": json.loads(row["output_event_ids_json"]),
        "artifact_ids": json.loads(row["artifact_ids_json"]),
        "input_digest": str(row["input_digest"]),
        "output_digest": str(row["output_digest"]),
        "status": str(row["status"]),
        "summary": str(row["summary"]),
        "human_review": json.loads(row["human_review_json"]),
        "model_execution": (
            None
            if row["model_execution_json"] is None
            else json.loads(row["model_execution_json"])
        ),
        "started_at": str(row["started_at"]),
        "completed_at": str(row["completed_at"]),
    }
