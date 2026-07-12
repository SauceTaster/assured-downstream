from __future__ import annotations

import os
import pwd
import sqlite3
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator


class PublicationLedgerError(RuntimeError):
    pass


def trusted_publication_ledger_path() -> Path:
    account_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    return (
        account_home
        / ".local"
        / "state"
        / "assured-downstream"
        / "publication-ledger.sqlite3"
    )


class PublicationLedger:
    """Global one-time consumption ledger for publication authorizations."""

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path.parent.chmod(0o700)
        self.initialize()
        self.path.chmod(0o600)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
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
                CREATE TABLE IF NOT EXISTS publication_consumptions (
                    request_id TEXT PRIMARY KEY,
                    request_sha256 TEXT NOT NULL UNIQUE,
                    run_id TEXT NOT NULL,
                    work_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    target_full_name TEXT NOT NULL,
                    secure_branch TEXT NOT NULL,
                    patch_sha TEXT NOT NULL,
                    expected_remote_sha TEXT,
                    result_status TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS publication_consumptions_run_idx
                    ON publication_consumptions(run_id, work_id);
                """
            )

    def reserve(
        self,
        *,
        request_id: str,
        request_sha256: str,
        run_id: str,
        work_id: str,
        target_full_name: str,
        secure_branch: str,
        patch_sha: str,
        expected_remote_sha: str | None,
    ) -> dict[str, Any]:
        expected = {
            "request_id": request_id,
            "request_sha256": request_sha256,
            "run_id": run_id,
            "work_id": work_id,
            "target_full_name": target_full_name,
            "secure_branch": secure_branch,
            "patch_sha": patch_sha,
            "expected_remote_sha": expected_remote_sha,
        }
        now = utc_now()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO publication_consumptions(
                    request_id, request_sha256, run_id, work_id, status,
                    target_full_name, secure_branch, patch_sha,
                    expected_remote_sha, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'reserved', ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    request_sha256,
                    run_id,
                    work_id,
                    target_full_name,
                    secure_branch,
                    patch_sha,
                    expected_remote_sha,
                    now,
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM publication_consumptions WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise PublicationLedgerError(
                    "Failed to reserve publication authorization"
                )
            record = record_from_row(row)
            for field, value in expected.items():
                if record[field] != value:
                    raise PublicationLedgerError(
                        "Publication authorization replay or scope collision detected"
                    )
            if record["status"] == "blocked":
                raise PublicationLedgerError(
                    "Publication authorization was already consumed by a blocked attempt"
                )
            return record

    def mark_published(
        self,
        *,
        request_id: str,
        run_id: str,
        work_id: str,
        result_status: str,
    ) -> dict[str, Any]:
        if result_status not in {"published", "already-published"}:
            raise PublicationLedgerError("Invalid publication success status")
        return self._mark(
            request_id=request_id,
            run_id=run_id,
            work_id=work_id,
            status="published",
            result_status=result_status,
        )

    def mark_blocked(
        self,
        *,
        request_id: str,
        run_id: str,
        work_id: str,
        result_status: str,
    ) -> dict[str, Any]:
        return self._mark(
            request_id=request_id,
            run_id=run_id,
            work_id=work_id,
            status="blocked",
            result_status=result_status,
        )

    def _mark(
        self,
        *,
        request_id: str,
        run_id: str,
        work_id: str,
        status: str,
        result_status: str,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM publication_consumptions WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise PublicationLedgerError(
                    "Publication authorization has not been reserved"
                )
            record = record_from_row(row)
            if record["run_id"] != run_id or record["work_id"] != work_id:
                raise PublicationLedgerError(
                    "Publication authorization is reserved by another run"
                )
            if record["status"] == "published" and status == "published":
                return record
            if record["status"] != "reserved":
                raise PublicationLedgerError(
                    f"Publication authorization is already {record['status']}"
                )
            connection.execute(
                """
                UPDATE publication_consumptions
                SET status = ?, result_status = ?, updated_at = ?
                WHERE request_id = ? AND run_id = ? AND work_id = ?
                    AND status = 'reserved'
                """,
                (status, result_status, now, request_id, run_id, work_id),
            )
            updated = connection.execute(
                "SELECT * FROM publication_consumptions WHERE request_id = ?",
                (request_id,),
            ).fetchone()
        if updated is None:
            raise PublicationLedgerError("Publication ledger update failed")
        return record_from_row(updated)

    def get(self, request_id: str) -> dict[str, Any]:
        with closing(self.connect()) as connection:
            row = connection.execute(
                "SELECT * FROM publication_consumptions WHERE request_id = ?",
                (request_id,),
            ).fetchone()
        if row is None:
            raise KeyError(request_id)
        return record_from_row(row)


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def record_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "request_id": str(row["request_id"]),
        "request_sha256": str(row["request_sha256"]),
        "run_id": str(row["run_id"]),
        "work_id": str(row["work_id"]),
        "status": str(row["status"]),
        "target_full_name": str(row["target_full_name"]),
        "secure_branch": str(row["secure_branch"]),
        "patch_sha": str(row["patch_sha"]),
        "expected_remote_sha": (
            None
            if row["expected_remote_sha"] is None
            else str(row["expected_remote_sha"])
        ),
        "result_status": (
            None if row["result_status"] is None else str(row["result_status"])
        ),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }
