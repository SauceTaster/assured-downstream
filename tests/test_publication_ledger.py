from __future__ import annotations

import os
import pwd
import tempfile
import unittest
from pathlib import Path

from assured_downstream.publication_ledger import (
    PublicationLedger,
    PublicationLedgerError,
    trusted_publication_ledger_path,
)


class PublicationLedgerTests(unittest.TestCase):
    def test_trusted_ledger_path_is_derived_from_os_account(self) -> None:
        account_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
        path = trusted_publication_ledger_path()

        self.assertTrue(path.is_relative_to(account_home))
        self.assertEqual(path.name, "publication-ledger.sqlite3")

    def test_same_work_can_reconcile_reserved_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = PublicationLedger(Path(tmp) / "publications.sqlite3")
            fields = reservation_fields()

            first = ledger.reserve(**fields)
            repeated = ledger.reserve(**fields)
            published = ledger.mark_published(
                request_id=fields["request_id"],
                run_id=fields["run_id"],
                work_id=fields["work_id"],
                result_status="already-published",
            )

            self.assertEqual(first["status"], "reserved")
            self.assertEqual(repeated["status"], "reserved")
            self.assertEqual(published["status"], "published")

    def test_authorization_cannot_be_replayed_in_another_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = PublicationLedger(Path(tmp) / "publications.sqlite3")
            fields = reservation_fields()
            ledger.reserve(**fields)

            with self.assertRaisesRegex(PublicationLedgerError, "replay"):
                ledger.reserve(
                    **{
                        **fields,
                        "run_id": "another-run",
                        "work_id": "another-work",
                    }
                )

    def test_request_digest_collision_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = PublicationLedger(Path(tmp) / "publications.sqlite3")
            fields = reservation_fields()
            ledger.reserve(**fields)

            with self.assertRaises(PublicationLedgerError):
                ledger.reserve(
                    **{
                        **fields,
                        "request_id": "sha256:" + "2" * 64,
                    }
                )


def reservation_fields() -> dict:
    return {
        "request_id": "sha256:" + "1" * 64,
        "request_sha256": "2" * 64,
        "run_id": "run",
        "work_id": "work",
        "target_full_name": "user/target",
        "secure_branch": "secure/main",
        "patch_sha": "3" * 40,
        "expected_remote_sha": None,
    }


if __name__ == "__main__":
    unittest.main()
