from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from assured_downstream.attestations import INTOTO_STATEMENT_V1, create_intoto_statement


class AttestationTests(unittest.TestCase):
    def test_creates_intoto_statement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "tool"
            artifact.write_text("artifact", encoding="utf-8")

            statement = create_intoto_statement(
                subjects=[artifact],
                predicate_type="https://assured-downstream.dev/attestation/trace/v1",
                predicate={"builder": "test"},
            )

        self.assertEqual(statement["_type"], INTOTO_STATEMENT_V1)
        self.assertEqual(statement["subject"][0]["name"], "tool")
        self.assertIn("sha256", statement["subject"][0]["digest"])
        self.assertEqual(statement["predicate"]["builder"], "test")


if __name__ == "__main__":
    unittest.main()

