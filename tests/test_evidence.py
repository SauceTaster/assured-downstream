from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from assured_downstream.evidence import create_evidence_manifest, verify_evidence_manifest


class EvidenceTests(unittest.TestCase):
    def test_creates_and_verifies_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "tool"
            sbom = root / "sbom.json"
            artifact.write_text("binary-ish\n", encoding="utf-8")
            sbom.write_text("{}\n", encoding="utf-8")

            manifest = create_evidence_manifest(
                project="owner/project",
                target_repo="assured-oss/project",
                upstream_ref="abc123",
                overlay_ref="def456",
                release_tag="secure-v1.0.0+org.1",
                assurance="Attested",
                files={
                    "artifacts": [artifact],
                    "sboms": [sbom],
                    "attestations": [],
                    "traces": [],
                    "reports": [],
                },
            )

            result = verify_evidence_manifest(manifest)

        self.assertTrue(result["ok"])
        self.assertEqual(manifest["evidence"]["artifacts"][0]["name"], "tool")

    def test_detects_modified_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "tool"
            artifact.write_text("before", encoding="utf-8")
            manifest = create_evidence_manifest(
                project="owner/project",
                target_repo="assured-oss/project",
                upstream_ref="abc123",
                overlay_ref="def456",
                release_tag="secure-v1.0.0+org.1",
                assurance="Attested",
                files={
                    "artifacts": [artifact],
                    "sboms": [],
                    "attestations": [],
                    "traces": [],
                    "reports": [],
                },
            )
            artifact.write_text("after", encoding="utf-8")

            result = verify_evidence_manifest(manifest)

        self.assertFalse(result["ok"])
        self.assertIn("sha256 mismatch", result["failures"][0])


if __name__ == "__main__":
    unittest.main()

