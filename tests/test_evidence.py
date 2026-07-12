from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from assured_downstream.evidence import (
    compare_evidence_manifests,
    create_evidence_manifest,
    verify_evidence_manifest,
)


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

    def test_portable_manifest_verifies_after_bundle_move(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "bundle-a"
            artifact = bundle / "artifacts" / "tool"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("portable", encoding="utf-8")
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
                root=bundle,
            )
            self.assertEqual(
                manifest["evidence"]["artifacts"][0]["path"],
                "artifacts/tool",
            )
            moved = root / "bundle-b"
            bundle.rename(moved)

            result = verify_evidence_manifest(manifest, base_dir=moved)

        self.assertTrue(result["ok"])

    def test_portable_manifest_rejects_bundle_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside"
            outside.write_text("outside", encoding="utf-8")
            manifest = {
                "evidence": {
                    "artifacts": [
                        {
                            "path": "../outside",
                            "sha256": "0" * 64,
                            "size": 7,
                        }
                    ]
                }
            }

            result = verify_evidence_manifest(
                manifest,
                base_dir=root / "bundle",
            )

        self.assertFalse(result["ok"])
        self.assertIn("escapes evidence bundle", result["failures"][0])

    def test_compares_matching_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as left_tmp, tempfile.TemporaryDirectory() as right_tmp:
            left_artifact = Path(left_tmp) / "tool"
            right_artifact = Path(right_tmp) / "tool"
            left_artifact.write_text("same", encoding="utf-8")
            right_artifact.write_text("same", encoding="utf-8")
            left = minimal_manifest(left_artifact)
            right = minimal_manifest(right_artifact)

            result = compare_evidence_manifests(left, right)

        self.assertTrue(result["ok"])
        self.assertEqual(result["summary"]["matches"], 1)

    def test_compares_mismatching_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as left_tmp, tempfile.TemporaryDirectory() as right_tmp:
            left_artifact = Path(left_tmp) / "tool"
            right_artifact = Path(right_tmp) / "tool"
            left_artifact.write_text("left", encoding="utf-8")
            right_artifact.write_text("right", encoding="utf-8")
            left = minimal_manifest(left_artifact)
            right = minimal_manifest(right_artifact)

            result = compare_evidence_manifests(left, right)

        self.assertFalse(result["ok"])
        self.assertIn("sha256 differs", result["failures"][0])


def minimal_manifest(artifact: Path) -> dict:
    return create_evidence_manifest(
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


if __name__ == "__main__":
    unittest.main()
