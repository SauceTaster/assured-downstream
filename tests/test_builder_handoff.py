from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from assured_downstream.builder_handoff import (
    BUILDER_DIGEST,
    BUILDER_IMAGE,
    BuilderHandoffError,
    assemble_evidence,
    bind_spdx,
    create_build_predicate,
    validate_builder_output,
)
from assured_downstream.evidence import sha256_file, verify_evidence_manifest


SOURCE_REPOSITORY = "PyCQA/bandit"
SOURCE_COMMIT = "a" * 40
SOURCE_TREE = "b" * 40
UPSTREAM_COMMIT = SOURCE_COMMIT
PROJECT_VERSION = "1.9.4"


class BuilderHandoffTests(unittest.TestCase):
    def test_validates_binds_and_assembles_portable_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_builder_output(root)
            create_base_sbom(root)

            validate_builder_output(
                root,
                source_repository=SOURCE_REPOSITORY,
                source_commit=SOURCE_COMMIT,
                source_tree=SOURCE_TREE,
                project_version=PROJECT_VERSION,
            )
            bind_spdx(root)
            predicate = create_build_predicate(
                root,
                source_repository=SOURCE_REPOSITORY,
                source_commit=SOURCE_COMMIT,
                source_tree=SOURCE_TREE,
                upstream_repository=SOURCE_REPOSITORY,
                upstream_commit=UPSTREAM_COMMIT,
                target_repository="SauceTaster/assured-bandit",
                project_version=PROJECT_VERSION,
                release_tag="case-001-bandit",
                case_id="case-001",
                caller_repository="SauceTaster/assured-downstream",
                caller_commit="c" * 40,
                caller_ref="refs/heads/main",
                source_date_epoch="1783382521",
            )
            create_attestations(root)
            result = assemble_evidence(
                root,
                source_repository=SOURCE_REPOSITORY,
                source_commit=SOURCE_COMMIT,
                source_tree=SOURCE_TREE,
                upstream_repository=SOURCE_REPOSITORY,
                upstream_commit=UPSTREAM_COMMIT,
                target_repository="SauceTaster/assured-bandit",
                project_version=PROJECT_VERSION,
                release_tag="case-001-bandit",
            )

            manifest = result["manifest"]
            self.assertEqual(predicate["builder"]["imageDigest"], BUILDER_DIGEST)
            self.assertTrue(verify_evidence_manifest(manifest, base_dir=root)["ok"])
            self.assertEqual(
                result["build_result"]["builder"]["builder_id"],
                f"{BUILDER_IMAGE}@{BUILDER_DIGEST}",
            )
            self.assertEqual(len(manifest["evidence"]["attestations"]), 3)

    def test_rejects_artifact_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_builder_output(root)
            (root / "dist" / "bandit.whl").write_bytes(b"changed")

            with self.assertRaisesRegex(
                BuilderHandoffError,
                "artifact inventory",
            ):
                validate_builder_output(
                    root,
                    source_repository=SOURCE_REPOSITORY,
                    source_commit=SOURCE_COMMIT,
                    source_tree=SOURCE_TREE,
                    project_version=PROJECT_VERSION,
                )

    def test_rejects_hard_links_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_builder_output(root)
            os.link(
                root / "dist" / "bandit.whl",
                root / "dist" / "bandit-copy.whl",
            )
            with self.assertRaisesRegex(BuilderHandoffError, "hard-linked"):
                validate_builder_output(
                    root,
                    source_repository=SOURCE_REPOSITORY,
                    source_commit=SOURCE_COMMIT,
                    source_tree=SOURCE_TREE,
                    project_version=PROJECT_VERSION,
                )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_builder_output(root)
            (root / "reports" / "escape").symlink_to("/etc/passwd")
            with self.assertRaisesRegex(BuilderHandoffError, "not a regular file"):
                validate_builder_output(
                    root,
                    source_repository=SOURCE_REPOSITORY,
                    source_commit=SOURCE_COMMIT,
                    source_tree=SOURCE_TREE,
                    project_version=PROJECT_VERSION,
                )

    def test_rejects_dishonest_trace_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_builder_output(root)
            trace_path = root / "traces" / "observed-trace.json"
            trace = json.loads(trace_path.read_text())
            trace["unparsed_line_count"] = 1
            trace_path.write_text(json.dumps(trace), encoding="utf-8")

            with self.assertRaisesRegex(BuilderHandoffError, "claims coverage"):
                validate_builder_output(
                    root,
                    source_repository=SOURCE_REPOSITORY,
                    source_commit=SOURCE_COMMIT,
                    source_tree=SOURCE_TREE,
                    project_version=PROJECT_VERSION,
                )

    def test_rejects_sbom_without_document_describes_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_builder_output(root)
            (root / "sbom").mkdir()
            write_json(
                root / "sbom" / "sbom.spdx.json",
                {
                    "spdxVersion": "SPDX-2.3",
                    "SPDXID": "SPDXRef-DOCUMENT",
                    "files": [],
                    "relationships": [],
                },
            )

            with self.assertRaisesRegex(BuilderHandoffError, "does not describe"):
                validate_builder_output(
                    root,
                    source_repository=SOURCE_REPOSITORY,
                    source_commit=SOURCE_COMMIT,
                    source_tree=SOURCE_TREE,
                    project_version=PROJECT_VERSION,
                    require_sbom=True,
                )


def create_builder_output(root: Path) -> None:
    for directory in ("dist", "reports", "traces/raw"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    artifact = root / "dist" / "bandit.whl"
    artifact.write_bytes(b"wheel")
    inventory = {
        "schema_version": 1,
        "artifacts": [
            {
                "path": "dist/bandit.whl",
                "size": artifact.stat().st_size,
                "sha256": sha256_file(artifact),
            }
        ],
    }
    write_json(root / "reports" / "artifact-inventory.json", inventory)
    write_json(root / "reports" / "source-inventory.json", {"schema_version": 1})
    write_json(
        root / "reports" / "builder.json",
        {
            "schema_version": 1,
            "status": "succeeded",
            "profile": "python-wheel-v1",
            "builder": {
                "image": BUILDER_IMAGE,
                "image_digest": BUILDER_DIGEST,
            },
            "source": {
                "repository": SOURCE_REPOSITORY,
                "commit": SOURCE_COMMIT,
                "git_tree": SOURCE_TREE,
                "project_version": PROJECT_VERSION,
            },
            "execution": {
                "network_policy": "deny",
                "returncode": 0,
                "validation_error": None,
            },
        },
    )
    (root / "traces" / "raw" / "strace.1").write_text(
        "1783382521.0 execve() = 0\n",
        encoding="utf-8",
    )
    write_json(
        root / "traces" / "observed-trace.json",
        {
            "schema_version": 1,
            "collector": {
                "name": "strace",
                "version": "6.1",
                "mode": "follow-forks-full-syscall",
            },
            "coverage": {
                "process": True,
                "file": True,
                "network": True,
                "syscall": True,
            },
            "coverage_basis": "complete-parser-pass",
            "raw_file_count": 1,
            "parsed_line_count": 1,
            "unparsed_line_count": 0,
            "events": [],
        },
    )


def create_attestations(root: Path) -> None:
    directory = root / "attestations"
    directory.mkdir()
    for name in (
        "build.sigstore.json",
        "provenance.sigstore.json",
        "sbom.sigstore.json",
    ):
        write_json(directory / name, {"mediaType": "application/vnd.dev.sigstore.bundle"})


def create_base_sbom(root: Path) -> None:
    write_json(
        root / "sbom" / "sbom.spdx.json",
        {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "files": [],
            "relationships": [],
        },
    )


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
