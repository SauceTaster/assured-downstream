from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from assured_downstream.builder_handoff import (
    BUILDER_CLAIM_LIMIT,
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
            self.assertEqual(
                predicate["builder"]["identityBoundary"]["collectorUid"], 0
            )
            self.assertEqual(
                predicate["builder"]["identityBoundary"]["buildUid"], 65532
            )
            self.assertFalse(
                predicate["builder"]["identityBoundary"][
                    "collectorOutputWritableByBuild"
                ]
            )
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

    def test_rejects_identity_boundary_drift(self) -> None:
        mutations = {
            "collector uid": ("collector_uid", 65532),
            "evidence mode": ("evidence_mode", "0755"),
            "trace ownership": ("raw_trace_owner_uid", 65532),
            "writable evidence": ("collector_output_writable_by_build", True),
            "surviving process": ("remaining_process_count", 1),
            "missing separation": ("separate_collector_identity", False),
            "wrong barrier": ("quiescence_barrier", "strace-follow-forks"),
        }
        for label, (field, value) in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                create_builder_output(root)
                builder_path = root / "reports" / "builder.json"
                report = json.loads(builder_path.read_text())
                report["execution"]["identity_boundary"][field] = value
                builder_path.write_text(json.dumps(report), encoding="utf-8")

                with self.assertRaisesRegex(
                    BuilderHandoffError,
                    "identity boundary",
                ):
                    validate_builder_output(
                        root,
                        source_repository=SOURCE_REPOSITORY,
                        source_commit=SOURCE_COMMIT,
                        source_tree=SOURCE_TREE,
                        project_version=PROJECT_VERSION,
                    )

    def test_rejects_invalid_killed_process_count(self) -> None:
        for value in (-1, True, "0"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                create_builder_output(root)
                builder_path = root / "reports" / "builder.json"
                report = json.loads(builder_path.read_text())
                report["execution"]["identity_boundary"]["killed_process_count"] = value
                builder_path.write_text(json.dumps(report), encoding="utf-8")

                with self.assertRaisesRegex(BuilderHandoffError, "process count"):
                    validate_builder_output(
                        root,
                        source_repository=SOURCE_REPOSITORY,
                        source_commit=SOURCE_COMMIT,
                        source_tree=SOURCE_TREE,
                        project_version=PROJECT_VERSION,
                    )

    def test_rejects_incomplete_reports_and_boolean_numbers(self) -> None:
        mutations = (
            (
                "missing validation error",
                "reports/builder.json",
                lambda value: value["execution"].pop("validation_error"),
            ),
            (
                "boolean return code",
                "reports/builder.json",
                lambda value: value["execution"].__setitem__("returncode", False),
            ),
            (
                "boolean trace schema",
                "traces/observed-trace.json",
                lambda value: value.__setitem__("schema_version", True),
            ),
            (
                "boolean parsed count",
                "traces/observed-trace.json",
                lambda value: value.__setitem__("parsed_line_count", True),
            ),
            (
                "boolean unparsed count",
                "traces/observed-trace.json",
                lambda value: value.__setitem__("unparsed_line_count", False),
            ),
            (
                "boolean inventory schema",
                "reports/artifact-inventory.json",
                lambda value: value.__setitem__("schema_version", True),
            ),
            (
                "boolean report trace count",
                "reports/builder.json",
                lambda value: value["trace"].__setitem__("signal_line_count", False),
            ),
        )
        for label, relative_path, mutate in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                create_builder_output(root)
                path = root / relative_path
                value = json.loads(path.read_text())
                mutate(value)
                path.write_text(json.dumps(value), encoding="utf-8")

                with self.assertRaises(BuilderHandoffError):
                    validate_builder_output(
                        root,
                        source_repository=SOURCE_REPOSITORY,
                        source_commit=SOURCE_COMMIT,
                        source_tree=SOURCE_TREE,
                        project_version=PROJECT_VERSION,
                    )

    def test_rejects_missing_trace_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_builder_output(root)
            trace_path = root / "traces" / "observed-trace.json"
            trace = json.loads(trace_path.read_text())
            trace["coverage"] = {
                "process": False,
                "file": False,
                "network": False,
                "syscall": False,
            }
            trace["coverage_basis"] = "insufficient-parser-pass"
            trace["parsed_line_count"] = 0
            trace["raw_file_count"] = 0
            trace_path.write_text(json.dumps(trace), encoding="utf-8")
            builder_path = root / "reports" / "builder.json"
            report = json.loads(builder_path.read_text())
            report["trace"] = {
                "coverage": trace["coverage"],
                "raw_file_count": 0,
                "parsed_line_count": 0,
                "unparsed_line_count": 0,
            }
            builder_path.write_text(json.dumps(report), encoding="utf-8")

            with self.assertRaisesRegex(BuilderHandoffError, "requires complete"):
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
            "profile": "python-wheel-v2",
            "builder": {
                "architecture": "x86_64",
                "image": BUILDER_IMAGE,
                "image_digest": BUILDER_DIGEST,
                "python": "3.12.11",
                "tools": {
                    "build": "1.5.1",
                    "packaging": "26.2",
                    "pbr": "7.0.3",
                    "pyproject-hooks": "1.2.0",
                    "setuptools": "83.0.0",
                    "wheel": "0.47.0",
                },
            },
            "source": {
                "repository": SOURCE_REPOSITORY,
                "commit": SOURCE_COMMIT,
                "git_tree": SOURCE_TREE,
                "project_version": PROJECT_VERSION,
                "source_date_epoch": "1783382521",
                "filesystem_sha256": "c" * 64,
            },
            "execution": {
                "argv": [
                    "/usr/bin/strace",
                    "-u",
                    "assured",
                    "-ff",
                    "-qq",
                    "-ttt",
                    "-T",
                    "-yy",
                    "-s",
                    "4096",
                    "-o",
                    "/out/traces/raw/strace",
                    "--",
                    "/usr/local/bin/python",
                    "-I",
                    "-m",
                    "build",
                    "--no-isolation",
                    "--outdir",
                    "/workspace/output/dist",
                    "/workspace/source",
                ],
                "cwd": "/workspace/source",
                "finished_at": "2026-07-13T03:21:22Z",
                "identity_boundary": {
                    "build_gid": 65532,
                    "build_uid": 65532,
                    "collector_gid": 0,
                    "collector_output_writable_by_build": False,
                    "collector_uid": 0,
                    "evidence_gid": 0,
                    "evidence_mode": "0700",
                    "evidence_uid": 0,
                    "killed_process_count": 0,
                    "quiescence_barrier": "private-pid-namespace-sigkill",
                    "raw_trace_owner_gid": 0,
                    "raw_trace_owner_uid": 0,
                    "remaining_process_count": 0,
                    "separate_collector_identity": True,
                },
                "network_policy": "deny",
                "returncode": 0,
                "started_at": "2026-07-13T03:21:21Z",
                "validation_error": None,
            },
            "trace": {
                "collector": {
                    "name": "strace",
                    "version": "6.1",
                    "platform": "linux",
                    "mode": "follow-forks-full-syscall",
                },
                "coverage": {
                    "process": True,
                    "file": True,
                    "network": True,
                    "syscall": True,
                },
                "raw_file_count": 1,
                "parsed_line_count": 1,
                "syscall_line_count": 1,
                "signal_line_count": 0,
                "exit_line_count": 0,
                "unparsed_line_count": 0,
            },
            "claim_limit": BUILDER_CLAIM_LIMIT,
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
                "platform": "linux",
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
            "syscall_line_count": 1,
            "signal_line_count": 0,
            "exit_line_count": 0,
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
        write_json(
            directory / name, {"mediaType": "application/vnd.dev.sigstore.bundle"}
        )


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
