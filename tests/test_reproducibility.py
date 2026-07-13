from __future__ import annotations

import gzip
import hashlib
import json
import shutil
import tarfile
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from assured_downstream.reproducibility import (
    ReproducibilityError,
    compare_verified_builds,
    inspect_tar_archive,
)


class ReproducibilityTests(unittest.TestCase):
    def test_classifies_archive_metadata_drift_without_granting_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            left = write_bundle(
                root / "left",
                archive_mtime=100,
                builder_started="2026-07-13T01:00:00Z",
                sbom_created="2026-07-13T01:01:00Z",
                namespace="left",
                temp_token="aaaaaaaa",
            )
            right = write_bundle(
                root / "right",
                archive_mtime=200,
                builder_started="2026-07-13T02:00:00Z",
                sbom_created="2026-07-13T02:01:00Z",
                namespace="right",
                temp_token="bbbbbbbb",
                reverse_artifacts=True,
            )

            analysis = compare_verified_builds(
                left_evidence_path=left,
                right_evidence_path=right,
                left_verification=verification_record("1", left),
                right_verification=verification_record("2", right),
                left_execution_id="github-actions:1",
                right_execution_id="github-actions:2",
            )

            report = analysis.report
            self.assertFalse(report["reproducible"])
            self.assertFalse(report["provider_independent"])
            self.assertTrue(report["artifacts"]["payload_equivalent"])
            comparisons = report["artifacts"]["comparisons"]
            self.assertEqual(
                [entry["name"] for entry in comparisons],
                ["project-1.0-py3-none-any.whl", "project-1.0.tar.gz"],
            )
            archive = comparisons[1]
            self.assertEqual(archive["classification"], "archive-metadata-only")
            self.assertEqual(
                archive["archive"]["metadata_difference_fields"],
                ["gzip_mtime", "mtime"],
            )
            self.assertTrue(report["sbom"]["package_inventory_match"])
            self.assertFalse(report["sbom"]["artifact_bindings_match"])
            self.assertTrue(report["builder"]["stable_match"])
            self.assertTrue(report["behavior_diagnostic"]["normalized_match"])
            self.assertEqual(
                [finding["code"] for finding in report["blocking_findings"]],
                ["artifact-byte-mismatch", "sbom-byte-mismatch"],
            )

    def test_exact_artifacts_and_sbom_can_match_across_distinct_executions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            left = write_bundle(
                root / "left",
                archive_mtime=100,
                builder_started="2026-07-13T01:00:00Z",
                sbom_created="2026-07-13T01:01:00Z",
                namespace="stable",
                temp_token="aaaaaaaa",
            )
            right = write_bundle(
                root / "right",
                archive_mtime=100,
                builder_started="2026-07-13T02:00:00Z",
                sbom_created="2026-07-13T01:01:00Z",
                namespace="stable",
                temp_token="bbbbbbbb",
                copy_artifacts_from=left.parent,
            )

            analysis = compare_verified_builds(
                left_evidence_path=left,
                right_evidence_path=right,
                left_verification=verification_record("1", left),
                right_verification=verification_record("2", right),
                left_execution_id="github-actions:1",
                right_execution_id="github-actions:2",
            )

            self.assertTrue(analysis.report["reproducible"])
            self.assertTrue(analysis.report["ok"])
            self.assertEqual(analysis.report["blocking_findings"], [])
            self.assertFalse(analysis.report["provider_independent"])

    def test_rejects_reused_attestation_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            left = write_bundle(
                root / "left",
                archive_mtime=100,
                builder_started="2026-07-13T01:00:00Z",
                sbom_created="2026-07-13T01:01:00Z",
                namespace="stable",
                temp_token="aaaaaaaa",
            )
            right = write_bundle(
                root / "right",
                archive_mtime=100,
                builder_started="2026-07-13T02:00:00Z",
                sbom_created="2026-07-13T01:01:00Z",
                namespace="stable",
                temp_token="bbbbbbbb",
                copy_artifacts_from=left.parent,
            )
            left_record = verification_record("1", left)
            right_record = verification_record("1", right)

            with self.assertRaisesRegex(
                ReproducibilityError,
                "same verified attestation set",
            ):
                compare_verified_builds(
                    left_evidence_path=left,
                    right_evidence_path=right,
                    left_verification=left_record,
                    right_verification=right_record,
                    left_execution_id="github-actions:1",
                    right_execution_id="github-actions:2",
                )

    def test_rejects_unsafe_archive_member(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "unsafe.tar.gz"
            write_tar(path, mtime=100, member_name="../escape")

            with self.assertRaisesRegex(ReproducibilityError, "unsafe"):
                inspect_tar_archive(path)

    def test_binds_compared_manifest_to_fresh_verification_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            left = write_bundle(
                root / "left",
                archive_mtime=100,
                builder_started="2026-07-13T01:00:00Z",
                sbom_created="2026-07-13T01:01:00Z",
                namespace="stable",
                temp_token="aaaaaaaa",
            )
            right = write_bundle(
                root / "right",
                archive_mtime=100,
                builder_started="2026-07-13T02:00:00Z",
                sbom_created="2026-07-13T01:01:00Z",
                namespace="stable",
                temp_token="bbbbbbbb",
                copy_artifacts_from=left.parent,
            )
            left_record = verification_record("1", left)
            right_record = verification_record("2", right)
            left.write_text("{}\n", encoding="utf-8")

            with self.assertRaisesRegex(
                ReproducibilityError,
                "does not match its verification record",
            ):
                compare_verified_builds(
                    left_evidence_path=left,
                    right_evidence_path=right,
                    left_verification=left_record,
                    right_verification=right_record,
                    left_execution_id="github-actions:1",
                    right_execution_id="github-actions:2",
                )

    def test_rejects_duplicate_normalized_archive_members(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "duplicate.tar.gz"
            write_custom_tar(path, ["project/file.py", "./project/file.py"])

            with self.assertRaisesRegex(ReproducibilityError, "duplicate member"):
                inspect_tar_archive(path)

    def test_rejects_archive_links_and_malformed_gzip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            linked = root / "linked.tar.gz"
            with linked.open("wb") as raw:
                with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=1) as zipped:
                    with tarfile.open(fileobj=zipped, mode="w") as archive:
                        member = tarfile.TarInfo("project/link")
                        member.type = tarfile.SYMTYPE
                        member.linkname = "target"
                        archive.addfile(member)
            with self.assertRaisesRegex(ReproducibilityError, "special member"):
                inspect_tar_archive(linked)

            malformed = root / "malformed.tar.gz"
            malformed.write_bytes(b"not gzip")
            with self.assertRaisesRegex(ReproducibilityError, "inspect tar archive"):
                inspect_tar_archive(malformed)

    def test_enforces_archive_member_and_payload_limits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "limited.tar.gz"
            write_custom_tar(path, ["project/a", "project/b"])

            with (
                patch(
                    "assured_downstream.reproducibility.MAX_ARCHIVE_MEMBERS",
                    1,
                ),
                self.assertRaisesRegex(ReproducibilityError, "member count limit"),
            ):
                inspect_tar_archive(path)
            with (
                patch(
                    "assured_downstream.reproducibility.MAX_ARCHIVE_PAYLOAD_BYTES",
                    1,
                ),
                self.assertRaisesRegex(ReproducibilityError, "payload size limit"),
            ):
                inspect_tar_archive(path)

    def test_behavior_difference_is_diagnostic_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            left = write_bundle(
                root / "left",
                archive_mtime=100,
                builder_started="2026-07-13T01:00:00Z",
                sbom_created="2026-07-13T01:01:00Z",
                namespace="stable",
                temp_token="aaaaaaaa",
            )
            right = write_bundle(
                root / "right",
                archive_mtime=100,
                builder_started="2026-07-13T02:00:00Z",
                sbom_created="2026-07-13T01:01:00Z",
                namespace="stable",
                temp_token="bbbbbbbb",
                behavior_variant=True,
                copy_artifacts_from=left.parent,
            )

            analysis = compare_verified_builds(
                left_evidence_path=left,
                right_evidence_path=right,
                left_verification=verification_record("1", left),
                right_verification=verification_record("2", right),
                left_execution_id="github-actions:1",
                right_execution_id="github-actions:2",
            )

            self.assertTrue(analysis.report["reproducible"])
            self.assertFalse(
                analysis.report["behavior_diagnostic"]["normalized_match"]
            )
            self.assertIn(
                "diagnostic-behavior-mismatch",
                [warning["code"] for warning in analysis.report["warnings"]],
            )


def write_bundle(
    root: Path,
    *,
    archive_mtime: int,
    builder_started: str,
    sbom_created: str,
    namespace: str,
    temp_token: str,
    reverse_artifacts: bool = False,
    copy_artifacts_from: Path | None = None,
    behavior_variant: bool = False,
) -> Path:
    dist = root / "dist"
    reports = root / "reports"
    traces = root / "traces"
    sbom_root = root / "sbom"
    for directory in (dist, reports, traces, sbom_root):
        directory.mkdir(parents=True, exist_ok=True)

    wheel = dist / "project-1.0-py3-none-any.whl"
    archive = dist / "project-1.0.tar.gz"
    if copy_artifacts_from is None:
        wheel.write_bytes(b"wheel\n")
        write_tar(archive, mtime=archive_mtime)
    else:
        shutil.copyfile(copy_artifacts_from / "dist" / wheel.name, wheel)
        shutil.copyfile(copy_artifacts_from / "dist" / archive.name, archive)

    source_inventory = reports / "source-inventory.json"
    write_json(source_inventory, {"files": [{"path": "src/project.py", "sha256": "a" * 64}]})
    builder = reports / "builder.json"
    write_json(
        builder,
        {
            "schema_version": 1,
            "status": "succeeded",
            "profile": "python-wheel-v2",
            "builder": {"image_digest": "sha256:" + "b" * 64},
            "source": {"commit": "c" * 40, "git_tree": "d" * 40},
            "execution": {
                "cwd": "/workspace/source",
                "started_at": builder_started,
                "finished_at": builder_started,
                "returncode": 0,
                "network_policy": "deny",
            },
            "trace": {"raw_file_count": 1, "parsed_line_count": 4},
        },
    )
    trace = traces / "observed-trace.json"
    write_json(
        trace,
        {
            "schema_version": 1,
            "collector": {"name": "strace", "version": "6.1"},
            "coverage": {
                "file": True,
                "network": True,
                "process": True,
                "syscall": True,
            },
            "parsed_line_count": 4,
            "raw_file_count": 1,
            "signal_line_count": 0,
            "syscall_line_count": 4,
            "exit_line_count": 0,
            "unparsed_line_count": 0,
            "events": [
                {
                    "kind": "file",
                    "operation": "write",
                    "outcome": "success",
                    "count": 1,
                    "path": f"/tmp/build-via-sdist-{temp_token}/project.py",
                },
                {
                    "kind": "syscall",
                    "name": "openat",
                    "outcome": "success",
                    "count": 3 if behavior_variant else 4,
                },
                *(
                    [
                        {
                            "kind": "syscall",
                            "name": "close",
                            "outcome": "success",
                            "count": 1,
                        }
                    ]
                    if behavior_variant
                    else []
                ),
            ],
        },
    )
    sbom = sbom_root / "sbom.spdx.json"
    artifact_entries = [entry_for(wheel, root), entry_for(archive, root)]
    if reverse_artifacts:
        artifact_entries.reverse()
    write_json(
        sbom,
        {
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "name": "dist",
            "documentNamespace": f"https://example.invalid/{namespace}",
            "creationInfo": {
                "created": sbom_created,
                "creators": ["Tool: fixture"],
            },
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package",
                    "name": "project",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                }
            ],
            "files": [
                {
                    "SPDXID": f"SPDXRef-{entry['sha256'][:12]}",
                    "fileName": entry["path"],
                    "checksums": [
                        {
                            "algorithm": "SHA256",
                            "checksumValue": entry["sha256"],
                        }
                    ],
                }
                for entry in artifact_entries
            ],
            "relationships": [],
        },
    )

    artifacts = [entry_for(wheel, root), entry_for(archive, root)]
    if reverse_artifacts:
        artifacts.reverse()
    manifest = {
        "schema_version": 1,
        "project": {
            "source_full_name": "example/project",
            "target_full_name": "SauceTaster/assured-project",
            "upstream_ref": "c" * 40,
            "overlay_ref": "c" * 40,
            "release_tag": "case-project",
            "assurance": "Evidence-candidate",
        },
        "evidence": {
            "artifacts": artifacts,
            "reports": [entry_for(source_inventory, root), entry_for(builder, root)],
            "sboms": [entry_for(sbom, root)],
            "traces": [entry_for(trace, root)],
        },
    }
    manifest_path = root / "evidence.json"
    write_json(manifest_path, manifest)
    return manifest_path


def write_tar(
    path: Path,
    *,
    mtime: int,
    member_name: str = "project-1.0/project.py",
) -> None:
    payload = b"print('hello')\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=mtime) as zipped:
            with tarfile.open(fileobj=zipped, mode="w") as archive:
                directory = tarfile.TarInfo("project-1.0")
                directory.type = tarfile.DIRTYPE
                directory.mode = 0o755
                directory.mtime = mtime
                archive.addfile(directory)
                member = tarfile.TarInfo(member_name)
                member.size = len(payload)
                member.mode = 0o644
                member.mtime = mtime
                archive.addfile(member, BytesIO(payload))


def write_custom_tar(path: Path, names: list[str]) -> None:
    payload = b"payload\n"
    with path.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=1) as zipped:
            with tarfile.open(fileobj=zipped, mode="w") as archive:
                for name in names:
                    member = tarfile.TarInfo(name)
                    member.size = len(payload)
                    member.mode = 0o644
                    member.mtime = 1
                    archive.addfile(member, BytesIO(payload))


def entry_for(path: Path, root: Path) -> dict[str, object]:
    payload = path.read_bytes()
    return {
        "name": path.name,
        "path": path.relative_to(root).as_posix(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }


def verification_record(
    bundle_token: str,
    evidence_path: Path,
) -> dict[str, object]:
    values = {
        "authority": "code-anchored-reusable-workflow-sigstore",
        "builder_image": "builder@sha256:" + "b" * 64,
        "case_id": "case-project",
        "policy_sha256": "3" * 64,
        "signer": "SauceTaster/assured-downstream/reusable.yml",
        "signer_digest": "4" * 40,
        "source_commit": "c" * 40,
        "source_repository": "example/project",
        "target_full_name": "SauceTaster/assured-project",
        "trust_policy_sha256": "5" * 64,
    }
    return {
        "schema_version": 1,
        "status": "verified-evidence-candidate",
        "ok": True,
        **values,
        "evidence_sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
        "caller_digest": "6" * 40,
        "bundles": {
            "build": {"sha256": bundle_token * 64},
            "provenance": {"sha256": bundle_token * 64},
            "sbom": {"sha256": bundle_token * 64},
        },
    }


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
