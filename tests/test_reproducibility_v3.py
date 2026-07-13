from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from assured_downstream.reproducibility_v3 import (
    ReproducibilityV3Error,
    compare_verified_builds_v3,
)


class ReproducibilityV3Tests(unittest.TestCase):
    def test_matches_canonical_outputs_and_normalized_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            left_manifest, left_verification = write_bundle(
                root / "left",
                run_id="1001",
                temp_token="abcdefgh",
                raw_sdist=b"raw-sdist-left",
            )
            right_manifest, right_verification = write_bundle(
                root / "right",
                run_id="1002",
                temp_token="ijklmnop",
                raw_sdist=b"raw-sdist-right",
            )

            analysis = compare_verified_builds_v3(
                left_evidence_path=left_manifest,
                right_evidence_path=right_manifest,
                left_verification=left_verification,
                right_verification=right_verification,
                left_execution_id="github-actions:1001",
                right_execution_id="github-actions:1002",
            )

            self.assertTrue(analysis.report["reproducible"])
            self.assertTrue(
                analysis.report["behavior_reproducibility_candidate"]
            )
            self.assertFalse(analysis.report["provider_independent"])
            self.assertFalse(analysis.report["raw_artifacts"]["exact_match"])
            self.assertEqual(analysis.report["blocking_findings"], [])

    def test_final_artifact_mismatch_blocks_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            left_manifest, left_verification = write_bundle(
                root / "left",
                run_id="2001",
                temp_token="abcdefgh",
                raw_sdist=b"raw-left",
            )
            right_manifest, right_verification = write_bundle(
                root / "right",
                run_id="2002",
                temp_token="ijklmnop",
                raw_sdist=b"raw-right",
                final_wheel=b"different-wheel",
            )

            analysis = compare_verified_builds_v3(
                left_evidence_path=left_manifest,
                right_evidence_path=right_manifest,
                left_verification=left_verification,
                right_verification=right_verification,
                left_execution_id="github-actions:2001",
                right_execution_id="github-actions:2002",
            )

            self.assertFalse(analysis.report["reproducible"])
            self.assertFalse(analysis.report["core_checks"]["artifacts"])
            self.assertIn(
                "artifacts-mismatch",
                {item["code"] for item in analysis.report["blocking_findings"]},
            )

    def test_run_and_attestation_bindings_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            left_manifest, left_verification = write_bundle(
                root / "left",
                run_id="3001",
                temp_token="abcdefgh",
                raw_sdist=b"raw-left",
            )
            right_manifest, right_verification = write_bundle(
                root / "right",
                run_id="3002",
                temp_token="ijklmnop",
                raw_sdist=b"raw-right",
            )
            with self.assertRaisesRegex(
                ReproducibilityV3Error,
                "execution id is not bound",
            ):
                compare_verified_builds_v3(
                    left_evidence_path=left_manifest,
                    right_evidence_path=right_manifest,
                    left_verification=left_verification,
                    right_verification=right_verification,
                    left_execution_id="github-actions:9999",
                    right_execution_id="github-actions:3002",
                )

            left_verification["bundles"]["build"]["sha256"] = "0" * 64
            with self.assertRaisesRegex(
                ReproducibilityV3Error,
                "build bundle is not bound",
            ):
                compare_verified_builds_v3(
                    left_evidence_path=left_manifest,
                    right_evidence_path=right_manifest,
                    left_verification=left_verification,
                    right_verification=right_verification,
                    left_execution_id="github-actions:3001",
                    right_execution_id="github-actions:3002",
                )


def write_bundle(
    root: Path,
    *,
    run_id: str,
    temp_token: str,
    raw_sdist: bytes,
    final_wheel: bytes = b"canonical-wheel",
) -> tuple[Path, dict]:
    source_inventory = {
        "schema_version": 1,
        "entries": [
            {
                "path": "pyproject.toml",
                "type": "file",
                "size": 1,
                "sha256": "1" * 64,
                "executable": False,
            }
        ],
        "tree_sha256": "2" * 64,
    }
    builder = {
        "schema_version": 1,
        "profile": "python-wheel-v3",
        "execution": {
            "cwd": "/workspace/source",
            "started_at": f"2026-07-13T00:00:{run_id[-1]}0Z",
            "finished_at": f"2026-07-13T00:00:{run_id[-1]}1Z",
        },
        "artifact_transforms": {
            "policy_id": "python-sdist-pax-v1",
            "report_path": "reports/artifact-transforms.json",
            "report_sha256": hashlib.sha256(run_id.encode()).hexdigest(),
        },
        "source": {"filesystem_sha256": source_inventory["tree_sha256"]},
    }
    trace = {
        "schema_version": 1,
        "collector": {
            "name": "strace",
            "version": "6.1",
            "platform": "linux",
            "mode": "follow-forks-full-syscall",
        },
        "coverage": {"process": True, "file": True, "network": True, "syscall": True},
        "coverage_basis": "complete-parser-pass",
        "raw_file_count": 1,
        "parsed_line_count": 2,
        "syscall_line_count": 1,
        "signal_line_count": 1,
        "exit_line_count": 0,
        "unparsed_line_count": 0,
        "events": [
            {
                "kind": "file",
                "operation": "access",
                "outcome": "success",
                "path": f"/tmp/tmp{temp_token}/input.json",
                "count": 1,
            },
            {
                "kind": "signal",
                "name": "SIGCHLD",
                "count": 1,
            },
            {
                "kind": "syscall",
                "name": "openat",
                "outcome": "success",
                "count": 1,
            },
        ],
    }
    files = {
        "artifacts": {
            "dist/package-1.0-py3-none-any.whl": final_wheel,
            "dist/package-1.0.tar.gz": b"canonical-sdist",
        },
        "attestations": {
            "attestations/build.sigstore.json": f"build-{run_id}\n".encode(),
            "attestations/provenance.sigstore.json": (
                f"provenance-{run_id}\n".encode()
            ),
            "attestations/sbom.sigstore.json": f"sbom-{run_id}\n".encode(),
        },
        "raw_artifacts": {
            "raw-artifacts/package-1.0-py3-none-any.whl": final_wheel,
            "raw-artifacts/package-1.0.tar.gz": raw_sdist,
        },
        "reports": {
            "reports/builder.json": json_bytes(builder),
            "reports/source-inventory.json": json_bytes(source_inventory),
            "reports/trusted-source-inventory.json": json_bytes(
                {"inventory": source_inventory}
            ),
        },
        "sboms": {
            "sbom/raw/syft.spdx.json": json_bytes(
                {"created": run_id, "name": "raw"}
            ),
            "sbom/sbom.spdx.json": json_bytes(
                {"SPDXID": "SPDXRef-DOCUMENT", "name": "canonical"}
            ),
        },
        "traces": {"traces/observed-trace.json": json_bytes(trace)},
    }
    roles = {}
    for role, role_files in files.items():
        entries = []
        for logical_path, payload in sorted(role_files.items()):
            path = root / logical_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            entries.append(
                {
                    "logical_path": logical_path,
                    "name": path.name,
                    "path": logical_path,
                    "role": role,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                }
            )
        roles[role] = entries
    manifest = {
        "schema_version": 2,
        "generated_at": "2026-07-13T00:00:00+00:00",
        "project": {
            "source_full_name": "PyCQA/bandit",
            "target_full_name": "SauceTaster/assured-bandit",
            "upstream_ref": "a" * 40,
            "overlay_ref": "a" * 40,
            "release_tag": "case-001-bandit-source-canary-v3",
            "assurance": "Evidence-candidate",
        },
        "evidence": roles,
    }
    manifest_path = root / "evidence.json"
    manifest_path.write_bytes(json_bytes(manifest))
    artifacts = [
        {
            "name": entry["logical_path"],
            "sha256": entry["sha256"],
        }
        for entry in roles["artifacts"]
    ]
    attestation_by_name = {
        entry["logical_path"]: entry for entry in roles["attestations"]
    }
    verification = {
        "schema_version": 2,
        "status": "verified-evidence-candidate",
        "ok": True,
        "authority": "code-anchored-reusable-workflow-sigstore",
        "builder_image": "example.invalid/builder@sha256:" + "3" * 64,
        "case_id": "case-001-bandit-source-canary-v3",
        "caller_digest": "4" * 40,
        "policy_sha256": "5" * 64,
        "signer": "SauceTaster/assured-downstream/.github/workflows/reusable.yml",
        "signer_digest": "6" * 40,
        "source_commit": "7" * 40,
        "source_repository": "PyCQA/bandit",
        "target_full_name": "SauceTaster/assured-bandit",
        "trust_policy_sha256": "8" * 64,
        "evidence_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "workflow_run": {"id": run_id},
        "verified_subjects": artifacts,
        "bundles": {
            role: {
                "sha256": attestation_by_name[
                    f"attestations/{role}.sigstore.json"
                ]["sha256"]
            }
            for role in ("build", "provenance", "sbom")
        },
    }
    return manifest_path, verification


def json_bytes(value: dict) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


if __name__ == "__main__":
    unittest.main()
