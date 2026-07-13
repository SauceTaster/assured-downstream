from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from assured_downstream.release_render import (
    ASSURED_DOWNSTREAM_PREDICATE_TYPE,
    artifact_inventory_verification_script,
    artifact_validation_script,
    evidence_assembly_script,
    render_release_workflow,
    sbom_subject_binding_script,
    write_text_confined,
)
from assured_downstream.workflow_yaml import parse_workflow_yaml


FULL_SHA = "0123456789abcdef0123456789abcdef01234567"


class ReleaseRenderTests(unittest.TestCase):
    def test_skips_without_required_pins(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = render_release_workflow(profile(), root=Path(tmp), pins={})

        self.assertEqual(result.written, [])
        self.assertEqual(result.skipped[0]["id"], "attested-release-workflow")

    def test_renders_release_workflow_with_pins(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = render_release_workflow(
                profile(),
                root=root,
                pins={
                    "actions/checkout": FULL_SHA,
                    "actions/attest": FULL_SHA,
                    "actions/download-artifact": FULL_SHA,
                    "actions/upload-artifact": FULL_SHA,
                    "anchore/sbom-action": FULL_SHA,
                },
                execute=True,
            )
            workflow = (
                root
                / ".github"
                / "workflows"
                / "assured-downstream-attested-release.yml"
            )

            self.assertEqual(len(result.written), 1)
            text = workflow.read_text(encoding="utf-8")
            self.assertIn("actions/attest@", text)
            self.assertIn("sbom-path: assured-evidence/sbom.spdx.json", text)
            self.assertIn(f"predicate-type: {ASSURED_DOWNSTREAM_PREDICATE_TYPE}", text)
            self.assertIn("steps.provenance.outputs['bundle-path']", text)
            self.assertIn("steps.sbom.outputs['bundle-path']", text)
            self.assertIn("steps.assured_downstream.outputs['bundle-path']", text)
            self.assertIn(FULL_SHA, text)
            self.assertIn("workflow_dispatch:", text)
            self.assertNotIn("push:", text)
            self.assertNotIn("echo hi > dist/tool", text)
            self.assertIn("isolated builder is not confirmed", text)
            self.assertIn("persist-credentials: false", text)
            self.assertIn("fetch-depth: 0", text)
            self.assertIn("source lineage is not fully confirmed", text)
            self.assertIn("Verify SBOM generation did not alter build outputs", text)
            self.assertIn("Bind release artifact subjects into SBOM", text)
            workflow = parse_workflow_yaml(text)
            self.assertIn("jobs", workflow)
            self.assertEqual(
                workflow["jobs"]["build"]["permissions"],
                {"contents": "read"},
            )
            self.assertEqual(
                workflow["jobs"]["attest-evidence"]["permissions"]["id-token"],
                "write",
            )
            self.assertEqual(
                workflow["jobs"]["inspect-evidence"]["permissions"],
                {},
            )
            self.assertEqual(
                workflow["jobs"]["attest-evidence"]["needs"],
                "inspect-evidence",
            )
            self.assertNotIn(
                "id-token",
                workflow["jobs"]["inspect-evidence"]["permissions"],
            )
            self.assertNotIn(
                "artifact-metadata",
                workflow["jobs"]["attest-evidence"]["permissions"],
            )
            self.assertIn("actions/download-artifact@", text)
            self.assertIn('manifest_path = Path("evidence.json")', text)
            self.assertIn('Path("VERIFY.md")', text)

    def test_confirmed_profile_renders_tag_trigger(self) -> None:
        confirmed = profile()
        confirmed["review"] = {
            "release_workflow_confirmed": True,
            "artifact_paths_confirmed": True,
            "isolated_builder_confirmed": True,
            "lineage_confirmed": True,
        }
        confirmed["lineage"] = {
            "source_full_name": "owner/project",
            "upstream_ref": "b" * 40,
        }
        confirmed["release"]["isolated_builder"] = {
            "status": "confirmed",
            "image": "ghcr.io/assured-downstream/python-builder",
            "image_digest": "a" * 64,
            "run_as": "65532:65532",
            "command_argv": ["build-package", "/src", "/out"],
            "network": "none",
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            render_release_workflow(
                confirmed,
                root=root,
                pins={
                    "actions/checkout": FULL_SHA,
                    "actions/attest": FULL_SHA,
                    "actions/download-artifact": FULL_SHA,
                    "actions/upload-artifact": FULL_SHA,
                    "anchore/sbom-action": FULL_SHA,
                },
                execute=True,
            )
            workflow = (
                root
                / ".github"
                / "workflows"
                / "assured-downstream-attested-release.yml"
            )

            text = workflow.read_text(encoding="utf-8")
            self.assertIn("push:", text)
            self.assertIn("'secure-v*'", text)
            self.assertIn("docker run --rm --network none --read-only", text)
            self.assertIn("--cap-drop ALL", text)
            self.assertIn("$GITHUB_WORKSPACE:/src:ro", text)
            self.assertIn("install -d -m 0777 dist", text)
            self.assertIn("git merge-base --is-ancestor", text)
            self.assertIn("https://github.com/${SOURCE_REPOSITORY}.git", text)

    def test_skips_with_stale_pin_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = render_release_workflow(
                profile(),
                root=Path(tmp),
                pins=pin_lock(
                    {
                        "actions/checkout": {
                            "status": "resolved",
                            "sha": FULL_SHA,
                            "expires_at": "2999-01-01T00:00:00+00:00",
                            "refresh_status": "current",
                        },
                        "actions/attest": {
                            "status": "resolved",
                            "sha": FULL_SHA,
                            "expires_at": "2000-01-01T00:00:00+00:00",
                            "refresh_status": "current",
                        },
                        "actions/download-artifact": {
                            "status": "resolved",
                            "sha": FULL_SHA,
                            "expires_at": "2999-01-01T00:00:00+00:00",
                            "refresh_status": "current",
                        },
                        "actions/upload-artifact": {
                            "status": "resolved",
                            "sha": FULL_SHA,
                            "expires_at": "2999-01-01T00:00:00+00:00",
                            "refresh_status": "current",
                        },
                        "anchore/sbom-action": {
                            "status": "resolved",
                            "sha": FULL_SHA,
                            "expires_at": "2999-01-01T00:00:00+00:00",
                            "refresh_status": "current",
                        },
                    }
                ),
            )

        self.assertEqual(result.written, [])
        self.assertEqual(result.skipped[0]["id"], "attested-release-workflow")

    def test_confirmed_flags_with_invalid_lineage_still_fail_closed(self) -> None:
        invalid = profile()
        invalid["review"] = {
            "release_workflow_confirmed": True,
            "artifact_paths_confirmed": True,
            "isolated_builder_confirmed": True,
            "lineage_confirmed": True,
        }
        invalid["lineage"] = {
            "source_full_name": "owner/project",
            "upstream_ref": "not-a-commit",
        }
        invalid["release"]["isolated_builder"] = {
            "status": "confirmed",
            "image": "ghcr.io/assured-downstream/python-builder",
            "image_digest": "a" * 64,
            "run_as": "65532:65532",
            "command_argv": ["build-package", "/src", "/out"],
            "network": "none",
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            render_release_workflow(
                invalid,
                root=root,
                pins={
                    "actions/checkout": FULL_SHA,
                    "actions/attest": FULL_SHA,
                    "actions/download-artifact": FULL_SHA,
                    "actions/upload-artifact": FULL_SHA,
                    "anchore/sbom-action": FULL_SHA,
                },
                execute=True,
            )
            text = (
                root
                / ".github"
                / "workflows"
                / "assured-downstream-attested-release.yml"
            ).read_text(encoding="utf-8")

        self.assertNotIn("push:", text)
        self.assertIn("source lineage is not fully confirmed", text)

    def test_non_boolean_confirmation_values_fail_closed(self) -> None:
        invalid = confirmed_profile()
        invalid["review"]["release_workflow_confirmed"] = "true"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            render_release_workflow(
                invalid,
                root=root,
                pins=valid_pins(),
                execute=True,
            )
            text = (
                root
                / ".github"
                / "workflows"
                / "assured-downstream-attested-release.yml"
            ).read_text(encoding="utf-8")

        self.assertNotIn("push:", text)
        self.assertNotIn("docker pull", text)
        self.assertIn("source lineage is not fully confirmed", text)

    def test_embedded_evidence_scripts_are_valid_python(self) -> None:
        for script in (
            artifact_validation_script(),
            artifact_inventory_verification_script(),
            sbom_subject_binding_script("assured-evidence/sbom.spdx.json"),
            evidence_assembly_script("assured-evidence/sbom.spdx.json"),
        ):
            lines = script.splitlines()
            self.assertEqual(lines[0], "python - <<'PY'")
            self.assertEqual(lines[-1], "PY")
            compile("\n".join(lines[1:-1]), "<generated-evidence-script>", "exec")

    def test_inventory_verification_blocks_artifact_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "assured-input" / "artifacts" / "tool.bin"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"original\n")

            initial = run_embedded_script(artifact_validation_script(), cwd=root)
            unchanged = run_embedded_script(
                artifact_inventory_verification_script(),
                cwd=root,
            )
            artifact.write_bytes(b"changed\n")
            changed = run_embedded_script(
                artifact_inventory_verification_script(),
                cwd=root,
            )

        self.assertEqual(initial.returncode, 0, initial.stderr)
        self.assertEqual(unchanged.returncode, 0, unchanged.stderr)
        self.assertNotEqual(changed.returncode, 0)
        self.assertIn("changed after boundary validation", changed.stderr)

    def test_sbom_binding_references_every_inventoried_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "assured-input" / "artifacts" / "tool.bin"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"release artifact\n")
            sbom_path = root / "assured-evidence" / "sbom.spdx.json"
            sbom_path.parent.mkdir(parents=True)
            sbom_path.write_text(
                json.dumps(
                    {
                        "spdxVersion": "SPDX-2.3",
                        "SPDXID": "SPDXRef-DOCUMENT",
                        "files": [],
                        "relationships": [],
                    }
                ),
                encoding="utf-8",
            )

            inventory = run_embedded_script(artifact_validation_script(), cwd=root)
            binding = run_embedded_script(
                sbom_subject_binding_script("assured-evidence/sbom.spdx.json"),
                cwd=root,
            )
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))

        digest = hashlib.sha256(b"release artifact\n").hexdigest()
        self.assertEqual(inventory.returncode, 0, inventory.stderr)
        self.assertEqual(binding.returncode, 0, binding.stderr)
        self.assertTrue(
            any(
                checksum == {"algorithm": "SHA256", "checksumValue": digest}
                for entry in sbom["files"]
                for checksum in entry.get("checksums", [])
            )
        )
        self.assertTrue(
            any(
                relation.get("relationshipType") == "DESCRIBES"
                for relation in sbom["relationships"]
            )
        )

    def test_rejects_profile_fields_that_can_inject_workflow_yaml(self) -> None:
        cases = (
            ("runs_on", "ubuntu-latest\npermissions: write-all"),
            ("confirmed_tag_pattern", "secure-v*'\n      - '**"),
            ("sbom_path", "assured-evidence/sbom.json\n          token: unsafe"),
            ("artifact_paths", ["dist/*\n          retention-days: 90"]),
        )
        for field, value in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                invalid = profile()
                invalid["release"][field] = value
                with self.assertRaises(ValueError):
                    render_release_workflow(
                        invalid,
                        root=Path(tmp),
                        pins=valid_pins(),
                    )

    def test_rejects_workflow_path_outside_checkout(self) -> None:
        invalid = profile()
        invalid["release"]["workflow_path"] = "../../outside.yml"

        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
            render_release_workflow(
                invalid,
                root=Path(tmp),
                pins=valid_pins(),
                execute=True,
            )

    def test_rejects_workflow_path_through_symlink(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            tempfile.TemporaryDirectory() as outside,
        ):
            root = Path(tmp)
            (root / ".github").symlink_to(Path(outside), target_is_directory=True)
            with self.assertRaises(ValueError):
                render_release_workflow(
                    profile(),
                    root=root,
                    pins=valid_pins(),
                    execute=True,
                )

    def test_confined_force_write_replaces_symlink_without_following_it(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            tempfile.TemporaryDirectory() as outside,
        ):
            root = Path(tmp)
            workflow_dir = root / ".github" / "workflows"
            workflow_dir.mkdir(parents=True)
            external = Path(outside) / "outside.yml"
            external.write_text("outside\n", encoding="utf-8")
            target = workflow_dir / "release.yml"
            target.symlink_to(external)

            write_text_confined(
                root,
                ".github/workflows/release.yml",
                "inside\n",
                force=True,
            )

            self.assertFalse(target.is_symlink())
            self.assertEqual(target.read_text(encoding="utf-8"), "inside\n")
            self.assertEqual(external.read_text(encoding="utf-8"), "outside\n")


def profile() -> dict:
    return {
        "status": "draft-human-review-required",
        "review": {
            "release_workflow_confirmed": False,
            "artifact_paths_confirmed": False,
            "isolated_builder_confirmed": False,
            "lineage_confirmed": False,
        },
        "release": {
            "workflow_path": ".github/workflows/assured-downstream-attested-release.yml",
            "runs_on": "ubuntu-latest",
            "confirmed_tag_pattern": "secure-v*",
            "build_commands": ["mkdir -p dist", "echo hi > dist/tool"],
            "artifact_paths": ["dist/*"],
            "sbom_path": "assured-evidence/sbom.spdx.json",
            "sbom_format": "spdx-json",
            "required_actions": [
                "actions/checkout",
                "actions/attest",
                "actions/download-artifact",
                "actions/upload-artifact",
                "anchore/sbom-action",
            ],
        },
    }


def pin_lock(entries: dict[str, dict[str, str]]) -> dict:
    return {
        "schema_version": 1,
        "status": "complete",
        "entries": entries,
        "pins": {name: entry["sha"] for name, entry in entries.items()},
    }


def valid_pins() -> dict[str, str]:
    return {
        "actions/checkout": FULL_SHA,
        "actions/attest": FULL_SHA,
        "actions/download-artifact": FULL_SHA,
        "actions/upload-artifact": FULL_SHA,
        "anchore/sbom-action": FULL_SHA,
    }


def confirmed_profile() -> dict:
    value = profile()
    value["review"] = {
        "release_workflow_confirmed": True,
        "artifact_paths_confirmed": True,
        "isolated_builder_confirmed": True,
        "lineage_confirmed": True,
    }
    value["lineage"] = {
        "source_full_name": "owner/project",
        "upstream_ref": "b" * 40,
    }
    value["release"]["isolated_builder"] = {
        "status": "confirmed",
        "image": "ghcr.io/assured-downstream/python-builder",
        "image_digest": "a" * 64,
        "run_as": "65532:65532",
        "command_argv": ["build-package", "/src", "/out"],
        "network": "none",
    }
    return value


def run_embedded_script(script: str, *, cwd: Path) -> subprocess.CompletedProcess[str]:
    lines = script.splitlines()
    return subprocess.run(
        [sys.executable, "-c", "\n".join(lines[1:-1])],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


if __name__ == "__main__":
    unittest.main()
