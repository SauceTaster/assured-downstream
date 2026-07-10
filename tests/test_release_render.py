from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from assured_downstream.release_render import (
    ASSURED_DOWNSTREAM_PREDICATE_TYPE,
    render_release_workflow,
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
                    "actions/upload-artifact": FULL_SHA,
                    "anchore/sbom-action": FULL_SHA,
                },
                execute=True,
            )
            workflow = root / ".github" / "workflows" / "assured-downstream-attested-release.yml"

            self.assertEqual(len(result.written), 1)
            text = workflow.read_text(encoding="utf-8")
            self.assertIn("actions/attest@", text)
            self.assertIn("sbom-path: dist/assured-downstream-sbom.spdx.json", text)
            self.assertIn(f"predicate-type: {ASSURED_DOWNSTREAM_PREDICATE_TYPE}", text)
            self.assertIn("steps.provenance.outputs['bundle-path']", text)
            self.assertIn("steps.sbom.outputs['bundle-path']", text)
            self.assertIn("steps.assured_downstream.outputs['bundle-path']", text)
            self.assertIn("created_attestation_paths.txt", text)
            self.assertIn(FULL_SHA, text)
            self.assertIn("workflow_dispatch:", text)
            self.assertNotIn("push:", text)
            self.assertIn("jobs", parse_workflow_yaml(text))

    def test_confirmed_profile_renders_tag_trigger(self) -> None:
        confirmed = profile()
        confirmed["review"] = {
            "release_workflow_confirmed": True,
            "artifact_paths_confirmed": True,
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            render_release_workflow(
                confirmed,
                root=root,
                pins={
                    "actions/checkout": FULL_SHA,
                    "actions/attest": FULL_SHA,
                    "actions/upload-artifact": FULL_SHA,
                    "anchore/sbom-action": FULL_SHA,
                },
                execute=True,
            )
            workflow = root / ".github" / "workflows" / "assured-downstream-attested-release.yml"

            text = workflow.read_text(encoding="utf-8")
            self.assertIn("push:", text)
            self.assertIn("'secure-v*'", text)

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


def profile() -> dict:
    return {
        "status": "draft-human-review-required",
        "review": {
            "release_workflow_confirmed": False,
            "artifact_paths_confirmed": False,
        },
        "release": {
            "workflow_path": ".github/workflows/assured-downstream-attested-release.yml",
            "runs_on": "ubuntu-latest",
            "confirmed_tag_pattern": "secure-v*",
            "build_commands": ["mkdir -p dist", "echo hi > dist/tool"],
            "artifact_paths": ["dist/*"],
            "sbom_path": "dist/assured-downstream-sbom.spdx.json",
            "sbom_format": "spdx-json",
            "required_actions": [
                "actions/checkout",
                "actions/attest",
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


if __name__ == "__main__":
    unittest.main()
