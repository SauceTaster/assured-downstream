from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from assured_downstream.release_render import render_release_workflow


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
            self.assertIn(FULL_SHA, text)


def profile() -> dict:
    return {
        "status": "draft-human-review-required",
        "release": {
            "workflow_path": ".github/workflows/assured-downstream-attested-release.yml",
            "runs_on": "ubuntu-latest",
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


if __name__ == "__main__":
    unittest.main()

