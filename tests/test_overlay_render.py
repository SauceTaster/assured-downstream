from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from assured_downstream.overlay_render import render_overlay


FULL_SHA = "0123456789abcdef0123456789abcdef01234567"


class OverlayRenderTests(unittest.TestCase):
    def test_dry_run_lists_renderable_files_without_writing(self) -> None:
        overlay = overlay_with_changes(["dependabot-baseline", "in-toto-evidence"])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = render_overlay(overlay, root=root)

            self.assertEqual(len(result.written), 2)
            self.assertFalse((root / ".github" / "dependabot.yml").exists())

    def test_execute_writes_safe_files(self) -> None:
        overlay = overlay_with_changes(["dependabot-baseline", "in-toto-evidence"])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = render_overlay(overlay, root=root, execute=True)

            self.assertEqual(len(result.written), 2)
            self.assertTrue((root / ".github" / "dependabot.yml").exists())
            self.assertTrue((root / "evidence" / "saucetotal" / "README.md").exists())

    def test_skips_workflows_without_full_sha_pins(self) -> None:
        overlay = overlay_with_changes(["dependency-review"])

        with tempfile.TemporaryDirectory() as tmp:
            result = render_overlay(overlay, root=Path(tmp), pins={"actions/checkout": "v4"})

        self.assertEqual(result.written, [])
        self.assertEqual(result.skipped[0]["id"], "dependency-review")

    def test_renders_workflow_with_full_sha_pins(self) -> None:
        overlay = overlay_with_changes(["dependency-review"])
        pins = {
            "actions/checkout": FULL_SHA,
            "actions/dependency-review-action": FULL_SHA,
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = render_overlay(overlay, root=root, pins=pins, execute=True)
            workflow = root / ".github" / "workflows" / "saucetotal-dependency-review.yml"

            self.assertEqual(len(result.written), 1)
            self.assertIn(FULL_SHA, workflow.read_text(encoding="utf-8"))


def overlay_with_changes(change_ids: list[str]) -> dict:
    return {
        "target": "Attested",
        "generated_at": "2026-07-09T00:00:00+00:00",
        "proposed_changes": [
            {
                "id": change_id,
                "stage": "Hardened",
                "action": "add",
                "paths": [],
                "rationale": "test",
            }
            for change_id in change_ids
        ],
    }


if __name__ == "__main__":
    unittest.main()

