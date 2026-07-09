from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from assured_downstream.checkout_pipeline import run_checkout_analysis


FULL_SHA = "0123456789abcdef0123456789abcdef01234567"


class CheckoutPipelineTests(unittest.TestCase):
    def test_runs_checkout_analysis_without_rendering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout = root / "checkout"
            run_dir = root / "run"
            checkout.mkdir()
            (checkout / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")

            summary = run_checkout_analysis(
                checkout_path=checkout,
                run_dir=run_dir,
                target="Attested",
            )

            self.assertTrue((run_dir / "recon.json").exists())
            self.assertTrue((run_dir / "overlay-plan.json").exists())
            self.assertTrue((run_dir / "render-result.json").exists())
            self.assertTrue((run_dir / "release-profile.json").exists())
            self.assertTrue((run_dir / "release-render-result.json").exists())
            self.assertTrue((run_dir / "CHECKOUT_SUMMARY.md").exists())
            self.assertFalse((checkout / ".github" / "dependabot.yml").exists())
            self.assertGreater(summary["overlay_changes"], 0)
            self.assertGreater(summary["planned_writable_files"], 0)
            self.assertEqual(summary["rendered_files"], 0)
            self.assertEqual(summary["release_rendered_files"], 0)

    def test_runs_checkout_analysis_with_rendering_and_pins(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout = root / "checkout"
            run_dir = root / "run"
            checkout.mkdir()
            (checkout / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")

            summary = run_checkout_analysis(
                checkout_path=checkout,
                run_dir=run_dir,
                target="Hardened",
                pins={
                    "actions/checkout": FULL_SHA,
                    "actions/attest": FULL_SHA,
                    "actions/dependency-review-action": FULL_SHA,
                    "actions/upload-artifact": FULL_SHA,
                    "anchore/sbom-action": FULL_SHA,
                    "ossf/scorecard-action": FULL_SHA,
                },
                render=True,
            )

            self.assertTrue((checkout / ".github" / "dependabot.yml").exists())
            self.assertTrue(
                (checkout / ".github" / "workflows" / "saucetotal-attested-release.yml").exists()
            )
            self.assertGreater(summary["rendered_files"], 0)
            self.assertEqual(summary["planned_writable_files"], summary["rendered_files"])
            self.assertEqual(
                summary["release_planned_writable_files"],
                summary["release_rendered_files"],
            )


if __name__ == "__main__":
    unittest.main()
