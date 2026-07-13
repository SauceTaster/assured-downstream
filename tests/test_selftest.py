from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from assured_downstream.cli import build_parser, command_self_test
from assured_downstream.selftest import run_self_test


FIXTURES = Path(__file__).parent / "fixtures" / "recon"


class SelfTestTests(unittest.TestCase):
    def test_runs_self_test_for_java_and_dotnet_fixtures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "self-test"

            result = run_self_test(
                output_dir=output_dir,
                fixtures_root=FIXTURES,
                ecosystems=["java", "dotnet"],
            )

            self.assertTrue(result["ok"])
            self.assertEqual(result["summary"]["failed"], 0)
            self.assertTrue((output_dir / "self-test-result.json").exists())
            self.assertTrue((output_dir / "SELF_TEST_SUMMARY.md").exists())
            self.assertTrue(
                (output_dir / "agent-system" / "agent-system.json").exists()
            )
            self.assertTrue(
                (output_dir / "evidence-smoke" / "release-evaluation.json").exists()
            )
            self.assertIn("agent_system", result)
            self.assertTrue(
                all(check["ok"] for check in result["agent_system"]["checks"])
            )
            ecosystems = {entry["ecosystem"]: entry for entry in result["ecosystems"]}
            self.assertEqual(ecosystems["java"]["language_family"], "java")
            self.assertEqual(ecosystems["dotnet"]["language_family"], "dotnet")

    def test_self_test_cli_writes_result_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "self-test"
            args = build_parser().parse_args(
                [
                    "self-test",
                    "--output-dir",
                    str(output_dir),
                    "--fixtures-root",
                    str(FIXTURES),
                    "--ecosystem",
                    "java",
                ]
            )

            code = command_self_test(args)

            self.assertEqual(code, 0)
            result = json.loads(
                (output_dir / "self-test-result.json").read_text(encoding="utf-8")
            )
            self.assertTrue(result["ok"])
            self.assertEqual(result["agent_system"]["summary"]["agent_count"], 22)
            self.assertEqual(result["ecosystems"][0]["ecosystem"], "java")


if __name__ == "__main__":
    unittest.main()
