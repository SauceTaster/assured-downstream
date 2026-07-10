from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from assured_downstream.codex_driver import (
    CodexDriver,
    CodexDriverError,
    validate_result,
)


VALID_RESULT = {
    "schema_version": 1,
    "status": "succeeded",
    "summary": "reviewed",
    "findings": [],
    "recommendations": [],
    "data": [],
}


class CodexDriverTests(unittest.TestCase):
    def test_command_places_approval_before_exec_and_uses_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            driver = CodexDriver(codex_home=root)
            with patch("assured_downstream.codex_driver.shutil.which", return_value="/bin/codex"):
                command = driver.command(
                    workdir=root,
                    output_path=root / "result.json",
                    prompt="review",
                )

            self.assertEqual(command[:6], [
                "/bin/codex",
                "-a",
                "never",
                "exec",
                "-p",
                "assured-downstream-luna",
            ])
            self.assertIn("--ephemeral", command)
            self.assertIn("--skip-git-repo-check", command)
            self.assertEqual(command[command.index("-s") + 1], "read-only")

    def test_run_loads_strict_structured_result_and_records_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile_path = root / "assured-downstream-luna.config.toml"
            profile_path.write_text(
                'model = "gpt-5.6-luna"\nmodel_reasoning_effort = "high"\n',
                encoding="utf-8",
            )
            output_path = root / "result.json"
            driver = CodexDriver(codex_home=root)

            def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                if "--version" in argv:
                    return subprocess.CompletedProcess(argv, 0, "codex-cli 0.144.1\n", "")
                result_index = argv.index("-o") + 1
                Path(argv[result_index]).write_text(
                    json.dumps(VALID_RESULT),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(argv, 0, "", "")

            with (
                patch("assured_downstream.codex_driver.shutil.which", return_value="/bin/codex"),
                patch("assured_downstream.codex_driver.subprocess.run", side_effect=fake_run),
            ):
                result = driver.run(
                    workdir=root,
                    output_path=output_path,
                    prompt="review",
                )

            self.assertEqual(result.payload, VALID_RESULT)
            self.assertEqual(result.execution.model, "gpt-5.6-luna")
            self.assertEqual(result.execution.reasoning_effort, "high")
            self.assertEqual(result.execution.sandbox, "read-only")

    def test_validation_rejects_extra_fields(self) -> None:
        invalid = dict(VALID_RESULT)
        invalid["unexpected"] = True
        with self.assertRaises(CodexDriverError):
            validate_result(invalid)

    def test_validation_accepts_null_finding_path_from_schema(self) -> None:
        result = dict(VALID_RESULT)
        result["findings"] = [
            {
                "code": "review",
                "severity": "medium",
                "message": "No repository path applies.",
                "path": None,
            }
        ]
        validate_result(result)

    def test_rejects_profile_path_traversal_and_write_sandbox(self) -> None:
        with self.assertRaises(ValueError):
            CodexDriver(profile="../../escape")
        with self.assertRaises(ValueError):
            CodexDriver(sandbox="workspace-write")


if __name__ == "__main__":
    unittest.main()
