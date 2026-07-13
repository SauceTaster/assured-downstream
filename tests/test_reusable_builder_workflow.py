from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path

from assured_downstream.builder_handoff import BUILDER_DIGEST
from assured_downstream.workflow_yaml import parse_workflow_yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "reusable-python-build.yml"
CASE_WORKFLOW = ROOT / ".github" / "workflows" / "case-study-bandit-build.yml"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


class ReusableBuilderWorkflowTests(unittest.TestCase):
    def test_reusable_workflow_separates_permission_domains(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        workflow = parse_workflow_yaml(text)
        jobs = workflow["jobs"]

        self.assertIn("workflow_call", workflow["on"])
        self.assertEqual(jobs["build"]["permissions"], {"contents": "read"})
        self.assertEqual(jobs["inspect"]["permissions"], {})
        self.assertEqual(
            jobs["attest"]["permissions"],
            {
                "attestations": "write",
                "contents": "read",
                "id-token": "write",
            },
        )
        self.assertNotIn("id-token", jobs["build"]["permissions"])
        self.assertNotIn("id-token", jobs["inspect"]["permissions"])
        self.assertEqual(jobs["inspect"]["needs"], "build")
        self.assertEqual(jobs["attest"]["needs"], ["build", "inspect"])

    def test_reusable_workflow_pins_builder_verifier_and_actions(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        workflow = parse_workflow_yaml(text)
        policy = json.loads(
            (ROOT / "policies" / "builders" / "python-wheel-v1.json").read_text()
        )
        expected_actions = policy["reusable_workflow"]["actions"]

        self.assertEqual(workflow["env"]["BUILDER_DIGEST"], BUILDER_DIGEST)
        self.assertEqual(policy["published_image_digest"], BUILDER_DIGEST)
        self.assertTrue(FULL_SHA.fullmatch(workflow["env"]["HANDOFF_COMMIT"]))
        self.assertEqual(
            workflow["env"]["HANDOFF_COMMIT"],
            policy["reusable_workflow"]["handoff_verifier_commit"],
        )
        for value in policy["reusable_workflow"]["approved_request"].values():
            self.assertIn(str(value), text)
        self.assertIn(f"ref: {workflow['env']['HANDOFF_COMMIT']}", text)
        for action, sha in expected_actions.items():
            self.assertIn(f"{action}@{sha}", text)
        self.assertNotRegex(text, r"uses:\s+[^\n]+@(main|master|v\d+)\s*$")

    def test_staged_handoff_tool_hashes_match_immutable_sources(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        for name in (
            "__init__.py",
            "builder_handoff.py",
            "catalog.py",
            "evidence.py",
            "seed.py",
        ):
            path = ROOT / "src" / "assured_downstream" / name
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertIn(f"{digest} src/assured_downstream/{name}", text)

    def test_container_is_fixed_and_has_no_network_or_secrets(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")

        for control in (
            "--network none",
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges:true",
            "--pids-limit 512",
            "--memory 2g",
            "--user 65532:65532",
            "--ipc none",
            "dst=/input,readonly",
        ):
            self.assertIn(control, text)
        self.assertNotIn("secrets: inherit", text)
        self.assertNotIn("GITHUB_TOKEN=", text)
        self.assertNotIn("${{ inputs.command", text)
        self.assertNotRegex(text, r"\+\s+--")
        self.assertNotIn("validate +", text)
        self.assertIn("collector_summary=", text)
        self.assertNotIn('trace.get("events")', text)
        self.assertIn('test "$CALLER_OWNER" = "SauceTaster"', text)
        self.assertIn(
            'test "$CALLER_REPOSITORY" = "SauceTaster/assured-downstream"',
            text,
        )
        self.assertIn('test "$CALLER_REF_PROTECTED" = "true"', text)
        self.assertIn("get-regexp '^http\\..*\\.extraheader$' >/dev/null 2>&1", text)

    def test_bandit_caller_pins_the_reusable_signer_and_request(self) -> None:
        policy = json.loads(
            (ROOT / "policies" / "builders" / "python-wheel-v1.json").read_text()
        )
        workflow = parse_workflow_yaml(CASE_WORKFLOW.read_text(encoding="utf-8"))
        build = workflow["jobs"]["build"]
        inputs = build["with"]
        signer_commit = policy["reusable_workflow"]["signer_commit"]

        self.assertEqual(
            build["uses"],
            (
                "SauceTaster/assured-downstream/.github/workflows/"
                f"reusable-python-build.yml@{signer_commit}"
            ),
        )
        self.assertTrue(FULL_SHA.fullmatch(signer_commit))
        request = policy["reusable_workflow"]["approved_request"]
        for name in (
            "source_repository",
            "source_commit",
            "source_tree",
            "upstream_repository",
            "upstream_commit",
            "target_repository",
            "project_version",
            "release_tag",
            "case_id",
        ):
            self.assertEqual(inputs[name], request[name])
        self.assertEqual(inputs["source_commit"], inputs["upstream_commit"])
        self.assertIn("source-canary", inputs["release_tag"])
        self.assertNotIn("secure", inputs["release_tag"])

if __name__ == "__main__":
    unittest.main()
