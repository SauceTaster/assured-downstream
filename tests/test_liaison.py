from __future__ import annotations

import unittest

from assured_downstream.liaison import create_liaison_packet
from assured_downstream.publication import create_project_packet


class PublicationTests(unittest.TestCase):
    def test_builds_packet_with_fetch_instructions_and_summary(self) -> None:
        packet = create_project_packet(
            fork_plan_entry=fork_plan_entry(),
            checkout_analysis={
                "path": "/tmp/project",
                "generated_at": "2026-07-09T00:00:00+00:00",
                "package_managers": [{"name": "python"}],
                "risk_signals": [
                    {
                        "path": ".github/workflows/ci.yml",
                        "signal": "uses pull_request_target",
                    }
                ],
            },
            overlay_plan={
                "proposed_changes": [
                    {
                        "id": "dependabot-baseline",
                        "paths": [".github/dependabot.yml"],
                        "rationale": "Add dependency update monitoring.",
                    },
                    {
                        "id": "gha-pr-target-review",
                        "paths": [".github/workflows/ci.yml"],
                        "rationale": "Review pull_request_target usage.",
                        "human_review_required": True,
                    },
                ]
            },
            render_result={
                "written": [
                    {
                        "id": "dependabot-baseline",
                        "path": ".github/dependabot.yml",
                    }
                ],
                "skipped": [
                    {
                        "id": "gha-pr-target-review",
                        "reason": "change requires repository-specific patch logic or human review",
                    }
                ],
            },
            release_profile={
                "release": {
                    "workflow_path": ".github/workflows/assured-downstream-attested-release.yml",
                },
                "review_notes": [
                    "Confirm this downstream workflow does not replace upstream release authority.",
                ],
            },
        )

        self.assertEqual(packet["status"], "passive-publication-ready")
        self.assertFalse(packet["mutation_policy"]["network_mutation"])
        self.assertFalse(packet["mutation_policy"]["automatic_pr_creation"])
        self.assertFalse(packet["mutation_policy"]["outbound_contact"])
        self.assertEqual(packet["publication"]["discoverability"], "github-fork-network")
        self.assertEqual(packet["source_analysis"]["package_managers"], ["python"])
        self.assertIn(".github/dependabot.yml", packet["proposal_summary"]["affected_paths"])
        self.assertIn(
            ".github/workflows/assured-downstream-attested-release.yml",
            packet["proposal_summary"]["affected_paths"],
        )
        self.assertEqual(
            packet["proposal_summary"]["skipped_items"][0]["id"],
            "gha-pr-target-review",
        )
        self.assertTrue(
            any(
                "pull_request_target" in note
                for note in packet["proposal_summary"]["human_review_required"]
            )
        )

        commands = packet["fetch_instructions"]["commands"]
        self.assertIn(
            "git remote add assured-downstream https://github.com/assured-oss/project.git",
            commands,
        )
        self.assertIn("git fetch assured-downstream secure/main", commands)
        self.assertIn(
            "git switch -c review/assured-oss-project assured-downstream/secure/main",
            commands,
        )
        self.assertIn("upstream remains authoritative", packet["fetch_instructions_markdown"])
        self.assertNotIn("pr_description_draft", packet)

    def test_outbound_contact_is_disabled_regardless_of_legacy_preferences(self) -> None:
        packet = create_project_packet(
            fork_plan_entry=fork_plan_entry(),
            suppression_state={
                "suppressed_repos": [
                    {
                        "source_full_name": "owner/project",
                        "outreach": "suppress",
                        "reason": "maintainer requested no repeated outreach",
                    }
                ]
            },
        )

        self.assertEqual(packet["status"], "passive-publication-ready")
        self.assertNotIn("outreach", packet)
        self.assertFalse(packet["publication"]["outbound_contact"])
        self.assertIsNotNone(packet["fetch_instructions"])
        self.assertNotIn("pr_description_draft", packet)

    def test_legacy_liaison_api_returns_passive_packet(self) -> None:
        packet = create_liaison_packet(
            fork_plan_entry=fork_plan_entry(),
        )

        self.assertEqual(packet["status"], "passive-publication-ready")
        self.assertFalse(packet["mutation_policy"]["outbound_contact"])


def fork_plan_entry() -> dict:
    return {
        "source_full_name": "owner/project",
        "target_full_name": "assured-oss/project",
        "target_repo_name": "project",
        "metadata": {
            "default_branch": "main",
        },
        "branch_model": {"secure_default": "secure/<default>"},
    }


if __name__ == "__main__":
    unittest.main()
