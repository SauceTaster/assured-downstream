from __future__ import annotations

import unittest

from assured_downstream.liaison import create_liaison_packet


class LiaisonTests(unittest.TestCase):
    def test_builds_packet_with_fetch_instructions_and_summary(self) -> None:
        packet = create_liaison_packet(
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

        self.assertEqual(packet["status"], "draft-local-only")
        self.assertFalse(packet["mutation_policy"]["network_mutation"])
        self.assertFalse(packet["mutation_policy"]["automatic_pr_creation"])
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
        self.assertIn("git fetch assured-downstream proposal/main", commands)
        self.assertIn(
            "git switch -c review/assured-oss-project assured-downstream/proposal/main",
            commands,
        )
        self.assertIn("Upstream remains authoritative", packet["fetch_instructions_markdown"])
        self.assertIn("Upstream remains authoritative", packet["pr_description_draft"])

    def test_suppressed_repo_omits_outreach_drafts(self) -> None:
        packet = create_liaison_packet(
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

        self.assertEqual(packet["status"], "outreach-suppressed")
        self.assertTrue(packet["outreach"]["suppressed"])
        self.assertEqual(
            packet["outreach"]["reason"],
            "maintainer requested no repeated outreach",
        )
        self.assertIsNone(packet["fetch_instructions"])
        self.assertIsNone(packet["fetch_instructions_markdown"])
        self.assertIsNone(packet["pr_description_draft"])

    def test_preferences_map_can_suppress_repeated_outreach(self) -> None:
        packet = create_liaison_packet(
            fork_plan_entry=fork_plan_entry(),
            maintainer_preferences={
                "repos": {
                    "owner/project": {
                        "outreach": "no-outreach",
                        "reason": "maintainer prefers manual fetch only",
                    }
                }
            },
        )

        self.assertEqual(packet["status"], "outreach-suppressed")
        self.assertEqual(packet["outreach"]["preference_source"], "maintainer_preferences")
        self.assertEqual(
            packet["preference_controls"]["suppression_key"],
            "owner/project",
        )


def fork_plan_entry() -> dict:
    return {
        "source_full_name": "owner/project",
        "target_full_name": "assured-oss/project",
        "target_repo_name": "project",
        "metadata": {
            "default_branch": "main",
        },
        "branch_model": {
            "proposal_prefix": "proposal/",
        },
    }


if __name__ == "__main__":
    unittest.main()
