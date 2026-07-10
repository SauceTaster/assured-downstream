from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from assured_downstream.fork_plan import create_fork_plan
from assured_downstream.selection import CandidateSelectionPolicy, load_candidate_policy


def repo(owner: str, name: str, score: int) -> dict[str, object]:
    return {
        "owner": owner,
        "name": name,
        "html_url": f"https://github.com/{owner}/{name}",
        "score": score,
        "recommended_mode": "DownstreamAssured",
        "seeds": [],
    }


class SelectionTests(unittest.TestCase):
    def test_policy_file_source_does_not_expose_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "suppressions.json"
            path.write_text(
                json.dumps({"repositories": ["owner/blocked"]}),
                encoding="utf-8",
            )
            policy = load_candidate_policy(suppression_path=path)

        entry = policy.suppression_entry("owner/blocked")
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry.source, "suppressions.json")
        self.assertFalse(Path(entry.source).is_absolute())

    def test_suppressed_repo_never_enters_fork_plan(self) -> None:
        catalog = {
            "repositories": [
                repo("owner", "keep", 20),
                repo("owner", "blocked", 100),
            ]
        }
        policy = CandidateSelectionPolicy.from_entries(
            suppressions=[
                {
                    "full_name": "owner/blocked",
                    "reason": "manual suppression during pilot",
                }
            ]
        )

        plan = create_fork_plan(catalog, org="assured-oss", selection_policy=policy)

        sources = {entry["source_full_name"] for entry in plan["forks"]}
        self.assertEqual(sources, {"owner/keep"})
        self.assertEqual(plan["selection_counts"]["suppressed"], 1)
        blocked_reason = reason_for(plan, "owner/blocked")
        self.assertFalse(blocked_reason["selected"])
        self.assertEqual(blocked_reason["decision"], "suppressed")

    def test_allowlist_overrides_score_but_not_suppression(self) -> None:
        catalog = {
            "repositories": [
                repo("owner", "low-score", 1),
                repo("owner", "normal", 20),
                repo("owner", "both", 100),
            ]
        }
        policy = CandidateSelectionPolicy.from_entries(
            allowlist=[
                {"full_name": "owner/low-score", "reason": "pilot inclusion"},
                {"full_name": "owner/both", "reason": "also requested"},
            ],
            suppressions=[
                {"full_name": "owner/both", "reason": "legal hold"},
            ],
        )

        plan = create_fork_plan(
            catalog,
            org="assured-oss",
            min_score=10,
            selection_policy=policy,
        )

        sources = {entry["source_full_name"] for entry in plan["forks"]}
        self.assertEqual(sources, {"owner/low-score", "owner/normal"})

        low_score_codes = reason_codes(reason_for(plan, "owner/low-score"))
        self.assertIn("allowlisted", low_score_codes)
        self.assertIn("allowlist_score_override", low_score_codes)

        both_codes = reason_codes(reason_for(plan, "owner/both"))
        self.assertIn("suppressed", both_codes)
        self.assertIn("suppression_precedence", both_codes)


def reason_for(plan: dict[str, object], full_name: str) -> dict[str, object]:
    for reason in plan["selection_reasons"]:
        if reason["source_full_name"] == full_name:
            return reason
    raise AssertionError(f"missing reason for {full_name}")


def reason_codes(reason: dict[str, object]) -> set[str]:
    return {entry["code"] for entry in reason["reasons"]}


if __name__ == "__main__":
    unittest.main()
