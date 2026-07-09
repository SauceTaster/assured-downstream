from __future__ import annotations

import unittest

from assured_downstream.policy_eval import evaluate_release


class PolicyEvalTests(unittest.TestCase):
    def test_attested_release_passes_with_artifact_and_attestation(self) -> None:
        result = evaluate_release(
            evidence=manifest(
                artifacts=[{"name": "tool"}],
                sboms=[{"name": "sbom.spdx.json"}],
                attestations=[{"name": "build.intoto.json"}],
            ),
            target="Attested",
            evidence_verification={"ok": True},
        )

        self.assertEqual(result["decision"], "pass")
        self.assertEqual(result["promoted_assurance"], "Attested")

    def test_reproducible_release_requires_matching_comparison(self) -> None:
        result = evaluate_release(
            evidence=manifest(
                artifacts=[{"name": "tool"}],
                sboms=[{"name": "sbom.spdx.json"}],
                attestations=[{"name": "build.intoto.json"}],
            ),
            target="Reproducible",
            evidence_verification={"ok": True},
            evidence_comparison={"ok": False},
        )

        self.assertEqual(result["decision"], "block")
        self.assertIn("evidence comparison", result["failures"][0])

    def test_behavior_reproducible_requires_behavior_match(self) -> None:
        result = evaluate_release(
            evidence=manifest(
                artifacts=[{"name": "tool"}],
                sboms=[{"name": "sbom.spdx.json"}],
                attestations=[{"name": "build.intoto.json"}],
            ),
            target="Behavior-Reproducible",
            evidence_verification={"ok": True},
            evidence_comparison={"ok": True},
            behavior_comparison={"ok": True},
        )

        self.assertEqual(result["decision"], "pass")

    def test_attested_release_requires_verified_evidence(self) -> None:
        result = evaluate_release(
            evidence=manifest(
                artifacts=[{"name": "tool"}],
                sboms=[{"name": "sbom.spdx.json"}],
                attestations=[{"name": "build.intoto.json"}],
            ),
            target="Attested",
            evidence_verification={"ok": False},
        )

        self.assertEqual(result["decision"], "block")
        self.assertIn("verification failed", result["failures"][-1])

    def test_attested_release_requires_sbom_evidence(self) -> None:
        result = evaluate_release(
            evidence=manifest(
                artifacts=[{"name": "tool"}],
                sboms=[],
                attestations=[{"name": "build.intoto.json"}],
            ),
            target="Attested",
            evidence_verification={"ok": True},
        )

        self.assertEqual(result["decision"], "block")
        self.assertIn("sboms", result["failures"][0])


def manifest(*, artifacts: list[dict], sboms: list[dict], attestations: list[dict]) -> dict:
    return {
        "project": {
            "source_full_name": "owner/project",
            "target_full_name": "assured-oss/project",
            "upstream_ref": "abc123",
            "overlay_ref": "def456",
            "release_tag": "secure-v1.0.0+org.1",
        },
        "evidence": {
            "artifacts": artifacts,
            "sboms": sboms,
            "attestations": attestations,
            "traces": [],
            "reports": [],
        },
    }


if __name__ == "__main__":
    unittest.main()
