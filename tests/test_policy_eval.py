from __future__ import annotations

import unittest

from assured_downstream.policy_eval import (
    evaluate_release,
    evaluate_release_candidate,
)


SHA_A = "a" * 64


class PolicyEvalTests(unittest.TestCase):
    def test_attested_candidate_shape_is_complete_with_required_inputs(self) -> None:
        result = evaluate_with_verifications(
            evidence=manifest(
                artifacts=[{"name": "tool"}],
                sboms=[{"name": "sbom.spdx.json"}],
                attestations=[{"name": "build.intoto.json"}],
            ),
            target="Attested",
            evidence_verification={"ok": True},
        )

        self.assertEqual(result["decision"], "candidate")
        self.assertIsNone(result["promoted_assurance"])
        self.assertEqual(result["candidate_assurance"], "Attested")
        self.assertEqual(result["authority"], "untrusted-input-shape-only")

    def test_reproducible_release_requires_matching_comparison(self) -> None:
        result = evaluate_with_verifications(
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
        result = evaluate_with_verifications(
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

        self.assertEqual(result["decision"], "candidate")

    def test_attested_release_requires_verified_evidence(self) -> None:
        result = evaluate_with_verifications(
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
        result = evaluate_with_verifications(
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

    def test_attested_candidate_requires_attestation_subject_claims(
        self,
    ) -> None:
        evidence = manifest(
            artifacts=[{"name": "tool"}],
            sboms=[{"name": "sbom.spdx.json"}],
            attestations=[{"name": "build.sigstore.json"}],
        )

        result = evaluate_release_candidate(
            evidence=evidence,
            target="Attested",
            evidence_verification={"ok": True},
            tooling_verification=tooling_verification(),
            workflow_risk_verification=workflow_risk_verification(),
        )

        self.assertEqual(result["decision"], "block")
        self.assertIn("attestation verification claim", " ".join(result["failures"]))

    def test_attested_release_rejects_subject_digest_mismatch(self) -> None:
        evidence = manifest(
            artifacts=[{"name": "tool"}],
            sboms=[{"name": "sbom.spdx.json"}],
            attestations=[{"name": "build.sigstore.json"}],
        )
        verification = attestation_verification(evidence)
        verification["verified_subjects"] = [{"sha256": "b" * 64}]

        result = evaluate_release_candidate(
            evidence=evidence,
            target="Attested",
            evidence_verification={"ok": True},
            attestation_verification=verification,
            tooling_verification=tooling_verification(),
            workflow_risk_verification=workflow_risk_verification(),
        )

        self.assertEqual(result["decision"], "block")
        self.assertIn("does not represent every artifact", " ".join(result["failures"]))

    def test_production_attested_gate_requires_code_anchored_verifier(self) -> None:
        evidence = manifest(
            artifacts=[{"name": "tool"}],
            sboms=[{"name": "sbom.spdx.json"}],
            attestations=[{"name": "build.sigstore.json"}],
        )

        result = evaluate_release(
            evidence=evidence,
            target="Attested",
            evidence_verification={"ok": True},
            attestation_verification=attestation_verification(evidence),
            tooling_verification=tooling_verification(),
            workflow_risk_verification=workflow_risk_verification(),
        )

        self.assertEqual(result["decision"], "block")
        self.assertIn("code-anchored", result["failures"][-1])


def manifest(
    *, artifacts: list[dict], sboms: list[dict], attestations: list[dict]
) -> dict:
    artifact_entries = [
        {**item, "sha256": item.get("sha256", SHA_A)} for item in artifacts
    ]
    return {
        "project": {
            "source_full_name": "owner/project",
            "target_full_name": "assured-oss/project",
            "upstream_ref": "abc123",
            "overlay_ref": "def456",
            "release_tag": "secure-v1.0.0+org.1",
        },
        "evidence": {
            "artifacts": artifact_entries,
            "sboms": sboms,
            "attestations": attestations,
            "traces": [],
            "reports": [],
        },
    }


def evaluate_with_verifications(**kwargs: object) -> dict:
    evidence = kwargs["evidence"]
    assert isinstance(evidence, dict)
    return evaluate_release_candidate(
        **kwargs,
        attestation_verification=attestation_verification(evidence),
        tooling_verification=tooling_verification(),
        workflow_risk_verification=workflow_risk_verification(),
    )


def attestation_verification(evidence: dict) -> dict:
    return {
        "ok": True,
        "verification_type": "sigstore-bundle",
        "issuer": "https://token.actions.githubusercontent.com",
        "signer": "owner/project/.github/workflows/release.yml",
        "verified_subjects": [
            {"sha256": item["sha256"]} for item in evidence["evidence"]["artifacts"]
        ],
    }


def tooling_verification() -> dict:
    return {
        "ok": True,
        "policy_sha256": "1" * 64,
        "lock_sha256": "2" * 64,
    }


def workflow_risk_verification() -> dict:
    return {
        "ok": True,
        "analyzed_workflow_sha256": "3" * 64,
        "findings": [],
    }


if __name__ == "__main__":
    unittest.main()
