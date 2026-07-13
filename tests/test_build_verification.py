from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from assured_downstream.build_verification import (
    BUILD_CLAIM_LIMIT,
    BuildVerificationError,
    TRUSTED_BUILD_VERIFICATION_POLICY_SHA256,
    validate_build_certificate,
    validate_build_predicate,
    validate_build_provenance,
    validate_build_verification_policy,
    validate_complete_trace,
    verify_raw_trace_records,
    verify_build_attestations,
)
from assured_downstream.cli import build_parser
from assured_downstream.release_verification import (
    GITHUB_WORKFLOW_BUILD_TYPE,
    ReleaseVerificationError,
    github_attestation_verify_command,
)


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies" / "build-verification.json"
TRUST_POLICY_PATH = ROOT / "policies" / "release-verification.json"
FIRST_V2_CASE_PATH = (
    ROOT / "case-studies" / "001-pilot-cohort" / "bandit-build-canary-v2.json"
)


class BuildVerificationTests(unittest.TestCase):
    def test_policy_is_code_anchored_and_structurally_valid(self) -> None:
        policy_bytes = POLICY_PATH.read_bytes()
        self.assertEqual(
            hashlib.sha256(policy_bytes).hexdigest(),
            TRUSTED_BUILD_VERIFICATION_POLICY_SHA256,
        )
        policy = validate_build_verification_policy(json.loads(policy_bytes))
        self.assertEqual(
            policy["approved_request"]["case_id"],
            "case-001-bandit-source-canary-v2",
        )

    def test_first_v2_case_preserves_its_policy_and_staged_manifest(self) -> None:
        policy = load_policy()
        case = json.loads(FIRST_V2_CASE_PATH.read_bytes())

        self.assertEqual(case["case_id"], policy["approved_request"]["case_id"])
        self.assertEqual(
            case["verification"]["build_policy_sha256"],
            "dbd2f2dd11a3de58ee247d161e27c482817b09158709dd571d83a6d4338dc6c0",
        )
        self.assertIn(
            case["workflow_run"]["caller_commit"],
            policy["signer"]["caller_digests"],
        )
        self.assertEqual(
            case["workflow_run"]["signer_commit"],
            policy["signer"]["workflow_digest"],
        )
        self.assertEqual(
            case["durable_agent_run"]["staged_evidence_sha256"],
            case["verification"]["evidence_sha256"],
        )
        self.assertNotEqual(
            case["durable_agent_run"]["source_evidence_snapshot_sha256"],
            case["durable_agent_run"]["staged_evidence_sha256"],
        )

    def test_command_pins_distinct_signer_and_caller_digests(self) -> None:
        policy = load_policy()
        signer = policy["signer"]
        caller_digest = signer["caller_digests"][0]
        command = github_attestation_verify_command(
            artifact_path=Path("artifact.whl"),
            bundle_path=Path("bundle.json"),
            predicate_type=policy["predicates"]["build"],
            target_repository=policy["control_repository"],
            source_digest=caller_digest,
            signer_digest=signer["workflow_digest"],
            source_ref=signer["source_ref"],
            certificate_identity=signer["certificate_identity"],
            oidc_issuer=signer["oidc_issuer"],
            deny_self_hosted_runners=True,
            executable_path=Path("gh"),
            trusted_root_path=Path("trusted-root.jsonl"),
        )

        self.assertEqual(
            flag_value(command, "--signer-digest"), signer["workflow_digest"]
        )
        self.assertEqual(
            flag_value(command, "--source-digest"), caller_digest
        )
        self.assertNotEqual(signer["workflow_digest"], caller_digest)

    def test_policy_requires_a_bounded_canonical_caller_allowlist(self) -> None:
        policy = load_policy()
        second_caller = "f" * 40
        policy["signer"]["caller_digests"].append(second_caller)
        validate_build_verification_policy(policy)

        policy["signer"]["caller_digests"].append(second_caller)
        with self.assertRaisesRegex(BuildVerificationError, "canonical"):
            validate_build_verification_policy(policy)

    def test_second_approved_caller_flows_through_every_identity_check(self) -> None:
        policy = load_policy()
        second_caller = "f" * 40
        policy["signer"]["caller_digests"].append(second_caller)
        entries = evidence_entries()
        predicate = build_predicate(
            policy,
            entries=entries,
            artifact_count=2,
            caller_digest=second_caller,
        )

        selected = validate_build_predicate(
            predicate,
            policy=policy,
            artifact_count=2,
            evidence_entries=entries,
        )
        validate_build_certificate(
            certificate(policy, caller_digest=second_caller),
            policy=policy,
            caller_digest=selected,
        )
        validate_build_provenance(
            provenance_predicate(policy, caller_digest=second_caller),
            policy=policy,
            caller_digest=selected,
        )
        command = github_attestation_verify_command(
            artifact_path=Path("artifact.whl"),
            bundle_path=Path("bundle.json"),
            predicate_type=policy["predicates"]["build"],
            target_repository=policy["control_repository"],
            source_digest=selected,
            signer_digest=policy["signer"]["workflow_digest"],
            source_ref=policy["signer"]["source_ref"],
            certificate_identity=policy["signer"]["certificate_identity"],
            oidc_issuer=policy["signer"]["oidc_issuer"],
            deny_self_hosted_runners=True,
            executable_path=Path("gh"),
            trusted_root_path=Path("trusted-root.jsonl"),
        )

        self.assertEqual(selected, second_caller)
        self.assertEqual(flag_value(command, "--source-digest"), second_caller)
        self.assertEqual(
            flag_value(command, "--signer-digest"),
            policy["signer"]["workflow_digest"],
        )

    def test_v2_policy_requires_a_pinned_source_date(self) -> None:
        policy = load_policy()
        policy["builder"] = {
            "profile": "python-wheel-v2",
            "image": "ghcr.io/saucetaster/assured-downstream-python-builder",
            "image_digest": "sha256:" + "a" * 64,
            "handoff_verifier_commit": "b" * 40,
        }
        policy["approved_request"]["source_date_epoch"] = "1783382521"
        validate_build_verification_policy(policy)

        del policy["approved_request"]["source_date_epoch"]
        with self.assertRaisesRegex(
            (BuildVerificationError, ReleaseVerificationError), "fields"
        ):
            validate_build_verification_policy(policy)

    def test_certificate_keeps_reusable_signer_and_caller_separate(self) -> None:
        policy = load_policy()
        caller_digest = policy["signer"]["caller_digests"][0]
        validate_build_certificate(
            certificate(policy),
            policy=policy,
            caller_digest=caller_digest,
        )

        confused = certificate(policy)
        confused["githubWorkflowSHA"] = policy["signer"]["workflow_digest"]
        with self.assertRaisesRegex(BuildVerificationError, "githubWorkflowSHA"):
            validate_build_certificate(
                confused,
                policy=policy,
                caller_digest=caller_digest,
            )

    def test_provenance_binds_the_caller_commit_and_reusable_builder(self) -> None:
        policy = load_policy()
        caller_digest = policy["signer"]["caller_digests"][0]
        provenance = provenance_predicate(policy, caller_digest=caller_digest)
        validate_build_provenance(
            provenance,
            policy=policy,
            caller_digest=caller_digest,
        )

        confused = copy.deepcopy(provenance)
        confused["buildDefinition"]["resolvedDependencies"][0]["digest"][
            "gitCommit"
        ] = policy["signer"]["workflow_digest"]
        with self.assertRaisesRegex(BuildVerificationError, "caller commit"):
            validate_build_provenance(
                confused,
                policy=policy,
                caller_digest=caller_digest,
            )

    def test_trace_requires_complete_counts_and_retained_raw_files(self) -> None:
        trace = complete_trace()
        validate_complete_trace(trace, raw_trace_counts=complete_raw_counts())

        trace["unparsed_line_count"] = 1
        with self.assertRaisesRegex(BuildVerificationError, "unparsed"):
            validate_complete_trace(trace, raw_trace_counts=complete_raw_counts())

        trace = complete_trace()
        trace["unparsed_line_count"] = False
        with self.assertRaisesRegex(BuildVerificationError, "unparsed"):
            validate_complete_trace(trace, raw_trace_counts=complete_raw_counts())

    def test_raw_trace_is_independently_reparsed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace = root / "traces" / "raw" / "strace.9"
            trace.parent.mkdir(parents=True)
            trace.write_text(
                "1783382521.000001 getpid() = 9 <0.000001>\n"
                "1783382521.000002 --- SIGCHLD {si_signo=SIGCHLD} ---\n",
                encoding="utf-8",
            )
            raw = trace.read_bytes()
            entry = {
                "path": "traces/raw/strace.9",
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            }

            counts = verify_raw_trace_records([entry], base_dir=root)
            self.assertEqual(
                counts,
                {"raw": 1, "parsed": 2, "syscall": 1, "signal": 1, "exit": 0},
            )

            trace.write_text("fabricated summary companion\n", encoding="utf-8")
            entry["sha256"] = hashlib.sha256(trace.read_bytes()).hexdigest()
            with self.assertRaisesRegex(BuildVerificationError, "independent grammar"):
                verify_raw_trace_records([entry], base_dir=root)

    def test_build_predicate_uses_the_actual_artifact_count(self) -> None:
        policy = load_policy()
        entries = evidence_entries()
        predicate = build_predicate(policy, entries=entries, artifact_count=2)
        validate_build_predicate(
            predicate,
            policy=policy,
            artifact_count=2,
            evidence_entries=entries,
        )

        predicate["evidence"]["artifactCount"] = 3
        with self.assertRaisesRegex(BuildVerificationError, "evidence digests"):
            validate_build_predicate(
                predicate,
                policy=policy,
                artifact_count=2,
                evidence_entries=entries,
            )

    def test_v2_build_predicate_requires_exact_identity_boundary(self) -> None:
        policy = load_policy()
        policy["builder"] = {
            "profile": "python-wheel-v2",
            "image": "ghcr.io/saucetaster/assured-downstream-python-builder",
            "image_digest": "sha256:" + "a" * 64,
            "handoff_verifier_commit": "b" * 40,
        }
        policy["approved_request"]["source_date_epoch"] = "1783382521"
        entries = evidence_entries()
        predicate = build_predicate(policy, entries=entries, artifact_count=2)
        validate_build_predicate(
            predicate,
            policy=policy,
            artifact_count=2,
            evidence_entries=entries,
        )

        predicate["builder"]["identityBoundary"]["killedProcessCount"] = True
        with self.assertRaisesRegex(BuildVerificationError, "builder claim"):
            validate_build_predicate(
                predicate,
                policy=policy,
                artifact_count=2,
                evidence_entries=entries,
            )

        predicate = build_predicate(policy, entries=entries, artifact_count=2)
        predicate["caller"]["commit"] = "f" * 40
        with self.assertRaisesRegex(BuildVerificationError, "not approved"):
            validate_build_predicate(
                predicate,
                policy=policy,
                artifact_count=2,
                evidence_entries=entries,
            )

        predicate = build_predicate(policy, entries=entries, artifact_count=2)
        predicate["source"]["unreviewedClaim"] = True
        with self.assertRaisesRegex(BuildVerificationError, "source fields"):
            validate_build_predicate(
                predicate,
                policy=policy,
                artifact_count=2,
                evidence_entries=entries,
            )

        predicate = build_predicate(policy, entries=entries, artifact_count=2)
        predicate["source"]["sourceDateEpoch"] = "1"
        with self.assertRaisesRegex(BuildVerificationError, "source date"):
            validate_build_predicate(
                predicate,
                policy=policy,
                artifact_count=2,
                evidence_entries=entries,
            )

    def test_build_predicate_rejects_boolean_integer_fields(self) -> None:
        policy = load_policy()
        entries = evidence_entries()
        predicate = build_predicate(policy, entries=entries, artifact_count=1)
        predicate["schemaVersion"] = True
        with self.assertRaisesRegex(BuildVerificationError, "identity"):
            validate_build_predicate(
                predicate,
                policy=policy,
                artifact_count=1,
                evidence_entries=entries,
            )

        predicate = build_predicate(policy, entries=entries, artifact_count=1)
        predicate["evidence"]["artifactCount"] = True
        with self.assertRaisesRegex(BuildVerificationError, "artifact count"):
            validate_build_predicate(
                predicate,
                policy=policy,
                artifact_count=1,
                evidence_entries=entries,
            )

    def test_unanchored_policy_fails_before_evidence_is_processed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = load_policy()
            policy["claim_limit"] += " tampered"
            policy_path = root / "policy.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            evidence_path = root / "evidence.json"
            evidence_path.write_text("{}\n", encoding="utf-8")

            with self.assertRaisesRegex(BuildVerificationError, "not anchored"):
                verify_build_attestations(
                    evidence_path=evidence_path,
                    policy_path=policy_path,
                    trust_policy_path=TRUST_POLICY_PATH,
                )

    def test_cli_exposes_build_attestation_verification(self) -> None:
        args = build_parser().parse_args(
            [
                "verify-build-attestations",
                "--evidence",
                "evidence.json",
                "--policy",
                "build-policy.json",
                "--trust-policy",
                "trust-policy.json",
                "--output",
                "verification.json",
            ]
        )
        self.assertEqual(args.evidence, Path("evidence.json"))
        self.assertEqual(args.trust_policy, Path("trust-policy.json"))


def load_policy() -> dict:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def certificate(
    policy: dict,
    *,
    caller_digest: str | None = None,
) -> dict[str, str]:
    signer = policy["signer"]
    caller_digest = caller_digest or signer["caller_digests"][0]
    repository = policy["control_repository"]
    caller_identity = (
        f"https://github.com/{repository}/{signer['caller_workflow_path']}"
        f"@{signer['source_ref']}"
    )
    return {
        "subjectAlternativeName": signer["certificate_identity"],
        "issuer": signer["oidc_issuer"],
        "githubWorkflowSHA": caller_digest,
        "githubWorkflowRepository": repository,
        "githubWorkflowRef": signer["source_ref"],
        "githubWorkflowTrigger": signer["trigger"],
        "buildSignerURI": signer["certificate_identity"],
        "buildSignerDigest": signer["workflow_digest"],
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": f"https://github.com/{repository}",
        "sourceRepositoryDigest": caller_digest,
        "sourceRepositoryRef": signer["source_ref"],
        "buildConfigURI": caller_identity,
        "buildConfigDigest": caller_digest,
        "buildTrigger": signer["trigger"],
    }


def provenance_predicate(
    policy: dict,
    *,
    caller_digest: str | None = None,
) -> dict:
    signer = policy["signer"]
    caller_digest = caller_digest or signer["caller_digests"][0]
    repository = policy["control_repository"]
    return {
        "buildDefinition": {
            "buildType": GITHUB_WORKFLOW_BUILD_TYPE,
            "externalParameters": {
                "workflow": {
                    "path": signer["caller_workflow_path"],
                    "ref": signer["source_ref"],
                    "repository": f"https://github.com/{repository}",
                }
            },
            "resolvedDependencies": [
                {
                    "uri": f"git+https://github.com/{repository}@{signer['source_ref']}",
                    "digest": {"gitCommit": caller_digest},
                }
            ],
        },
        "runDetails": {"builder": {"id": signer["certificate_identity"]}},
    }


def complete_trace() -> dict:
    return {
        "coverage": {"process": True, "file": True, "network": True, "syscall": True},
        "coverage_basis": "complete-parser-pass",
        "raw_file_count": 14,
        "parsed_line_count": 36_170,
        "syscall_line_count": 36_157,
        "signal_line_count": 13,
        "exit_line_count": 0,
        "unparsed_line_count": 0,
    }


def complete_raw_counts() -> dict[str, int]:
    return {"raw": 14, "parsed": 36_170, "syscall": 36_157, "signal": 13, "exit": 0}


def evidence_entries() -> dict[str, dict[str, str]]:
    return {
        "artifact_inventory": {"sha256": "1" * 64},
        "builder_report": {"sha256": "2" * 64},
        "source_inventory": {"sha256": "3" * 64},
        "trace": {"sha256": "4" * 64},
        "sbom": {"sha256": "5" * 64},
    }


def build_predicate(
    policy: dict,
    *,
    entries: dict[str, dict[str, str]],
    artifact_count: int,
    caller_digest: str | None = None,
) -> dict:
    request = policy["approved_request"]
    signer = policy["signer"]
    caller_digest = caller_digest or signer["caller_digests"][0]
    builder = policy["builder"]
    if builder["profile"] == "python-wheel-v1":
        builder_claim = {
            "profile": builder["profile"],
            "image": builder["image"],
            "imageDigest": builder["image_digest"],
            "uid": 65532,
            "gid": 65532,
            "network": "none",
            "readOnlyRoot": True,
            "capabilities": [],
            "noNewPrivileges": True,
        }
    else:
        builder_claim = {
            "profile": builder["profile"],
            "image": builder["image"],
            "imageDigest": builder["image_digest"],
            "network": "none",
            "traceArgv": [
                "/usr/bin/strace",
                "-u",
                "assured",
                "-ff",
                "-qq",
                "-ttt",
                "-T",
                "-yy",
                "-s",
                "4096",
                "-o",
                "/out/traces/raw/strace",
                "--",
                "/usr/local/bin/python",
                "-I",
                "-m",
                "build",
                "--no-isolation",
                "--outdir",
                "/workspace/output/dist",
                "/workspace/source",
            ],
            "identityBoundary": {
                "collectorUid": 0,
                "collectorGid": 0,
                "buildUid": 65532,
                "buildGid": 65532,
                "evidenceUid": 0,
                "evidenceGid": 0,
                "evidenceMode": "0700",
                "separateCollectorIdentity": True,
                "collectorOutputWritableByBuild": False,
                "quiescenceBarrier": "private-pid-namespace-sigkill",
                "killedProcessCount": 0,
                "remainingProcessCount": 0,
            },
        }
    return {
        "schemaVersion": 1,
        "predicateType": policy["predicates"]["build"],
        "source": {
            "repository": request["source_repository"],
            "commit": request["source_commit"],
            "tree": request["source_tree"],
            "projectVersion": request["project_version"],
            "sourceDateEpoch": "1783382521",
            "upstreamRepository": request["upstream_repository"],
            "upstreamCommit": request["upstream_commit"],
        },
        "downstream": {
            "caseId": request["case_id"],
            "releaseTag": request["release_tag"],
            "targetRepository": request["target_repository"],
        },
        "caller": {
            "repository": policy["control_repository"],
            "commit": caller_digest,
            "ref": signer["source_ref"],
        },
        "builder": builder_claim,
        "evidence": {
            "artifactCount": artifact_count,
            "artifactInventorySha256": entries["artifact_inventory"]["sha256"],
            "builderReportSha256": entries["builder_report"]["sha256"],
            "sourceInventorySha256": entries["source_inventory"]["sha256"],
            "traceSha256": entries["trace"]["sha256"],
            "sbomSha256": entries["sbom"]["sha256"],
        },
        "claimLimit": BUILD_CLAIM_LIMIT,
    }


def flag_value(command: list[str], flag: str) -> str:
    return command[command.index(flag) + 1]


if __name__ == "__main__":
    unittest.main()
