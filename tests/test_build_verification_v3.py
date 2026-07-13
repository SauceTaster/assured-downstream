from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from assured_downstream import builder_handoff_v3
from assured_downstream.build_verification_v3 import (
    BUILD_CLAIM_LIMIT,
    BUILD_PREDICATE_TYPE,
    BUILDER_DIGEST,
    BUILDER_IMAGE,
    CANONICALIZATION_POLICY_ID,
    PROFILE_ID,
    SPDX_NORMALIZATION_POLICY_ID,
    V3_EXPECTED_TRACE_ARGV,
    BuildVerificationError,
    decode_json_object,
    independently_normalize_spdx,
    validate_local_verifier_sources,
    validate_build_certificate,
    validate_build_predicate,
    validate_build_provenance,
    validate_build_verification_policy,
    validate_spdx_evidence,
    validate_v3_evidence_manifest,
)
from assured_downstream.build_verification_trust_v3 import (
    TRUSTED_BUILD_VERIFICATION_POLICY_SHA256,
    BuildVerificationTrustError,
    require_trusted_build_v3_policy,
    require_trusted_build_v3_sources,
)
from tests.test_builder_handoff_v3 import create_dist, create_raw_sbom


CALLER_COMMIT = "c" * 40
CALLED_COMMIT = "d" * 40
HANDOFF_COMMIT = "e" * 40
SOURCE_FILESYSTEM_SHA256 = "9" * 64
ROOT = Path(__file__).resolve().parents[1]


class BuildVerificationV3Tests(unittest.TestCase):
    def test_checked_in_policy_is_hash_anchored_and_case_scoped(self) -> None:
        policy_path = ROOT / "policies" / "build-verification-v3.json"
        payload = policy_path.read_bytes()
        policy = decode_json_object(payload, label="checked-in v3 build policy")

        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            TRUSTED_BUILD_VERIFICATION_POLICY_SHA256,
        )
        validate_build_verification_policy(policy)
        sources = validate_local_verifier_sources(policy)
        self.assertEqual(policy["status"], "active-dev-case-study")
        self.assertEqual(
            policy["approved_request"]["case_id"],
            "case-001-bandit-source-canary-v3",
        )
        self.assertEqual(len(policy["signer"]["caller_digests"]), 1)
        self.assertEqual(
            sources["source_sha256"],
            policy["verifier"]["source_sha256"],
        )

        profile = json.loads(
            (
                ROOT / "policies" / "builders" / "python-wheel-v3.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            profile["verification"]["policy_sha256"],
            TRUSTED_BUILD_VERIFICATION_POLICY_SHA256,
        )
        self.assertFalse(profile["validated_case"]["provider_independent"])
        self.assertFalse(profile["validated_case"]["promotion_authorized"])

    def test_joint_policy_and_verifier_mutation_cannot_reanchor_trust(self) -> None:
        policy_path = ROOT / "policies" / "build-verification-v3.json"
        policy_bytes = policy_path.read_bytes()
        policy = decode_json_object(policy_bytes, label="checked-in v3 build policy")
        mutated_source_sha256 = hashlib.sha256(b"mutated verifier source").hexdigest()
        mutated_policy_bytes = policy_bytes.replace(
            policy["verifier"]["source_sha256"].encode("ascii"),
            mutated_source_sha256.encode("ascii"),
        )
        mutated_policy_sha256 = hashlib.sha256(mutated_policy_bytes).hexdigest()

        with self.assertRaisesRegex(BuildVerificationTrustError, "code trust root"):
            require_trusted_build_v3_policy(mutated_policy_sha256)
        with self.assertRaisesRegex(BuildVerificationTrustError, "code trust root"):
            require_trusted_build_v3_sources(
                verifier_module=policy["verifier"]["module"],
                verifier_source_sha256=mutated_source_sha256,
                archive_validator_module=policy["verifier"][
                    "archive_validator_module"
                ],
                archive_validator_source_sha256=policy["verifier"][
                    "archive_validator_sha256"
                ],
            )

    def test_policy_is_exact_and_rejects_action_drift(self) -> None:
        policy = valid_policy()
        self.assertIs(validate_build_verification_policy(policy), policy)

        policy["actions"]["actions/attest"] = "f" * 40
        with self.assertRaisesRegex(BuildVerificationError, "action pin"):
            validate_build_verification_policy(policy)

    def test_independent_spdx_rebuild_matches_handoff_bytes(self) -> None:
        policy = valid_policy()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_dist(root)
            create_raw_sbom(root, include_second_package=True)
            artifacts = builder_handoff_v3.artifact_entries(root)
            request = policy["approved_request"]
            builder_handoff_v3.normalize_spdx(
                root,
                source_repository=request["source_repository"],
                source_commit=request["source_commit"],
                source_tree=request["source_tree"],
                project_version=request["project_version"],
                source_date_epoch=request["source_date_epoch"],
            )
            raw_bytes = (root / "sbom" / "raw" / "syft.spdx.json").read_bytes()
            normalized_bytes = (root / "sbom" / "sbom.spdx.json").read_bytes()
            normalized = json.loads(normalized_bytes)
            report = json.loads(
                (root / "reports" / "spdx-normalization.json").read_text()
            )

            result = validate_spdx_evidence(
                raw_bytes=raw_bytes,
                normalized_bytes=normalized_bytes,
                normalized=normalized,
                artifacts=artifacts,
                policy=policy,
                report=report,
            )
            independently_built, _ = independently_normalize_spdx(
                json.loads(raw_bytes),
                artifacts=artifacts,
                policy=policy,
            )

            self.assertEqual(independently_built, normalized)
            self.assertEqual(
                result["bindings"],
                [
                    {"path": item["path"], "sha256": item["sha256"]}
                    for item in artifacts
                ],
            )
            normalized["documentNamespace"] += "-tampered"
            with self.assertRaisesRegex(BuildVerificationError, "canonical"):
                validate_spdx_evidence(
                    raw_bytes=raw_bytes,
                    normalized_bytes=normalized_bytes,
                    normalized=normalized,
                    artifacts=artifacts,
                    policy=policy,
                    report=report,
                )

    def test_predicate_binds_paths_run_and_evidence(self) -> None:
        policy = valid_policy()
        artifacts = [
            {"path": "dist/bandit.whl", "size": 5, "sha256": "1" * 64},
            {"path": "dist/bandit.tar.gz", "size": 7, "sha256": "2" * 64},
        ]
        entries = evidence_entries()
        spdx = {
            "document_namespace": (
                "https://assured-downstream.dev/spdx/python-wheel-v3/" + "3" * 64
            ),
            "creation_time": "2026-07-07T00:02:01Z",
            "bindings": [
                {"path": item["path"], "sha256": item["sha256"]} for item in artifacts
            ],
        }
        predicate = build_predicate(policy, artifacts, entries, spdx)

        caller = validate_build_predicate(
            predicate,
            policy=policy,
            artifact_records=artifacts,
            evidence_entries=entries,
            spdx_bindings=spdx,
            source_filesystem_sha256=SOURCE_FILESYSTEM_SHA256,
        )
        self.assertEqual(caller, CALLER_COMMIT)

        predicate["run"]["id"] = "0"
        with self.assertRaisesRegex(BuildVerificationError, "run identity"):
            validate_build_predicate(
                predicate,
                policy=policy,
                artifact_records=artifacts,
                evidence_entries=entries,
                spdx_bindings=spdx,
                source_filesystem_sha256=SOURCE_FILESYSTEM_SHA256,
            )

    def test_certificate_and_provenance_bind_run_invocation(self) -> None:
        policy = valid_policy()
        run = run_claim()
        certificate = certificate_claim(policy, run)
        validate_build_certificate(
            certificate,
            policy=policy,
            caller_digest=CALLER_COMMIT,
            run_claim=run,
        )
        provenance = provenance_claim(policy, run)
        validate_build_provenance(
            provenance,
            policy=policy,
            caller_digest=CALLER_COMMIT,
            run_claim=run,
        )

        certificate["runInvocationURI"] = certificate["runInvocationURI"].replace(
            "/1", "/2"
        )
        with self.assertRaisesRegex(BuildVerificationError, "runInvocationURI"):
            validate_build_certificate(
                certificate,
                policy=policy,
                caller_digest=CALLER_COMMIT,
                run_claim=run,
            )

    def test_json_and_evidence_storage_schema_fail_closed(self) -> None:
        with self.assertRaisesRegex(BuildVerificationError, "duplicate key"):
            decode_json_object(b'{"value":1,"value":2}', label="test JSON")
        with self.assertRaisesRegex(BuildVerificationError, "Could not parse"):
            decode_json_object(b'{"value":1e999}', label="test JSON")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logical_paths = {
                "artifacts": "dist/example.whl",
                "attestations": "attestations/example.sigstore.json",
                "raw_artifacts": "raw-artifacts/example.whl",
                "reports": "reports/example.json",
                "sboms": "sbom/example.spdx.json",
                "traces": "traces/example.json",
            }
            roles = {}
            for role, logical_path in logical_paths.items():
                payload = f"{role}\n".encode()
                digest = hashlib.sha256(payload).hexdigest()
                name = Path(logical_path).name
                storage_path = f"files/{role}/{digest}-00001-{name}"
                path = root / storage_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
                roles[role] = [
                    {
                        "logical_path": logical_path,
                        "name": name,
                        "path": storage_path,
                        "role": role,
                        "sha256": digest,
                        "size": len(payload),
                    }
                ]
            manifest = {
                "schema_version": 2,
                "generated_at": "2026-07-13T00:00:00+00:00",
                "project": {},
                "evidence": roles,
            }
            self.assertEqual(
                set(validate_v3_evidence_manifest(manifest, base_dir=root)),
                set(roles),
            )

            roles["artifacts"][0]["path"] = roles["reports"][0]["path"]
            with self.assertRaisesRegex(BuildVerificationError, "not bound"):
                validate_v3_evidence_manifest(manifest, base_dir=root)


def valid_policy() -> dict:
    return {
        "schema_version": 4,
        "status": "active-dev-case-study",
        "control_repository": "SauceTaster/assured-downstream",
        "signer": {
            "workflow_path": ".github/workflows/reusable-python-build-v3.yml",
            "workflow_digest": CALLED_COMMIT,
            "certificate_identity": (
                "https://github.com/SauceTaster/assured-downstream/.github/"
                f"workflows/reusable-python-build-v3.yml@{CALLED_COMMIT}"
            ),
            "caller_workflow_path": (
                ".github/workflows/case-study-bandit-build-v3.yml"
            ),
            "caller_digests": [CALLER_COMMIT],
            "source_ref": "refs/heads/main",
            "trigger": "workflow_dispatch",
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "deny_self_hosted_runners": True,
            "workflow_name": "Case Study 001 Bandit Build Canary v3",
            "actor": "SauceTaster",
            "triggering_actor": "SauceTaster",
            "run_attempt": "1",
        },
        "approved_request": {
            "case_id": "case-001-bandit-source-canary-v3",
            "source_repository": "PyCQA/bandit",
            "source_commit": "c45446eaa30c4f28289c3b8ba9a955e1d78ba715",
            "source_tree": "5313408ad294e5a95f214620ec3064f8e40bc608",
            "source_date_epoch": "1783382521",
            "upstream_repository": "PyCQA/bandit",
            "upstream_commit": "c45446eaa30c4f28289c3b8ba9a955e1d78ba715",
            "target_repository": "SauceTaster/assured-bandit",
            "project_version": "1.9.4",
            "release_tag": "case-001-bandit-source-canary-v3",
        },
        "builder": {
            "profile": PROFILE_ID,
            "image": BUILDER_IMAGE,
            "image_digest": BUILDER_DIGEST,
            "handoff_verifier_commit": HANDOFF_COMMIT,
            "handoff_verifier_sha256": "4" * 64,
            "canonicalization_policy": CANONICALIZATION_POLICY_ID,
            "base_image_index_digest": (
                "sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7"
            ),
            "source_digests": {
                "builders/python-v3/Dockerfile": (
                    "def67c917675090d4b147f1b89b6ce5bedeb803591fae8322adb70dac3db88a6"
                ),
                "builders/python-v3/entrypoint.py": (
                    "9601c51e015dd7b45cb4e78f62f4de6af98fdeff048f0c23af467ae5c27d6884"
                ),
                "builders/python-v3/requirements.lock": (
                    "6a060a27d9e1d93a78a969d67b7d5e7f9508b73b99c0332315f8646ae80fd2a6"
                ),
            },
        },
        "spdx": {
            "normalization_policy": SPDX_NORMALIZATION_POLICY_ID,
            "syft_version": "1.42.3",
            "creators": ["Organization: Anchore, Inc", "Tool: syft-1.42.3"],
            "license_list_version": "3.28",
        },
        "actions": {
            "actions/attest": "a1948c3f048ba23858d222213b7c278aabede763",
            "actions/checkout": "34e114876b0b11c390a56381ad16ebd13914f8d5",
            "actions/download-artifact": ("3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"),
            "actions/upload-artifact": ("043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"),
            "anchore/sbom-action": "e22c389904149dbc22b58101806040fa8d37a610",
        },
        "predicates": {
            "provenance": "https://slsa.dev/provenance/v1",
            "sbom": "https://spdx.dev/Document/v2.3",
            "build": BUILD_PREDICATE_TYPE,
        },
        "verifier": {
            "module": "src/assured_downstream/build_verification_v3.py",
            "source_sha256": "1" * 64,
            "archive_validator_module": (
                "src/assured_downstream/archive_validation_v3.py"
            ),
            "archive_validator_sha256": "2" * 64,
        },
        "trust_policy_sha256": (
            "abca9090eebb736a72ce30102f812a5ed6f4ffb46dc3e9f3f041fad2d1fac344"
        ),
        "claim_limit": (
            "This policy verifies one bounded Bandit v3 evidence candidate. It "
            "does not establish upstream ancestry, provider-independent rebuilds, "
            "builder or collector tamper resistance, or semantic safety."
        ),
    }


def evidence_entries() -> dict[str, dict]:
    records = {
        "artifact_inventory": ("reports/artifact-inventory.json", "a" * 64),
        "artifact_transform": ("reports/artifact-transforms.json", "b" * 64),
        "artifact_subject_manifest": (
            "reports/artifact-subjects.sha256",
            "c" * 64,
        ),
        "builder_report": ("reports/builder.json", "d" * 64),
        "source_inventory": ("reports/source-inventory.json", "e" * 64),
        "trusted_source_inventory": (
            "reports/trusted-source-inventory.json",
            "4" * 64,
        ),
        "handoff_seal": ("reports/handoff-seal.json", "5" * 64),
        "trace": ("traces/observed-trace.json", "f" * 64),
        "raw_sbom": ("sbom/raw/syft.spdx.json", "1" * 64),
        "sbom": ("sbom/sbom.spdx.json", "2" * 64),
        "spdx_normalization": ("reports/spdx-normalization.json", "3" * 64),
    }
    return {
        name: {
            "logical_path": path,
            "path": path,
            "size": 123,
            "sha256": digest,
        }
        for name, (path, digest) in records.items()
    }


def run_claim() -> dict:
    return {
        "id": "29240000001",
        "attempt": "1",
        "event": "workflow_dispatch",
        "actor": "SauceTaster",
        "triggeringActor": "SauceTaster",
        "runnerEnvironment": "github-hosted",
    }


def build_predicate(
    policy: dict,
    artifacts: list[dict],
    entries: dict[str, dict],
    spdx: dict,
) -> dict:
    request = policy["approved_request"]
    signer = policy["signer"]
    builder = policy["builder"]
    return {
        "schemaVersion": 2,
        "predicateType": BUILD_PREDICATE_TYPE,
        "profile": PROFILE_ID,
        "source": {
            "repository": request["source_repository"],
            "commit": request["source_commit"],
            "tree": request["source_tree"],
            "filesystemSha256": SOURCE_FILESYSTEM_SHA256,
            "upstreamRepository": request["upstream_repository"],
            "upstreamCommit": request["upstream_commit"],
            "projectVersion": request["project_version"],
            "sourceDateEpoch": request["source_date_epoch"],
        },
        "downstream": {
            "targetRepository": request["target_repository"],
            "releaseTag": request["release_tag"],
            "caseId": request["case_id"],
        },
        "caller": {
            "repository": policy["control_repository"],
            "workflowPath": signer["caller_workflow_path"],
            "workflowRef": (
                f"{policy['control_repository']}/{signer['caller_workflow_path']}"
                f"@{signer['source_ref']}"
            ),
            "workflowSha": CALLER_COMMIT,
        },
        "called": {
            "repository": policy["control_repository"],
            "workflowPath": signer["workflow_path"],
            "workflowRef": (
                f"{policy['control_repository']}/{signer['workflow_path']}"
                f"@{CALLED_COMMIT}"
            ),
            "workflowSha": CALLED_COMMIT,
        },
        "run": run_claim(),
        "builder": {
            "image": builder["image"],
            "imageDigest": builder["image_digest"],
            "network": "none",
            "traceArgv": V3_EXPECTED_TRACE_ARGV,
            "canonicalizationPolicy": builder["canonicalization_policy"],
            "handoffVerifierCommit": HANDOFF_COMMIT,
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
                "remainingProcessCount": 0,
                "killedProcessCount": 0,
            },
        },
        "materials": {
            "builderSources": [
                {"path": path, "sha256": digest}
                for path, digest in sorted(builder["source_digests"].items())
            ],
            "baseImageIndexDigest": builder["base_image_index_digest"],
            "actionPins": policy["actions"],
        },
        "artifacts": artifacts,
        "sbom": {
            "normalizationPolicy": SPDX_NORMALIZATION_POLICY_ID,
            "raw": evidence_record(entries["raw_sbom"]),
            "normalized": evidence_record(entries["sbom"]),
            "normalizationReport": {
                "path": "reports/spdx-normalization.json",
                "sha256": entries["spdx_normalization"]["sha256"],
            },
            "documentNamespace": spdx["document_namespace"],
            "creationTime": spdx["creation_time"],
            "artifactBindings": spdx["bindings"],
        },
        "evidence": {
            "artifactSubjectManifest": evidence_record(
                entries["artifact_subject_manifest"]
            ),
            "artifactInventorySha256": entries["artifact_inventory"]["sha256"],
            "artifactTransformSha256": entries["artifact_transform"]["sha256"],
            "builderReportSha256": entries["builder_report"]["sha256"],
            "sourceInventorySha256": entries["source_inventory"]["sha256"],
            "trustedSourceInventorySha256": entries["trusted_source_inventory"][
                "sha256"
            ],
            "handoffSealSha256": entries["handoff_seal"]["sha256"],
            "traceSha256": entries["trace"]["sha256"],
        },
        "claimLimit": BUILD_CLAIM_LIMIT,
    }


def evidence_record(entry: dict) -> dict:
    return {
        "path": entry["logical_path"],
        "size": entry["size"],
        "sha256": entry["sha256"],
    }


def certificate_claim(policy: dict, run: dict) -> dict:
    signer = policy["signer"]
    repo = policy["control_repository"]
    caller_identity = (
        f"https://github.com/{repo}/{signer['caller_workflow_path']}"
        f"@{signer['source_ref']}"
    )
    return {
        "subjectAlternativeName": signer["certificate_identity"],
        "issuer": signer["oidc_issuer"],
        "githubWorkflowSHA": CALLER_COMMIT,
        "githubWorkflowName": signer["workflow_name"],
        "githubWorkflowRepository": repo,
        "githubWorkflowRef": signer["source_ref"],
        "githubWorkflowTrigger": signer["trigger"],
        "buildSignerURI": signer["certificate_identity"],
        "buildSignerDigest": CALLED_COMMIT,
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": f"https://github.com/{repo}",
        "sourceRepositoryDigest": CALLER_COMMIT,
        "sourceRepositoryRef": signer["source_ref"],
        "buildConfigURI": caller_identity,
        "buildConfigDigest": CALLER_COMMIT,
        "buildTrigger": signer["trigger"],
        "runInvocationURI": (
            f"https://github.com/{repo}/actions/runs/{run['id']}/attempts/"
            f"{run['attempt']}"
        ),
    }


def provenance_claim(policy: dict, run: dict) -> dict:
    signer = policy["signer"]
    repo = policy["control_repository"]
    return {
        "buildDefinition": {
            "buildType": ("https://actions.github.io/buildtypes/workflow/v1"),
            "externalParameters": {
                "workflow": {
                    "path": signer["caller_workflow_path"],
                    "ref": signer["source_ref"],
                    "repository": f"https://github.com/{repo}",
                }
            },
            "resolvedDependencies": [
                {
                    "uri": f"git+https://github.com/{repo}@{signer['source_ref']}",
                    "digest": {"gitCommit": CALLER_COMMIT},
                }
            ],
        },
        "runDetails": {
            "builder": {"id": signer["certificate_identity"]},
            "metadata": {
                "invocationId": (
                    f"https://github.com/{repo}/actions/runs/{run['id']}/attempts/"
                    f"{run['attempt']}"
                )
            },
        },
    }


if __name__ == "__main__":
    unittest.main()
