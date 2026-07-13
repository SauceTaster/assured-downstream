from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Callable
from unittest.mock import patch

from assured_downstream.command_runner import CommandResult
from assured_downstream.evidence import create_evidence_manifest, sha256_file
from assured_downstream.release_render import ASSURED_DOWNSTREAM_PREDICATE_TYPE
from assured_downstream.release_verification import (
    GITHUB_ACTIONS_OIDC_ISSUER,
    GITHUB_WORKFLOW_BUILD_TYPE,
    SLSA_PROVENANCE_PREDICATE_TYPE,
    SPDX_23_PREDICATE_TYPE,
    ReleaseVerificationError,
    github_attestation_verify_command,
    verify_release_attestations,
)


class FakeReleaseVerifier:
    def __init__(
        self,
        fixture: dict,
        *,
        mutate: Callable[[str, list[dict]], None] | None = None,
        returncode: int = 0,
    ) -> None:
        self.fixture = fixture
        self.mutate = mutate
        self.returncode = returncode
        self.calls: list[dict] = []

    def run(
        self,
        command: list[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
        timeout_seconds: float | None = None,
        inherit_env: bool = True,
    ) -> CommandResult:
        self.calls.append(
            {
                "command": command,
                "cwd": cwd,
                "env": env,
                "timeout_seconds": timeout_seconds,
                "inherit_env": inherit_env,
            }
        )
        predicate_type = flag_value(command, "--predicate-type")
        role = {
            SLSA_PROVENANCE_PREDICATE_TYPE: "provenance",
            SPDX_23_PREDICATE_TYPE: "sbom",
            ASSURED_DOWNSTREAM_PREDICATE_TYPE: "policy",
        }[predicate_type]
        output = self.verification_output(role, command)
        if self.mutate is not None:
            self.mutate(role, output)
        return CommandResult(
            command=command,
            executed=True,
            returncode=self.returncode,
            stdout=json.dumps(output),
            stderr="verification rejected" if self.returncode else "",
        )

    def verification_output(self, role: str, command: list[str]) -> list[dict]:
        project = self.fixture["project"]
        source_ref = flag_value(command, "--source-ref")
        certificate_identity = flag_value(command, "--cert-identity")
        workflow_path = self.fixture["policy"]["workflow_path"]
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {"name": name, "digest": {"sha256": digest}}
                for name, digest in zip(
                    self.fixture["artifact_names"],
                    self.fixture["artifact_digests"],
                    strict=True,
                )
            ],
            "predicateType": self.fixture["policy"]["predicates"][role],
            "predicate": self.predicate(
                role,
                project=project,
                source_ref=source_ref,
                certificate_identity=certificate_identity,
                workflow_path=workflow_path,
            ),
        }
        certificate = {
            "subjectAlternativeName": certificate_identity,
            "issuer": GITHUB_ACTIONS_OIDC_ISSUER,
            "githubWorkflowSHA": project["overlay_ref"],
            "githubWorkflowRepository": project["target_full_name"],
            "githubWorkflowRef": source_ref,
            "buildSignerURI": certificate_identity,
            "buildSignerDigest": project["overlay_ref"],
            "runnerEnvironment": "github-hosted",
            "sourceRepositoryURI": (
                f"https://github.com/{project['target_full_name']}"
            ),
            "sourceRepositoryDigest": project["overlay_ref"],
            "sourceRepositoryRef": source_ref,
            "buildConfigURI": certificate_identity,
            "buildConfigDigest": project["overlay_ref"],
        }
        return [
            {
                "verificationResult": {
                    "statement": statement,
                    "signature": {"certificate": certificate},
                    "verifiedTimestamps": [{"type": "Tlog"}],
                }
            }
        ]

    def predicate(
        self,
        role: str,
        *,
        project: dict,
        source_ref: str,
        certificate_identity: str,
        workflow_path: str,
    ) -> dict:
        if role == "sbom":
            return self.fixture["sbom"]
        if role == "policy":
            signer = f"{project['target_full_name']}/{workflow_path}"
            return {
                "policyVersion": "assured-downstream-attested-v1",
                "sourceRepository": project["source_full_name"],
                "targetRepository": project["target_full_name"],
                "upstreamRef": project["upstream_ref"],
                "overlayRef": project["overlay_ref"],
                "workflowRef": f"{signer}@{source_ref}",
                "lineagePolicy": (
                    "upstream ref is an ancestor of the attested overlay ref"
                ),
            }
        return {
            "buildDefinition": {
                "buildType": GITHUB_WORKFLOW_BUILD_TYPE,
                "externalParameters": {
                    "workflow": {
                        "path": workflow_path,
                        "ref": source_ref,
                        "repository": (
                            f"https://github.com/{project['target_full_name']}"
                        ),
                    }
                },
                "resolvedDependencies": [
                    {
                        "digest": {"gitCommit": project["overlay_ref"]},
                        "uri": (
                            "git+https://github.com/"
                            f"{project['target_full_name']}@{source_ref}"
                        ),
                    }
                ],
            },
            "runDetails": {"builder": {"id": certificate_identity}},
        }


class ReleaseVerificationTests(unittest.TestCase):
    def test_generated_command_uses_a_supported_gh_identity_flag_set(self) -> None:
        executable = shutil.which("gh")
        if executable is None:
            self.skipTest("gh is not installed")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "artifact.bin"
            bundle = root / "bundle.json"
            trusted_root = root / "trusted-root.jsonl"
            artifact.write_bytes(b"fixture\n")
            bundle.write_text("{}\n", encoding="utf-8")
            policy = json.loads(
                (
                    Path(__file__).resolve().parents[1]
                    / "policies"
                    / "release-verification.json"
                ).read_text(encoding="utf-8")
            )
            trusted_root.write_text(
                json.dumps(
                    policy["sigstore_trusted_root"],
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            command = github_attestation_verify_command(
                artifact_path=artifact,
                bundle_path=bundle,
                predicate_type=SLSA_PROVENANCE_PREDICATE_TYPE,
                target_repository="SauceTaster/assured-demo",
                source_digest="b" * 40,
                source_ref="refs/tags/secure-v1.0.0",
                certificate_identity=(
                    "https://github.com/SauceTaster/assured-demo/.github/workflows/"
                    "assured-downstream-attested-release.yml@refs/tags/secure-v1.0.0"
                ),
                oidc_issuer=GITHUB_ACTIONS_OIDC_ISSUER,
                deny_self_hosted_runners=True,
                executable_path=Path(executable),
                trusted_root_path=trusted_root,
            )

            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

        output = completed.stdout + completed.stderr
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn("if any flags in the group", output)
        self.assertNotIn("unknown flag", output)
        self.assertNotIn("custom trusted root", output.lower())

    def test_verifies_three_retained_bundles_with_exact_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = write_fixture(Path(tmp))
            runner = FakeReleaseVerifier(fixture)

            with trust_release_policy(fixture["policy_path"]):
                record = verify_release_attestations(
                    evidence_path=fixture["evidence_path"],
                    policy_path=fixture["policy_path"],
                    runner=runner,
                )

        self.assertEqual(record["status"], "verified")
        self.assertEqual(record["authority"], "code-anchored-github-sigstore")
        self.assertEqual(record["overlay_ref"], "b" * 40)
        self.assertEqual(
            {item["sha256"] for item in record["verified_subjects"]},
            set(fixture["artifact_digests"]),
        )
        self.assertEqual(set(record["bundles"]), {"provenance", "sbom", "policy"})
        self.assertEqual(len(runner.calls), 3)
        for call in runner.calls:
            command = call["command"]
            self.assertIn("--bundle", command)
            self.assertIn("--deny-self-hosted-runners", command)
            self.assertNotIn("--signer-workflow", command)
            self.assertEqual(flag_value(command, "--hostname"), "github.com")
            self.assertIn("--custom-trusted-root", command)
            self.assertEqual(flag_value(command, "--source-digest"), "b" * 40)
            self.assertEqual(
                flag_value(command, "--source-ref"), "refs/tags/secure-v1.0.0"
            )
            self.assertEqual(call["env"]["GH_TOKEN"], "")
            self.assertEqual(call["env"]["GITHUB_TOKEN"], "")
            self.assertEqual(call["env"]["GH_HOST"], "github.com")
            self.assertEqual(call["env"]["DYLD_INSERT_LIBRARIES"], "")
            self.assertEqual(call["env"]["LD_PRELOAD"], "")
            self.assertEqual(call["timeout_seconds"], 60.0)
            self.assertFalse(call["inherit_env"])
            self.assertNotEqual(call["cwd"], str(fixture["root"]))
        self.assertFalse(record["independently_verified"]["upstream_lineage"])
        self.assertEqual(
            record["attested_claims"]["lineage"],
            "workflow-asserted-ancestor",
        )

    def test_rejects_bundle_with_missing_artifact_subject(self) -> None:
        def mutate(role: str, output: list[dict]) -> None:
            if role == "provenance":
                output[0]["verificationResult"]["statement"]["subject"].pop()

        with tempfile.TemporaryDirectory() as tmp:
            fixture = write_fixture(Path(tmp))
            with trust_release_policy(fixture["policy_path"]):
                with self.assertRaisesRegex(
                    ReleaseVerificationError,
                    "exactly match release artifacts",
                ):
                    verify_release_attestations(
                        evidence_path=fixture["evidence_path"],
                        policy_path=fixture["policy_path"],
                        runner=FakeReleaseVerifier(fixture, mutate=mutate),
                    )

    def test_rejects_custom_predicate_that_misstates_recorded_upstream(self) -> None:
        def mutate(role: str, output: list[dict]) -> None:
            if role == "policy":
                output[0]["verificationResult"]["statement"]["predicate"][
                    "upstreamRef"
                ] = "c" * 40

        with tempfile.TemporaryDirectory() as tmp:
            fixture = write_fixture(Path(tmp))
            with trust_release_policy(fixture["policy_path"]):
                with self.assertRaisesRegex(
                    ReleaseVerificationError,
                    "Policy predicate",
                ):
                    verify_release_attestations(
                        evidence_path=fixture["evidence_path"],
                        policy_path=fixture["policy_path"],
                        runner=FakeReleaseVerifier(fixture, mutate=mutate),
                    )

    def test_rejects_sbom_without_release_artifact_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = write_fixture(Path(tmp), bind_sbom_subjects=False)
            runner = FakeReleaseVerifier(fixture)

            with trust_release_policy(fixture["policy_path"]):
                with self.assertRaisesRegex(
                    ReleaseVerificationError,
                    "does not reference every release artifact subject",
                ):
                    verify_release_attestations(
                        evidence_path=fixture["evidence_path"],
                        policy_path=fixture["policy_path"],
                        runner=runner,
                    )

        self.assertEqual(runner.calls, [])

    def test_rejects_sbom_subject_without_document_describes_relationship(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = write_fixture(Path(tmp), describe_sbom_subjects=False)
            runner = FakeReleaseVerifier(fixture)

            with trust_release_policy(fixture["policy_path"]):
                with self.assertRaisesRegex(
                    ReleaseVerificationError,
                    "does not reference every release artifact subject",
                ):
                    verify_release_attestations(
                        evidence_path=fixture["evidence_path"],
                        policy_path=fixture["policy_path"],
                        runner=runner,
                    )

        self.assertEqual(runner.calls, [])

    def test_rejects_certificate_for_a_different_workflow_commit(self) -> None:
        def mutate(role: str, output: list[dict]) -> None:
            output[0]["verificationResult"]["signature"]["certificate"][
                "githubWorkflowSHA"
            ] = "c" * 40

        with tempfile.TemporaryDirectory() as tmp:
            fixture = write_fixture(Path(tmp))
            with trust_release_policy(fixture["policy_path"]):
                with self.assertRaisesRegex(
                    ReleaseVerificationError,
                    "githubWorkflowSHA",
                ):
                    verify_release_attestations(
                        evidence_path=fixture["evidence_path"],
                        policy_path=fixture["policy_path"],
                        runner=FakeReleaseVerifier(fixture, mutate=mutate),
                    )

    def test_rejects_verification_without_transparency_log_timestamp(self) -> None:
        def mutate(role: str, output: list[dict]) -> None:
            output[0]["verificationResult"]["verifiedTimestamps"] = [
                {"type": "timestamp-authority"}
            ]

        with tempfile.TemporaryDirectory() as tmp:
            fixture = write_fixture(Path(tmp))
            with trust_release_policy(fixture["policy_path"]):
                with self.assertRaisesRegex(
                    ReleaseVerificationError,
                    "no transparency-log timestamp",
                ):
                    verify_release_attestations(
                        evidence_path=fixture["evidence_path"],
                        policy_path=fixture["policy_path"],
                        runner=FakeReleaseVerifier(fixture, mutate=mutate),
                    )

    def test_rejects_sbom_predicate_that_differs_from_retained_document(self) -> None:
        def mutate(role: str, output: list[dict]) -> None:
            if role == "sbom":
                output[0]["verificationResult"]["statement"]["predicate"]["name"] = (
                    "different"
                )

        with tempfile.TemporaryDirectory() as tmp:
            fixture = write_fixture(Path(tmp))
            with trust_release_policy(fixture["policy_path"]):
                with self.assertRaisesRegex(
                    ReleaseVerificationError,
                    "Sbom predicate",
                ):
                    verify_release_attestations(
                        evidence_path=fixture["evidence_path"],
                        policy_path=fixture["policy_path"],
                        runner=FakeReleaseVerifier(fixture, mutate=mutate),
                    )

    def test_rejects_unanchored_policy_before_running_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = write_fixture(Path(tmp))
            runner = FakeReleaseVerifier(fixture)

            with self.assertRaisesRegex(
                ReleaseVerificationError,
                "not anchored",
            ):
                verify_release_attestations(
                    evidence_path=fixture["evidence_path"],
                    policy_path=fixture["policy_path"],
                    runner=runner,
                )

        self.assertEqual(runner.calls, [])

    def test_rejects_malformed_manifest_with_domain_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = write_fixture(Path(tmp))
            manifest = json.loads(fixture["evidence_path"].read_text(encoding="utf-8"))
            manifest["evidence"] = []
            write_json(fixture["evidence_path"], manifest)

            with trust_release_policy(fixture["policy_path"]):
                with self.assertRaisesRegex(
                    ReleaseVerificationError,
                    "manifest structure is invalid",
                ):
                    verify_release_attestations(
                        evidence_path=fixture["evidence_path"],
                        policy_path=fixture["policy_path"],
                        runner=FakeReleaseVerifier(fixture),
                    )

    def test_rejects_tampered_verifier_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = write_fixture(Path(tmp))
            fixture["executable"].chmod(0o700)
            fixture["executable"].write_bytes(b"tampered verifier\n")
            runner = FakeReleaseVerifier(fixture)

            with trust_release_policy(fixture["policy_path"]):
                with self.assertRaisesRegex(
                    ReleaseVerificationError,
                    "executable digest",
                ):
                    verify_release_attestations(
                        evidence_path=fixture["evidence_path"],
                        policy_path=fixture["policy_path"],
                        runner=runner,
                    )

        self.assertEqual(runner.calls, [])

    def test_rejects_target_repository_outside_controlled_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = write_fixture(Path(tmp), target_full_name="other/project")
            runner = FakeReleaseVerifier(fixture)

            with trust_release_policy(fixture["policy_path"]):
                with self.assertRaisesRegex(
                    ReleaseVerificationError,
                    "outside the release verification policy",
                ):
                    verify_release_attestations(
                        evidence_path=fixture["evidence_path"],
                        policy_path=fixture["policy_path"],
                        runner=runner,
                    )

        self.assertEqual(runner.calls, [])


def write_fixture(
    root: Path,
    *,
    target_full_name: str = "SauceTaster/assured-demo",
    bind_sbom_subjects: bool = True,
    describe_sbom_subjects: bool = True,
) -> dict:
    executable = root / "trusted-gh"
    executable.write_bytes(b"test gh verifier\n")
    executable.chmod(0o500)
    policy = {
        "schema_version": 1,
        "status": "active-dev",
        "target_owner": "SauceTaster",
        "repository_prefix": "assured-",
        "workflow_path": (".github/workflows/assured-downstream-attested-release.yml"),
        "release_tag_prefix": "secure-v",
        "predicates": {
            "provenance": SLSA_PROVENANCE_PREDICATE_TYPE,
            "sbom": SPDX_23_PREDICATE_TYPE,
            "policy": ASSURED_DOWNSTREAM_PREDICATE_TYPE,
        },
        "signer": {
            "oidc_issuer": GITHUB_ACTIONS_OIDC_ISSUER,
            "deny_self_hosted_runners": True,
        },
        "sigstore_trusted_root": {
            "mediaType": (
                "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
            ),
            "tlogs": [{"fixture": True}],
            "certificateAuthorities": [{"fixture": True}],
        },
        "verifier": {
            "executable": str(executable.resolve()),
            "sha256": sha256_file(executable),
        },
    }
    policy_path = write_json(root / "release-verification-policy.json", policy)
    bundle_root = root / "bundle"
    artifacts_dir = bundle_root / "assured-input" / "artifacts"
    evidence_dir = bundle_root / "assured-evidence"
    attestations_dir = evidence_dir / "attestations"
    artifacts_dir.mkdir(parents=True)
    attestations_dir.mkdir(parents=True)
    artifacts = [artifacts_dir / "first.bin", artifacts_dir / "second.bin"]
    artifacts[0].write_bytes(b"first artifact\n")
    artifacts[1].write_bytes(b"second artifact\n")
    artifact_digests = [sha256_file(path) for path in artifacts]
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "fixture",
        "files": (
            [
                {
                    "SPDXID": f"SPDXRef-File-{index}",
                    "fileName": artifact.name,
                    "checksums": [
                        {
                            "algorithm": "SHA256",
                            "checksumValue": digest,
                        }
                    ],
                }
                for index, (artifact, digest) in enumerate(
                    zip(artifacts, artifact_digests, strict=True),
                    start=1,
                )
            ]
            if bind_sbom_subjects
            else []
        ),
        "relationships": (
            [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": f"SPDXRef-File-{index}",
                }
                for index in range(1, len(artifacts) + 1)
            ]
            if bind_sbom_subjects and describe_sbom_subjects
            else []
        ),
    }
    sbom_path = write_json(evidence_dir / "sbom.spdx.json", sbom)
    bundles = []
    for filename in (
        "provenance.sigstore.json",
        "sbom.sigstore.json",
        "policy.sigstore.json",
    ):
        bundles.append(write_json(attestations_dir / filename, {"fixture": filename}))
    project = {
        "source_full_name": "owner/project",
        "target_full_name": target_full_name,
        "upstream_ref": "a" * 40,
        "overlay_ref": "b" * 40,
        "release_tag": "secure-v1.0.0",
    }
    manifest = create_evidence_manifest(
        project=project["source_full_name"],
        target_repo=project["target_full_name"],
        upstream_ref=project["upstream_ref"],
        overlay_ref=project["overlay_ref"],
        release_tag=project["release_tag"],
        assurance="Evidence-candidate",
        files={
            "artifacts": artifacts,
            "sboms": [sbom_path],
            "attestations": bundles,
            "traces": [],
            "reports": [],
        },
        root=bundle_root,
    )
    evidence_path = write_json(bundle_root / "evidence.json", manifest)
    return {
        "root": root,
        "project": project,
        "policy": policy,
        "policy_path": policy_path,
        "evidence_path": evidence_path,
        "executable": executable,
        "artifact_digests": artifact_digests,
        "artifact_names": [path.name for path in artifacts],
        "sbom": sbom,
    }


def flag_value(command: list[str], flag: str) -> str:
    return command[command.index(flag) + 1]


def write_json(path: Path, value: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path


@contextmanager
def trust_release_policy(path: Path):
    with patch(
        "assured_downstream.release_verification.TRUSTED_RELEASE_VERIFICATION_POLICY_SHA256",
        sha256_file(path),
    ):
        yield


if __name__ == "__main__":
    unittest.main()
