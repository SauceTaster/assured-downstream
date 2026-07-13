from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from assured_downstream.command_runner import (
    CommandResult,
    CommandRunner,
    display_command,
)
from assured_downstream.evidence import verify_evidence_manifest
from assured_downstream.release_render import ASSURED_DOWNSTREAM_PREDICATE_TYPE


RELEASE_VERIFICATION_POLICY_SCHEMA_VERSION = 1
RELEASE_VERIFICATION_RECORD_SCHEMA_VERSION = 1
GITHUB_ACTIONS_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_HOSTNAME = "github.com"
SLSA_PROVENANCE_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
SPDX_23_PREDICATE_TYPE = "https://spdx.dev/Document/v2.3"
GITHUB_WORKFLOW_BUILD_TYPE = "https://actions.github.io/buildtypes/workflow/v1"
TRUSTED_RELEASE_VERIFICATION_POLICY_SHA256 = (
    "abca9090eebb736a72ce30102f812a5ed6f4ffb46dc3e9f3f041fad2d1fac344"
)
SIGSTORE_TRUSTED_ROOT_MEDIA_TYPE = (
    "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
)
VERIFIER_TIMEOUT_SECONDS = 60.0
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
TAG_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
COPY_CHUNK_SIZE = 1024 * 1024
BUNDLE_FILENAMES = {
    "provenance": "provenance.sigstore.json",
    "sbom": "sbom.sigstore.json",
    "policy": "policy.sigstore.json",
}


class ReleaseVerificationError(RuntimeError):
    pass


class VerificationRunner(Protocol):
    def run(
        self,
        command: list[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
        timeout_seconds: float | None = None,
        inherit_env: bool = True,
    ) -> CommandResult: ...


def verify_release_attestations(
    *,
    evidence_path: Path,
    policy_path: Path,
    runner: VerificationRunner | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    evidence_path = evidence_path.expanduser().resolve()
    policy_path = policy_path.expanduser().resolve()
    evidence_bytes, evidence_sha256 = snapshot_bytes(
        evidence_path,
        label="release evidence manifest",
        max_bytes=MAX_JSON_BYTES,
    )
    policy_bytes, policy_sha256 = snapshot_bytes(
        policy_path,
        label="release verification policy",
        max_bytes=MAX_JSON_BYTES,
    )
    require_trusted_policy_digest(policy_sha256)
    evidence = decode_json_object(evidence_bytes, label="release evidence manifest")
    policy = validate_release_verification_policy(
        decode_json_object(policy_bytes, label="release verification policy")
    )
    try:
        evidence_verification = verify_evidence_manifest(
            evidence,
            base_dir=evidence_path.parent,
        )
    except (AttributeError, KeyError, OSError, TypeError, ValueError) as exc:
        raise ReleaseVerificationError(
            "Release evidence manifest structure is invalid"
        ) from exc
    if not evidence_verification["ok"]:
        raise ReleaseVerificationError(
            "Release evidence manifest failed local verification: "
            + "; ".join(evidence_verification["failures"])
        )

    project = validate_project(evidence.get("project"), policy=policy)
    roles = require_evidence_roles(evidence.get("evidence"))
    artifact_entries = roles["artifacts"]
    if not artifact_entries:
        raise ReleaseVerificationError("Release evidence has no artifact subjects")
    sbom_entries = roles["sboms"]
    if len(sbom_entries) != 1:
        raise ReleaseVerificationError(
            "Release verification requires exactly one SPDX SBOM"
        )
    bundles = identify_attestation_bundles(roles["attestations"])
    expected_subjects = {
        (
            require_subject_name(entry.get("name"), label="artifact subject name"),
            require_sha256(entry.get("sha256"), label="artifact digest"),
        )
        for entry in artifact_entries
    }
    if len(expected_subjects) != len(artifact_entries):
        raise ReleaseVerificationError("Artifact evidence contains duplicate subjects")
    executable = Path(policy["verifier"]["executable"]).expanduser().resolve()
    executable_bytes, executable_sha256 = snapshot_bytes(
        executable,
        label="release verifier executable",
        max_bytes=MAX_EXECUTABLE_BYTES,
    )
    if not hmac.compare_digest(executable_sha256, policy["verifier"]["sha256"]):
        raise ReleaseVerificationError(
            "Release verifier executable digest does not match policy"
        )

    sbom_path = resolve_evidence_entry(
        sbom_entries[0],
        base_dir=evidence_path.parent,
        label="SBOM",
    )
    sbom_bytes, sbom_sha256 = snapshot_bytes(
        sbom_path,
        label="SPDX SBOM",
        max_bytes=MAX_JSON_BYTES,
    )
    if not hmac.compare_digest(
        sbom_sha256,
        require_sha256(sbom_entries[0].get("sha256"), label="SBOM digest"),
    ):
        raise ReleaseVerificationError("SPDX SBOM changed before verification")
    sbom = decode_json_object(sbom_bytes, label="SPDX SBOM")
    if sbom.get("spdxVersion") != "SPDX-2.3":
        raise ReleaseVerificationError("SBOM is not an SPDX 2.3 document")
    spdx_subjects = validate_spdx_subject_binding(
        sbom,
        expected_subjects=expected_subjects,
    )
    trusted_root_bytes = (
        json.dumps(
            policy["sigstore_trusted_root"],
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    trusted_root_sha256 = hashlib.sha256(trusted_root_bytes).hexdigest()

    effective_runner = runner or CommandRunner(execute=True)
    source_ref = f"refs/tags/{project['release_tag']}"
    signer_workflow = f"{project['target_full_name']}/{policy['workflow_path']}"
    certificate_identity = f"https://github.com/{signer_workflow}@{source_ref}"
    expected_predicates = {
        "provenance": None,
        "sbom": sbom,
        "policy": expected_policy_predicate(
            project,
            workflow_ref=f"{signer_workflow}@{source_ref}",
        ),
    }
    bundle_results: dict[str, dict[str, Any]] = {}
    commands: list[str] = []

    with tempfile.TemporaryDirectory(prefix="assured-release-verify-") as tmp:
        isolation_root = Path(tmp)
        home = isolation_root / "home"
        gh_config = isolation_root / "gh-config"
        temp_root = isolation_root / "tmp"
        home.mkdir(mode=0o700)
        gh_config.mkdir(mode=0o700)
        temp_root.mkdir(mode=0o700)
        staged_executable = isolation_root / "gh"
        staged_executable.write_bytes(executable_bytes)
        staged_executable.chmod(0o500)
        staged_trusted_root = isolation_root / "sigstore-trusted-root.jsonl"
        staged_trusted_root.write_bytes(trusted_root_bytes)
        staged_trusted_root.chmod(0o400)
        staged_artifacts = []
        for position, artifact_entry in enumerate(artifact_entries, start=1):
            artifact = resolve_evidence_entry(
                artifact_entry,
                base_dir=evidence_path.parent,
                label="artifact",
            )
            staged_artifact = isolation_root / f"artifact-{position}.subject"
            copy_verified_file(
                artifact,
                staged_artifact,
                expected_sha256=require_sha256(
                    artifact_entry.get("sha256"),
                    label="artifact digest",
                ),
            )
            staged_artifacts.append(staged_artifact)
        verification_subject = staged_artifacts[0]

        for role in ("provenance", "sbom", "policy"):
            entry = bundles[role]
            bundle_path = resolve_evidence_entry(
                entry,
                base_dir=evidence_path.parent,
                label=f"{role} bundle",
            )
            bundle_bytes, bundle_sha256 = snapshot_bytes(
                bundle_path,
                label=f"{role} bundle",
                max_bytes=MAX_JSON_BYTES,
            )
            if not hmac.compare_digest(
                bundle_sha256,
                require_sha256(entry.get("sha256"), label=f"{role} bundle digest"),
            ):
                raise ReleaseVerificationError(
                    f"{role.capitalize()} bundle changed before verification"
                )
            staged_bundle = isolation_root / BUNDLE_FILENAMES[role]
            staged_bundle.write_bytes(bundle_bytes)
            staged_bundle.chmod(0o400)
            command = github_attestation_verify_command(
                artifact_path=verification_subject,
                bundle_path=staged_bundle,
                predicate_type=policy["predicates"][role],
                target_repository=project["target_full_name"],
                source_digest=project["overlay_ref"],
                source_ref=source_ref,
                certificate_identity=certificate_identity,
                oidc_issuer=policy["signer"]["oidc_issuer"],
                deny_self_hosted_runners=policy["signer"]["deny_self_hosted_runners"],
                executable_path=staged_executable,
                trusted_root_path=staged_trusted_root,
            )
            result = effective_runner.run(
                command,
                cwd=str(isolation_root),
                env=isolated_verifier_environment(
                    home=home,
                    gh_config=gh_config,
                    temp_root=temp_root,
                ),
                timeout_seconds=VERIFIER_TIMEOUT_SECONDS,
                inherit_env=False,
            )
            require_successful_verifier_result(result, role=role)
            verification_entries = decode_json_array(
                result.stdout,
                label=f"{role} verifier output",
            )
            timestamp_count = validate_verification_output(
                verification_entries,
                role=role,
                predicate_type=policy["predicates"][role],
                expected_subjects=expected_subjects,
                expected_predicate=expected_predicates[role],
                target_repository=project["target_full_name"],
                workflow_path=policy["workflow_path"],
                source_ref=source_ref,
                overlay_ref=project["overlay_ref"],
                certificate_identity=certificate_identity,
                oidc_issuer=policy["signer"]["oidc_issuer"],
            )
            bundle_results[role] = {
                "predicate_type": policy["predicates"][role],
                "sha256": bundle_sha256,
                "verified_transparency_timestamp_count": timestamp_count,
                "predicate_authority": (
                    "workflow-authored-signed-claim"
                    if role == "policy"
                    else "predicate-content-validated"
                ),
            }
            commands.append(display_command(command))

    verified_at = (
        (now or datetime.now(UTC)).astimezone(UTC).isoformat(timespec="seconds")
    )
    return {
        "schema_version": RELEASE_VERIFICATION_RECORD_SCHEMA_VERSION,
        "status": "verified",
        "ok": True,
        "authority": "code-anchored-github-sigstore",
        "verification_type": "sigstore-bundle",
        "verified_at": verified_at,
        "evidence_sha256": evidence_sha256,
        "policy_sha256": policy_sha256,
        "verifier_sha256": executable_sha256,
        "sigstore_trusted_root_sha256": trusted_root_sha256,
        "target_full_name": project["target_full_name"],
        "overlay_ref": project["overlay_ref"],
        "release_tag": project["release_tag"],
        "source_ref": source_ref,
        "issuer": policy["signer"]["oidc_issuer"],
        "signer": signer_workflow,
        "signer_digest": project["overlay_ref"],
        "verified_subjects": [
            {"name": name, "sha256": digest}
            for name, digest in sorted(expected_subjects)
        ],
        "spdx_referenced_subjects": [
            {"sha256": digest} for digest in sorted(spdx_subjects)
        ],
        "verified_controls": [
            "bundle-signature",
            "sigstore-trusted-root",
            "transparency-timestamp",
            "github-actions-certificate",
            "workflow-certificate-identity",
            "source-overlay-commit",
            "release-tag-ref",
            "artifact-subject-set",
            "spdx-artifact-reference",
            "predicate-content",
        ],
        "attested_claims": {
            "upstream_repository": project["source_full_name"],
            "upstream_ref": project["upstream_ref"],
            "lineage": "workflow-asserted-ancestor",
        },
        "independently_verified": {
            "upstream_lineage": False,
            "builder_isolation": False,
            "workflow_implementation": False,
            "tooling": False,
        },
        "bundles": bundle_results,
        "commands": commands,
    }


def validate_release_verification_policy(policy: dict[str, Any]) -> dict[str, Any]:
    require_exact_keys(
        policy,
        {
            "schema_version",
            "status",
            "target_owner",
            "repository_prefix",
            "workflow_path",
            "release_tag_prefix",
            "predicates",
            "signer",
            "sigstore_trusted_root",
            "verifier",
        },
        label="release verification policy",
    )
    if policy.get("schema_version") != RELEASE_VERIFICATION_POLICY_SCHEMA_VERSION:
        raise ReleaseVerificationError("Unsupported release verification policy schema")
    if policy.get("status") != "active-dev":
        raise ReleaseVerificationError("Release verification policy is not active")
    for field in (
        "target_owner",
        "repository_prefix",
        "workflow_path",
        "release_tag_prefix",
    ):
        if not isinstance(policy.get(field), str) or not policy[field]:
            raise ReleaseVerificationError(
                f"Release verification policy {field} is invalid"
            )
    if policy["workflow_path"] != (
        ".github/workflows/assured-downstream-attested-release.yml"
    ):
        raise ReleaseVerificationError("Release signer workflow path is not approved")
    predicates = policy.get("predicates")
    if not isinstance(predicates, dict):
        raise ReleaseVerificationError("Release predicate policy is invalid")
    require_exact_keys(
        predicates,
        {"provenance", "sbom", "policy"},
        label="release predicate policy",
    )
    expected_predicates = {
        "provenance": SLSA_PROVENANCE_PREDICATE_TYPE,
        "sbom": SPDX_23_PREDICATE_TYPE,
        "policy": ASSURED_DOWNSTREAM_PREDICATE_TYPE,
    }
    if predicates != expected_predicates:
        raise ReleaseVerificationError("Release predicate types are not approved")
    signer = policy.get("signer")
    if not isinstance(signer, dict):
        raise ReleaseVerificationError("Release signer policy is invalid")
    require_exact_keys(
        signer,
        {"oidc_issuer", "deny_self_hosted_runners"},
        label="release signer policy",
    )
    if signer.get("oidc_issuer") != GITHUB_ACTIONS_OIDC_ISSUER:
        raise ReleaseVerificationError("Release signer OIDC issuer is not approved")
    if signer.get("deny_self_hosted_runners") is not True:
        raise ReleaseVerificationError("Release signer must reject self-hosted runners")
    trusted_root = policy.get("sigstore_trusted_root")
    if (
        not isinstance(trusted_root, dict)
        or trusted_root.get("mediaType") != SIGSTORE_TRUSTED_ROOT_MEDIA_TYPE
        or not isinstance(trusted_root.get("tlogs"), list)
        or not trusted_root["tlogs"]
        or not isinstance(trusted_root.get("certificateAuthorities"), list)
        or not trusted_root["certificateAuthorities"]
    ):
        raise ReleaseVerificationError("Sigstore trusted root policy is invalid")
    verifier = policy.get("verifier")
    if not isinstance(verifier, dict):
        raise ReleaseVerificationError("Release verifier policy is invalid")
    require_exact_keys(
        verifier,
        {"executable", "sha256"},
        label="release verifier policy",
    )
    executable = Path(str(verifier.get("executable")))
    if not executable.is_absolute() or not executable.resolve().is_file():
        raise ReleaseVerificationError(
            "Release verifier executable must be an existing absolute file"
        )
    require_sha256(verifier.get("sha256"), label="release verifier digest")
    return policy


def validate_project(value: Any, *, policy: dict[str, Any]) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ReleaseVerificationError("Release evidence project is invalid")
    required = {
        "source_full_name",
        "target_full_name",
        "upstream_ref",
        "overlay_ref",
        "release_tag",
    }
    if not required.issubset(value):
        raise ReleaseVerificationError("Release evidence project is incomplete")
    source = require_repository(
        value.get("source_full_name"), label="source repository"
    )
    target = require_repository(
        value.get("target_full_name"), label="target repository"
    )
    owner, repository = target.split("/", 1)
    if owner != policy["target_owner"] or not repository.startswith(
        policy["repository_prefix"]
    ):
        raise ReleaseVerificationError(
            "Target repository is outside the release verification policy"
        )
    upstream_ref = require_git_sha(value.get("upstream_ref"), label="upstream ref")
    overlay_ref = require_git_sha(value.get("overlay_ref"), label="overlay ref")
    release_tag = value.get("release_tag")
    if (
        not isinstance(release_tag, str)
        or TAG_PATTERN.fullmatch(release_tag) is None
        or not release_tag.startswith(policy["release_tag_prefix"])
    ):
        raise ReleaseVerificationError("Release tag is outside policy")
    return {
        "source_full_name": source,
        "target_full_name": target,
        "upstream_ref": upstream_ref,
        "overlay_ref": overlay_ref,
        "release_tag": release_tag,
    }


def require_evidence_roles(value: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(value, dict):
        raise ReleaseVerificationError("Release evidence roles are invalid")
    result: dict[str, list[dict[str, Any]]] = {}
    for role in ("artifacts", "sboms", "attestations"):
        entries = value.get(role)
        if not isinstance(entries, list) or not all(
            isinstance(entry, dict) for entry in entries
        ):
            raise ReleaseVerificationError(f"Release evidence {role} are invalid")
        result[role] = entries
    return result


def identify_attestation_bundles(
    entries: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    if len(entries) != len(BUNDLE_FILENAMES):
        raise ReleaseVerificationError(
            "Release verification requires exactly three attestation bundles"
        )
    found: dict[str, dict[str, Any]] = {}
    for entry in entries:
        name = entry.get("name")
        if not isinstance(name, str):
            raise ReleaseVerificationError("Attestation bundle name is invalid")
        matches = [
            role for role, suffix in BUNDLE_FILENAMES.items() if name.endswith(suffix)
        ]
        if len(matches) != 1 or matches[0] in found:
            raise ReleaseVerificationError(
                f"Attestation bundle role is ambiguous: {name}"
            )
        found[matches[0]] = entry
    if set(found) != set(BUNDLE_FILENAMES):
        raise ReleaseVerificationError("Release attestation bundle set is incomplete")
    return found


def github_attestation_verify_command(
    *,
    artifact_path: Path,
    bundle_path: Path,
    predicate_type: str,
    target_repository: str,
    source_digest: str,
    signer_digest: str | None = None,
    source_ref: str,
    certificate_identity: str,
    oidc_issuer: str,
    deny_self_hosted_runners: bool,
    executable_path: Path,
    trusted_root_path: Path,
) -> list[str]:
    command = [
        str(executable_path),
        "attestation",
        "verify",
        str(artifact_path),
        "--bundle",
        str(bundle_path),
        "--repo",
        target_repository,
        "--predicate-type",
        predicate_type,
        "--signer-digest",
        signer_digest or source_digest,
        "--source-digest",
        source_digest,
        "--source-ref",
        source_ref,
        "--cert-identity",
        certificate_identity,
        "--cert-oidc-issuer",
        oidc_issuer,
        "--custom-trusted-root",
        str(trusted_root_path),
        "--hostname",
        GITHUB_HOSTNAME,
        "--format",
        "json",
    ]
    if deny_self_hosted_runners:
        command.append("--deny-self-hosted-runners")
    return command


def validate_verification_output(
    entries: list[Any],
    *,
    role: str,
    predicate_type: str,
    expected_subjects: set[tuple[str, str]],
    expected_predicate: dict[str, Any] | None,
    target_repository: str,
    workflow_path: str,
    source_ref: str,
    overlay_ref: str,
    certificate_identity: str,
    oidc_issuer: str,
) -> int:
    if len(entries) != 1 or not isinstance(entries[0], dict):
        raise ReleaseVerificationError(
            f"{role.capitalize()} verifier must return exactly one attestation"
        )
    verification = entries[0].get("verificationResult")
    if not isinstance(verification, dict):
        raise ReleaseVerificationError(
            f"{role.capitalize()} verifier output has no verification result"
        )
    statement = verification.get("statement")
    timestamps = verification.get("verifiedTimestamps")
    signature = verification.get("signature")
    if (
        not isinstance(statement, dict)
        or not isinstance(timestamps, list)
        or not timestamps
        or not isinstance(signature, dict)
    ):
        raise ReleaseVerificationError(
            f"{role.capitalize()} verifier output is incomplete"
        )
    if not all(
        isinstance(timestamp, dict)
        and isinstance(timestamp.get("type"), str)
        and bool(timestamp["type"])
        for timestamp in timestamps
    ):
        raise ReleaseVerificationError(
            f"{role.capitalize()} verified timestamp set is invalid"
        )
    transparency_timestamps = [
        timestamp
        for timestamp in timestamps
        if "tlog" in timestamp["type"].casefold()
        or "transparency" in timestamp["type"].casefold()
    ]
    if not transparency_timestamps:
        raise ReleaseVerificationError(
            f"{role.capitalize()} verification has no transparency-log timestamp"
        )
    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        raise ReleaseVerificationError(
            f"{role.capitalize()} statement type is not in-toto v1"
        )
    if statement.get("predicateType") != predicate_type:
        raise ReleaseVerificationError(
            f"{role.capitalize()} predicate type does not match policy"
        )
    actual_subjects = statement_subjects(statement)
    if actual_subjects != expected_subjects:
        raise ReleaseVerificationError(
            f"{role.capitalize()} subjects do not exactly match release artifacts"
        )
    validate_certificate(
        signature.get("certificate"),
        target_repository=target_repository,
        source_ref=source_ref,
        overlay_ref=overlay_ref,
        certificate_identity=certificate_identity,
        oidc_issuer=oidc_issuer,
    )
    predicate = statement.get("predicate")
    if role == "provenance":
        validate_provenance_predicate(
            predicate,
            target_repository=target_repository,
            workflow_path=workflow_path,
            source_ref=source_ref,
            overlay_ref=overlay_ref,
            certificate_identity=certificate_identity,
        )
    elif predicate != expected_predicate:
        raise ReleaseVerificationError(
            f"{role.capitalize()} predicate does not match retained evidence"
        )
    return len(transparency_timestamps)


def validate_certificate(
    value: Any,
    *,
    target_repository: str,
    source_ref: str,
    overlay_ref: str,
    certificate_identity: str,
    oidc_issuer: str,
) -> None:
    if not isinstance(value, dict):
        raise ReleaseVerificationError("Verified attestation has no certificate")
    expected = {
        "subjectAlternativeName": certificate_identity,
        "issuer": oidc_issuer,
        "githubWorkflowSHA": overlay_ref,
        "githubWorkflowRepository": target_repository,
        "githubWorkflowRef": source_ref,
        "buildSignerURI": certificate_identity,
        "buildSignerDigest": overlay_ref,
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": f"https://github.com/{target_repository}",
        "sourceRepositoryDigest": overlay_ref,
        "sourceRepositoryRef": source_ref,
        "buildConfigURI": certificate_identity,
        "buildConfigDigest": overlay_ref,
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            raise ReleaseVerificationError(
                f"Verified certificate does not match {field}"
            )


def validate_provenance_predicate(
    value: Any,
    *,
    target_repository: str,
    workflow_path: str,
    source_ref: str,
    overlay_ref: str,
    certificate_identity: str,
) -> None:
    if not isinstance(value, dict):
        raise ReleaseVerificationError("Provenance predicate is invalid")
    build_definition = value.get("buildDefinition")
    run_details = value.get("runDetails")
    if not isinstance(build_definition, dict) or not isinstance(run_details, dict):
        raise ReleaseVerificationError("Provenance predicate is incomplete")
    if build_definition.get("buildType") != GITHUB_WORKFLOW_BUILD_TYPE:
        raise ReleaseVerificationError("Provenance build type is not GitHub Actions")
    external = build_definition.get("externalParameters")
    workflow = external.get("workflow") if isinstance(external, dict) else None
    expected_workflow = {
        "path": workflow_path,
        "ref": source_ref,
        "repository": f"https://github.com/{target_repository}",
    }
    if not isinstance(workflow, dict) or any(
        workflow.get(field) != expected for field, expected in expected_workflow.items()
    ):
        raise ReleaseVerificationError("Provenance workflow identity is invalid")
    dependencies = build_definition.get("resolvedDependencies")
    if not isinstance(dependencies, list) or not any(
        isinstance(dependency, dict)
        and isinstance(dependency.get("digest"), dict)
        and dependency["digest"].get("gitCommit") == overlay_ref
        and dependency.get("uri")
        == f"git+https://github.com/{target_repository}@{source_ref}"
        for dependency in dependencies
    ):
        raise ReleaseVerificationError("Provenance does not resolve the overlay commit")
    builder = run_details.get("builder")
    if not isinstance(builder, dict) or builder.get("id") != certificate_identity:
        raise ReleaseVerificationError("Provenance builder identity is invalid")


def expected_policy_predicate(
    project: dict[str, str],
    *,
    workflow_ref: str,
) -> dict[str, Any]:
    return {
        "policyVersion": "assured-downstream-attested-v1",
        "sourceRepository": project["source_full_name"],
        "targetRepository": project["target_full_name"],
        "upstreamRef": project["upstream_ref"],
        "overlayRef": project["overlay_ref"],
        "workflowRef": workflow_ref,
        "lineagePolicy": "upstream ref is an ancestor of the attested overlay ref",
    }


def validate_spdx_subject_binding(
    value: dict[str, Any],
    *,
    expected_subjects: set[tuple[str, str]],
) -> set[str]:
    document_id = value.get("SPDXID")
    files = value.get("files")
    relationships = value.get("relationships")
    if not isinstance(document_id, str) or not document_id:
        raise ReleaseVerificationError("SPDX document identifier is invalid")
    if not isinstance(files, list) or not isinstance(relationships, list):
        raise ReleaseVerificationError("SPDX artifact binding collections are invalid")
    described_ids = {
        relationship.get("relatedSpdxElement")
        for relationship in relationships
        if isinstance(relationship, dict)
        and relationship.get("spdxElementId") == document_id
        and relationship.get("relationshipType") == "DESCRIBES"
        and isinstance(relationship.get("relatedSpdxElement"), str)
    }
    referenced: set[tuple[str, str]] = set()
    for element in files:
        if not isinstance(element, dict):
            raise ReleaseVerificationError("SPDX file element is invalid")
        spdx_id = element.get("SPDXID")
        file_name = element.get("fileName")
        checksums = element.get("checksums")
        if (
            not isinstance(spdx_id, str)
            or spdx_id not in described_ids
            or not isinstance(file_name, str)
            or not isinstance(checksums, list)
        ):
            continue
        subject_name = Path(file_name).name
        for checksum in checksums:
            if not isinstance(checksum, dict):
                raise ReleaseVerificationError("SPDX checksum entry is invalid")
            algorithm = checksum.get("algorithm")
            if not isinstance(algorithm, str):
                continue
            if algorithm.upper().replace("-", "") != "SHA256":
                continue
            checksum_value = checksum.get("checksumValue")
            if not isinstance(checksum_value, str):
                raise ReleaseVerificationError("SPDX SHA-256 checksum is invalid")
            referenced.add(
                (
                    subject_name,
                    require_sha256(
                        checksum_value.lower(),
                        label="SPDX SHA-256 checksum",
                    ),
                )
            )
    missing = sorted(expected_subjects - referenced)
    if missing:
        raise ReleaseVerificationError(
            "SPDX document does not reference every release artifact subject: "
            + ", ".join(f"{name}@sha256:{digest}" for name, digest in missing)
        )
    return {digest for _, digest in expected_subjects & referenced}


def statement_subjects(statement: dict[str, Any]) -> set[tuple[str, str]]:
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        raise ReleaseVerificationError("Verified statement has no subjects")
    identities: set[tuple[str, str]] = set()
    for subject in subjects:
        if not isinstance(subject, dict):
            raise ReleaseVerificationError("Verified statement subject is invalid")
        name = require_subject_name(
            subject.get("name"),
            label="verified subject name",
        )
        digest = subject.get("digest")
        sha256 = digest.get("sha256") if isinstance(digest, dict) else None
        identities.add((name, require_sha256(sha256, label="verified subject digest")))
    if len(identities) != len(subjects):
        raise ReleaseVerificationError("Verified statement has duplicate subjects")
    return identities


def resolve_evidence_entry(
    entry: dict[str, Any],
    *,
    base_dir: Path,
    label: str,
) -> Path:
    value = entry.get("path")
    if not isinstance(value, str) or not value:
        raise ReleaseVerificationError(f"{label.capitalize()} path is invalid")
    recorded = Path(value)
    candidate = recorded if recorded.is_absolute() else base_dir / recorded
    if candidate.is_symlink():
        raise ReleaseVerificationError(f"{label.capitalize()} symlink is forbidden")
    resolved = candidate.resolve()
    root = base_dir.resolve()
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise ReleaseVerificationError(
            f"{label.capitalize()} path escapes the evidence bundle"
        )
    return resolved


def snapshot_bytes(
    path: Path,
    *,
    label: str,
    max_bytes: int,
) -> tuple[bytes, str]:
    path = path.expanduser()
    try:
        path_stat = path.lstat()
    except OSError as exc:
        raise ReleaseVerificationError(f"Missing {label}: {path}") from exc
    if not stat.S_ISREG(path_stat.st_mode) or path_stat.st_nlink != 1:
        raise ReleaseVerificationError(f"{label.capitalize()} is not a regular file")
    if path_stat.st_size > max_bytes:
        raise ReleaseVerificationError(f"{label.capitalize()} exceeds size limit")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        file_descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseVerificationError(f"Unable to open {label}: {path}") from exc
    try:
        opened_stat = os.fstat(file_descriptor)
        if file_identity(opened_stat) != file_identity(path_stat):
            raise ReleaseVerificationError(
                f"{label.capitalize()} changed before snapshotting"
            )
        with os.fdopen(file_descriptor, "rb", closefd=False) as handle:
            value = handle.read(max_bytes + 1)
        final_stat = os.fstat(file_descriptor)
        if file_identity(final_stat) != file_identity(opened_stat):
            raise ReleaseVerificationError(
                f"{label.capitalize()} changed while snapshotting"
            )
    finally:
        os.close(file_descriptor)
    if len(value) > max_bytes or len(value) != path_stat.st_size:
        raise ReleaseVerificationError(f"{label.capitalize()} snapshot size is invalid")
    return value, hashlib.sha256(value).hexdigest()


def copy_verified_file(
    source: Path,
    target: Path,
    *,
    expected_sha256: str,
) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        source_fd = os.open(source, flags)
    except OSError as exc:
        raise ReleaseVerificationError(f"Unable to stage artifact: {source}") from exc
    digest = hashlib.sha256()
    try:
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_nlink != 1:
            raise ReleaseVerificationError("Artifact is not a regular file")
        with (
            os.fdopen(source_fd, "rb", closefd=False) as source_handle,
            target.open("xb") as target_handle,
        ):
            while chunk := source_handle.read(COPY_CHUNK_SIZE):
                digest.update(chunk)
                target_handle.write(chunk)
        final_stat = os.fstat(source_fd)
        if file_identity(final_stat) != file_identity(source_stat):
            raise ReleaseVerificationError("Artifact changed while staging")
    finally:
        os.close(source_fd)
    if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
        raise ReleaseVerificationError("Staged artifact digest does not match evidence")
    target.chmod(0o400)


def file_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_nlink,
    )


def isolated_verifier_environment(
    *,
    home: Path,
    gh_config: Path,
    temp_root: Path,
) -> dict[str, str]:
    return {
        "HOME": str(home),
        "GH_CONFIG_DIR": str(gh_config),
        "TMPDIR": str(temp_root),
        "GH_NO_UPDATE_NOTIFIER": "1",
        "GH_PROMPT_DISABLED": "1",
        "GH_HOST": GITHUB_HOSTNAME,
        "GH_TOKEN": "",
        "GITHUB_TOKEN": "",
        "GH_ENTERPRISE_TOKEN": "",
        "GITHUB_ENTERPRISE_TOKEN": "",
        "GIT_CONFIG_COUNT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_PARAMETERS": "",
        "GIT_TERMINAL_PROMPT": "0",
        "DYLD_INSERT_LIBRARIES": "",
        "DYLD_LIBRARY_PATH": "",
        "LD_PRELOAD": "",
        "LD_LIBRARY_PATH": "",
        "SSL_CERT_FILE": "",
        "SSL_CERT_DIR": "",
        "PATH": "/usr/bin:/bin",
    }


def require_successful_verifier_result(result: CommandResult, *, role: str) -> None:
    if not result.executed:
        raise ReleaseVerificationError(
            f"{role.capitalize()} attestation verifier did not execute"
        )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or "verification failed"
        if len(detail) > 2048:
            detail = detail[:2048] + "...<truncated>"
        raise ReleaseVerificationError(
            f"{role.capitalize()} attestation verification failed: {detail}"
        )


def decode_json_object(value: bytes, *, label: str) -> dict[str, Any]:
    try:
        decoded = json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseVerificationError(f"{label.capitalize()} is invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise ReleaseVerificationError(f"{label.capitalize()} must be an object")
    return decoded


def decode_json_array(value: str, *, label: str) -> list[Any]:
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ReleaseVerificationError(f"{label.capitalize()} is invalid JSON") from exc
    if not isinstance(decoded, list):
        raise ReleaseVerificationError(f"{label.capitalize()} must be an array")
    return decoded


def require_exact_keys(
    value: dict[str, Any],
    expected: set[str],
    *,
    label: str,
) -> None:
    if set(value) != expected:
        raise ReleaseVerificationError(f"{label.capitalize()} fields are invalid")


def require_trusted_policy_digest(value: Any) -> str:
    digest = require_sha256(value, label="release verification policy digest")
    if not hmac.compare_digest(
        digest,
        TRUSTED_RELEASE_VERIFICATION_POLICY_SHA256,
    ):
        raise ReleaseVerificationError(
            "Release verification policy is not anchored by this build"
        )
    return digest


def require_repository(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or REPOSITORY_PATTERN.fullmatch(value) is None
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        raise ReleaseVerificationError(f"{label.capitalize()} is invalid")
    return value


def require_git_sha(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or GIT_SHA_PATTERN.fullmatch(value) is None:
        raise ReleaseVerificationError(f"{label.capitalize()} is invalid")
    return value


def require_subject_name(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or "\n" in value
        or "\r" in value
    ):
        raise ReleaseVerificationError(f"{label.capitalize()} is invalid")
    return value


def require_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise ReleaseVerificationError(f"{label.capitalize()} is invalid")
    return value
