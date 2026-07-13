from __future__ import annotations

import argparse
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from assured_downstream.evidence import (
    create_evidence_manifest,
    sha256_file,
    verify_evidence_manifest,
)


PROFILE_ID = "python-wheel-v1"
BUILDER_IMAGE = "ghcr.io/saucetaster/assured-downstream-python-builder"
BUILDER_DIGEST = (
    "sha256:fabfecbd48689108af585a49c6c9ee5522bb02aad716fcdc84a8799560ab791b"
)
CUSTOM_PREDICATE_TYPE = (
    "https://assured-downstream.dev/attestation/build/v1"
)
SAFE_PATH_PATTERN = re.compile(r"^[A-Za-z0-9._+/-]+$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MAX_FILES = 10_000
MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_JSON_BYTES = 32 * 1024 * 1024


class BuilderHandoffError(RuntimeError):
    pass


def validate_builder_output(
    root: Path,
    *,
    source_repository: str,
    source_commit: str,
    source_tree: str,
    project_version: str,
    require_sbom: bool = False,
    require_attestations: bool = False,
) -> dict[str, Any]:
    root = root.resolve()
    validate_identity(source_repository, source_commit, source_tree)
    validate_regular_tree(root)

    builder_report = read_json(root / "reports" / "builder.json")
    expected_report = {
        "status": "succeeded",
        "profile": PROFILE_ID,
    }
    for field, expected in expected_report.items():
        if builder_report.get(field) != expected:
            raise BuilderHandoffError(
                f"builder report {field} does not match the fixed profile"
            )
    builder = require_mapping(builder_report.get("builder"), "builder identity")
    if (
        builder.get("image") != BUILDER_IMAGE
        or builder.get("image_digest") != BUILDER_DIGEST
    ):
        raise BuilderHandoffError("builder report image identity is not approved")
    source = require_mapping(builder_report.get("source"), "builder source")
    expected_source = {
        "repository": source_repository,
        "commit": source_commit,
        "git_tree": source_tree,
        "project_version": project_version,
    }
    for field, expected in expected_source.items():
        if source.get(field) != expected:
            raise BuilderHandoffError(
                f"builder report source {field} does not match the request"
            )
    execution = require_mapping(builder_report.get("execution"), "builder execution")
    if (
        execution.get("network_policy") != "deny"
        or execution.get("returncode") != 0
        or execution.get("validation_error") is not None
    ):
        raise BuilderHandoffError("builder execution did not fail closed")

    inventory = read_json(root / "reports" / "artifact-inventory.json")
    actual_artifacts = artifact_entries(root)
    recorded_artifacts = inventory.get("artifacts")
    if (
        inventory.get("schema_version") != 1
        or not isinstance(recorded_artifacts, list)
        or recorded_artifacts != actual_artifacts
    ):
        raise BuilderHandoffError(
            "artifact inventory does not exactly match the retained artifacts"
        )

    trace = read_json(root / "traces" / "observed-trace.json")
    validate_trace(trace)
    if require_sbom:
        validate_spdx_binding(
            root / "sbom" / "sbom.spdx.json",
            expected_artifacts=actual_artifacts,
        )
    if require_attestations:
        names = sorted(
            path.name for path in (root / "attestations").glob("*.sigstore.json")
        )
        if names != [
            "build.sigstore.json",
            "provenance.sigstore.json",
            "sbom.sigstore.json",
        ]:
            raise BuilderHandoffError(
                "retained attestation bundle set is incomplete or ambiguous"
            )
    return {
        "builder_report": builder_report,
        "artifact_inventory": inventory,
        "trace": trace,
    }


def validate_regular_tree(root: Path) -> None:
    if not root.is_dir() or root.is_symlink():
        raise BuilderHandoffError("evidence root must be a regular directory")
    file_count = 0
    total_bytes = 0
    for directory, directory_names, file_names in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        directory_path = Path(directory)
        for name in sorted(directory_names):
            path = directory_path / name
            relative = path.relative_to(root).as_posix()
            if not SAFE_PATH_PATTERN.fullmatch(relative):
                raise BuilderHandoffError(f"unsafe evidence directory path: {relative}")
            if path.is_symlink() or not stat.S_ISDIR(path.lstat().st_mode):
                raise BuilderHandoffError(
                    f"evidence directory is not a regular directory: {relative}"
                )
        for name in sorted(file_names):
            path = directory_path / name
            relative = path.relative_to(root).as_posix()
            if not SAFE_PATH_PATTERN.fullmatch(relative):
                raise BuilderHandoffError(f"unsafe evidence file path: {relative}")
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
                raise BuilderHandoffError(
                    f"evidence entry is not a regular file: {relative}"
                )
            if metadata.st_nlink != 1:
                raise BuilderHandoffError(
                    f"hard-linked evidence is forbidden: {relative}"
                )
            if metadata.st_size > MAX_FILE_BYTES:
                raise BuilderHandoffError(
                    f"evidence file exceeds size limit: {relative}"
                )
            file_count += 1
            total_bytes += metadata.st_size
            if file_count > MAX_FILES or total_bytes > MAX_TOTAL_BYTES:
                raise BuilderHandoffError("evidence tree exceeds retention limits")


def validate_trace(trace: dict[str, Any]) -> None:
    collector = require_mapping(trace.get("collector"), "trace collector")
    coverage = require_mapping(trace.get("coverage"), "trace coverage")
    if (
        trace.get("schema_version") != 1
        or collector.get("name") != "strace"
        or collector.get("mode") != "follow-forks-full-syscall"
        or not isinstance(trace.get("events"), list)
        or not all(isinstance(event, dict) for event in trace["events"])
    ):
        raise BuilderHandoffError("trace document does not match the collector contract")
    values = [coverage.get(name) for name in ("process", "file", "network", "syscall")]
    if not all(isinstance(value, bool) for value in values):
        raise BuilderHandoffError("trace coverage values must be boolean")
    if any(values) and (
        not all(values)
        or trace.get("coverage_basis") != "complete-parser-pass"
        or not isinstance(trace.get("parsed_line_count"), int)
        or trace["parsed_line_count"] <= 0
        or trace.get("unparsed_line_count") != 0
        or not isinstance(trace.get("raw_file_count"), int)
        or trace["raw_file_count"] <= 0
    ):
        raise BuilderHandoffError("trace claims coverage without a complete parser pass")


def bind_spdx(root: Path) -> dict[str, Any]:
    root = root.resolve()
    validate_regular_tree(root)
    artifacts = artifact_entries(root)
    path = root / "sbom" / "sbom.spdx.json"
    sbom = read_json(path)
    if not isinstance(sbom.get("SPDXID"), str):
        raise BuilderHandoffError("SPDX document has no document identifier")
    files = sbom.setdefault("files", [])
    relationships = sbom.setdefault("relationships", [])
    if not isinstance(files, list) or not isinstance(relationships, list):
        raise BuilderHandoffError("SPDX document collections are invalid")
    existing_ids = {
        entry.get("SPDXID")
        for entry in files
        if isinstance(entry, dict) and isinstance(entry.get("SPDXID"), str)
    }
    document_id = sbom["SPDXID"]
    for artifact in artifacts:
        spdx_id = f"SPDXRef-Artifact-{artifact['sha256'][:24]}"
        if spdx_id in existing_ids:
            raise BuilderHandoffError("SPDX artifact identifier collision")
        existing_ids.add(spdx_id)
        files.append(
            {
                "SPDXID": spdx_id,
                "fileName": artifact["path"],
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": artifact["sha256"],
                    }
                ],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": document_id,
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": spdx_id,
            }
        )
    write_json(path, sbom)
    validate_regular_tree(root)
    validate_spdx_binding(path, expected_artifacts=artifacts)
    return sbom


def validate_spdx_binding(
    path: Path,
    *,
    expected_artifacts: list[dict[str, Any]],
) -> None:
    sbom = read_json(path)
    document_id = sbom.get("SPDXID")
    files = sbom.get("files")
    relationships = sbom.get("relationships")
    if (
        not isinstance(document_id, str)
        or not isinstance(files, list)
        or not isinstance(relationships, list)
    ):
        raise BuilderHandoffError("SPDX artifact binding collections are invalid")
    described = {
        entry.get("relatedSpdxElement")
        for entry in relationships
        if isinstance(entry, dict)
        and entry.get("spdxElementId") == document_id
        and entry.get("relationshipType") == "DESCRIBES"
    }
    referenced: set[tuple[str, str]] = set()
    for entry in files:
        if not isinstance(entry, dict) or entry.get("SPDXID") not in described:
            continue
        checksums = entry.get("checksums")
        if not isinstance(entry.get("fileName"), str) or not isinstance(
            checksums, list
        ):
            continue
        for checksum in checksums:
            if (
                isinstance(checksum, dict)
                and checksum.get("algorithm") == "SHA256"
                and isinstance(checksum.get("checksumValue"), str)
            ):
                referenced.add(
                    (
                        Path(entry["fileName"]).name,
                        checksum["checksumValue"].lower(),
                    )
                )
    expected = {
        (Path(entry["path"]).name, entry["sha256"]) for entry in expected_artifacts
    }
    if not expected.issubset(referenced):
        raise BuilderHandoffError(
            "SPDX document does not describe every retained artifact digest"
        )


def create_build_predicate(
    root: Path,
    *,
    source_repository: str,
    source_commit: str,
    source_tree: str,
    upstream_repository: str,
    upstream_commit: str,
    target_repository: str,
    project_version: str,
    release_tag: str,
    case_id: str,
    caller_repository: str,
    caller_commit: str,
    caller_ref: str,
    source_date_epoch: str,
) -> dict[str, Any]:
    root = root.resolve()
    validate_identity(source_repository, source_commit, source_tree)
    validate_repository(upstream_repository, "upstream repository")
    validate_repository(target_repository, "target repository")
    require_sha(upstream_commit, "upstream commit")
    require_sha(caller_commit, "caller commit")
    validated = validate_builder_output(
        root,
        source_repository=source_repository,
        source_commit=source_commit,
        source_tree=source_tree,
        project_version=project_version,
        require_sbom=True,
    )
    predicate = {
        "schemaVersion": 1,
        "predicateType": CUSTOM_PREDICATE_TYPE,
        "builder": {
            "profile": PROFILE_ID,
            "image": BUILDER_IMAGE,
            "imageDigest": BUILDER_DIGEST,
            "network": "none",
            "readOnlyRoot": True,
            "uid": 65532,
            "gid": 65532,
            "capabilities": [],
            "noNewPrivileges": True,
        },
        "source": {
            "repository": source_repository,
            "commit": source_commit,
            "tree": source_tree,
            "upstreamRepository": upstream_repository,
            "upstreamCommit": upstream_commit,
            "projectVersion": project_version,
            "sourceDateEpoch": source_date_epoch,
        },
        "downstream": {
            "targetRepository": target_repository,
            "releaseTag": release_tag,
            "caseId": case_id,
        },
        "caller": {
            "repository": caller_repository,
            "commit": caller_commit,
            "ref": caller_ref,
        },
        "evidence": {
            "artifactInventorySha256": sha256_file(
                root / "reports" / "artifact-inventory.json"
            ),
            "builderReportSha256": sha256_file(root / "reports" / "builder.json"),
            "sourceInventorySha256": sha256_file(
                root / "reports" / "source-inventory.json"
            ),
            "traceSha256": sha256_file(root / "traces" / "observed-trace.json"),
            "sbomSha256": sha256_file(root / "sbom" / "sbom.spdx.json"),
            "artifactCount": len(validated["artifact_inventory"]["artifacts"]),
        },
        "claimLimit": (
            "The workflow signs these build observations. Source ancestry, "
            "workflow approval, builder containment, and semantic safety require "
            "independent verification."
        ),
    }
    write_json(root / "predicates" / "build.json", predicate)
    return predicate


def assemble_evidence(
    root: Path,
    *,
    source_repository: str,
    source_commit: str,
    source_tree: str,
    upstream_repository: str,
    upstream_commit: str,
    target_repository: str,
    project_version: str,
    release_tag: str,
) -> dict[str, Any]:
    root = root.resolve()
    validate_builder_output(
        root,
        source_repository=source_repository,
        source_commit=source_commit,
        source_tree=source_tree,
        project_version=project_version,
        require_sbom=True,
        require_attestations=True,
    )
    artifacts = [
        root / entry["path"]
        for entry in read_json(
            root / "reports" / "artifact-inventory.json"
        )["artifacts"]
    ]
    sboms = [root / "sbom" / "sbom.spdx.json"]
    attestations = sorted((root / "attestations").glob("*.sigstore.json"))
    traces = [root / "traces" / "observed-trace.json"]
    reports = sorted((root / "reports").glob("*.json"))
    reports.extend(sorted((root / "traces" / "raw").glob("*")))
    reports.append(root / "predicates" / "build.json")
    manifest = create_evidence_manifest(
        project=upstream_repository,
        target_repo=target_repository,
        upstream_ref=upstream_commit,
        overlay_ref=source_commit,
        release_tag=release_tag,
        assurance="Evidence-candidate",
        files={
            "artifacts": artifacts,
            "sboms": sboms,
            "attestations": attestations,
            "traces": traces,
            "reports": reports,
        },
        root=root,
    )
    write_json(root / "evidence.json", manifest)
    verification = verify_evidence_manifest(manifest, base_dir=root)
    if not verification["ok"]:
        raise BuilderHandoffError("assembled evidence manifest does not verify")
    build_result = {
        "schema_version": 1,
        "status": "succeeded",
        "project": {
            "source_full_name": upstream_repository,
            "target_full_name": target_repository,
            "upstream_ref": upstream_commit,
            "overlay_ref": source_commit,
            "release_tag": release_tag,
        },
        "builder": {
            "mode": "external-isolated",
            "builder_id": f"{BUILDER_IMAGE}@{BUILDER_DIGEST}",
            "isolated": True,
            "secrets_exposed": False,
            "network_policy": "deny",
            "workspace_root": "/workspace",
        },
        "evidence": {
            "artifacts": [path.relative_to(root).as_posix() for path in artifacts],
            "sboms": [path.relative_to(root).as_posix() for path in sboms],
            "attestations": [
                path.relative_to(root).as_posix() for path in attestations
            ],
            "raw_traces": [path.relative_to(root).as_posix() for path in traces],
            "reports": [path.relative_to(root).as_posix() for path in reports],
        },
    }
    write_json(root / "build-result.json", build_result)
    validate_regular_tree(root)
    return {"manifest": manifest, "build_result": build_result}


def artifact_entries(root: Path) -> list[dict[str, Any]]:
    dist = root / "dist"
    if not dist.is_dir() or dist.is_symlink():
        raise BuilderHandoffError("evidence bundle has no regular dist directory")
    entries = []
    for path in sorted(dist.rglob("*")):
        if path.is_dir():
            continue
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or path.is_symlink()
            or metadata.st_nlink != 1
        ):
            raise BuilderHandoffError("release artifact is not a standalone regular file")
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "size": metadata.st_size,
                "sha256": sha256_file(path),
            }
        )
    if not entries:
        raise BuilderHandoffError("evidence bundle has no release artifacts")
    return entries


def validate_identity(repository: str, commit: str, tree: str) -> None:
    validate_repository(repository, "source repository")
    require_sha(commit, "source commit")
    require_sha(tree, "source tree")


def validate_repository(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or not REPOSITORY_PATTERN.fullmatch(value)
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        raise BuilderHandoffError(f"{label} is invalid")


def require_sha(value: str, label: str) -> None:
    if not isinstance(value, str) or not SHA_PATTERN.fullmatch(value):
        raise BuilderHandoffError(f"{label} is not a lowercase 40-character SHA")


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BuilderHandoffError(f"{label} must be an object")
    return value


def read_json(path: Path) -> dict[str, Any]:
    if (
        not path.is_file()
        or path.is_symlink()
        or path.lstat().st_nlink != 1
        or path.stat().st_size > MAX_JSON_BYTES
    ):
        raise BuilderHandoffError(f"JSON input is not a bounded regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BuilderHandoffError(f"could not parse JSON input: {path}") from exc
    if not isinstance(value, dict):
        raise BuilderHandoffError(f"JSON input must contain an object: {path}")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="builder-handoff")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "bind-sbom", "predicate", "assemble"):
        command = subparsers.add_parser(name)
        command.add_argument("--root", required=True, type=Path)
        if name != "bind-sbom":
            add_source_arguments(command)
    validate = subparsers.choices["validate"]
    validate.add_argument("--require-sbom", action="store_true")
    validate.add_argument("--require-attestations", action="store_true")
    predicate = subparsers.choices["predicate"]
    add_project_arguments(predicate)
    predicate.add_argument("--case-id", required=True)
    predicate.add_argument("--caller-repository", required=True)
    predicate.add_argument("--caller-commit", required=True)
    predicate.add_argument("--caller-ref", required=True)
    predicate.add_argument("--source-date-epoch", required=True)
    assemble = subparsers.choices["assemble"]
    add_project_arguments(assemble)
    return parser


def add_source_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--project-version", required=True)


def add_project_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--upstream-repository", required=True)
    parser.add_argument("--upstream-commit", required=True)
    parser.add_argument("--target-repository", required=True)
    parser.add_argument("--release-tag", required=True)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "bind-sbom":
        bind_spdx(args.root)
    elif args.command == "validate":
        validate_builder_output(
            args.root,
            source_repository=args.source_repository,
            source_commit=args.source_commit,
            source_tree=args.source_tree,
            project_version=args.project_version,
            require_sbom=args.require_sbom,
            require_attestations=args.require_attestations,
        )
    elif args.command == "predicate":
        create_build_predicate(
            args.root,
            source_repository=args.source_repository,
            source_commit=args.source_commit,
            source_tree=args.source_tree,
            upstream_repository=args.upstream_repository,
            upstream_commit=args.upstream_commit,
            target_repository=args.target_repository,
            project_version=args.project_version,
            release_tag=args.release_tag,
            case_id=args.case_id,
            caller_repository=args.caller_repository,
            caller_commit=args.caller_commit,
            caller_ref=args.caller_ref,
            source_date_epoch=args.source_date_epoch,
        )
    else:
        assemble_evidence(
            args.root,
            source_repository=args.source_repository,
            source_commit=args.source_commit,
            source_tree=args.source_tree,
            upstream_repository=args.upstream_repository,
            upstream_commit=args.upstream_commit,
            target_repository=args.target_repository,
            project_version=args.project_version,
            release_tag=args.release_tag,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuilderHandoffError as error:
        print(f"builder handoff rejected: {error}", file=os.sys.stderr)
        raise SystemExit(2) from error
