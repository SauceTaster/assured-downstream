from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from assured_downstream.builder_handoff_v3 import (
    BUILDER_CLAIM_LIMIT,
    BUILDER_DIGEST,
    BUILDER_IMAGE,
    CALLED_WORKFLOW_PATH,
    CALLER_WORKFLOW_PATH,
    CONTROL_REPOSITORY,
    CUSTOM_PREDICATE_TYPE,
    SPDX_NORMALIZATION_POLICY_ID,
    BuilderHandoffError,
    assemble_evidence,
    create_build_predicate,
    create_subject_checksums,
    expected_canonicalization_policy,
    inventory_trusted_source,
    normalize_spdx,
    validate_builder_output,
)
from assured_downstream.archive_validation_v3 import (
    ArchiveValidationError,
    inspect_sdist,
    validate_wheel,
)
from assured_downstream.evidence import sha256_file, verify_evidence_manifest


SOURCE_REPOSITORY = "PyCQA/bandit"
SOURCE_COMMIT = "a" * 40
SOURCE_TREE = "b" * 40
CALLER_COMMIT = "c" * 40
CALLED_COMMIT = "d" * 40
HANDOFF_COMMIT = "e" * 40
PROJECT_VERSION = "1.9.4"
SOURCE_DATE_EPOCH = "1783382521"


class BuilderHandoffV3Tests(unittest.TestCase):
    def test_full_handoff_is_path_bound_and_run_bound(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_builder_output(root)
            raw = create_raw_sbom(root)

            validate_builder_output(
                root,
                source_repository=SOURCE_REPOSITORY,
                source_commit=SOURCE_COMMIT,
                source_tree=SOURCE_TREE,
                project_version=PROJECT_VERSION,
            )
            result = normalize(root)
            create_subject_checksums_for(root)
            predicate = create_predicate(root)
            create_attestations(root)
            assembled = assemble_evidence(
                root,
                source_repository=SOURCE_REPOSITORY,
                source_commit=SOURCE_COMMIT,
                source_tree=SOURCE_TREE,
                upstream_repository=SOURCE_REPOSITORY,
                upstream_commit=SOURCE_COMMIT,
                target_repository="SauceTaster/assured-bandit",
                project_version=PROJECT_VERSION,
                release_tag="case-001-bandit-source-canary-v3",
            )

            self.assertEqual(
                (root / "sbom" / "raw" / "syft.spdx.json").read_bytes(), raw
            )
            self.assertEqual(predicate["schemaVersion"], 2)
            self.assertEqual(predicate["predicateType"], CUSTOM_PREDICATE_TYPE)
            self.assertEqual(predicate["run"]["id"], "29240000001")
            self.assertEqual(predicate["run"]["attempt"], "1")
            self.assertEqual(predicate["called"]["workflowSha"], CALLED_COMMIT)
            self.assertEqual(
                predicate["sbom"]["normalizationPolicy"],
                SPDX_NORMALIZATION_POLICY_ID,
            )
            self.assertEqual(
                predicate["artifacts"],
                json.loads((root / "reports" / "artifact-inventory.json").read_text())[
                    "artifacts"
                ],
            )
            subject_lines = (
                (root / "reports" / "artifact-subjects.sha256").read_text().splitlines()
            )
            self.assertTrue(all("  dist/" in line for line in subject_lines))
            self.assertEqual(len(subject_lines), 2)
            self.assertTrue(
                verify_evidence_manifest(assembled["manifest"], base_dir=root)["ok"]
            )
            self.assertEqual(assembled["manifest"]["schema_version"], 2)
            self.assertTrue(
                all(
                    entry["logical_path"] == entry["path"]
                    for entries in assembled["manifest"]["evidence"].values()
                    for entry in entries
                )
            )
            self.assertEqual(len(assembled["manifest"]["evidence"]["sboms"]), 2)
            self.assertEqual(result["report"]["creation_time"], "2026-07-07T00:02:01Z")

    def test_normalization_ignores_syft_time_namespace_ids_and_order(self) -> None:
        outputs: list[bytes] = []
        namespaces: list[str] = []
        for variant in (1, 2):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                create_dist(root)
                create_raw_sbom(root, variant=variant, include_second_package=True)
                result = normalize(root)
                outputs.append((root / "sbom" / "sbom.spdx.json").read_bytes())
                namespaces.append(result["document"]["documentNamespace"])

        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(namespaces[0], namespaces[1])

    def test_same_digest_at_two_paths_gets_distinct_artifact_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_dist(root)
            (root / "dist" / "copy.whl").write_bytes(b"wheel")
            create_raw_sbom(root)
            document = normalize(root)["document"]
            artifacts = [
                item
                for item in document["files"]
                if item["SPDXID"].startswith("SPDXRef-Artifact-")
            ]
            self.assertEqual(len(artifacts), 3)
            self.assertEqual(len({item["SPDXID"] for item in artifacts}), 3)
            self.assertIn("dist/copy.whl", {item["fileName"] for item in artifacts})

    def test_rejects_duplicate_json_keys_and_dangling_relationships(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_dist(root)
            raw_path = root / "sbom" / "raw" / "syft.spdx.json"
            raw_path.parent.mkdir(parents=True)
            raw_path.write_text(
                '{"SPDXID":"SPDXRef-DOCUMENT","SPDXID":"SPDXRef-DOCUMENT"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(BuilderHandoffError, "duplicate key"):
                normalize(root)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_dist(root)
            create_raw_sbom(root, dangling=True)
            with self.assertRaisesRegex(BuilderHandoffError, "dangling"):
                normalize(root)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_dist(root)
            create_raw_sbom(root)
            raw_path = root / "sbom" / "raw" / "syft.spdx.json"
            sbom = json.loads(raw_path.read_text())
            sbom["packages"][0]["hasFiles"] = ["SPDXRef-File-From-Syft"]
            write_json(raw_path, sbom)
            with self.assertRaisesRegex(BuilderHandoffError, "inline identifier"):
                normalize(root)

    def test_rejects_artifact_alias_and_transform_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_dist(root)
            create_raw_sbom(root)
            path = root / "sbom" / "raw" / "syft.spdx.json"
            sbom = json.loads(path.read_text())
            sbom["files"] = [
                {
                    "SPDXID": "SPDXRef-Aliased-Artifact",
                    "fileName": "DIST/BANDIT-1.9.4-PY3-NONE-ANY.WHL",
                    "checksums": [{"algorithm": "SHA256", "checksumValue": "0" * 64}],
                }
            ]
            sbom["relationships"].append(
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "SPDXRef-Aliased-Artifact",
                }
            )
            write_json(path, sbom)
            with self.assertRaisesRegex(BuilderHandoffError, "aliases"):
                normalize(root)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_builder_output(root)
            path = root / "reports" / "artifact-transforms.json"
            report = json.loads(path.read_text())
            report["artifacts"][0]["final"]["sha256"] = "0" * 64
            write_json(path, report)
            update_transform_pointer(root)
            with self.assertRaisesRegex(BuilderHandoffError, "retained files"):
                validate_builder_output(
                    root,
                    source_repository=SOURCE_REPOSITORY,
                    source_commit=SOURCE_COMMIT,
                    source_tree=SOURCE_TREE,
                    project_version=PROJECT_VERSION,
                )

    def test_rejects_fabricated_sdist_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_builder_output(root)
            path = root / "reports" / "artifact-transforms.json"
            report = json.loads(path.read_text())
            report["artifacts"][1]["payload_sha256"] = "0" * 64
            write_json(path, report)
            update_transform_pointer(root)

            with self.assertRaisesRegex(BuilderHandoffError, "archive semantics"):
                validate_builder_output(
                    root,
                    source_repository=SOURCE_REPOSITORY,
                    source_commit=SOURCE_COMMIT,
                    source_tree=SOURCE_TREE,
                    project_version=PROJECT_VERSION,
                )

    def test_rejects_unbound_source_inventory_and_raw_trace_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_builder_output(root)
            path = root / "reports" / "source-inventory.json"
            inventory = json.loads(path.read_text())
            inventory["entries"][0]["size"] += 1
            inventory["tree_sha256"] = hashlib.sha256(
                json.dumps(
                    inventory["entries"],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            write_json(path, inventory)
            with self.assertRaisesRegex(BuilderHandoffError, "digest is inconsistent"):
                validate_builder_output(
                    root,
                    source_repository=SOURCE_REPOSITORY,
                    source_commit=SOURCE_COMMIT,
                    source_tree=SOURCE_TREE,
                    project_version=PROJECT_VERSION,
                )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_builder_output(root)
            path = root / "traces" / "observed-trace.json"
            trace = json.loads(path.read_text())
            trace["events"][1]["name"] = "clone"
            write_json(path, trace)
            with self.assertRaisesRegex(BuilderHandoffError, "raw trace events"):
                validate_builder_output(
                    root,
                    source_repository=SOURCE_REPOSITORY,
                    source_commit=SOURCE_COMMIT,
                    source_tree=SOURCE_TREE,
                    project_version=PROJECT_VERSION,
                )

    def test_trusted_source_inventory_and_seal_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "evidence"
            source = Path(tmp) / "source"
            root.mkdir()
            source.mkdir()
            (source / ".git").mkdir()
            (source / ".git" / "ignored").write_text("git metadata")
            (source / "pyproject.toml").write_bytes(b"[build-system]\n")
            create_builder_output(root)

            expected = json.loads(
                (root / "reports" / "source-inventory.json").read_text()
            )
            self.assertEqual(inventory_trusted_source(source), expected)

            trusted_path = root / "reports" / "trusted-source-inventory.json"
            trusted = json.loads(trusted_path.read_text())
            trusted["source"]["tree"] = "f" * 40
            write_json(trusted_path, trusted)
            with self.assertRaisesRegex(BuilderHandoffError, "trusted source binding"):
                validate_builder_output(
                    root,
                    source_repository=SOURCE_REPOSITORY,
                    source_commit=SOURCE_COMMIT,
                    source_tree=SOURCE_TREE,
                    project_version=PROJECT_VERSION,
                )

    def test_rejects_noncanonical_sdist_padding_and_wheel_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sdist = root / "bandit-1.9.4.tar.gz"
            write_test_sdist(sdist, canonical=True)
            expanded = (
                gzip.decompress(sdist.read_bytes()) + b"\x00" * tarfile.RECORDSIZE
            )
            with sdist.open("wb") as raw:
                with gzip.GzipFile(
                    filename="",
                    fileobj=raw,
                    mode="wb",
                    compresslevel=9,
                    mtime=int(SOURCE_DATE_EPOCH),
                ) as compressed:
                    compressed.write(expanded)
            with self.assertRaisesRegex(ArchiveValidationError, "record padding"):
                inspect_sdist(
                    sdist,
                    source_date_epoch=int(SOURCE_DATE_EPOCH),
                    require_canonical=True,
                )

            wheel = root / "bandit-1.9.4-py3-none-any.whl"
            write_test_wheel(wheel)
            with zipfile.ZipFile(wheel) as archive:
                records = {
                    info.filename: archive.read(info) for info in archive.infolist()
                }
            record_path = "bandit-1.9.4.dist-info/RECORD"
            lines = records[record_path].decode().splitlines()
            fields = lines[0].split(",")
            fields[1] = "sha256=" + "A" * 43
            lines[0] = ",".join(fields)
            records[record_path] = ("\n".join(lines) + "\n").encode()
            with zipfile.ZipFile(
                wheel,
                "w",
                compression=zipfile.ZIP_DEFLATED,
            ) as archive:
                for name, payload in records.items():
                    info = zipfile.ZipInfo(name)
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = 0o100644 << 16
                    archive.writestr(info, payload)
            with self.assertRaisesRegex(ArchiveValidationError, "digest or size"):
                validate_wheel(wheel)


def normalize(root: Path) -> dict:
    return normalize_spdx(
        root,
        source_repository=SOURCE_REPOSITORY,
        source_commit=SOURCE_COMMIT,
        source_tree=SOURCE_TREE,
        project_version=PROJECT_VERSION,
        source_date_epoch=SOURCE_DATE_EPOCH,
    )


def create_subject_checksums_for(root: Path) -> dict:
    return create_subject_checksums(
        root,
        source_repository=SOURCE_REPOSITORY,
        source_commit=SOURCE_COMMIT,
        source_tree=SOURCE_TREE,
        project_version=PROJECT_VERSION,
    )


def create_predicate(root: Path) -> dict:
    return create_build_predicate(
        root,
        source_repository=SOURCE_REPOSITORY,
        source_commit=SOURCE_COMMIT,
        source_tree=SOURCE_TREE,
        upstream_repository=SOURCE_REPOSITORY,
        upstream_commit=SOURCE_COMMIT,
        target_repository="SauceTaster/assured-bandit",
        project_version=PROJECT_VERSION,
        release_tag="case-001-bandit-source-canary-v3",
        case_id="case-001-bandit-source-canary-v3",
        caller_repository=CONTROL_REPOSITORY,
        caller_commit=CALLER_COMMIT,
        caller_workflow_ref=(
            f"{CONTROL_REPOSITORY}/{CALLER_WORKFLOW_PATH}@refs/heads/main"
        ),
        called_repository=CONTROL_REPOSITORY,
        called_workflow_ref=(
            f"{CONTROL_REPOSITORY}/{CALLED_WORKFLOW_PATH}@{CALLED_COMMIT}"
        ),
        called_workflow_sha=CALLED_COMMIT,
        handoff_commit=HANDOFF_COMMIT,
        run_id="29240000001",
        run_attempt="1",
        event_name="workflow_dispatch",
        actor="SauceTaster",
        triggering_actor="SauceTaster",
        source_date_epoch=SOURCE_DATE_EPOCH,
    )


def create_dist(root: Path) -> None:
    dist = root / "dist"
    dist.mkdir(parents=True)
    (dist / "bandit-1.9.4-py3-none-any.whl").write_bytes(b"wheel")
    (dist / "bandit-1.9.4.tar.gz").write_bytes(b"canonical-sdist")


def create_builder_output(root: Path) -> None:
    create_dist(root)
    write_test_wheel(root / "dist" / "bandit-1.9.4-py3-none-any.whl")
    write_test_sdist(
        root / "dist" / "bandit-1.9.4.tar.gz",
        canonical=True,
    )
    raw = root / "raw-artifacts"
    raw.mkdir()
    (raw / "bandit-1.9.4-py3-none-any.whl").write_bytes(
        (root / "dist" / "bandit-1.9.4-py3-none-any.whl").read_bytes()
    )
    write_test_sdist(raw / "bandit-1.9.4.tar.gz", canonical=False)
    (root / "reports").mkdir()
    (root / "traces" / "raw").mkdir(parents=True)

    artifacts = artifact_records(root / "dist", "dist")
    raw_artifacts = artifact_records(raw, "raw-artifacts")
    write_json(
        root / "reports" / "artifact-inventory.json",
        {"schema_version": 1, "artifacts": artifacts},
    )
    source_entries = [
        {
            "path": "pyproject.toml",
            "type": "file",
            "size": 15,
            "sha256": hashlib.sha256(b"[build-system]\n").hexdigest(),
            "executable": False,
        }
    ]
    write_json(
        root / "reports" / "source-inventory.json",
        {
            "schema_version": 1,
            "entries": source_entries,
            "tree_sha256": hashlib.sha256(
                json.dumps(
                    source_entries,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
        },
    )
    sdist_semantics = inspect_sdist(
        raw / "bandit-1.9.4.tar.gz",
        require_canonical=False,
    )
    transform = {
        "schema_version": 1,
        "status": "succeeded",
        "policy": expected_canonicalization_policy(SOURCE_DATE_EPOCH),
        "artifacts": [
            {
                "path": "bandit-1.9.4-py3-none-any.whl",
                "format": "pass-through",
                "changed": False,
                "original": raw_artifacts[0],
                "final": artifacts[0],
                "member_count": None,
                "payload_size": raw_artifacts[0]["size"],
                "payload_sha256": raw_artifacts[0]["sha256"],
                "sdist_layout": None,
            },
            {
                "path": "bandit-1.9.4.tar.gz",
                "format": "python-sdist-tar-gzip",
                "changed": True,
                "original": raw_artifacts[1],
                "final": artifacts[1],
                "member_count": sdist_semantics["member_count"],
                "payload_size": sdist_semantics["payload_size"],
                "payload_sha256": sdist_semantics["payload_sha256"],
                "sdist_layout": sdist_semantics["sdist_layout"],
            },
        ],
        "error": None,
    }
    write_json(root / "reports" / "artifact-transforms.json", transform)
    write_trace(root)
    write_builder_report(root)
    write_trust_reports(root)


def artifact_records(root: Path, prefix: str) -> list[dict]:
    return [
        {
            "path": f"{prefix}/{path.name}",
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(root.iterdir(), key=lambda item: item.name.encode("utf-8"))
    ]


def write_test_wheel(path: Path) -> None:
    records = {
        "bandit/__init__.py": b"__version__ = '1.9.4'\n",
        "bandit-1.9.4.dist-info/METADATA": b"Name: bandit\nVersion: 1.9.4\n",
        "bandit-1.9.4.dist-info/WHEEL": (b"Wheel-Version: 1.0\nTag: py3-none-any\n"),
    }
    record_path = "bandit-1.9.4.dist-info/RECORD"
    record_lines = []
    for name, payload in records.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
        record_lines.append(f"{name},sha256={digest.decode('ascii')},{len(payload)}\n")
    record_lines.append(f"{record_path},,\n")
    records[record_path] = "".join(record_lines).encode()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in records.items():
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, payload)


def write_test_sdist(path: Path, *, canonical: bool) -> None:
    root = "bandit-1.9.4"
    records = [
        (root, None),
        (f"{root}/PKG-INFO", b"Name: bandit\nVersion: 1.9.4\n"),
        (f"{root}/pyproject.toml", b"[build-system]\nrequires = []\n"),
    ]
    if not canonical:
        records.reverse()
    with path.open("wb") as raw:
        with gzip.GzipFile(
            filename="",
            fileobj=raw,
            mode="wb",
            compresslevel=9,
            mtime=int(SOURCE_DATE_EPOCH) if canonical else 1,
        ) as compressed:
            with tarfile.open(
                fileobj=compressed,
                mode="w",
                format=tarfile.PAX_FORMAT,
                encoding="utf-8",
                errors="strict",
            ) as archive:
                for name, payload in records:
                    member = tarfile.TarInfo(name)
                    member.type = (
                        tarfile.DIRTYPE if payload is None else tarfile.REGTYPE
                    )
                    member.mode = 0o755 if payload is None else 0o644
                    member.uid = 0 if canonical else 1000
                    member.gid = 0 if canonical else 1000
                    member.uname = "" if canonical else "builder"
                    member.gname = "" if canonical else "builder"
                    member.mtime = int(SOURCE_DATE_EPOCH) if canonical else 1
                    member.size = 0 if payload is None else len(payload)
                    if payload is None:
                        archive.addfile(member)
                    else:
                        archive.addfile(member, io.BytesIO(payload))


def write_builder_report(root: Path) -> None:
    write_json(
        root / "reports" / "builder.json",
        {
            "schema_version": 1,
            "status": "succeeded",
            "profile": "python-wheel-v3",
            "builder": {
                "architecture": "x86_64",
                "image": BUILDER_IMAGE,
                "image_digest": BUILDER_DIGEST,
                "python": "3.12.11",
                "tools": {
                    "build": "1.5.1",
                    "packaging": "26.2",
                    "pbr": "7.0.3",
                    "pyproject-hooks": "1.2.0",
                    "setuptools": "83.0.0",
                    "wheel": "0.47.0",
                },
            },
            "source": {
                "repository": SOURCE_REPOSITORY,
                "commit": SOURCE_COMMIT,
                "git_tree": SOURCE_TREE,
                "project_version": PROJECT_VERSION,
                "source_date_epoch": SOURCE_DATE_EPOCH,
                "filesystem_sha256": json.loads(
                    (root / "reports" / "source-inventory.json").read_text()
                )["tree_sha256"],
            },
            "execution": {
                "argv": expected_argv(),
                "cwd": "/workspace/source",
                "finished_at": "2026-07-13T03:21:22Z",
                "identity_boundary": identity_boundary(),
                "network_policy": "deny",
                "returncode": 0,
                "started_at": "2026-07-13T03:21:21Z",
                "validation_error": None,
            },
            "trace": trace_summary(),
            "artifact_transforms": {
                "policy_id": "python-sdist-pax-v1",
                "report_path": "reports/artifact-transforms.json",
                "report_sha256": sha256_file(
                    root / "reports" / "artifact-transforms.json"
                ),
            },
            "claim_limit": BUILDER_CLAIM_LIMIT,
        },
    )


def update_transform_pointer(root: Path) -> None:
    path = root / "reports" / "builder.json"
    report = json.loads(path.read_text())
    report["artifact_transforms"]["report_sha256"] = sha256_file(
        root / "reports" / "artifact-transforms.json"
    )
    write_json(path, report)


def write_trust_reports(root: Path) -> None:
    inventory = json.loads((root / "reports" / "source-inventory.json").read_text())
    trusted = {
        "schema_version": 1,
        "source": {
            "repository": SOURCE_REPOSITORY,
            "commit": SOURCE_COMMIT,
            "tree": SOURCE_TREE,
        },
        "inventory": inventory,
    }
    trusted_path = root / "reports" / "trusted-source-inventory.json"
    write_json(trusted_path, trusted)
    write_json(
        root / "reports" / "handoff-seal.json",
        {
            "schema_version": 1,
            "status": "validated",
            "source": trusted["source"],
            "trusted_source": {
                "path": "reports/trusted-source-inventory.json",
                "sha256": sha256_file(trusted_path),
                "tree_sha256": inventory["tree_sha256"],
            },
            "boundary": {
                "evidence_root": {"uid": 0, "gid": 0, "mode": "0700"},
                "raw_trace_directory": {"uid": 0, "gid": 0, "mode": "0700"},
                "raw_trace_files": [
                    {
                        "path": "traces/raw/strace.1",
                        "uid": 0,
                        "gid": 0,
                        "mode": "0644",
                    }
                ],
            },
            "claim_limit": (
                "This seal records a host-side source comparison and live ownership "
                "check before the evidence bundle was made read-only."
            ),
        },
    )


def write_trace(root: Path) -> None:
    (root / "traces" / "raw" / "strace.1").write_text(
        "1783382521.0 execve() = 0\n",
        encoding="utf-8",
    )
    write_json(
        root / "traces" / "observed-trace.json",
        {
            "schema_version": 1,
            "collector": {
                "name": "strace",
                "version": "6.1",
                "platform": "linux",
                "mode": "follow-forks-full-syscall",
            },
            "coverage": {
                "process": True,
                "file": True,
                "network": True,
                "syscall": True,
            },
            "coverage_basis": "complete-parser-pass",
            "raw_file_count": 1,
            "parsed_line_count": 1,
            "syscall_line_count": 1,
            "signal_line_count": 0,
            "exit_line_count": 0,
            "unparsed_line_count": 0,
            "events": [
                {
                    "kind": "process",
                    "exe": "unknown",
                    "argv": ["unknown"],
                    "outcome": "success",
                    "count": 1,
                },
                {
                    "kind": "syscall",
                    "name": "execve",
                    "outcome": "success",
                    "count": 1,
                },
            ],
        },
    )


def trace_summary() -> dict:
    return {
        "collector": {
            "name": "strace",
            "version": "6.1",
            "platform": "linux",
            "mode": "follow-forks-full-syscall",
        },
        "coverage": {"process": True, "file": True, "network": True, "syscall": True},
        "raw_file_count": 1,
        "parsed_line_count": 1,
        "syscall_line_count": 1,
        "signal_line_count": 0,
        "exit_line_count": 0,
        "unparsed_line_count": 0,
    }


def identity_boundary() -> dict:
    return {
        "build_gid": 65532,
        "build_uid": 65532,
        "collector_gid": 0,
        "collector_output_writable_by_build": False,
        "collector_uid": 0,
        "evidence_gid": 0,
        "evidence_mode": "0700",
        "evidence_uid": 0,
        "killed_process_count": 0,
        "quiescence_barrier": "private-pid-namespace-sigkill",
        "raw_trace_owner_gid": 0,
        "raw_trace_owner_uid": 0,
        "remaining_process_count": 0,
        "separate_collector_identity": True,
    }


def expected_argv() -> list[str]:
    return [
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
    ]


def create_raw_sbom(
    root: Path,
    *,
    variant: int = 1,
    include_second_package: bool = False,
    dangling: bool = False,
) -> bytes:
    package_id = f"SPDXRef-Root-{variant}"
    packages = [root_package(package_id)]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": ("SPDXRef-Missing" if dangling else package_id),
        }
    ]
    if include_second_package:
        second_id = f"SPDXRef-Dependency-{variant}"
        packages.append(
            {
                "SPDXID": second_id,
                "name": "dependency",
                "versionInfo": "1.0",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": package_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": second_id,
            }
        )
    if variant == 2:
        packages.reverse()
        relationships.reverse()
    value = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "assured-evidence/dist",
        "documentNamespace": f"https://anchore.invalid/random-{variant}",
        "creationInfo": {
            "created": f"2026-07-13T00:00:0{variant}Z",
            "creators": ["Tool: syft-1.42.3", "Organization: Anchore, Inc"],
            "licenseListVersion": "3.28",
        },
        "packages": packages,
        "relationships": relationships,
    }
    path = root / "sbom" / "raw" / "syft.spdx.json"
    write_json(path, value)
    return path.read_bytes()


def root_package(spdx_id: str) -> dict:
    return {
        "SPDXID": spdx_id,
        "name": "assured-evidence/dist",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "FILE",
        "supplier": "NOASSERTION",
    }


def create_attestations(root: Path) -> None:
    directory = root / "attestations"
    directory.mkdir()
    for name in (
        "build.sigstore.json",
        "provenance.sigstore.json",
        "sbom.sigstore.json",
    ):
        write_json(
            directory / name, {"mediaType": "application/vnd.dev.sigstore.bundle"}
        )


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    unittest.main()
