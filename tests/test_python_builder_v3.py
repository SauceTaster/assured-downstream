from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import re
import tarfile
import tempfile
import unittest
from pathlib import Path

from assured_downstream.workflow_yaml import parse_workflow_yaml


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "builders" / "python-v3" / "entrypoint.py"
WORKFLOW = ROOT / ".github" / "workflows" / "publish-python-builder-v3.yml"


def load_entrypoint():
    spec = importlib.util.spec_from_file_location(
        "assured_python_builder_v3", ENTRYPOINT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Python v3 builder entrypoint")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PythonBuilderV3Tests(unittest.TestCase):
    def test_v2_sources_remain_immutable(self) -> None:
        expected = {
            "builders/python/entrypoint.py": (
                "ccfb8bfac1a89b1085a8a76c3cca895ce36ea163608d7c42141ce84003f8120d"
            ),
            "builders/python/Dockerfile": (
                "bd09a87eba036785dd7a7b579ec415bf508d0492ae40e44e495ed8a6a312c4c0"
            ),
            "builders/python/requirements.lock": (
                "6a060a27d9e1d93a78a969d67b7d5e7f9508b73b99c0332315f8646ae80fd2a6"
            ),
            ".github/workflows/publish-python-builder.yml": (
                "aee01db6ca859553402b1b04c66ef21289a05ef4dd04391ba3f88e2f7d7e965c"
            ),
        }
        for relative, digest in expected.items():
            with self.subTest(path=relative):
                actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
                self.assertEqual(actual, digest)

    def test_v3_is_parallel_and_not_live(self) -> None:
        builder = load_entrypoint()
        dockerfile = (ROOT / "builders" / "python-v3" / "Dockerfile").read_text()
        reusable = (
            ROOT / ".github" / "workflows" / "reusable-python-build.yml"
        ).read_text()

        self.assertEqual(builder.PROFILE_ID, "python-wheel-v3")
        self.assertIn('builder.profile="python-wheel-v3"', dockerfile)
        self.assertIn("COPY builders/python-v3/entrypoint.py", dockerfile)
        self.assertNotIn("python-wheel-v3", reusable)

    def test_published_bootstrap_policy_has_no_activation_identity(self) -> None:
        policy = json.loads(
            (
                ROOT / "policies" / "builders" / "python-wheel-v3-bootstrap.json"
            ).read_text()
        )
        dockerfile = (ROOT / policy["source"]["dockerfile"]).read_text()
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertEqual(policy["profile_id"], "python-wheel-v3")
        self.assertEqual(
            policy["status"],
            "published-bootstrap-sigstore-verified-not-activated",
        )
        self.assertEqual(
            policy["published_image_digest"],
            "sha256:5f52c4bfe05c4947877d6d80f2124062b79a46764cc2161dc4caaa631d65833a",
        )
        self.assertTrue(policy["publication"]["verified"])
        self.assertEqual(policy["publication"]["workflow_run_id"], 29230841506)
        self.assertEqual(policy["publication"]["actor"], "SauceTaster")
        self.assertEqual(policy["publication"]["triggering_actor"], "SauceTaster")
        self.assertTrue(policy["activation"]["status"].startswith("disabled-"))
        for key in (
            "reusable_workflow",
            "handoff_verifier",
            "build_predicate_type",
            "build_verification_policy",
        ):
            self.assertIsNone(policy["activation"][key])
        self.assertEqual(
            policy["canonicalization"]["policy_id"],
            "python-sdist-pax-v1",
        )
        self.assertEqual(
            policy["runtime"]["artifact_namespace"],
            "flat-casefold-unique",
        )
        self.assertEqual(
            policy["canonicalization"]["limits"][
                "pax_record_bytes_per_member_before_parse"
            ],
            65536,
        )
        self.assertEqual(
            policy["canonicalization"]["tar_padding"],
            "zero-filled-members-and-two-block-end-marker",
        )
        self.assertEqual(
            policy["bootstrap_canaries"]["dispatch_actor_and_triggering_actor"],
            "SauceTaster-only",
        )
        self.assertEqual(
            policy["bootstrap_canaries"]["python_3_12_11_archive_suite"],
            "passed-before-publication",
        )
        self.assertEqual(
            policy["bootstrap_canaries"]["local_archive_adversarial_suite"],
            "passed-before-commit",
        )
        source_digests = {
            "dockerfile_sha256": policy["source"]["dockerfile"],
            "entrypoint_sha256": policy["source"]["entrypoint"],
            "python_lock_sha256": policy["source"]["python_lock"],
            "publication_workflow_sha256": policy["source"]["publication_workflow"],
        }
        for field, relative in source_digests.items():
            self.assertEqual(
                policy["source"][field],
                hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
            )
        verified_run = policy["bootstrap_canaries"]["verified_run"]
        self.assertEqual(
            verified_run["source_commit"],
            policy["publication"]["source_commit"],
        )
        self.assertEqual(
            verified_run["final_artifact_manifest_sha256"],
            "598b1b541cc7e5de8a6c25b44cb500abb57a30b16a9f3bb4af7feeaae14ae653",
        )
        self.assertNotEqual(*verified_run["raw_sdist_sha256"])
        self.assertFalse(verified_run["provider_independent"])
        self.assertTrue(verified_run["durable_release"]["portable_replay_verified"])

        case = json.loads(
            (
                ROOT
                / "case-studies"
                / "001-pilot-cohort"
                / "python-builder-v3-canary.json"
            ).read_text()
        )
        self.assertEqual(
            case["image"]["published_manifest_digest"],
            policy["published_image_digest"],
        )
        self.assertEqual(
            case["workflow_run"]["source_commit"],
            policy["publication"]["source_commit"],
        )
        self.assertEqual(
            case["retention"]["durable_release_asset"]["sha256"],
            verified_run["durable_release"]["sha256"],
        )
        self.assertFalse(case["independently_verified"]["v3_consumer_activated"])
        self.assertIn(policy["base_image"]["index_digest"], dockerfile)
        for package in policy["system_packages"]:
            self.assertIn(package["url"], dockerfile)
            self.assertIn(package["sha256"], dockerfile)
        for action, digest in policy["bootstrap_actions"].items():
            self.assertIn(f"{action}@{digest}", workflow)

    def test_source_date_epoch_fits_the_canonical_gzip_header(self) -> None:
        builder = load_entrypoint()
        environment = {
            "ASSURED_SOURCE_REPOSITORY": "SauceTaster/assured-example",
            "ASSURED_SOURCE_COMMIT": "a" * 40,
            "ASSURED_SOURCE_TREE": "b" * 40,
            "ASSURED_PROJECT_VERSION": "1.0.0",
            "SOURCE_DATE_EPOCH": "1",
            "ASSURED_BUILDER_IMAGE": "ghcr.io/saucetaster/example",
            "ASSURED_BUILDER_IMAGE_DIGEST": f"sha256:{'c' * 64}",
        }

        self.assertEqual(builder.load_metadata(environment)["source_date_epoch"], "1")
        environment["SOURCE_DATE_EPOCH"] = str(0xFFFFFFFF)
        self.assertEqual(
            builder.load_metadata(environment)["source_date_epoch"],
            str(0xFFFFFFFF),
        )
        for invalid in ("0", str(0x100000000), "-1", "NaN"):
            with self.subTest(value=invalid):
                environment["SOURCE_DATE_EPOCH"] = invalid
                with self.assertRaises(builder.BuilderError):
                    builder.load_metadata(environment)

    def test_realistic_metadata_drift_canonicalizes_exactly(self) -> None:
        builder = load_entrypoint()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            left = root / "left" / "example-1.0.tar.gz"
            right = root / "right" / "example-1.0.tar.gz"
            left.parent.mkdir()
            right.parent.mkdir()
            write_sdist(left, mtime=1_700_000_001, uid=1000, uname="left")
            write_sdist(right, mtime=1_800_000_009, uid=65532, uname="right")
            left_output = root / "left-output" / left.name
            right_output = root / "right-output" / right.name
            left_output.parent.mkdir()
            right_output.parent.mkdir()

            left_result = builder.canonicalize_sdist(
                left,
                left_output,
                source_date_epoch=1_600_000_000,
            )
            right_result = builder.canonicalize_sdist(
                right,
                right_output,
                source_date_epoch=1_600_000_000,
            )

            self.assertEqual(left_output.read_bytes(), right_output.read_bytes())
            self.assertEqual(left_result, right_result)
            self.assertEqual(left_result["member_count"], 4)
            self.assertEqual(left_result["sdist_layout"], "modern-pyproject")
            self.assertEqual(
                builder.read_gzip_header(left_output),
                {"flags": 0, "mtime": 1_600_000_000, "xfl": 2, "os": 255},
            )
            with tarfile.open(left_output, "r:gz") as archive:
                members = archive.getmembers()
            self.assertEqual(archive.format, tarfile.PAX_FORMAT)
            self.assertEqual(
                [member.name for member in members],
                sorted(
                    [member.name for member in members],
                    key=lambda value: value.encode(),
                ),
            )
            self.assertEqual({member.uid for member in members}, {0})
            self.assertEqual({member.gid for member in members}, {0})
            self.assertEqual({member.uname for member in members}, {""})
            self.assertEqual({member.gname for member in members}, {""})
            self.assertEqual({int(member.mtime) for member in members}, {1_600_000_000})

    def test_legacy_setup_py_layout_is_retained(self) -> None:
        builder = load_entrypoint()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "legacy-1.0.tar.gz"
            output = root / "output" / source.name
            output.parent.mkdir()
            write_sdist(source, mtime=1_700_000_001, modern=False)

            result = builder.canonicalize_sdist(
                source,
                output,
                source_date_epoch=1_600_000_000,
            )

            self.assertEqual(result["sdist_layout"], "legacy-setup-py")
            with tarfile.open(output, "r:gz") as archive:
                self.assertIn("legacy-1.0/setup.py", archive.getnames())

    def test_valid_pax_path_and_mtime_are_canonicalized(self) -> None:
        builder = load_entrypoint()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "extended-1.0.tar.gz"
            output = root / "output" / source.name
            output.parent.mkdir()
            long_name = f"extended-1.0/package/{'long-module-' * 12}value.py"
            write_sdist(
                source,
                mtime=1_700_000_001,
                extra_members=[file_member(long_name, b"VALUE = 2\n")],
            )

            result = builder.canonicalize_sdist(
                source,
                output,
                source_date_epoch=1_600_000_000,
            )

            self.assertEqual(result["member_count"], 5)
            with tarfile.open(output, "r:gz") as archive:
                self.assertIn(long_name, archive.getnames())
                self.assertEqual(
                    {int(member.mtime) for member in archive}, {1_600_000_000}
                )

    def test_rejects_ambiguous_or_dangerous_archives(self) -> None:
        builder = load_entrypoint()
        root_name = "unsafe-1.0"
        scenarios = {
            "traversal": [file_member("../escape", b"escape")],
            "dot alias": [file_member(f"{root_name}/./module.py", b"value")],
            "duplicate": [file_member(f"{root_name}/PKG-INFO", b"duplicate")],
            "case alias": [
                file_member(f"{root_name}/Module.py", b"one"),
                file_member(f"{root_name}/module.py", b"two"),
            ],
            "prefix collision": [
                file_member(f"{root_name}/package", b"file"),
                file_member(f"{root_name}/package/module.py", b"module"),
            ],
            "non-NFC": [file_member(f"{root_name}/cafe\u0301.py", b"value")],
            "setuid mode": [
                file_member(f"{root_name}/privileged.py", b"value", mode=0o4644)
            ],
            "symlink": [link_member(f"{root_name}/link")],
            "device": [device_member(f"{root_name}/device")],
            "unsupported PAX": [
                file_member(
                    f"{root_name}/extended.py",
                    b"value",
                    pax_headers={"SCHILY.xattr.user.demo": "value"},
                )
            ],
            "PAX path override": [
                file_member(
                    f"{root_name}/extended.py",
                    b"value",
                    pax_headers={"path": "../escape"},
                )
            ],
            "invalid PAX mtime": [
                file_member(
                    f"{root_name}/extended.py",
                    b"value",
                    pax_headers={"mtime": "NaN"},
                )
            ],
        }
        for label, extra_members in scenarios.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / f"{root_name}.tar.gz"
                output = root / "output" / source.name
                output.parent.mkdir()
                write_sdist(source, mtime=1_700_000_001, extra_members=extra_members)

                with self.assertRaises(builder.BuilderError):
                    builder.canonicalize_sdist(
                        source,
                        output,
                        source_date_epoch=1_600_000_000,
                    )
                self.assertFalse(output.exists())

    def test_rejects_pax_extensions_before_unbounded_body_reads(self) -> None:
        builder = load_entrypoint()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            oversized = root / "oversized-1.0.tar.gz"
            write_declared_pax_header(
                oversized,
                declared_size=builder.MAX_PAX_BYTES + 1,
            )
            output = root / "output" / oversized.name
            output.parent.mkdir()
            with self.assertRaisesRegex(builder.BuilderError, "pre-parse size"):
                builder.canonicalize_sdist(
                    oversized,
                    output,
                    source_date_epoch=1_600_000_000,
                )

            global_pax = root / "global-1.0.tar.gz"
            write_sdist(
                global_pax,
                mtime=1_700_000_001,
                global_pax_headers={"comment": "global metadata"},
            )
            global_output = root / "global-output" / global_pax.name
            global_output.parent.mkdir()
            with self.assertRaisesRegex(builder.BuilderError, "global or Solaris"):
                builder.canonicalize_sdist(
                    global_pax,
                    global_output,
                    source_date_epoch=1_600_000_000,
                )

            chained_pax = root / "chained-1.0.tar.gz"
            write_extension_headers(
                chained_pax,
                [(tarfile.XHDTYPE, pax_record("mtime", "1.0"))] * 2,
            )
            chained_output = root / "chained-output" / chained_pax.name
            chained_output.parent.mkdir()
            with self.assertRaisesRegex(builder.BuilderError, "chained PAX"):
                builder.canonicalize_sdist(
                    chained_pax,
                    chained_output,
                    source_date_epoch=1_600_000_000,
                )

            gnu_longname = root / "gnu-longname-1.0.tar.gz"
            write_extension_headers(
                gnu_longname,
                [(tarfile.GNUTYPE_LONGNAME, b"name\x00")],
            )
            gnu_output = root / "gnu-output" / gnu_longname.name
            gnu_output.parent.mkdir()
            with self.assertRaisesRegex(builder.BuilderError, "GNU extension"):
                builder.canonicalize_sdist(
                    gnu_longname,
                    gnu_output,
                    source_date_epoch=1_600_000_000,
                )

            extension_cases = {
                "GNU long-link": (tarfile.GNUTYPE_LONGLINK, b"target\x00", "GNU"),
                "GNU sparse": (tarfile.GNUTYPE_SPARSE, b"", "GNU"),
                "Solaris PAX": (
                    tarfile.SOLARIS_XHDTYPE,
                    pax_record("mtime", "1.0"),
                    "Solaris",
                ),
            }
            for label, (member_type, payload, error) in extension_cases.items():
                with self.subTest(label=label):
                    extension = root / f"{label.replace(' ', '-')}-1.0.tar.gz"
                    write_extension_headers(extension, [(member_type, payload)])
                    extension_output = root / f"{label}-output" / extension.name
                    extension_output.parent.mkdir()
                    with self.assertRaisesRegex(builder.BuilderError, error):
                        builder.canonicalize_sdist(
                            extension,
                            extension_output,
                            source_date_epoch=1_600_000_000,
                        )

            malformed_framing = root / "malformed-pax-1.0.tar.gz"
            write_extension_headers(
                malformed_framing,
                [(tarfile.XHDTYPE, b"99 path=value\n")],
            )
            malformed_output = root / "malformed-pax-output" / malformed_framing.name
            malformed_output.parent.mkdir()
            with self.assertRaisesRegex(builder.BuilderError, "framing"):
                builder.canonicalize_sdist(
                    malformed_framing,
                    malformed_output,
                    source_date_epoch=1_600_000_000,
                )

            malformed_padding = root / "pax-padding-1.0.tar.gz"
            write_extension_headers(
                malformed_padding,
                [(tarfile.XHDTYPE, pax_record("mtime", "1.0"))],
                padding_byte=b"x",
            )
            padding_output = root / "pax-padding-output" / malformed_padding.name
            padding_output.parent.mkdir()
            with self.assertRaisesRegex(builder.BuilderError, "padding"):
                builder.canonicalize_sdist(
                    malformed_padding,
                    padding_output,
                    source_date_epoch=1_600_000_000,
                )

            truncated_pax = root / "truncated-pax-1.0.tar.gz"
            write_declared_pax_header(truncated_pax, declared_size=10)
            truncated_output = root / "truncated-pax-output" / truncated_pax.name
            truncated_output.parent.mkdir()
            with self.assertRaisesRegex(builder.BuilderError, "truncated"):
                builder.canonicalize_sdist(
                    truncated_pax,
                    truncated_output,
                    source_date_epoch=1_600_000_000,
                )

            cross_type_chain = root / "cross-chain-1.0.tar.gz"
            write_extension_headers(
                cross_type_chain,
                [
                    (tarfile.XHDTYPE, pax_record("mtime", "1.0")),
                    (tarfile.GNUTYPE_LONGLINK, b"target\x00"),
                ],
            )
            chain_output = root / "cross-chain-output" / cross_type_chain.name
            chain_output.parent.mkdir()
            with self.assertRaisesRegex(builder.BuilderError, "GNU"):
                builder.canonicalize_sdist(
                    cross_type_chain,
                    chain_output,
                    source_date_epoch=1_600_000_000,
                )

    def test_rejects_nonzero_tar_padding_and_missing_end_markers(self) -> None:
        builder = load_entrypoint()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            member_padding = root / "member-padding-1.0.tar.gz"
            write_sdist(member_padding, mtime=1_700_000_001)
            raw_member_padding = bytearray(gzip.decompress(member_padding.read_bytes()))
            with tarfile.open(
                fileobj=io.BytesIO(raw_member_padding), mode="r:"
            ) as archive:
                padded_member = next(
                    member
                    for member in archive
                    if member.isfile() and member.size % tarfile.BLOCKSIZE
                )
            raw_member_padding[padded_member.offset_data + padded_member.size] = 1
            write_gzip_payload(member_padding, raw_member_padding)
            member_output = root / "member-padding-output" / member_padding.name
            member_output.parent.mkdir()
            with self.assertRaisesRegex(builder.BuilderError, "member padding"):
                builder.canonicalize_sdist(
                    member_padding,
                    member_output,
                    source_date_epoch=1_600_000_000,
                )

            trailing = root / "trailing-1.0.tar.gz"
            write_sdist(trailing, mtime=1_700_000_001)
            raw_trailing = bytearray(gzip.decompress(trailing.read_bytes()))
            end_offset = tar_data_end(raw_trailing)
            self.assertEqual(
                raw_trailing[end_offset : end_offset + 2 * tarfile.BLOCKSIZE],
                b"\x00" * (2 * tarfile.BLOCKSIZE),
            )
            raw_trailing[end_offset + tarfile.BLOCKSIZE] = 1
            write_gzip_payload(trailing, raw_trailing)
            trailing_output = root / "trailing-output" / trailing.name
            trailing_output.parent.mkdir()
            with self.assertRaisesRegex(builder.BuilderError, "nonzero trailing"):
                builder.canonicalize_sdist(
                    trailing,
                    trailing_output,
                    source_date_epoch=1_600_000_000,
                )

            truncated = root / "truncated-end-1.0.tar.gz"
            write_sdist(truncated, mtime=1_700_000_001)
            raw_truncated = bytearray(gzip.decompress(truncated.read_bytes()))
            write_gzip_payload(truncated, raw_truncated[: tar_data_end(raw_truncated)])
            truncated_output = root / "truncated-output" / truncated.name
            truncated_output.parent.mkdir()
            with self.assertRaisesRegex(builder.BuilderError, "end marker"):
                builder.canonicalize_sdist(
                    truncated,
                    truncated_output,
                    source_date_epoch=1_600_000_000,
                )

    def test_snapshot_requires_a_flat_case_unique_artifact_namespace(self) -> None:
        builder = load_entrypoint()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            target = root / "target"
            (source / "nested").mkdir(parents=True)
            target.mkdir()
            (source / "nested" / "example.whl").write_bytes(b"wheel")
            with self.assertRaisesRegex(builder.BuilderError, "must be flat"):
                builder.snapshot_artifacts(source, target)

        names: set[str] = set()
        folded_names: set[str] = set()
        builder.register_artifact_path(
            Path("stra\u00dfe.whl"),
            names=names,
            folded_names=folded_names,
        )
        with self.assertRaisesRegex(builder.BuilderError, "aliased name"):
            builder.register_artifact_path(
                Path("STRASSE.whl"),
                names=names,
                folded_names=folded_names,
            )

    def test_snapshot_rejects_a_pre_open_identity_change(self) -> None:
        builder = load_entrypoint()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "example.whl"
            target = root / "snapshot.whl"
            source.write_bytes(b"first")
            expected = source.stat()
            source.write_bytes(b"changed-size")

            with self.assertRaisesRegex(
                builder.BuilderError, "changed before snapshot"
            ):
                builder.snapshot_regular_artifact(source, target, expected=expected)
            self.assertFalse(target.exists())

    def test_snapshot_rejects_a_mid_copy_identity_change(self) -> None:
        builder = load_entrypoint()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "example.whl"
            target = root / "snapshot.whl"
            source.write_bytes(b"a" * (builder.COPY_CHUNK_SIZE + 1))
            expected = source.stat()
            original_read = builder.os.read
            mutated = False

            def mutate_after_read(descriptor: int, size: int) -> bytes:
                nonlocal mutated
                payload = original_read(descriptor, size)
                if payload and not mutated:
                    mutated = True
                    source.write_bytes(b"b" * expected.st_size)
                return payload

            builder.os.read = mutate_after_read
            try:
                with self.assertRaisesRegex(builder.BuilderError, "changed while"):
                    builder.snapshot_regular_artifact(source, target, expected=expected)
            finally:
                builder.os.read = original_read

    def test_archive_stream_and_payload_limits_fail_closed(self) -> None:
        builder = load_entrypoint()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "limited-1.0.tar.gz"
            write_sdist(source, mtime=1_700_000_001)

            original_stream_limit = builder.MAX_ARCHIVE_STREAM_BYTES
            try:
                builder.MAX_ARCHIVE_STREAM_BYTES = tarfile.BLOCKSIZE
                stream_output = root / "stream-output" / source.name
                stream_output.parent.mkdir()
                with self.assertRaisesRegex(builder.BuilderError, "stream limit"):
                    builder.canonicalize_sdist(
                        source,
                        stream_output,
                        source_date_epoch=1_600_000_000,
                    )
            finally:
                builder.MAX_ARCHIVE_STREAM_BYTES = original_stream_limit

            original_payload_limit = builder.MAX_TOTAL_ARTIFACT_BYTES
            try:
                builder.MAX_TOTAL_ARTIFACT_BYTES = 8
                payload_output = root / "payload-output" / source.name
                payload_output.parent.mkdir()
                with self.assertRaisesRegex(builder.BuilderError, "payload size"):
                    builder.canonicalize_sdist(
                        source,
                        payload_output,
                        source_date_epoch=1_600_000_000,
                    )
            finally:
                builder.MAX_TOTAL_ARTIFACT_BYTES = original_payload_limit

    def test_rejects_malformed_gzip_and_enforces_member_limit(self) -> None:
        builder = load_entrypoint()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            malformed = root / "malformed-1.0.tar.gz"
            malformed.write_bytes(b"not gzip")
            output = root / "output" / malformed.name
            output.parent.mkdir()
            with self.assertRaisesRegex(builder.BuilderError, "gzip"):
                builder.canonicalize_sdist(
                    malformed,
                    output,
                    source_date_epoch=1_600_000_000,
                )

            malformed_tar = root / "malformed-tar-1.0.tar.gz"
            with malformed_tar.open("wb") as raw:
                with gzip.GzipFile(
                    filename="",
                    fileobj=raw,
                    mode="wb",
                    mtime=1,
                ) as compressed:
                    compressed.write(b"x" * tarfile.BLOCKSIZE)
            malformed_tar_output = root / "tar-output" / malformed_tar.name
            malformed_tar_output.parent.mkdir()
            with self.assertRaisesRegex(builder.BuilderError, "tar"):
                builder.canonicalize_sdist(
                    malformed_tar,
                    malformed_tar_output,
                    source_date_epoch=1_600_000_000,
                )

        original_limit = builder.MAX_ARCHIVE_MEMBERS
        try:
            builder.MAX_ARCHIVE_MEMBERS = 2
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "limited-1.0.tar.gz"
                output = root / "output" / source.name
                output.parent.mkdir()
                write_sdist(source, mtime=1_700_000_001)
                with self.assertRaisesRegex(builder.BuilderError, "member count"):
                    builder.canonicalize_sdist(
                        source,
                        output,
                        source_date_epoch=1_600_000_000,
                    )
        finally:
            builder.MAX_ARCHIVE_MEMBERS = original_limit

    def test_publish_workflow_gates_push_on_two_canaries(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        workflow = parse_workflow_yaml(text)
        publish = workflow["jobs"]["publish"]

        self.assertEqual(workflow["on"], {"workflow_dispatch": None})
        self.assertEqual(publish["runs-on"], "ubuntu-24.04")
        self.assertIn("builders/python-v3/Dockerfile", text)
        self.assertIn("hostile-builder-output-one", text)
        self.assertIn("hostile-builder-output-two", text)
        self.assertIn("python-wheel-v3-determinism.json", text)
        self.assertIn('cmp "$RUNNER_TEMP/hostile-artifacts-one.sha256"', text)
        self.assertIn("github.actor == 'SauceTaster'", publish["if"])
        self.assertIn("github.triggering_actor == 'SauceTaster'", publish["if"])
        for actor in ("SauceTaster", "other-account"):
            for triggering_actor in ("SauceTaster", "other-account"):
                with self.subTest(actor=actor, triggering_actor=triggering_actor):
                    allowed = evaluate_static_gate(
                        publish["if"],
                        {
                            "github.repository": "SauceTaster/assured-downstream",
                            "github.actor": actor,
                            "github.triggering_actor": triggering_actor,
                            "github.ref": "refs/heads/main",
                            "github.ref_protected": True,
                        },
                    )
                    self.assertEqual(
                        allowed,
                        actor == "SauceTaster" and triggering_actor == "SauceTaster",
                    )
        repeat_position = text.index("Repeat hostile package for byte determinism")
        login_position = text.index("uses: docker/login-action@")
        push_position = text.index("Publish the canary-tested image")
        self.assertLess(repeat_position, login_position)
        self.assertLess(login_position, push_position)
        self.assertNotRegex(text, r"uses:\s+[^\n]+@(main|master|v\d+)\s*$")


def write_sdist(
    path: Path,
    *,
    mtime: int,
    uid: int = 1000,
    uname: str = "builder",
    modern: bool = True,
    extra_members: list[tuple[tarfile.TarInfo, bytes | None]] | None = None,
    global_pax_headers: dict[str, str] | None = None,
) -> None:
    root = path.name.removesuffix(".tar.gz")
    members = [
        directory_member(root, mtime=mtime, uid=uid, uname=uname),
        file_member(
            f"{root}/PKG-INFO",
            b"Metadata-Version: 2.4\nName: example\nVersion: 1.0\n",
            mtime=mtime,
            uid=uid,
            uname=uname,
        ),
        file_member(
            f"{root}/pyproject.toml" if modern else f"{root}/setup.py",
            b"[build-system]\nrequires = []\n"
            if modern
            else b"from setuptools import setup\nsetup()\n",
            mtime=mtime,
            uid=uid,
            uname=uname,
        ),
        file_member(
            f"{root}/module.py",
            b"VALUE = 1\n",
            mtime=mtime,
            uid=uid,
            uname=uname,
        ),
    ]
    members.extend(extra_members or [])
    with path.open("wb") as raw:
        with gzip.GzipFile(
            filename=f"volatile-{mtime}.tar.gz",
            fileobj=raw,
            mode="wb",
            compresslevel=6,
            mtime=mtime,
        ) as compressed:
            with tarfile.open(
                fileobj=compressed,
                mode="w",
                format=tarfile.PAX_FORMAT,
                pax_headers=global_pax_headers,
            ) as archive:
                for member, payload in members:
                    archive.addfile(
                        member,
                        io.BytesIO(payload) if payload is not None else None,
                    )


def write_declared_pax_header(path: Path, *, declared_size: int) -> None:
    member = tarfile.TarInfo("PaxHeader")
    member.type = tarfile.XHDTYPE
    member.size = declared_size
    header = member.tobuf(format=tarfile.PAX_FORMAT, encoding="utf-8", errors="strict")
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=1) as compressed:
            compressed.write(header)


def write_gzip_payload(path: Path, payload: bytes | bytearray) -> None:
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=1) as compressed:
            compressed.write(payload)


def tar_data_end(payload: bytes | bytearray) -> int:
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        members = archive.getmembers()
    return max(
        member.offset_data
        + ((member.size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE)
        * tarfile.BLOCKSIZE
        for member in members
    )


def write_extension_headers(
    path: Path,
    extensions: list[tuple[bytes, bytes]],
    *,
    padding_byte: bytes = b"\x00",
) -> None:
    if len(padding_byte) != 1:
        raise ValueError("padding_byte must contain one byte")
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=1) as compressed:
            for position, (member_type, payload) in enumerate(extensions):
                member = tarfile.TarInfo(f"Extension-{position}")
                member.type = member_type
                member.size = len(payload)
                compressed.write(
                    member.tobuf(
                        format=tarfile.PAX_FORMAT,
                        encoding="utf-8",
                        errors="strict",
                    )
                )
                compressed.write(payload)
                compressed.write(padding_byte * (-len(payload) % tarfile.BLOCKSIZE))


def pax_record(key: str, value: str) -> bytes:
    content = f" {key}={value}\n".encode()
    length = len(content) + 1
    while True:
        candidate = str(length).encode() + content
        if len(candidate) == length:
            return candidate
        length = len(candidate)


def evaluate_static_gate(condition: str, context: dict[str, object]) -> bool:
    results = []
    for raw_term in condition.split("&&"):
        term = raw_term.strip()
        equality = re.fullmatch(r"(github\.[a-z_]+)\s*==\s*'([^']*)'", term)
        if equality:
            results.append(context[equality.group(1)] == equality.group(2))
            continue
        if re.fullmatch(r"github\.[a-z_]+", term):
            results.append(bool(context[term]))
            continue
        raise AssertionError(f"unsupported static workflow gate term: {term}")
    return all(results)


def directory_member(
    name: str,
    *,
    mtime: int,
    uid: int,
    uname: str,
) -> tuple[tarfile.TarInfo, None]:
    member = tarfile.TarInfo(name)
    member.type = tarfile.DIRTYPE
    member.mode = 0o775
    member.uid = uid
    member.gid = uid
    member.uname = uname
    member.gname = uname
    member.mtime = mtime + 0.75
    return member, None


def file_member(
    name: str,
    payload: bytes,
    *,
    mode: int = 0o664,
    mtime: int = 1_700_000_001,
    uid: int = 1000,
    uname: str = "builder",
    pax_headers: dict[str, str] | None = None,
) -> tuple[tarfile.TarInfo, bytes]:
    member = tarfile.TarInfo(name)
    member.mode = mode
    member.size = len(payload)
    member.uid = uid
    member.gid = uid
    member.uname = uname
    member.gname = uname
    member.mtime = mtime + 0.25
    member.pax_headers = pax_headers or {}
    return member, payload


def link_member(name: str) -> tuple[tarfile.TarInfo, None]:
    member = tarfile.TarInfo(name)
    member.type = tarfile.SYMTYPE
    member.linkname = "/etc/passwd"
    return member, None


def device_member(name: str) -> tuple[tarfile.TarInfo, None]:
    member = tarfile.TarInfo(name)
    member.type = tarfile.CHRTYPE
    member.devmajor = 1
    member.devminor = 3
    return member, None


if __name__ == "__main__":
    unittest.main()
