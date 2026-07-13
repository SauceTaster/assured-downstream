from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from assured_downstream.builder_handoff_v3 import inventory_trusted_source
from assured_downstream.source_reacquisition_v3 import (
    BoundedGitRunner,
    SourceReacquisitionError,
    canonical_github_url,
    collect_bounded_output,
    hash_executable,
    inventory_git_tree,
    reacquire_source,
)


FIXED_TIME = datetime(2026, 7, 13, 17, 0, tzinfo=UTC)
DISCOVERED_GIT_PATH = Path(shutil.which("git") or "/usr/bin/git").resolve()
TEST_GIT_EXEC_PATH = Path(
    subprocess.run(
        [str(DISCOVERED_GIT_PATH), "--exec-path"],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()
).resolve()
NATIVE_GIT_CANDIDATE = TEST_GIT_EXEC_PATH.parent.parent / "bin" / "git"
TEST_GIT_PATH = (
    NATIVE_GIT_CANDIDATE.resolve()
    if NATIVE_GIT_CANDIDATE.is_file()
    else DISCOVERED_GIT_PATH
)
TEST_GIT_SHA256 = hash_executable(TEST_GIT_PATH)
TEST_GIT_HTTPS_HELPER_PATH = (TEST_GIT_EXEC_PATH / "git-remote-https").resolve()
TEST_GIT_HTTPS_HELPER_SHA256 = hash_executable(TEST_GIT_HTTPS_HELPER_PATH)


class SourceReacquisitionV3Tests(unittest.TestCase):
    def test_reacquires_sha1_tree_without_checkout_or_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = create_source_fixture(Path(tmp), object_format="sha1")

            result = reacquire_source(
                trusted_inventory_path=fixture["report"],
                source_ref="refs/heads/main",
                object_format="sha1",
                expected_trusted_inventory_sha256=file_digest(fixture["report"]),
                git_path=TEST_GIT_PATH,
                expected_git_sha256=TEST_GIT_SHA256,
                https_helper_path=TEST_GIT_HTTPS_HELPER_PATH,
                expected_https_helper_sha256=TEST_GIT_HTTPS_HELPER_SHA256,
                scratch_parent=Path(tmp) / "scratch",
                remote_url=str(fixture["remote"]),
                allow_local_remote=True,
                now=FIXED_TIME,
            )

            self.assertTrue(result.report["ok"])
            self.assertEqual(result.report["status"], "matched")
            self.assertTrue(result.report["comparison"]["exact_match"])
            self.assertFalse(result.report["claims"]["provider_independent"])
            self.assertFalse(result.report["claims"]["upstream_lineage"])
            self.assertTrue(result.report["git"]["executed_staged_copy"])
            self.assertTrue(
                result.report["git"]["digest_matched_request_before_execution"]
            )
            self.assertTrue(
                result.report["git"]["identity_checked_before_and_after_each_execution"]
            )
            self.assertFalse(result.report["observation"]["upstream_code_checked_out"])
            commands = "\n".join(
                entry["command"] for entry in result.report["executions"]
            )
            self.assertNotIn(" checkout ", commands)
            self.assertNotIn(" worktree ", commands)
            self.assertNotIn(" submodule ", commands)
            self.assertEqual(
                [
                    entry
                    for entry in result.inventory["entries"]
                    if entry["type"] == "symlink"
                ],
                [{"path": "docs-link", "target": "README.md", "type": "symlink"}],
            )

    def test_reacquires_sha256_repository_when_git_supports_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                fixture = create_source_fixture(Path(tmp), object_format="sha256")
            except subprocess.CalledProcessError as exc:
                self.skipTest(f"Git SHA-256 repositories are unavailable: {exc}")

            result = reacquire_source(
                trusted_inventory_path=fixture["report"],
                source_ref="refs/heads/main",
                object_format="sha256",
                expected_trusted_inventory_sha256=file_digest(fixture["report"]),
                git_path=TEST_GIT_PATH,
                expected_git_sha256=TEST_GIT_SHA256,
                https_helper_path=TEST_GIT_HTTPS_HELPER_PATH,
                expected_https_helper_sha256=TEST_GIT_HTTPS_HELPER_SHA256,
                scratch_parent=Path(tmp) / "scratch",
                remote_url=str(fixture["remote"]),
                allow_local_remote=True,
                now=FIXED_TIME,
            )

            self.assertTrue(result.report["ok"])
            self.assertEqual(len(result.report["observation"]["commit_object_id"]), 64)

    def test_inventory_difference_is_retained_as_a_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = create_source_fixture(Path(tmp), object_format="sha1")
            report = json.loads(fixture["report"].read_text(encoding="utf-8"))
            entry = next(
                item
                for item in report["inventory"]["entries"]
                if item["path"] == "README.md"
            )
            entry["sha256"] = "0" * 64
            report["inventory"]["tree_sha256"] = inventory_digest(
                report["inventory"]["entries"]
            )
            write_json(fixture["report"], report)

            result = reacquire_source(
                trusted_inventory_path=fixture["report"],
                source_ref="refs/heads/main",
                object_format="sha1",
                expected_trusted_inventory_sha256=file_digest(fixture["report"]),
                git_path=TEST_GIT_PATH,
                expected_git_sha256=TEST_GIT_SHA256,
                https_helper_path=TEST_GIT_HTTPS_HELPER_PATH,
                expected_https_helper_sha256=TEST_GIT_HTTPS_HELPER_SHA256,
                scratch_parent=Path(tmp) / "scratch",
                remote_url=str(fixture["remote"]),
                allow_local_remote=True,
                now=FIXED_TIME,
            )

            self.assertFalse(result.report["ok"])
            self.assertEqual(result.report["status"], "mismatch")
            self.assertEqual(result.report["comparison"]["finding_count"], 1)
            self.assertEqual(
                result.report["comparison"]["findings"][0],
                {
                    "code": "entry-mismatch",
                    "path": "README.md",
                    "fields": ["sha256"],
                },
            )

    def test_wrong_tree_and_unreachable_commit_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = create_source_fixture(root, object_format="sha1")
            report = json.loads(fixture["report"].read_text(encoding="utf-8"))
            report["source"]["tree"] = "f" * 40
            write_json(fixture["report"], report)
            with self.assertRaisesRegex(SourceReacquisitionError, "tree identity"):
                reacquire_source(
                    trusted_inventory_path=fixture["report"],
                    source_ref="refs/heads/main",
                    object_format="sha1",
                    expected_trusted_inventory_sha256=file_digest(fixture["report"]),
                    git_path=TEST_GIT_PATH,
                    expected_git_sha256=TEST_GIT_SHA256,
                    https_helper_path=TEST_GIT_HTTPS_HELPER_PATH,
                    expected_https_helper_sha256=TEST_GIT_HTTPS_HELPER_SHA256,
                    scratch_parent=root / "scratch-tree",
                    remote_url=str(fixture["remote"]),
                    allow_local_remote=True,
                )

            fixture = create_source_fixture(root / "second", object_format="sha1")
            work = fixture["work"]
            initial = fixture["commit"]
            git("-C", str(work), "checkout", "--orphan", "unrelated")
            git("-C", str(work), "rm", "-rf", ".")
            (work / "other.txt").write_text("other\n", encoding="utf-8")
            git("-C", str(work), "add", "other.txt")
            git("-C", str(work), "commit", "-m", "unrelated")
            git("-C", str(work), "push", "--force", "origin", "HEAD:main")
            report = json.loads(fixture["report"].read_text(encoding="utf-8"))
            report["source"]["commit"] = initial
            write_json(fixture["report"], report)
            with self.assertRaisesRegex(SourceReacquisitionError, "unavailable"):
                reacquire_source(
                    trusted_inventory_path=fixture["report"],
                    source_ref="refs/heads/main",
                    object_format="sha1",
                    expected_trusted_inventory_sha256=file_digest(fixture["report"]),
                    git_path=TEST_GIT_PATH,
                    expected_git_sha256=TEST_GIT_SHA256,
                    https_helper_path=TEST_GIT_HTTPS_HELPER_PATH,
                    expected_https_helper_sha256=TEST_GIT_HTTPS_HELPER_SHA256,
                    scratch_parent=root / "scratch-unreachable",
                    remote_url=str(fixture["remote"]),
                    allow_local_remote=True,
                )

    def test_gitlinks_are_rejected_before_blob_reads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = create_source_fixture(root, object_format="sha1")
            work = fixture["work"]
            git(
                "-C",
                str(work),
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{fixture['commit']},vendor/dependency",
            )
            git("-C", str(work), "commit", "-m", "add gitlink")
            git("-C", str(work), "push", "origin", "main")
            fixture["commit"] = git("-C", str(work), "rev-parse", "HEAD")
            fixture["tree"] = git("-C", str(work), "rev-parse", "HEAD^{tree}")
            report = json.loads(fixture["report"].read_text(encoding="utf-8"))
            report["source"]["commit"] = fixture["commit"]
            report["source"]["tree"] = fixture["tree"]
            write_json(fixture["report"], report)

            with self.assertRaisesRegex(SourceReacquisitionError, "Gitlinks"):
                reacquire_source(
                    trusted_inventory_path=fixture["report"],
                    source_ref="refs/heads/main",
                    object_format="sha1",
                    expected_trusted_inventory_sha256=file_digest(fixture["report"]),
                    git_path=TEST_GIT_PATH,
                    expected_git_sha256=TEST_GIT_SHA256,
                    https_helper_path=TEST_GIT_HTTPS_HELPER_PATH,
                    expected_https_helper_sha256=TEST_GIT_HTTPS_HELPER_SHA256,
                    scratch_parent=root / "scratch",
                    remote_url=str(fixture["remote"]),
                    allow_local_remote=True,
                )

    def test_hostile_tree_paths_and_canonical_urls_are_rejected(self) -> None:
        object_id = b"a" * 40
        for path in (b"../escape", b"folder\\file", b"bad\x01name", b".git/config"):
            with self.subTest(path=path):
                payload = b"100644 blob " + object_id + b" 1\t" + path + b"\0"
                with self.assertRaises(SourceReacquisitionError):
                    inventory_git_tree(
                        payload,
                        repository_path=Path("/unused"),
                        object_format="sha1",
                        session=NoBlobSession(),
                    )
        invalid_utf8 = b"100644 blob " + object_id + b" 1\tbad-\xff\0"
        with self.assertRaisesRegex(SourceReacquisitionError, "not UTF-8"):
            inventory_git_tree(
                invalid_utf8,
                repository_path=Path("/unused"),
                object_format="sha1",
                session=NoBlobSession(),
            )

        self.assertEqual(
            canonical_github_url("PyCQA/bandit"),
            "https://github.com/PyCQA/bandit.git",
        )
        with self.assertRaises(SourceReacquisitionError):
            canonical_github_url("https://github.com/PyCQA/bandit")

    def test_bounded_runner_caps_output_and_kills_timed_out_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = BoundedGitRunner(
                environment_root=Path(tmp) / "environment",
                git_path=TEST_GIT_PATH,
                expected_git_sha256=TEST_GIT_SHA256,
                https_helper_path=TEST_GIT_HTTPS_HELPER_PATH,
                expected_https_helper_sha256=TEST_GIT_HTTPS_HELPER_SHA256,
            )
            overflow = runner.run(
                ["help", "-a"],
                max_stdout_bytes=1,
                max_stderr_bytes=1024 * 1024,
            )
            self.assertTrue(overflow.output_limited)
            self.assertLessEqual(len(overflow.stdout), 1)

            started = time.monotonic()
            timeout = runner.run(
                ["-c", "alias.wait=!sleep 5", "wait"],
                timeout_seconds=0.1,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
            self.assertTrue(timeout.timed_out)
            self.assertLess(time.monotonic() - started, 3)

    def test_runner_executes_private_native_copies_after_source_path_changes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_git = root / "source-git"
            source_helper = root / "source-git-remote-https"
            shutil.copyfile(TEST_GIT_PATH, source_git)
            shutil.copyfile(TEST_GIT_HTTPS_HELPER_PATH, source_helper)
            source_git.chmod(0o700)
            source_helper.chmod(0o700)
            git_digest = hash_executable(source_git)
            helper_digest = hash_executable(source_helper)
            runner = BoundedGitRunner(
                environment_root=root / "environment",
                git_path=source_git,
                expected_git_sha256=git_digest,
                https_helper_path=source_helper,
                expected_https_helper_sha256=helper_digest,
            )
            source_git.write_bytes(b"replaced after staging\n")

            result = runner.run(["--version"], max_stdout_bytes=4096)

            self.assertTrue(result.ok)
            self.assertEqual(hash_executable(runner.git_path), git_digest)
            self.assertNotEqual(runner.git_path, source_git)

    def test_trusted_inventory_and_git_bytes_are_bound_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = create_source_fixture(root, object_format="sha1")
            trusted_digest = file_digest(fixture["report"])
            report = json.loads(fixture["report"].read_text(encoding="utf-8"))
            report["source"]["repository"] = "changed/project"
            write_json(fixture["report"], report)

            with self.assertRaisesRegex(SourceReacquisitionError, "durable request"):
                reacquire_source(
                    trusted_inventory_path=fixture["report"],
                    source_ref="refs/heads/main",
                    object_format="sha1",
                    expected_trusted_inventory_sha256=trusted_digest,
                    git_path=TEST_GIT_PATH,
                    expected_git_sha256=TEST_GIT_SHA256,
                    https_helper_path=TEST_GIT_HTTPS_HELPER_PATH,
                    expected_https_helper_sha256=TEST_GIT_HTTPS_HELPER_SHA256,
                    scratch_parent=root / "trusted-mismatch",
                    remote_url=str(fixture["remote"]),
                    allow_local_remote=True,
                )

            with self.assertRaisesRegex(SourceReacquisitionError, "trusted request"):
                reacquire_source(
                    trusted_inventory_path=fixture["report"],
                    source_ref="refs/heads/main",
                    object_format="sha1",
                    expected_trusted_inventory_sha256=file_digest(fixture["report"]),
                    git_path=TEST_GIT_PATH,
                    expected_git_sha256="0" * 64,
                    https_helper_path=TEST_GIT_HTTPS_HELPER_PATH,
                    expected_https_helper_sha256=TEST_GIT_HTTPS_HELPER_SHA256,
                    scratch_parent=root / "git-mismatch",
                    remote_url=str(fixture["remote"]),
                    allow_local_remote=True,
                )

    def test_runner_kills_a_process_that_exceeds_aggregate_storage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            storage = root / "objects.git"
            writer = root / "writer"
            writer.write_text(
                "#!/bin/sh\n"
                f"mkdir -p '{storage}'\n"
                f"printf '0123456789' > '{storage}/oversized.pack'\n"
                "sleep 5\n",
                encoding="utf-8",
            )
            writer.chmod(0o700)
            process = subprocess.Popen(
                [str(writer)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )

            started = time.monotonic()
            with patch(
                "assured_downstream.source_reacquisition_v3."
                "MAX_FETCHED_REPOSITORY_BYTES",
                4,
            ):
                _, _, _, _, storage_limited = collect_bounded_output(
                    process,
                    timeout_seconds=3,
                    max_stdout_bytes=1024,
                    max_stderr_bytes=1024,
                    storage_root=storage,
                )

            self.assertTrue(storage_limited)
            self.assertLess(time.monotonic() - started, 3)


class NoBlobSession:
    def required(self, *_args: object, **_kwargs: object) -> object:
        raise AssertionError("unsafe paths must fail before any blob read")


def create_source_fixture(root: Path, *, object_format: str) -> dict[str, object]:
    root.mkdir(parents=True, exist_ok=True)
    work = root / "work"
    remote = root / "upstream.git"
    git(
        "init",
        f"--object-format={object_format}",
        "--initial-branch=main",
        str(work),
    )
    git("-C", str(work), "config", "user.name", "Assured Test")
    git("-C", str(work), "config", "user.email", "assured@example.invalid")
    (work / "README.md").write_text("fixture\n", encoding="utf-8")
    executable = work / "tool.sh"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    (work / "docs-link").symlink_to("README.md")
    git("-C", str(work), "add", "README.md", "tool.sh", "docs-link")
    git("-C", str(work), "commit", "-m", "fixture")
    commit = git("-C", str(work), "rev-parse", "HEAD")
    tree = git("-C", str(work), "rev-parse", "HEAD^{tree}")
    git(
        "init",
        "--bare",
        f"--object-format={object_format}",
        "--initial-branch=main",
        str(remote),
    )
    git("-C", str(work), "remote", "add", "origin", str(remote))
    git("-C", str(work), "push", "-u", "origin", "main")
    report = root / "trusted-source-inventory.json"
    write_json(
        report,
        {
            "schema_version": 1,
            "source": {
                "repository": "owner/project",
                "commit": commit,
                "tree": tree,
            },
            "inventory": inventory_trusted_source(work),
        },
    )
    return {
        "work": work,
        "remote": remote,
        "report": report,
        "commit": commit,
        "tree": tree,
    }


def inventory_digest(entries: list[dict]) -> str:
    return hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        check=True,
        text=True,
        capture_output=True,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
    )
    return result.stdout.strip()


if __name__ == "__main__":
    unittest.main()
