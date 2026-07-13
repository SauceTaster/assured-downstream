from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from assured_downstream.workflow_yaml import parse_workflow_yaml


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "builders" / "python" / "entrypoint.py"


def load_entrypoint():
    spec = importlib.util.spec_from_file_location("assured_python_builder", ENTRYPOINT)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Python builder entrypoint")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PythonBuilderTests(unittest.TestCase):
    def test_bootstrap_policy_matches_dockerfile_and_workflow(self) -> None:
        policy = json.loads(
            (ROOT / "policies" / "builders" / "python-wheel-v2.json").read_text()
        )
        dockerfile = (ROOT / "builders" / "python" / "Dockerfile").read_text()
        workflow_text = (
            ROOT / ".github" / "workflows" / "publish-python-builder.yml"
        ).read_text()
        workflow = parse_workflow_yaml(workflow_text)

        self.assertEqual(policy["status"], "implementation-under-test")
        self.assertIsNone(policy["published_image_digest"])
        self.assertFalse(policy["publication"]["verified"])
        self.assertIn(policy["base_image"]["index_digest"], dockerfile)
        for package in policy["system_packages"]:
            self.assertIn(package["url"], dockerfile)
            self.assertIn(package["sha256"], dockerfile)
        self.assertIn('builder.profile="python-wheel-v2"', dockerfile)
        self.assertIn("USER 0:0", dockerfile)
        self.assertIn('ENTRYPOINT ["python", "-I"', dockerfile)
        self.assertNotIn("latest", dockerfile)
        self.assertEqual(workflow["on"], {"workflow_dispatch": None})
        publish = workflow["jobs"]["publish"]
        self.assertEqual(publish["runs-on"], "ubuntu-24.04")
        self.assertEqual(publish["permissions"]["packages"], "write")
        self.assertEqual(publish["permissions"]["id-token"], "write")
        self.assertIn(
            "github.repository == 'SauceTaster/assured-downstream'", publish["if"]
        )
        self.assertIn("github.ref == 'refs/heads/main'", publish["if"])
        self.assertIn("github.ref_protected", publish["if"])
        self.assertEqual(set(workflow["jobs"]), {"publish"})
        build_step = next(
            step for step in publish["steps"] if step.get("id") == "build"
        )
        self.assertTrue(build_step["with"]["load"])
        self.assertFalse(build_step["with"]["push"])
        canary_position = workflow_text.index("Run hostile package")
        login_position = workflow_text.index("uses: docker/login-action@")
        publish_position = workflow_text.index("Publish the canary-tested image")
        attest_position = workflow_text.index("Attest published builder image")
        self.assertLess(canary_position, login_position)
        self.assertLess(login_position, publish_position)
        self.assertLess(publish_position, attest_position)
        for capability in policy["runtime"]["capabilities"]:
            self.assertIn(f"--cap-add {capability}", workflow_text)
        self.assertIn("--cap-drop ALL", workflow_text)
        self.assertIn("--user 0:0", workflow_text)
        self.assertIn("--security-opt no-new-privileges:true", workflow_text)
        self.assertIn("(.attempts | keys | sort)", workflow_text)
        self.assertIn('all(.attempts[]; .outcome == "denied")', workflow_text)
        for action, sha in policy["bootstrap_actions"].items():
            self.assertIn(f"{action}@{sha}", workflow_text)

    def test_v2_collector_runs_only_the_tracee_as_assured(self) -> None:
        builder = load_entrypoint()
        command = builder.collector_command()

        self.assertEqual(command[:3], ["/usr/bin/strace", "-u", "assured"])
        self.assertEqual(command.count("--"), 1)
        self.assertIn("/workspace/output/dist", command)
        self.assertNotIn("/out/dist", command)
        self.assertEqual(builder.PROFILE_ID, "python-wheel-v2")
        self.assertEqual((builder.BUILD_UID, builder.BUILD_GID), (65532, 65532))

    def test_hostile_fixture_attempts_each_required_boundary(self) -> None:
        policy = json.loads(
            (ROOT / "policies" / "builders" / "python-wheel-v2.json").read_text()
        )
        backend = (
            ROOT
            / "tests"
            / "fixtures"
            / "hostile-python-package"
            / "hostile_backend.py"
        ).read_text(encoding="utf-8")
        workflow_text = (
            ROOT / ".github" / "workflows" / "publish-python-builder.yml"
        ).read_text(encoding="utf-8")

        for attack in policy["isolation_canary"]["required_denials"]:
            self.assertIn(f'"{attack}"', backend)
            self.assertIn(f'"{attack}"', workflow_text)
        self.assertIn('Path("/out/tamper-marker")', backend)
        self.assertIn("os.kill(1, signal.SIGTERM)", backend)

    def test_lock_uses_exact_versions_and_hashes(self) -> None:
        lock = (ROOT / "builders" / "python" / "requirements.lock").read_text()
        requirements = [line for line in lock.splitlines() if "==" in line]
        hashes = [line for line in lock.splitlines() if "--hash=sha256:" in line]

        self.assertEqual(len(requirements), 6)
        self.assertEqual(len(hashes), 6)
        self.assertNotIn(">=", lock)
        self.assertNotIn("http", lock)

    def test_metadata_rejects_commands_and_invalid_identity(self) -> None:
        builder = load_entrypoint()
        valid = {
            "ASSURED_SOURCE_REPOSITORY": "PyCQA/bandit",
            "ASSURED_SOURCE_COMMIT": "a" * 40,
            "ASSURED_SOURCE_TREE": "b" * 40,
            "ASSURED_PROJECT_VERSION": "1.9.4",
            "SOURCE_DATE_EPOCH": "1783382521",
            "ASSURED_BUILDER_IMAGE": "ghcr.io/saucetaster/builder",
            "ASSURED_BUILDER_IMAGE_DIGEST": "sha256:" + "c" * 64,
        }

        self.assertEqual(
            builder.load_metadata(valid)["source_repository"], "PyCQA/bandit"
        )
        with self.assertRaises(builder.BuilderError):
            builder.load_metadata({**valid, "ASSURED_SOURCE_REPOSITORY": "bad; id"})
        with self.assertRaises(builder.BuilderError):
            builder.load_metadata({**valid, "ASSURED_SOURCE_COMMIT": "HEAD"})
        with self.assertRaises(builder.BuilderError):
            builder.load_metadata({**valid, "ASSURED_PROJECT_VERSION": "1.0; id"})

    def test_strace_parser_records_syscalls_signals_and_process_exits(self) -> None:
        builder = load_entrypoint()
        with tempfile.TemporaryDirectory() as tmp:
            trace_dir = Path(tmp)
            (trace_dir / "strace.12").write_text(
                "\n".join(
                    [
                        '1783382521.000001 execve("/usr/local/bin/python", ["python", "-m", "build"], 0x0) = 0 <0.001>',
                        '1783382521.000002 openat(AT_FDCWD, "/workspace/source/setup.py", O_RDONLY|O_CLOEXEC) = 3</workspace/source/setup.py> <0.001>',
                        '1783382521.000003 connect(3<socket:[1]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("151.101.0.223")}, 16) = -1 ENETUNREACH (Network is unreachable) <0.001>',
                        '1783382521.000004 mount("none", "/mnt", "tmpfs", 0, NULL) = -1 EPERM (Operation not permitted) <0.001>',
                        "1783382521.000005 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=13, si_uid=65532, si_status=0, si_utime=0, si_stime=0} ---",
                        "1783382521.000006 +++ exited with 0 +++",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            trace = builder.parse_strace_directory(trace_dir, collector_version="6.1")

        self.assertTrue(trace["coverage"]["syscall"])
        self.assertEqual(trace["parsed_line_count"], 6)
        self.assertEqual(trace["syscall_line_count"], 4)
        self.assertEqual(trace["signal_line_count"], 1)
        self.assertEqual(trace["exit_line_count"], 1)
        self.assertEqual(trace["unparsed_line_count"], 0)
        network = [event for event in trace["events"] if event["kind"] == "network"]
        self.assertEqual(network[0]["host"], "151.101.0.223")
        self.assertEqual(network[0]["outcome"], "failed")
        mount = [
            event
            for event in trace["events"]
            if event["kind"] == "syscall" and event["name"] == "mount"
        ]
        self.assertEqual(mount[0]["outcome"], "failed")
        self.assertIn(
            {"kind": "signal", "name": "SIGCHLD", "count": 1},
            trace["events"],
        )
        self.assertIn(
            {"kind": "process-exit", "status": "exited with 0", "count": 1},
            trace["events"],
        )

    def test_strace_parser_does_not_claim_unparsed_coverage(self) -> None:
        builder = load_entrypoint()
        with tempfile.TemporaryDirectory() as tmp:
            trace_dir = Path(tmp)
            (trace_dir / "strace.12").write_text(
                "unsupported collector output\n",
                encoding="utf-8",
            )

            trace = builder.parse_strace_directory(trace_dir, collector_version="6.1")

        self.assertEqual(trace["parsed_line_count"], 0)
        self.assertEqual(trace["unparsed_line_count"], 1)
        self.assertFalse(any(trace["coverage"].values()))
        self.assertEqual(trace["coverage_basis"], "insufficient-parser-pass")

    def test_artifact_inventory_rejects_symlinks(self) -> None:
        builder = load_entrypoint()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "artifact.whl").write_bytes(b"wheel")
            (root / "escape").symlink_to("/etc/passwd")

            with self.assertRaises(builder.BuilderError):
                builder.inventory_artifacts(root)

    def test_artifact_snapshot_rejects_hard_links(self) -> None:
        builder = load_entrypoint()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            target = root / "target"
            source.mkdir()
            target.mkdir()
            artifact = source / "artifact.whl"
            artifact.write_bytes(b"wheel")
            (source / "alias.whl").hardlink_to(artifact)

            with self.assertRaisesRegex(builder.BuilderError, "standalone regular"):
                builder.snapshot_artifacts(source, target)

            self.assertEqual(list(target.iterdir()), [])

    def test_artifact_snapshot_rejects_symlinked_root(self) -> None:
        builder = load_entrypoint()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "artifact.whl").write_bytes(b"wheel")
            alias = root / "source-alias"
            alias.symlink_to(source, target_is_directory=True)
            target = root / "target"
            target.mkdir()

            with self.assertRaisesRegex(builder.BuilderError, "artifact root"):
                builder.snapshot_artifacts(alias, target)

            self.assertEqual(list(target.iterdir()), [])

    def test_artifact_snapshot_rejects_nested_directory_symlink(self) -> None:
        builder = load_entrypoint()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (outside / "secret.txt").write_text("secret\n", encoding="utf-8")
            (source / "escape").symlink_to(outside, target_is_directory=True)
            target = root / "target"
            target.mkdir()

            with self.assertRaisesRegex(builder.BuilderError, "artifact directory"):
                builder.snapshot_artifacts(source, target)

            self.assertEqual(list(target.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
