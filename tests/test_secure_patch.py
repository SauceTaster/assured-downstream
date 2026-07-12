from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from assured_downstream.lifecycle import StateStore
from assured_downstream.secure_patch import (
    SecurePatchError,
    apply_secure_patch,
    build_rendered_patch,
)
from assured_downstream.secure_publish import SecurePublishError, publish_secure_branch
from assured_downstream.sync_apply import apply_sync_plan
from assured_downstream.sync_plan import create_sync_plan
from tests.git_test_support import create_remote_fixture, git, local_fork_plan


FUTURE_PUBLICATION_DEADLINE = "2099-01-01T00:00:00+00:00"


class SecurePatchTests(unittest.TestCase):
    def test_same_immutable_inputs_create_same_patch_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _work, upstream, target = create_remote_fixture(root)
            checkouts = []
            for name in ("managed-a", "managed-b"):
                plan = create_sync_plan(
                    local_fork_plan(upstream_bare=upstream, target_bare=target),
                    workspace=root / name,
                    allow_local_remotes=True,
                )
                result = apply_sync_plan(
                    plan,
                    state=StateStore.empty(),
                    execute=True,
                    allow_local_remotes=True,
                )
                self.assertEqual(result.failed, 0)
                checkouts.append(Path(plan["repositories"][0]["local_path"]))
            base_sha = git(
                "-C",
                str(checkouts[0]),
                "rev-parse",
                "refs/heads/secure/main",
            )
            rendered = build_rendered_patch(
                overlay_plan(),
                pins=pin_lock(),
                approved_change_ids=["dependency-review"],
            )

            commits = []
            for index, checkout in enumerate(checkouts):
                result = apply_secure_patch(
                    checkout_path=checkout,
                    target_full_name="user/target",
                    secure_branch="secure/main",
                    expected_secure_sha=base_sha,
                    required_upstream_sha=base_sha,
                    rendered_patch=rendered,
                    approval_sha256="e" * 64,
                    approved_at="2026-07-10T12:00:00Z",
                    run_dir=root / f"run-{index}",
                    execute=True,
                    allow_local_remotes=True,
                )
                commits.append(result["patch_sha"])

            self.assertEqual(commits[0], commits[1])

    def test_commits_through_object_database_and_reuses_approved_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout, _upstream, target = managed_checkout(root)
            base_sha = git("-C", str(checkout), "rev-parse", "refs/heads/secure/main")
            rendered = build_rendered_patch(
                overlay_plan(),
                pins=pin_lock(),
                approved_change_ids=["dependency-review"],
            )

            first = apply_secure_patch(
                checkout_path=checkout,
                target_full_name="user/target",
                secure_branch="secure/main",
                expected_secure_sha=base_sha,
                required_upstream_sha=base_sha,
                rendered_patch=rendered,
                approval_sha256="a" * 64,
                approved_at="2026-07-10T12:00:00Z",
                run_dir=root / "run",
                execute=True,
                allow_local_remotes=True,
            )

            self.assertEqual(first["action"], "committed")
            self.assertNotEqual(first["patch_sha"], base_sha)
            self.assertEqual(
                git("-C", str(checkout), "rev-parse", "refs/heads/secure/main"),
                first["patch_sha"],
            )
            self.assertEqual(
                git("-C", str(checkout), "rev-parse", "HEAD"),
                base_sha,
            )
            workflow = git(
                "-C",
                str(checkout),
                "show",
                f"{first['patch_sha']}:.github/workflows/assured-downstream-dependency-review.yml",
            )
            self.assertIn("actions/dependency-review-action@" + "2" * 40, workflow)
            self.assertEqual(
                git(
                    "--git-dir",
                    str(target),
                    "show-ref",
                    "--verify",
                    "--hash",
                    "refs/heads/main",
                ),
                base_sha,
            )

            resumed = apply_secure_patch(
                checkout_path=checkout,
                target_full_name="user/target",
                secure_branch="secure/main",
                expected_secure_sha=base_sha,
                required_upstream_sha=base_sha,
                rendered_patch=rendered,
                approval_sha256="a" * 64,
                approved_at="2026-07-10T12:00:00Z",
                run_dir=root / "run-2",
                execute=True,
                allow_local_remotes=True,
            )

            self.assertEqual(resumed["action"], "reused-approved-commit")
            self.assertEqual(resumed["patch_sha"], first["patch_sha"])

    def test_blocks_existing_additive_path_with_different_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout, _upstream, _target = managed_checkout(root)
            git("-C", str(checkout), "config", "user.name", "Assured Test")
            git("-C", str(checkout), "config", "user.email", "assured@example.invalid")
            git("-C", str(checkout), "switch", "secure/main")
            path = checkout / ".github/workflows/assured-downstream-dependency-review.yml"
            path.parent.mkdir(parents=True)
            path.write_text("name: different\n", encoding="utf-8")
            git("-C", str(checkout), "add", str(path.relative_to(checkout)))
            git("-C", str(checkout), "commit", "-m", "existing workflow")
            base_sha = git("-C", str(checkout), "rev-parse", "HEAD")
            rendered = build_rendered_patch(
                overlay_plan(),
                pins=pin_lock(),
                approved_change_ids=["dependency-review"],
            )

            with self.assertRaisesRegex(SecurePatchError, "different content"):
                apply_secure_patch(
                    checkout_path=checkout,
                    target_full_name="user/target",
                    secure_branch="secure/main",
                    expected_secure_sha=base_sha,
                    required_upstream_sha=base_sha,
                    rendered_patch=rendered,
                    approval_sha256="b" * 64,
                    approved_at="2026-07-10T12:00:00Z",
                    run_dir=root / "run",
                    execute=True,
                    allow_local_remotes=True,
                )

            self.assertEqual(
                git("-C", str(checkout), "rev-parse", "refs/heads/secure/main"),
                base_sha,
            )

    def test_publication_is_plan_only_then_uses_expected_remote_sha(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout, _upstream, target = managed_checkout(root)
            base_sha = git("-C", str(checkout), "rev-parse", "refs/heads/secure/main")
            rendered = build_rendered_patch(
                overlay_plan(),
                pins=pin_lock(),
                approved_change_ids=["dependency-review"],
            )
            patch = apply_secure_patch(
                checkout_path=checkout,
                target_full_name="user/target",
                secure_branch="secure/main",
                expected_secure_sha=base_sha,
                required_upstream_sha=base_sha,
                rendered_patch=rendered,
                approval_sha256="c" * 64,
                approved_at="2026-07-10T12:00:00Z",
                run_dir=root / "run",
                execute=True,
                allow_local_remotes=True,
            )

            planned = publish_secure_branch(
                checkout_path=checkout,
                target_full_name="user/target",
                secure_branch="secure/main",
                patch_sha=patch["patch_sha"],
                patch_base_sha=base_sha,
                required_upstream_sha=base_sha,
                authorization_expires_at=FUTURE_PUBLICATION_DEADLINE,
                lease_expires_at=FUTURE_PUBLICATION_DEADLINE,
                expected_remote_sha=None,
                execute=False,
                allow_local_remotes=True,
            )
            self.assertEqual(planned["status"], "planned")
            self.assertIn(
                f"{patch['patch_sha']}:refs/heads/secure/main",
                planned["command"],
            )
            self.assertEqual(remote_ref(target, "refs/heads/secure/main"), None)

            with self.assertRaisesRegex(SecurePublishError, "approved base parent"):
                publish_secure_branch(
                    checkout_path=checkout,
                    target_full_name="user/target",
                    secure_branch="secure/main",
                    patch_sha=patch["patch_sha"],
                    patch_base_sha="d" * 40,
                    required_upstream_sha=base_sha,
                    authorization_expires_at=FUTURE_PUBLICATION_DEADLINE,
                    lease_expires_at=FUTURE_PUBLICATION_DEADLINE,
                    expected_remote_sha=None,
                    execute=False,
                    allow_local_remotes=True,
                )

            with self.assertRaisesRegex(SecurePublishError, "required upstream"):
                publish_secure_branch(
                    checkout_path=checkout,
                    target_full_name="user/target",
                    secure_branch="secure/main",
                    patch_sha=patch["patch_sha"],
                    patch_base_sha=base_sha,
                    required_upstream_sha="e" * 40,
                    authorization_expires_at=FUTURE_PUBLICATION_DEADLINE,
                    lease_expires_at=FUTURE_PUBLICATION_DEADLINE,
                    expected_remote_sha=None,
                    execute=False,
                    allow_local_remotes=True,
                )

            with self.assertRaisesRegex(SecurePublishError, "expires too soon"):
                publish_secure_branch(
                    checkout_path=checkout,
                    target_full_name="user/target",
                    secure_branch="secure/main",
                    patch_sha=patch["patch_sha"],
                    patch_base_sha=base_sha,
                    required_upstream_sha=base_sha,
                    authorization_expires_at="2000-01-01T00:00:00+00:00",
                    lease_expires_at=FUTURE_PUBLICATION_DEADLINE,
                    expected_remote_sha=None,
                    execute=True,
                    allow_local_remotes=True,
                )

            published = publish_secure_branch(
                checkout_path=checkout,
                target_full_name="user/target",
                secure_branch="secure/main",
                patch_sha=patch["patch_sha"],
                patch_base_sha=base_sha,
                required_upstream_sha=base_sha,
                authorization_expires_at=FUTURE_PUBLICATION_DEADLINE,
                lease_expires_at=FUTURE_PUBLICATION_DEADLINE,
                expected_remote_sha=None,
                execute=True,
                allow_local_remotes=True,
            )
            self.assertEqual(published["status"], "published")
            self.assertEqual(
                remote_ref(target, "refs/heads/secure/main"),
                patch["patch_sha"],
            )

            reconciled = publish_secure_branch(
                checkout_path=checkout,
                target_full_name="user/target",
                secure_branch="secure/main",
                patch_sha=patch["patch_sha"],
                patch_base_sha=base_sha,
                required_upstream_sha=base_sha,
                authorization_expires_at=FUTURE_PUBLICATION_DEADLINE,
                lease_expires_at=FUTURE_PUBLICATION_DEADLINE,
                expected_remote_sha=None,
                execute=True,
                allow_local_remotes=True,
            )
            self.assertEqual(reconciled["status"], "already-published")
            self.assertFalse(reconciled["executed"])

            git(
                "--git-dir",
                str(target),
                "update-ref",
                "refs/heads/secure/main",
                base_sha,
            )
            with self.assertRaisesRegex(SecurePublishError, "expected <absent>"):
                publish_secure_branch(
                    checkout_path=checkout,
                    target_full_name="user/target",
                    secure_branch="secure/main",
                    patch_sha=patch["patch_sha"],
                    patch_base_sha=base_sha,
                    required_upstream_sha=base_sha,
                    authorization_expires_at=FUTURE_PUBLICATION_DEADLINE,
                    lease_expires_at=FUTURE_PUBLICATION_DEADLINE,
                    expected_remote_sha=None,
                    execute=True,
                    allow_local_remotes=True,
                )

    def test_publication_ignores_global_git_url_rewrites(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout, _upstream, target = managed_checkout(root)
            base_sha = git("-C", str(checkout), "rev-parse", "refs/heads/secure/main")
            rendered = build_rendered_patch(
                overlay_plan(),
                pins=pin_lock(),
                approved_change_ids=["dependency-review"],
            )
            applied = apply_secure_patch(
                checkout_path=checkout,
                target_full_name="user/target",
                secure_branch="secure/main",
                expected_secure_sha=base_sha,
                required_upstream_sha=base_sha,
                rendered_patch=rendered,
                approval_sha256="9" * 64,
                approved_at="2026-07-10T12:00:00Z",
                run_dir=root / "run",
                execute=True,
                allow_local_remotes=True,
            )
            unexpected = root / "unexpected.git"
            git("init", "--bare", str(unexpected))
            malicious_config = root / "malicious.gitconfig"
            malicious_config.write_text(
                f'[url "{unexpected}"]\n\tinsteadOf = {target}\n',
                encoding="utf-8",
            )

            with patch.dict(
                os.environ,
                {
                    "GIT_CONFIG_GLOBAL": str(malicious_config),
                    "GIT_CONFIG_NOSYSTEM": "1",
                },
            ):
                published = publish_secure_branch(
                    checkout_path=checkout,
                    target_full_name="user/target",
                    secure_branch="secure/main",
                    patch_sha=applied["patch_sha"],
                    patch_base_sha=base_sha,
                    required_upstream_sha=base_sha,
                    authorization_expires_at=FUTURE_PUBLICATION_DEADLINE,
                    lease_expires_at=FUTURE_PUBLICATION_DEADLINE,
                    expected_remote_sha=None,
                    execute=True,
                    allow_local_remotes=True,
                )

            self.assertEqual(published["status"], "published")
            self.assertEqual(
                remote_ref(target, "refs/heads/secure/main"),
                applied["patch_sha"],
            )
            self.assertIsNone(remote_ref(unexpected, "refs/heads/secure/main"))

    def test_publication_rejects_repository_git_url_rewrites(self) -> None:
        for rewrite_name in ("insteadOf", "pushInsteadOf"):
            with self.subTest(rewrite_name=rewrite_name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                checkout, _upstream, target = managed_checkout(root)
                base_sha = git(
                    "-C", str(checkout), "rev-parse", "refs/heads/secure/main"
                )
                rendered = build_rendered_patch(
                    overlay_plan(),
                    pins=pin_lock(),
                    approved_change_ids=["dependency-review"],
                )
                applied = apply_secure_patch(
                    checkout_path=checkout,
                    target_full_name="user/target",
                    secure_branch="secure/main",
                    expected_secure_sha=base_sha,
                    required_upstream_sha=base_sha,
                    rendered_patch=rendered,
                    approval_sha256="8" * 64,
                    approved_at="2026-07-10T12:00:00Z",
                    run_dir=root / "run",
                    execute=True,
                    allow_local_remotes=True,
                )
                unexpected = root / "unexpected.git"
                git("init", "--bare", str(unexpected))
                git(
                    "-C",
                    str(checkout),
                    "config",
                    f"url.{unexpected}.{rewrite_name}",
                    str(target),
                )

                with self.assertRaisesRegex(SecurePublishError, "Git URL rewrite"):
                    publish_secure_branch(
                        checkout_path=checkout,
                        target_full_name="user/target",
                        secure_branch="secure/main",
                        patch_sha=applied["patch_sha"],
                        patch_base_sha=base_sha,
                        required_upstream_sha=base_sha,
                        authorization_expires_at=FUTURE_PUBLICATION_DEADLINE,
                        lease_expires_at=FUTURE_PUBLICATION_DEADLINE,
                        expected_remote_sha=None,
                        execute=True,
                        allow_local_remotes=True,
                    )

                self.assertIsNone(remote_ref(target, "refs/heads/secure/main"))
                self.assertIsNone(remote_ref(unexpected, "refs/heads/secure/main"))

    def test_blocks_secure_base_that_omits_synchronized_upstream(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            upstream_work, upstream, target = create_remote_fixture(root)
            plan = create_sync_plan(
                local_fork_plan(upstream_bare=upstream, target_bare=target),
                workspace=root / "managed",
                allow_local_remotes=True,
            )
            state = StateStore.empty()
            apply_sync_plan(
                plan,
                state=state,
                execute=True,
                allow_local_remotes=True,
            )
            checkout = Path(plan["repositories"][0]["local_path"])
            secure_sha = git(
                "-C",
                str(checkout),
                "rev-parse",
                "refs/heads/secure/main",
            )
            (upstream_work / "advanced.txt").write_text("advanced\n", encoding="utf-8")
            git("-C", str(upstream_work), "add", "advanced.txt")
            git("-C", str(upstream_work), "commit", "-m", "advance upstream")
            git("-C", str(upstream_work), "push", "origin", "main")
            upstream_sha = git("-C", str(upstream_work), "rev-parse", "HEAD")
            apply_sync_plan(
                plan,
                state=state,
                execute=True,
                allow_local_remotes=True,
            )
            rendered = build_rendered_patch(
                overlay_plan(),
                pins=pin_lock(),
                approved_change_ids=["dependency-review"],
            )

            with self.assertRaisesRegex(SecurePatchError, "does not contain"):
                apply_secure_patch(
                    checkout_path=checkout,
                    target_full_name="user/target",
                    secure_branch="secure/main",
                    expected_secure_sha=secure_sha,
                    required_upstream_sha=upstream_sha,
                    rendered_patch=rendered,
                    approval_sha256="d" * 64,
                    approved_at="2026-07-10T12:00:00Z",
                    run_dir=root / "run",
                    execute=True,
                    allow_local_remotes=True,
                )

            self.assertEqual(
                git("-C", str(checkout), "rev-parse", "refs/heads/secure/main"),
                secure_sha,
            )


def managed_checkout(root: Path) -> tuple[Path, Path, Path]:
    _work, upstream, target = create_remote_fixture(root)
    plan = create_sync_plan(
        local_fork_plan(upstream_bare=upstream, target_bare=target),
        workspace=root / "managed",
        allow_local_remotes=True,
    )
    state = StateStore.empty()
    result = apply_sync_plan(
        plan,
        state=state,
        execute=True,
        allow_local_remotes=True,
    )
    if result.failed:
        raise AssertionError("fixture reconciliation failed")
    return Path(plan["repositories"][0]["local_path"]), upstream, target


def overlay_plan() -> dict:
    return {
        "schema_version": 1,
        "generated_at": "2026-07-10T12:00:00Z",
        "target": "Hardened",
        "proposed_changes": [
            {
                "id": "dependency-review",
                "stage": "Hardened",
                "action": "add",
                "paths": [
                    ".github/workflows/assured-downstream-dependency-review.yml"
                ],
                "rationale": "Add dependency review.",
                "human_review_required": False,
            }
        ],
    }


def pin_lock() -> dict:
    return {
        "schema_version": 1,
        "generated_at": "2026-07-10T12:00:00+00:00",
        "status": "complete",
        "source_policy_status": "dev-idea-stage",
        "source_policy_sha256": "f" * 64,
        "coverage": {
            "required_actions": [
                "actions/checkout",
                "actions/dependency-review-action",
                "ossf/scorecard-action",
            ],
            "resolved_actions": [
                "actions/checkout",
                "actions/dependency-review-action",
                "ossf/scorecard-action",
            ],
            "missing_actions": [],
        },
        "pins": {
            "actions/checkout": "1" * 40,
            "actions/dependency-review-action": "2" * 40,
            "ossf/scorecard-action": "3" * 40,
        },
        "entries": {
            "actions/checkout": {
                "status": "resolved",
                "requires_full_sha_pin": True,
                "refresh_status": "current",
                "expires_at": "2099-01-01T00:00:00+00:00",
                "repository": "actions/checkout",
                "ref": "v4",
                "resolved_ref": "v4",
                "resolved_at": "2026-07-10T12:00:00+00:00",
                "sha": "1" * 40,
            },
            "actions/dependency-review-action": {
                "status": "resolved",
                "requires_full_sha_pin": True,
                "refresh_status": "current",
                "expires_at": "2099-01-01T00:00:00+00:00",
                "repository": "actions/dependency-review-action",
                "ref": "v4",
                "resolved_ref": "v4",
                "resolved_at": "2026-07-10T12:00:00+00:00",
                "sha": "2" * 40,
            },
            "ossf/scorecard-action": {
                "status": "resolved",
                "requires_full_sha_pin": True,
                "refresh_status": "current",
                "expires_at": "2099-01-01T00:00:00+00:00",
                "repository": "ossf/scorecard-action",
                "ref": "main",
                "resolved_ref": "main",
                "resolved_at": "2026-07-10T12:00:00+00:00",
                "sha": "3" * 40,
            },
        },
    }


def remote_ref(repository: Path, ref: str) -> str | None:
    try:
        return git(
            "--git-dir",
            str(repository),
            "show-ref",
            "--verify",
            "--hash",
            ref,
        )
    except Exception:
        return None


if __name__ == "__main__":
    unittest.main()
