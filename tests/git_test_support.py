from __future__ import annotations

import subprocess
from pathlib import Path


def create_remote_fixture(root: Path) -> tuple[Path, Path, Path]:
    upstream_work = root / "upstream-work"
    upstream_bare = root / "upstream.git"
    target_bare = root / "target.git"
    git("init", "--initial-branch=main", str(upstream_work))
    git("-C", str(upstream_work), "config", "user.name", "Assured Test")
    git("-C", str(upstream_work), "config", "user.email", "assured@example.invalid")
    (upstream_work / "README.md").write_text("fixture\n", encoding="utf-8")
    git("-C", str(upstream_work), "add", "README.md")
    git("-C", str(upstream_work), "commit", "-m", "initial")
    git("init", "--bare", "--initial-branch=main", str(upstream_bare))
    git("-C", str(upstream_work), "remote", "add", "origin", str(upstream_bare))
    git("-C", str(upstream_work), "push", "-u", "origin", "main")
    git("clone", "--bare", str(upstream_bare), str(target_bare))
    return upstream_work, upstream_bare, target_bare


def local_fork_plan(*, upstream_bare: Path, target_bare: Path) -> dict:
    return {
        "schema_version": 2,
        "target": {
            "owner": "user",
            "owner_type": "user",
            "name_prefix": "assured-",
        },
        "forks": [
            {
                "source_full_name": "owner/upstream",
                "target_full_name": "user/target",
                "target_repo_name": "target",
                "source_clone_url": str(upstream_bare),
                "target_clone_url": str(target_bare),
                "metadata": {"default_branch": "main"},
            }
        ],
    }


def git(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout.strip()
