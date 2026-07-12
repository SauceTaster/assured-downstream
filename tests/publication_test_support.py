from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from assured_downstream.evidence import sha256_file
from assured_downstream.publication_authorization import (
    PUBLICATION_AUTHORIZATION_PREDICATE_TYPE,
)


def write_publication_policy(
    root: Path,
    *,
    target_owner: str = "user",
    repository_prefix: str = "target",
    status: str = "active",
) -> tuple[Path, dict]:
    executable = root / "trusted-gh"
    if not executable.exists():
        executable.write_bytes(b"test gh verifier\n")
        executable.chmod(0o500)
    control_repository = f"{target_owner}/control"
    workflow = f"{control_repository}/.github/workflows/authorize-publication.yml"
    source_ref = "refs/heads/main"
    policy = {
        "schema_version": 1,
        "status": status,
        "predicate_type": PUBLICATION_AUTHORIZATION_PREDICATE_TYPE,
        "control_repository": control_repository,
        "environment": "secure-publication",
        "signer": {
            "workflow": workflow,
            "workflow_digest": "1" * 40,
            "source_digest": "1" * 40,
            "source_ref": source_ref,
            "certificate_identity": f"https://github.com/{workflow}@{source_ref}",
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "deny_self_hosted_runners": True,
        },
        "verifier": {
            "executable": str(executable.resolve()),
            "sha256": sha256_file(executable),
        },
        "scope": {
            "target_owner": target_owner,
            "repository_prefix": repository_prefix,
            "branch_prefix": "secure/",
            "max_request_lifetime_seconds": 604800,
        },
    }
    path = root / "publication-policy.json"
    path.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path, policy


def verification_output(request: dict, request_sha256: str, policy: dict) -> str:
    value = [
        {
            "verificationResult": {
                "statement": {
                    "_type": "https://in-toto.io/Statement/v1",
                    "subject": [
                        {
                            "name": "publication-request.json",
                            "digest": {"sha256": request_sha256},
                        }
                    ],
                    "predicateType": policy["predicate_type"],
                    "predicate": {
                        "schemaVersion": 1,
                        "decision": "authorized",
                        "requestId": request["request_id"],
                        "requestSha256": request_sha256,
                        "targetFullName": request["scope"]["target_full_name"],
                        "secureBranch": request["scope"]["secure_branch"],
                        "patchSha": request["scope"]["patch_sha"],
                        "environment": policy["environment"],
                    },
                },
                "verifiedTimestamps": [{"type": "transparency-log"}],
            }
        }
    ]
    return json.dumps(value)


@contextmanager
def trust_publication_policy(path: Path):
    with patch(
        "assured_downstream.publication_authorization.TRUSTED_PUBLICATION_POLICY_SHA256",
        sha256_file(path),
    ):
        yield
