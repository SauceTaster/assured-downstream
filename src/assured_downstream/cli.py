from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assured_downstream.agent_runtime import AgentRuntime
from assured_downstream.agent_store import AgentStore
from assured_downstream.account_boundary import load_github_account_boundary
from assured_downstream.attestations import create_intoto_statement
from assured_downstream.behavior import compare_behavior_reports, normalize_trace
from assured_downstream.build_verification import verify_build_attestations
from assured_downstream.build_verification_agents import (
    BUILD_VERIFICATION_WORKFLOW,
    build_verification_handlers,
    build_verification_routes,
    run_build_verification_agent_system,
)
from assured_downstream.catalog import load_catalog, save_catalog, upsert_findings
from assured_downstream.checkout_pipeline import run_checkout_analysis
from assured_downstream.custody import create_custodian_review
from assured_downstream.codex_driver import DEFAULT_CODEX_PROFILE, CodexDriver
from assured_downstream.enrichment import enrich_catalog
from assured_downstream.evidence import (
    compare_evidence_manifests,
    create_evidence_manifest,
    sha256_file,
    verify_evidence_manifest,
)
from assured_downstream.evidence_agents import (
    RELEASE_EVIDENCE_WORKFLOW,
    release_evidence_handlers,
    release_evidence_routes,
    run_release_evidence_agent_system,
)
from assured_downstream.fork_apply import apply_fork_plan
from assured_downstream.fork_plan import create_fork_plan
from assured_downstream.github_api import GitHubClient
from assured_downstream.intake_agents import (
    first_lane_handlers,
    run_intake_agent_system,
)
from assured_downstream.lifecycle import StateStore
from assured_downstream.managed_checkout_agents import (
    MANAGED_CHECKOUT_WORKFLOW,
    managed_checkout_handlers,
    run_managed_checkout_agent_system,
    write_json_atomic,
)
from assured_downstream.overlay import plan_overlay
from assured_downstream.overlay_render import render_overlay
from assured_downstream.patch_agents import (
    PATCH_PUBLICATION_WORKFLOW,
    patch_publication_handlers,
    run_patch_publication_agent_system,
)
from assured_downstream.patch_approval import create_patch_approval
from assured_downstream.pin_resolver import resolve_tooling_pins
from assured_downstream.policy_eval import evaluate_release
from assured_downstream.pipeline import run_pilot_pipeline
from assured_downstream.publication import create_project_packet
from assured_downstream.publication_agents import (
    AUTHORIZED_PUBLICATION_WORKFLOW,
    authorized_publication_handlers,
    run_authorized_publication_agent_system,
)
from assured_downstream.publication_control import (
    dispatch_publication_authorization,
)
from assured_downstream.publication_authorization import (
    verify_publication_authorization,
)
from assured_downstream.recon import inspect_repository
from assured_downstream.release_profile import plan_release_profile
from assured_downstream.release_render import render_release_workflow
from assured_downstream.release_verification import verify_release_attestations
from assured_downstream.reproducibility_agents import (
    REPRODUCIBILITY_WORKFLOW,
    reproducibility_handlers,
    reproducibility_routes,
    run_reproducibility_agent_system,
)
from assured_downstream.scoring import score_catalog
from assured_downstream.seed import parse_seed_source
from assured_downstream.selection import load_candidate_policy
from assured_downstream.selftest import DEFAULT_SELF_TEST_ECOSYSTEMS, run_self_test
from assured_downstream.sync_apply import apply_sync_plan
from assured_downstream.sync_plan import create_sync_plan
from assured_downstream.verification_guide import create_verification_guide


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return args.func(args)
    except Exception as exc:  # noqa: BLE001 - CLI should print clean errors.
        print(f"error: {exc}", file=sys.stderr)
        return 1


def add_fork_target_arguments(parser: argparse.ArgumentParser) -> None:
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument(
        "--org",
        help="Target GitHub organization.",
    )
    target.add_argument(
        "--user",
        dest="target_user",
        help="Target GitHub user account; must match the account authenticated in gh.",
    )
    parser.add_argument(
        "--name-prefix",
        default="",
        help="Prefix added to every downstream repository name.",
    )


def fork_target_kwargs(args: argparse.Namespace) -> dict[str, str]:
    if getattr(args, "target_user", None):
        return {
            "target_owner": args.target_user,
            "target_owner_type": "user",
            "name_prefix": args.name_prefix,
        }
    return {
        "org": args.org,
        "target_owner_type": "organization",
        "name_prefix": args.name_prefix,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="assured-downstream",
        description="Assured Downstream automation control-plane CLI.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest = subparsers.add_parser(
        "ingest",
        help="Extract GitHub repositories from seed files into a local catalog.",
    )
    ingest.add_argument(
        "--seed",
        action="append",
        required=True,
        help="Path or URL to an awesome list or markdown seed file. May be repeated.",
    )
    ingest.add_argument("--catalog", required=True, type=Path)
    ingest.set_defaults(func=command_ingest)

    pilot = subparsers.add_parser(
        "pilot",
        help="Run an observe-first Assured Downstream pilot pipeline from seed files.",
    )
    pilot.add_argument("--seed", action="append", required=True)
    add_fork_target_arguments(pilot)
    pilot.add_argument("--run-dir", required=True, type=Path)
    pilot.add_argument("--limit", type=int, default=None)
    pilot.add_argument("--run-index", type=Path)
    pilot.add_argument("--run-id")
    pilot.add_argument("--allowlist", type=Path)
    pilot.add_argument(
        "--suppress",
        "--suppression",
        dest="suppression",
        type=Path,
        help="JSON file of repositories to suppress from selection.",
    )
    pilot.add_argument(
        "--enrich",
        action="store_true",
        help="Fetch GitHub metadata during the run.",
    )
    pilot.add_argument(
        "--resolve-pins",
        action="store_true",
        help="Resolve approved tooling pins during the run.",
    )
    pilot.add_argument(
        "--tooling",
        type=Path,
        default=Path("policies/approved-tooling.json"),
        help="Approved tooling policy JSON.",
    )
    pilot.add_argument(
        "--token-env",
        default="GITHUB_TOKEN",
        help="Environment variable containing a GitHub token.",
    )
    pilot.set_defaults(func=command_pilot)

    agent_run = subparsers.add_parser(
        "agent-run",
        help="Start the durable discovery-to-fork-plan agent workflow.",
    )
    agent_run.add_argument("--seed", action="append", required=True)
    add_fork_target_arguments(agent_run)
    agent_run.add_argument("--run-dir", required=True, type=Path)
    agent_run.add_argument("--database", type=Path)
    agent_run.add_argument("--run-id")
    agent_run.add_argument("--limit", type=int, default=None)
    agent_run.add_argument("--min-score", type=int, default=None)
    agent_run.add_argument("--allowlist", type=Path)
    agent_run.add_argument(
        "--suppress",
        "--suppression",
        dest="suppression",
        type=Path,
    )
    agent_run.add_argument(
        "--codex-mode",
        choices=["off", "advisory", "required"],
        default="advisory",
    )
    agent_run.add_argument("--codex-profile", default=DEFAULT_CODEX_PROFILE)
    agent_run.add_argument("--codex-timeout", type=int, default=90)
    agent_run.add_argument(
        "--enrich",
        action="store_true",
        help="Fetch GitHub metadata before triage and require it at the Governor gate.",
    )
    agent_run.add_argument(
        "--token-env",
        default="GITHUB_TOKEN",
        help="Environment variable containing the optional GitHub token.",
    )
    agent_run.add_argument("--max-items", type=int, default=100)
    agent_run.add_argument(
        "--enqueue-only",
        action="store_true",
        help="Persist the initial event and leave execution to agent-worker.",
    )
    agent_run.set_defaults(func=command_agent_run)

    checkout_run = subparsers.add_parser(
        "checkout-run",
        help="Run durable fork sync, structural recon, and overlay planning agents.",
    )
    checkout_run.add_argument("--fork-plan", required=True, type=Path)
    checkout_run.add_argument("--state", required=True, type=Path)
    checkout_run.add_argument("--workspace", required=True, type=Path)
    checkout_run.add_argument("--run-dir", required=True, type=Path)
    checkout_run.add_argument("--database", type=Path)
    checkout_run.add_argument("--run-id")
    checkout_run.add_argument(
        "--target",
        choices=[
            "Hardened",
            "Attested",
            "Reproducible",
            "Behavior-Reproducible",
        ],
        default="Attested",
    )
    checkout_run.add_argument(
        "--execute-sync",
        action="store_true",
        help="Clone or reconcile local managed checkouts. Default is planning only.",
    )
    checkout_run.add_argument("--max-items", type=int, default=100)
    checkout_run.add_argument(
        "--enqueue-only",
        action="store_true",
        help="Persist the initial event and leave execution to agent-worker.",
    )
    checkout_run.set_defaults(func=command_checkout_run)

    patch_approval = subparsers.add_parser(
        "prepare-patch-approval",
        help="Prepare a digest-bound approval record for one analyzed repository.",
    )
    patch_approval.add_argument("--analysis-index", required=True, type=Path)
    patch_approval.add_argument("--pins", required=True, type=Path)
    patch_approval.add_argument("--tooling-policy", required=True, type=Path)
    patch_approval.add_argument("--repository", required=True)
    patch_approval.add_argument("--output", required=True, type=Path)
    patch_approval.add_argument(
        "--auto-approve-safe",
        action="store_true",
        help="Policy-approve only supported additive, non-overwriting changes.",
    )
    patch_approval.set_defaults(func=command_prepare_patch_approval)

    patch_run = subparsers.add_parser(
        "patch-run",
        help="Run durable governed patch and secure-branch publication agents.",
    )
    patch_run.add_argument("--analysis-index", required=True, type=Path)
    patch_run.add_argument("--pins", required=True, type=Path)
    patch_run.add_argument("--tooling-policy", required=True, type=Path)
    patch_run.add_argument("--approval", required=True, type=Path)
    patch_run.add_argument("--publication-policy", required=True, type=Path)
    patch_run.add_argument("--workspace", required=True, type=Path)
    patch_run.add_argument("--run-dir", required=True, type=Path)
    patch_run.add_argument("--database", type=Path)
    patch_run.add_argument("--run-id")
    patch_run.add_argument(
        "--execute-patch",
        action="store_true",
        help="Create and compare-and-swap the approved local secure commit.",
    )
    patch_run.add_argument("--max-items", type=int, default=100)
    patch_run.add_argument(
        "--enqueue-only",
        action="store_true",
        help="Persist the initial event and leave execution to agent-worker.",
    )
    patch_run.set_defaults(func=command_patch_run)

    publication_run = subparsers.add_parser(
        "publication-run",
        help="Verify an attested authorization and run the secure branch publisher.",
    )
    publication_run.add_argument("--request", required=True, type=Path)
    publication_run.add_argument("--bundle", required=True, type=Path)
    publication_run.add_argument("--publication-policy", required=True, type=Path)
    publication_run.add_argument("--checkout", required=True, type=Path)
    publication_run.add_argument("--workspace", required=True, type=Path)
    publication_run.add_argument("--run-dir", required=True, type=Path)
    publication_run.add_argument("--database", type=Path)
    publication_run.add_argument("--run-id")
    publication_run.add_argument(
        "--execute",
        action="store_true",
        help="Publish the exact authorized commit with an expected-remote lease.",
    )
    publication_run.add_argument("--max-items", type=int, default=100)
    publication_run.add_argument(
        "--enqueue-only",
        action="store_true",
        help="Persist the authorization event and leave execution to agent-worker.",
    )
    publication_run.set_defaults(func=command_publication_run)

    publication_dispatch = subparsers.add_parser(
        "dispatch-publication-authorization",
        help="Dispatch a canonical publication request to the protected control workflow.",
    )
    publication_dispatch.add_argument("--request", required=True, type=Path)
    publication_dispatch.add_argument(
        "--publication-policy",
        required=True,
        type=Path,
    )
    publication_dispatch.add_argument("--output", required=True, type=Path)
    publication_dispatch.add_argument(
        "--execute",
        action="store_true",
        help="Dispatch the workflow. Default is a validated plan only.",
    )
    publication_dispatch.set_defaults(func=command_publication_dispatch)

    publication_verify = subparsers.add_parser(
        "verify-publication-authorization",
        help="Verify a Sigstore publication bundle against the pinned trust policy.",
    )
    publication_verify.add_argument("--request", required=True, type=Path)
    publication_verify.add_argument("--bundle", required=True, type=Path)
    publication_verify.add_argument(
        "--publication-policy",
        required=True,
        type=Path,
    )
    publication_verify.add_argument("--output", required=True, type=Path)
    publication_verify.set_defaults(func=command_publication_verify)

    evidence_run = subparsers.add_parser(
        "evidence-run",
        help="Ingest outputs declaring external isolation through evidence agents.",
    )
    evidence_run.add_argument("--build-result", required=True, type=Path)
    evidence_run.add_argument("--evidence-root", required=True, type=Path)
    evidence_run.add_argument(
        "--release-verification-policy",
        required=True,
        type=Path,
    )
    evidence_run.add_argument("--tooling-verification", required=True, type=Path)
    evidence_run.add_argument(
        "--workflow-risk-verification",
        required=True,
        type=Path,
    )
    evidence_run.add_argument("--run-dir", required=True, type=Path)
    evidence_run.add_argument("--database", type=Path)
    evidence_run.add_argument("--run-id")
    evidence_run.add_argument("--max-items", type=int, default=100)
    evidence_run.add_argument(
        "--enqueue-only",
        action="store_true",
        help="Persist the build-result event and leave execution to agent-worker.",
    )
    evidence_run.set_defaults(func=command_evidence_run)

    build_verification_run = subparsers.add_parser(
        "build-verification-run",
        help="Snapshot and verify retained build evidence through a durable agent.",
    )
    build_verification_run.add_argument("--evidence", required=True, type=Path)
    build_verification_run.add_argument("--policy", required=True, type=Path)
    build_verification_run.add_argument("--trust-policy", required=True, type=Path)
    build_verification_run.add_argument("--run-dir", required=True, type=Path)
    build_verification_run.add_argument("--database", type=Path)
    build_verification_run.add_argument("--run-id")
    build_verification_run.add_argument("--max-items", type=int, default=20)
    build_verification_run.add_argument("--enqueue-only", action="store_true")
    build_verification_run.set_defaults(func=command_build_verification_run)

    reproducibility_run = subparsers.add_parser(
        "reproducibility-run",
        help=(
            "Reverify and compare two retained builds through the durable Repro "
            "Agent."
        ),
    )
    reproducibility_run.add_argument(
        "--left-evidence", required=True, type=Path
    )
    reproducibility_run.add_argument(
        "--right-evidence", required=True, type=Path
    )
    reproducibility_run.add_argument("--left-execution-id", required=True)
    reproducibility_run.add_argument("--right-execution-id", required=True)
    reproducibility_run.add_argument("--policy", required=True, type=Path)
    reproducibility_run.add_argument(
        "--trust-policy", required=True, type=Path
    )
    reproducibility_run.add_argument("--run-dir", required=True, type=Path)
    reproducibility_run.add_argument("--database", type=Path)
    reproducibility_run.add_argument("--run-id")
    reproducibility_run.add_argument("--max-items", type=int, default=20)
    reproducibility_run.add_argument("--enqueue-only", action="store_true")
    reproducibility_run.set_defaults(func=command_reproducibility_run)

    agent_worker = subparsers.add_parser(
        "agent-worker",
        help="Drain leased work for one durable agent run.",
    )
    agent_worker.add_argument("--database", required=True, type=Path)
    agent_worker.add_argument("--run-id")
    agent_worker.add_argument("--worker-id", default="manual-worker")
    agent_worker.add_argument(
        "--agent",
        action="append",
        choices=sorted(
            {
                handler.agent_id
                for handler in [
                    *first_lane_handlers(),
                    *managed_checkout_handlers(),
                    *patch_publication_handlers(),
                    *authorized_publication_handlers(),
                    *release_evidence_handlers(),
                    *build_verification_handlers(),
                    *reproducibility_handlers(),
                ]
            }
        ),
        help="Agent id to host. May be repeated; defaults to all implemented agents.",
    )
    agent_worker.add_argument("--lease-seconds", type=int, default=120)
    agent_worker.add_argument("--max-items", type=int, default=100)
    agent_worker.set_defaults(func=command_agent_worker)

    agent_status = subparsers.add_parser(
        "agent-status",
        help="Print a durable agent run summary from the local control plane.",
    )
    agent_status.add_argument("--database", required=True, type=Path)
    agent_status.add_argument("--run-id")
    agent_status.set_defaults(func=command_agent_status)

    codex_preflight = subparsers.add_parser(
        "codex-preflight",
        help="Verify the constrained Codex profile used by cognitive agents.",
    )
    codex_preflight.add_argument("--profile", default=DEFAULT_CODEX_PROFILE)
    codex_preflight.set_defaults(func=command_codex_preflight)

    checkout = subparsers.add_parser(
        "analyze-checkout",
        help="Run recon, overlay planning, and optional rendering for a local checkout.",
    )
    checkout.add_argument("--path", required=True, type=Path)
    checkout.add_argument("--run-dir", required=True, type=Path)
    checkout.add_argument(
        "--target",
        choices=["Hardened", "Attested", "Reproducible", "Behavior-Reproducible"],
        default="Attested",
    )
    checkout.add_argument("--pins", type=Path)
    checkout.add_argument(
        "--render",
        action="store_true",
        help="Render safe overlay artifacts into the checkout. Default is dry-run analysis only.",
    )
    checkout.add_argument("--force", action="store_true")
    checkout.set_defaults(func=command_analyze_checkout)

    score = subparsers.add_parser(
        "score",
        help="Apply local candidate scoring heuristics to a catalog.",
    )
    score.add_argument("--catalog", required=True, type=Path)
    score.add_argument(
        "--output",
        type=Path,
        help="Optional output path. Defaults to updating --catalog in place.",
    )
    score.add_argument("--limit", type=int, default=10)
    score.set_defaults(func=command_score)

    custody = subparsers.add_parser(
        "custodian-review",
        help="Generate a human-review packet for possible custodian projects.",
    )
    custody.add_argument("--catalog", required=True, type=Path)
    custody.add_argument("--output", required=True, type=Path)
    custody.add_argument("--min-score", type=int, default=0)
    custody.add_argument("--maintainer-contacts", type=Path)
    custody.set_defaults(func=command_custodian_review)

    publication = subparsers.add_parser(
        "create-project-packet",
        aliases=["create-liaison-packet"],
        help="Create passive downstream fork metadata from fork and checkout outputs.",
    )
    publication.add_argument("--fork-plan", required=True, type=Path)
    publication.add_argument(
        "--source",
        help="Source repository full name to select from the fork plan. Required when the plan has multiple forks.",
    )
    publication.add_argument(
        "--target", help="Target repository full name to select from the fork plan."
    )
    publication.add_argument("--checkout-analysis", type=Path)
    publication.add_argument("--overlay-plan", type=Path)
    publication.add_argument("--render-result", type=Path)
    publication.add_argument("--release-profile", type=Path)
    publication.add_argument(
        "--maintainer-preferences", type=Path, help=argparse.SUPPRESS
    )
    publication.add_argument("--suppression-state", type=Path, help=argparse.SUPPRESS)
    publication.add_argument("--output", required=True, type=Path)
    publication.add_argument("--markdown-output", type=Path)
    publication.set_defaults(func=command_create_project_packet)

    self_test = subparsers.add_parser(
        "self-test",
        help="Run local no-network validation checks against built-in fixtures.",
    )
    self_test.add_argument("--output-dir", required=True, type=Path)
    self_test.add_argument("--fixtures-root", type=Path)
    self_test.add_argument(
        "--ecosystem",
        action="append",
        choices=DEFAULT_SELF_TEST_ECOSYSTEMS,
        help="Fixture ecosystem to run. May be repeated. Defaults to all first-lane ecosystems.",
    )
    self_test.set_defaults(func=command_self_test)

    enrich = subparsers.add_parser(
        "enrich",
        help="Fetch GitHub metadata for catalog entries.",
    )
    enrich.add_argument("--catalog", required=True, type=Path)
    enrich.add_argument(
        "--output",
        type=Path,
        help="Optional output path. Defaults to updating --catalog in place.",
    )
    enrich.add_argument("--limit", type=int, default=None)
    enrich.add_argument(
        "--refresh",
        action="store_true",
        help="Refresh repositories that already have GitHub metadata.",
    )
    enrich.add_argument(
        "--token-env",
        default="GITHUB_TOKEN",
        help="Environment variable containing a GitHub token.",
    )
    enrich.set_defaults(func=command_enrich)

    recon = subparsers.add_parser(
        "recon",
        help="Inspect a local repository checkout without executing project code.",
    )
    recon.add_argument("--path", required=True, type=Path)
    recon.add_argument("--output", type=Path)
    recon.set_defaults(func=command_recon)

    overlay = subparsers.add_parser(
        "plan-overlay",
        help="Create a hardening overlay plan from a recon report.",
    )
    overlay.add_argument("--recon", required=True, type=Path)
    overlay.add_argument(
        "--target",
        choices=["Hardened", "Attested", "Reproducible", "Behavior-Reproducible"],
        default="Hardened",
    )
    overlay.add_argument("--output", type=Path)
    overlay.set_defaults(func=command_plan_overlay)

    release = subparsers.add_parser(
        "plan-release",
        help="Create a draft attested-release profile from a recon report.",
    )
    release.add_argument("--recon", required=True, type=Path)
    release.add_argument("--output", required=True, type=Path)
    release.set_defaults(func=command_plan_release)

    render_release = subparsers.add_parser(
        "render-release-workflow",
        help="Render a pinned attested-release workflow from a release profile.",
    )
    render_release.add_argument("--profile", required=True, type=Path)
    render_release.add_argument("--path", required=True, type=Path)
    render_release.add_argument("--pins", required=True, type=Path)
    render_release.add_argument("--execute", action="store_true")
    render_release.add_argument("--force", action="store_true")
    render_release.set_defaults(func=command_render_release_workflow)

    render = subparsers.add_parser(
        "render-overlay",
        help="Render safe overlay files into a local checkout. Dry-run by default.",
    )
    render.add_argument("--plan", required=True, type=Path)
    render.add_argument("--path", required=True, type=Path)
    render.add_argument(
        "--pins",
        type=Path,
        help="JSON file mapping approved action names to full commit SHAs.",
    )
    render.add_argument(
        "--execute",
        action="store_true",
        help="Write files. Default is dry-run.",
    )
    render.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing generated files.",
    )
    render.set_defaults(func=command_render_overlay)

    resolve_pins = subparsers.add_parser(
        "resolve-pins",
        help="Resolve approved GitHub Action refs to full commit SHA pins.",
    )
    resolve_pins.add_argument(
        "--tooling",
        required=True,
        type=Path,
        help="Approved tooling policy JSON.",
    )
    resolve_pins.add_argument("--output", required=True, type=Path)
    resolve_pins.add_argument(
        "--token-env",
        default="GITHUB_TOKEN",
        help="Environment variable containing a GitHub token.",
    )
    resolve_pins.set_defaults(func=command_resolve_pins)

    create_evidence = subparsers.add_parser(
        "create-evidence",
        help="Create a release evidence manifest with file digests.",
    )
    create_evidence.add_argument("--project", required=True)
    create_evidence.add_argument("--target-repo", required=True)
    create_evidence.add_argument("--upstream-ref", required=True)
    create_evidence.add_argument("--overlay-ref", required=True)
    create_evidence.add_argument("--release-tag", required=True)
    create_evidence.add_argument(
        "--assurance",
        choices=[
            "Tracked",
            "Hardened",
            "Attested",
            "Reproducible",
            "Behavior-Reproducible",
            "Validated",
        ],
        default="Attested",
    )
    create_evidence.add_argument("--artifact", action="append", type=Path, default=[])
    create_evidence.add_argument("--sbom", action="append", type=Path, default=[])
    create_evidence.add_argument(
        "--attestation", action="append", type=Path, default=[]
    )
    create_evidence.add_argument("--trace", action="append", type=Path, default=[])
    create_evidence.add_argument("--report", action="append", type=Path, default=[])
    create_evidence.add_argument("--output", required=True, type=Path)
    create_evidence.set_defaults(func=command_create_evidence)

    create_attestation = subparsers.add_parser(
        "create-attestation",
        help="Create an in-toto statement for one or more subject files.",
    )
    create_attestation.add_argument("--predicate-type", required=True)
    create_attestation.add_argument(
        "--subject", action="append", required=True, type=Path
    )
    create_attestation.add_argument(
        "--predicate",
        type=Path,
        help="Optional JSON predicate file. Defaults to an empty predicate.",
    )
    create_attestation.add_argument("--output", required=True, type=Path)
    create_attestation.set_defaults(func=command_create_attestation)

    verify_evidence = subparsers.add_parser(
        "verify-evidence",
        help="Verify file digests recorded in an evidence manifest.",
    )
    verify_evidence.add_argument("--manifest", required=True, type=Path)
    verify_evidence.set_defaults(func=command_verify_evidence)

    verify_release = subparsers.add_parser(
        "verify-release-attestations",
        help="Cryptographically verify retained release bundles against pinned policy.",
    )
    verify_release.add_argument("--evidence", required=True, type=Path)
    verify_release.add_argument("--policy", required=True, type=Path)
    verify_release.add_argument("--output", required=True, type=Path)
    verify_release.set_defaults(func=command_verify_release_attestations)

    verify_build = subparsers.add_parser(
        "verify-build-attestations",
        help="Verify retained reusable-builder bundles against pinned policy.",
    )
    verify_build.add_argument("--evidence", required=True, type=Path)
    verify_build.add_argument("--policy", required=True, type=Path)
    verify_build.add_argument("--trust-policy", required=True, type=Path)
    verify_build.add_argument("--output", required=True, type=Path)
    verify_build.set_defaults(func=command_verify_build_attestations)

    verification_guide = subparsers.add_parser(
        "write-verification-guide",
        help="Write a Markdown verification guide from an evidence manifest.",
    )
    verification_guide.add_argument("--evidence", required=True, type=Path)
    verification_guide.add_argument("--output", required=True, type=Path)
    verification_guide.set_defaults(func=command_write_verification_guide)

    compare_evidence = subparsers.add_parser(
        "compare-evidence",
        help="Compare two evidence manifests from independent builds.",
    )
    compare_evidence.add_argument("--left", required=True, type=Path)
    compare_evidence.add_argument("--right", required=True, type=Path)
    compare_evidence.add_argument("--output", type=Path)
    compare_evidence.set_defaults(func=command_compare_evidence)

    normalize_behavior = subparsers.add_parser(
        "normalize-trace",
        help="Normalize raw build trace JSON into a behavior digest report.",
    )
    normalize_behavior.add_argument("--trace", required=True, type=Path)
    normalize_behavior.add_argument("--output", required=True, type=Path)
    normalize_behavior.add_argument(
        "--workspace-root",
        type=Path,
        help="Optional workspace root to normalize paths.",
    )
    normalize_behavior.set_defaults(func=command_normalize_trace)

    compare_behavior = subparsers.add_parser(
        "compare-behavior",
        help="Compare two normalized behavior reports.",
    )
    compare_behavior.add_argument("--left", required=True, type=Path)
    compare_behavior.add_argument("--right", required=True, type=Path)
    compare_behavior.add_argument("--output", type=Path)
    compare_behavior.set_defaults(func=command_compare_behavior)

    evaluate = subparsers.add_parser(
        "evaluate-release",
        help="Evaluate release evidence against an assurance target.",
    )
    evaluate.add_argument("--evidence", required=True, type=Path)
    evaluate.add_argument(
        "--target",
        required=True,
        choices=[
            "Hardened",
            "Attested",
            "Reproducible",
            "Behavior-Reproducible",
            "Validated",
        ],
    )
    evaluate.add_argument("--evidence-comparison", type=Path)
    evaluate.add_argument("--behavior-comparison", type=Path)
    evaluate.add_argument("--attestation-verification", type=Path)
    evaluate.add_argument("--tooling-verification", type=Path)
    evaluate.add_argument("--workflow-risk-verification", type=Path)
    evaluate.add_argument(
        "--verification",
        type=Path,
        help="Optional JSON result from verify-evidence; if omitted, evaluate-release verifies the manifest locally.",
    )
    evaluate.add_argument("--output", type=Path)
    evaluate.set_defaults(func=command_evaluate_release)

    plan_forks = subparsers.add_parser(
        "plan-forks",
        help="Create a dry-run fork plan for selected catalog entries.",
    )
    plan_forks.add_argument("--catalog", required=True, type=Path)
    add_fork_target_arguments(plan_forks)
    plan_forks.add_argument("--min-score", type=int, default=None)
    plan_forks.add_argument("--limit", type=int, default=None)
    plan_forks.add_argument("--allowlist", type=Path)
    plan_forks.add_argument(
        "--suppress",
        "--suppression",
        dest="suppression",
        type=Path,
        help="JSON file of repositories to suppress from selection.",
    )
    plan_forks.add_argument(
        "--output",
        type=Path,
        help="Optional JSON output path for the dry-run plan.",
    )
    plan_forks.set_defaults(func=command_plan_forks)

    apply_forks = subparsers.add_parser(
        "apply-fork-plan",
        help="Apply or dry-run a fork plan with lifecycle state recording.",
    )
    apply_forks.add_argument("--plan", required=True, type=Path)
    apply_forks.add_argument("--state", required=True, type=Path)
    apply_forks.add_argument(
        "--execute",
        action="store_true",
        help="Actually run GitHub fork commands. Default is dry-run.",
    )
    apply_forks.set_defaults(func=command_apply_fork_plan)

    plan_sync = subparsers.add_parser(
        "plan-sync",
        help="Create a dry-run local clone/sync plan from a fork plan.",
    )
    plan_sync.add_argument("--fork-plan", required=True, type=Path)
    plan_sync.add_argument("--workspace", required=True, type=Path)
    plan_sync.add_argument("--output", type=Path)
    plan_sync.set_defaults(func=command_plan_sync)

    apply_sync = subparsers.add_parser(
        "apply-sync-plan",
        help="Apply or dry-run a local clone/sync plan with lifecycle state recording.",
    )
    apply_sync.add_argument("--plan", required=True, type=Path)
    apply_sync.add_argument("--state", required=True, type=Path)
    apply_sync.add_argument(
        "--execute",
        action="store_true",
        help="Actually run git sync commands. Default is dry-run.",
    )
    apply_sync.set_defaults(func=command_apply_sync_plan)

    return parser


def command_ingest(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    all_findings = []

    for seed_path in args.seed:
        findings = parse_seed_source(seed_path)
        all_findings.extend(findings)

    added_repositories, added_seed_refs = upsert_findings(catalog, all_findings)
    save_catalog(args.catalog, catalog)

    print(
        "ingested "
        f"{len(all_findings)} findings, "
        f"added {added_repositories} repositories, "
        f"added {added_seed_refs} seed references"
    )
    print(f"catalog: {args.catalog}")
    return 0


def command_pilot(args: argparse.Namespace) -> int:
    client = GitHubClient.from_environment(token_env=args.token_env)
    summary = run_pilot_pipeline(
        seed_paths=args.seed,
        run_dir=args.run_dir,
        limit=args.limit,
        enrich=args.enrich,
        resolve_pins=args.resolve_pins,
        tooling_path=args.tooling,
        run_index_path=args.run_index,
        run_id=args.run_id,
        allowlist_path=args.allowlist,
        suppression_path=args.suppression,
        client=client,
        **fork_target_kwargs(args),
    )
    print(f"pilot run complete: {args.run_dir}")
    print(f"summary: {summary['summary_path']}")
    print(f"candidates: {summary['repositories']}")
    return 0


def command_agent_run(args: argparse.Namespace) -> int:
    result = run_intake_agent_system(
        seed_sources=args.seed,
        run_dir=args.run_dir,
        database_path=args.database,
        run_id=args.run_id,
        limit=args.limit,
        min_score=args.min_score,
        allowlist_path=args.allowlist,
        suppression_path=args.suppression,
        codex_mode=args.codex_mode,
        codex_profile=args.codex_profile,
        codex_timeout_seconds=args.codex_timeout,
        enrich=args.enrich,
        token_env=args.token_env,
        max_items=args.max_items,
        enqueue_only=args.enqueue_only,
        **fork_target_kwargs(args),
    )
    print(f"agent run: {result['run_id']}")
    print(f"status: {result['status']}")
    print(f"processed work attempts: {result['processed_count']}")
    print(f"pending work: {result['pending_count']}")
    print(f"database: {result['database_path']}")
    print(f"summary: {result['summary_path']}")
    return 0 if result["status"] in {"running", "succeeded"} else 2


def command_checkout_run(args: argparse.Namespace) -> int:
    result = run_managed_checkout_agent_system(
        fork_plan_path=args.fork_plan,
        state_path=args.state,
        workspace=args.workspace,
        run_dir=args.run_dir,
        assurance_target=args.target,
        execute_sync=args.execute_sync,
        database_path=args.database,
        run_id=args.run_id,
        max_items=args.max_items,
        enqueue_only=args.enqueue_only,
    )
    print(f"managed checkout run: {result['run_id']}")
    print(f"status: {result['status']}")
    print(f"processed work attempts: {result['processed_count']}")
    print(f"pending work: {result['pending_count']}")
    print(f"database: {result['database_path']}")
    print(f"summary: {result['summary_path']}")
    return 0 if result["status"] in {"running", "succeeded"} else 2


def command_prepare_patch_approval(args: argparse.Namespace) -> int:
    with args.analysis_index.open("r", encoding="utf-8") as handle:
        analysis = json.load(handle)
    with args.pins.open("r", encoding="utf-8") as handle:
        pin_lock = json.load(handle)
    with args.tooling_policy.open("r", encoding="utf-8") as handle:
        tooling_policy = json.load(handle)
    approval = create_patch_approval(
        analysis_index=analysis,
        analysis_index_sha256=sha256_file(args.analysis_index),
        pin_lock=pin_lock,
        pin_lock_sha256=sha256_file(args.pins),
        tooling_policy=tooling_policy,
        tooling_policy_sha256=sha256_file(args.tooling_policy),
        target_full_name=args.repository,
        auto_approve_safe=args.auto_approve_safe,
    )
    write_json_atomic(args.output, approval)
    approved = approval["repository"]["approved_change_ids"]
    print(f"patch approval: {approval['status']}")
    print(f"repository: {approval['repository']['target_full_name']}")
    print(f"approved changes: {len(approved)}")
    print(f"output: {args.output.resolve()}")
    return 0 if approval["status"] == "approved" else 2


def command_patch_run(args: argparse.Namespace) -> int:
    result = run_patch_publication_agent_system(
        analysis_index_path=args.analysis_index,
        pin_lock_path=args.pins,
        tooling_policy_path=args.tooling_policy,
        approval_path=args.approval,
        publication_policy_path=args.publication_policy,
        workspace=args.workspace,
        run_dir=args.run_dir,
        execute_patch=args.execute_patch,
        database_path=args.database,
        run_id=args.run_id,
        max_items=args.max_items,
        enqueue_only=args.enqueue_only,
    )
    print(f"patch request run: {result['run_id']}")
    print(f"status: {result['status']}")
    print(f"processed work attempts: {result['processed_count']}")
    print(f"pending work: {result['pending_count']}")
    print(f"database: {result['database_path']}")
    print(f"summary: {result['summary_path']}")
    return 0 if result["status"] in {"running", "succeeded"} else 2


def command_publication_run(args: argparse.Namespace) -> int:
    result = run_authorized_publication_agent_system(
        request_path=args.request,
        bundle_path=args.bundle,
        publication_policy_path=args.publication_policy,
        checkout_path=args.checkout,
        workspace=args.workspace,
        run_dir=args.run_dir,
        execute=args.execute,
        database_path=args.database,
        run_id=args.run_id,
        max_items=args.max_items,
        enqueue_only=args.enqueue_only,
    )
    print(f"authorized publication run: {result['run_id']}")
    print(f"status: {result['status']}")
    print(f"processed work attempts: {result['processed_count']}")
    print(f"pending work: {result['pending_count']}")
    print(f"database: {result['database_path']}")
    print(f"authorization ledger: {result['authorization_ledger_path']}")
    print(f"summary: {result['summary_path']}")
    return 0 if result["status"] in {"running", "succeeded"} else 2


def command_publication_dispatch(args: argparse.Namespace) -> int:
    result = dispatch_publication_authorization(
        request_path=args.request,
        policy_path=args.publication_policy,
        execute=args.execute,
        account_boundary=load_github_account_boundary(),
    )
    write_json_atomic(args.output, result)
    print(f"publication authorization dispatch: {result['status']}")
    print(f"request: {result['request_id']}")
    if result["run_url"]:
        print(f"run: {result['run_url']}")
    print(f"output: {args.output.resolve()}")
    return 0


def command_publication_verify(args: argparse.Namespace) -> int:
    result = verify_publication_authorization(
        request_path=args.request,
        bundle_path=args.bundle,
        policy_path=args.publication_policy,
    )
    write_json_atomic(args.output, result)
    print(f"publication authorization verification: {result['status']}")
    print(f"request: {result['request_id']}")
    print(f"signer: {result['signer_workflow']}@{result['signer_digest']}")
    print(f"output: {args.output.resolve()}")
    return 0


def command_evidence_run(args: argparse.Namespace) -> int:
    result = run_release_evidence_agent_system(
        build_result_path=args.build_result,
        evidence_root=args.evidence_root,
        release_verification_policy_path=args.release_verification_policy,
        tooling_verification_path=args.tooling_verification,
        workflow_risk_verification_path=args.workflow_risk_verification,
        run_dir=args.run_dir,
        database_path=args.database,
        run_id=args.run_id,
        max_items=args.max_items,
        enqueue_only=args.enqueue_only,
    )
    print(f"release evidence run: {result['run_id']}")
    print(f"status: {result['status']}")
    print(f"processed work attempts: {result['processed_count']}")
    print(f"pending work: {result['pending_count']}")
    print(f"database: {result['database_path']}")
    print(f"summary: {result['summary_path']}")
    return 0 if result["status"] in {"running", "succeeded"} else 2


def command_build_verification_run(args: argparse.Namespace) -> int:
    result = run_build_verification_agent_system(
        evidence_path=args.evidence,
        policy_path=args.policy,
        trust_policy_path=args.trust_policy,
        run_dir=args.run_dir,
        database_path=args.database,
        run_id=args.run_id,
        max_items=args.max_items,
        enqueue_only=args.enqueue_only,
    )
    print(f"build verification run: {result['run_id']}")
    print(f"status: {result['status']}")
    print(f"processed work attempts: {result['processed_count']}")
    print(f"pending work: {result['pending_count']}")
    print(f"database: {result['database_path']}")
    print(f"summary: {result['summary_path']}")
    return 0 if result["status"] in {"running", "succeeded"} else 2


def command_reproducibility_run(args: argparse.Namespace) -> int:
    result = run_reproducibility_agent_system(
        left_evidence_path=args.left_evidence,
        right_evidence_path=args.right_evidence,
        left_execution_id=args.left_execution_id,
        right_execution_id=args.right_execution_id,
        policy_path=args.policy,
        trust_policy_path=args.trust_policy,
        run_dir=args.run_dir,
        database_path=args.database,
        run_id=args.run_id,
        max_items=args.max_items,
        enqueue_only=args.enqueue_only,
    )
    print(f"reproducibility run: {result['run_id']}")
    print(f"status: {result['status']}")
    print(f"processed work attempts: {result['processed_count']}")
    print(f"pending work: {result['pending_count']}")
    print(f"database: {result['database_path']}")
    print(f"summary: {result['summary_path']}")
    return 0 if result["status"] in {"running", "succeeded"} else 2


def command_agent_worker(args: argparse.Namespace) -> int:
    store = AgentStore(args.database)
    run_id = args.run_id or store.latest_run_id()
    if run_id is None:
        raise ValueError("The agent database contains no runs")
    workflow = store.get_run(run_id)["metadata"].get("workflow")
    routes = None
    if workflow == MANAGED_CHECKOUT_WORKFLOW:
        available_handlers = managed_checkout_handlers()
    elif workflow == PATCH_PUBLICATION_WORKFLOW:
        available_handlers = patch_publication_handlers()
    elif workflow == AUTHORIZED_PUBLICATION_WORKFLOW:
        available_handlers = authorized_publication_handlers()
    elif workflow == RELEASE_EVIDENCE_WORKFLOW:
        available_handlers = release_evidence_handlers()
        routes = release_evidence_routes()
    elif workflow == BUILD_VERIFICATION_WORKFLOW:
        available_handlers = build_verification_handlers()
        routes = build_verification_routes()
    elif workflow == REPRODUCIBILITY_WORKFLOW:
        available_handlers = reproducibility_handlers()
        routes = reproducibility_routes()
    elif workflow == "discovery-to-fork-plan":
        available_handlers = first_lane_handlers()
    else:
        raise ValueError(f"Unsupported agent workflow: {workflow!r}")
    selected_ids = set(args.agent or [])
    handlers = [
        handler
        for handler in available_handlers
        if not selected_ids or handler.agent_id in selected_ids
    ]
    if not handlers:
        raise ValueError("No selected agents belong to this run's workflow")
    runtime = AgentRuntime(
        backend=store,
        handlers=handlers,
        routes=routes,
        worker_id=args.worker_id,
        lease_seconds=args.lease_seconds,
    )
    result = runtime.drain(run_id=run_id, max_items=args.max_items)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] in {"running", "succeeded"} else 2


def command_agent_status(args: argparse.Namespace) -> int:
    store = AgentStore(args.database)
    run_id = args.run_id or store.latest_run_id()
    if run_id is None:
        raise ValueError("The agent database contains no runs")
    summary = store.run_summary(run_id)
    summary["artifact_verification"] = store.verify_artifacts(run_id)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def command_codex_preflight(args: argparse.Namespace) -> int:
    result = CodexDriver(profile=args.profile).preflight()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def command_analyze_checkout(args: argparse.Namespace) -> int:
    pins = {}
    if args.pins:
        with args.pins.open("r", encoding="utf-8") as handle:
            pins = json.load(handle)
    summary = run_checkout_analysis(
        checkout_path=args.path,
        run_dir=args.run_dir,
        target=args.target,
        pins=pins,
        render=args.render,
        force=args.force,
    )
    print(f"checkout analysis complete: {args.run_dir}")
    print(f"summary: {summary['summary_path']}")
    print(f"overlay changes: {summary['overlay_changes']}")
    return 0


def command_score(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    scored = score_catalog(catalog)
    output = args.output or args.catalog
    save_catalog(output, catalog)

    print(f"scored {scored} repositories")
    for repo in top_repositories(catalog, args.limit):
        print(f"{repo['score']:>4}  {repo['owner']}/{repo['name']}")
    return 0


def command_custodian_review(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    packet = create_custodian_review(
        catalog,
        min_score=args.min_score,
        maintainer_contacts=read_optional_json(args.maintainer_contacts),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        json.dump(packet, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"wrote custodian review packet: {args.output}")
    print(f"candidates: {len(packet['candidates'])}")
    return 0


def command_create_project_packet(args: argparse.Namespace) -> int:
    fork_plan = read_json(args.fork_plan)
    entry = select_fork_plan_entry(fork_plan, source=args.source, target=args.target)
    packet = create_project_packet(
        entry,
        checkout_analysis=read_optional_json(args.checkout_analysis),
        overlay_plan=read_optional_json(args.overlay_plan),
        render_result=read_optional_json(args.render_result),
        release_profile=read_optional_json(args.release_profile),
        maintainer_preferences=read_optional_json(args.maintainer_preferences),
        suppression_state=read_optional_json(args.suppression_state),
    )
    write_json_file(args.output, packet)
    print(f"wrote project publication packet: {args.output}")
    print(f"status: {packet['status']}")

    if args.markdown_output:
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text(
            project_packet_markdown(packet), encoding="utf-8"
        )
        print(f"wrote project publication markdown: {args.markdown_output}")
    return 0


def command_create_liaison_packet(args: argparse.Namespace) -> int:
    """Compatibility alias for callers of the former command function."""
    return command_create_project_packet(args)


def command_self_test(args: argparse.Namespace) -> int:
    result = run_self_test(
        output_dir=args.output_dir,
        fixtures_root=args.fixtures_root,
        ecosystems=args.ecosystem,
    )
    print(f"self-test {result['status']}: {args.output_dir}")
    print(f"summary: {args.output_dir / 'SELF_TEST_SUMMARY.md'}")
    print(
        f"checks: {result['summary']['passed']} passed, "
        f"{result['summary']['failed']} failed"
    )
    return 0 if result["ok"] else 1


def command_enrich(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    client = GitHubClient.from_environment(token_env=args.token_env)
    result = enrich_catalog(
        catalog,
        client=client,
        limit=args.limit,
        refresh=args.refresh,
    )
    output = args.output or args.catalog
    save_catalog(output, catalog)

    print(
        f"enriched {result.enriched} repositories, "
        f"skipped {result.skipped}, "
        f"failed {result.failed}"
    )
    print(f"catalog: {output}")
    return 0


def command_recon(args: argparse.Namespace) -> int:
    report = inspect_repository(args.path)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"wrote recon report: {args.output}")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def command_plan_overlay(args: argparse.Namespace) -> int:
    with args.recon.open("r", encoding="utf-8") as handle:
        recon_report = json.load(handle)
    overlay = plan_overlay(recon_report, target=args.target)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as handle:
            json.dump(overlay, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"wrote overlay plan: {args.output}")
    else:
        print(json.dumps(overlay, indent=2, sort_keys=True))
    return 0


def command_plan_release(args: argparse.Namespace) -> int:
    with args.recon.open("r", encoding="utf-8") as handle:
        recon_report = json.load(handle)
    profile = plan_release_profile(recon_report)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        json.dump(profile, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"wrote release profile: {args.output}")
    print(f"status: {profile['status']}")
    return 0


def command_render_release_workflow(args: argparse.Namespace) -> int:
    with args.profile.open("r", encoding="utf-8") as handle:
        profile = json.load(handle)
    with args.pins.open("r", encoding="utf-8") as handle:
        pin_payload = json.load(handle)
    result = render_release_workflow(
        profile,
        root=args.path,
        pins=pin_payload,
        execute=args.execute,
        force=args.force,
    )
    mode = "wrote" if args.execute else "planned"
    print(
        f"{mode} release workflow: {len(result.written)} writable, {len(result.skipped)} skipped"
    )
    for item in result.written:
        print(f"  {item['path']}")
    for item in result.skipped:
        print(f"  skipped {item['id']}: {item['reason']}")
    return 0


def command_render_overlay(args: argparse.Namespace) -> int:
    with args.plan.open("r", encoding="utf-8") as handle:
        overlay = json.load(handle)
    pins = {}
    if args.pins:
        with args.pins.open("r", encoding="utf-8") as handle:
            pins = json.load(handle)

    result = render_overlay(
        overlay,
        root=args.path,
        pins=pins,
        execute=args.execute,
        force=args.force,
    )
    mode = "wrote" if args.execute else "planned"
    print(
        f"{mode} overlay: {len(result.written)} writable, {len(result.skipped)} skipped"
    )
    for item in result.written:
        print(f"  {item['path']}")
    for item in result.skipped:
        print(f"  skipped {item['id']}: {item['reason']}")
    return 0


def command_resolve_pins(args: argparse.Namespace) -> int:
    with args.tooling.open("r", encoding="utf-8") as handle:
        tooling_policy = json.load(handle)

    client = GitHubClient.from_environment(token_env=args.token_env)
    lock = resolve_tooling_pins(
        tooling_policy,
        client=client,
        source_policy_sha256=sha256_file(args.tooling),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        json.dump(lock, handle, indent=2, sort_keys=True)
        handle.write("\n")

    print(f"resolved {len(lock['pins'])} action pins")
    print(f"pins: {args.output}")
    return 0


def command_create_evidence(args: argparse.Namespace) -> int:
    manifest = create_evidence_manifest(
        project=args.project,
        target_repo=args.target_repo,
        upstream_ref=args.upstream_ref,
        overlay_ref=args.overlay_ref,
        release_tag=args.release_tag,
        assurance=args.assurance,
        files={
            "artifacts": args.artifact,
            "sboms": args.sbom,
            "attestations": args.attestation,
            "traces": args.trace,
            "reports": args.report,
        },
        root=args.output.parent,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"wrote evidence manifest: {args.output}")
    return 0


def command_create_attestation(args: argparse.Namespace) -> int:
    predicate = {}
    if args.predicate:
        with args.predicate.open("r", encoding="utf-8") as handle:
            predicate = json.load(handle)
    statement = create_intoto_statement(
        subjects=args.subject,
        predicate_type=args.predicate_type,
        predicate=predicate,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        json.dump(statement, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"wrote in-toto statement: {args.output}")
    return 0


def command_verify_evidence(args: argparse.Namespace) -> int:
    with args.manifest.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    result = verify_evidence_manifest(
        manifest,
        base_dir=args.manifest.resolve().parent,
    )
    if result["ok"]:
        print(f"verified evidence manifest: {args.manifest}")
        return 0
    print(f"evidence manifest verification failed: {args.manifest}")
    for failure in result["failures"]:
        print(f"  {failure}")
    return 1


def command_verify_release_attestations(args: argparse.Namespace) -> int:
    result = verify_release_attestations(
        evidence_path=args.evidence,
        policy_path=args.policy,
    )
    write_json_atomic(args.output, result)
    print(f"verified release attestations: {args.evidence}")
    print(f"signer: {result['signer']}@{result['signer_digest']}")
    print(f"output: {args.output.resolve()}")
    return 0


def command_verify_build_attestations(args: argparse.Namespace) -> int:
    result = verify_build_attestations(
        evidence_path=args.evidence,
        policy_path=args.policy,
        trust_policy_path=args.trust_policy,
    )
    write_json_atomic(args.output, result)
    print(f"verified build attestations: {args.evidence}")
    print(f"signer: {result['signer']}@{result['signer_digest']}")
    print(f"status: {result['status']}")
    print(f"output: {args.output.resolve()}")
    return 0


def command_write_verification_guide(args: argparse.Namespace) -> int:
    with args.evidence.open("r", encoding="utf-8") as handle:
        evidence = json.load(handle)
    guide = create_verification_guide(evidence)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(guide, encoding="utf-8")
    print(f"wrote verification guide: {args.output}")
    return 0


def command_compare_evidence(args: argparse.Namespace) -> int:
    with args.left.open("r", encoding="utf-8") as handle:
        left = json.load(handle)
    with args.right.open("r", encoding="utf-8") as handle:
        right = json.load(handle)
    result = compare_evidence_manifests(left, right)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"wrote comparison report: {args.output}")
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


def command_normalize_trace(args: argparse.Namespace) -> int:
    with args.trace.open("r", encoding="utf-8") as handle:
        trace = json.load(handle)
    report = normalize_trace(trace, workspace_root=args.workspace_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"wrote behavior report: {args.output}")
    print(f"digest: {report['digest']}")
    return 0


def command_compare_behavior(args: argparse.Namespace) -> int:
    with args.left.open("r", encoding="utf-8") as handle:
        left = json.load(handle)
    with args.right.open("r", encoding="utf-8") as handle:
        right = json.load(handle)
    result = compare_behavior_reports(left, right)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"wrote behavior comparison: {args.output}")
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


def command_evaluate_release(args: argparse.Namespace) -> int:
    with args.evidence.open("r", encoding="utf-8") as handle:
        evidence = json.load(handle)
    evidence_verification = verify_evidence_manifest(
        evidence,
        base_dir=args.evidence.resolve().parent,
    )
    evidence_comparison = None
    behavior_comparison = None
    attestation_verification = None
    tooling_verification = None
    workflow_risk_verification = None
    if args.verification:
        with args.verification.open("r", encoding="utf-8") as handle:
            evidence_verification = json.load(handle)
    if args.evidence_comparison:
        with args.evidence_comparison.open("r", encoding="utf-8") as handle:
            evidence_comparison = json.load(handle)
    if args.behavior_comparison:
        with args.behavior_comparison.open("r", encoding="utf-8") as handle:
            behavior_comparison = json.load(handle)
    if args.attestation_verification:
        with args.attestation_verification.open("r", encoding="utf-8") as handle:
            attestation_verification = json.load(handle)
    if args.tooling_verification:
        with args.tooling_verification.open("r", encoding="utf-8") as handle:
            tooling_verification = json.load(handle)
    if args.workflow_risk_verification:
        with args.workflow_risk_verification.open("r", encoding="utf-8") as handle:
            workflow_risk_verification = json.load(handle)

    result = evaluate_release(
        evidence=evidence,
        target=args.target,
        evidence_verification=evidence_verification,
        attestation_verification=attestation_verification,
        tooling_verification=tooling_verification,
        workflow_risk_verification=workflow_risk_verification,
        evidence_comparison=evidence_comparison,
        behavior_comparison=behavior_comparison,
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"wrote release evaluation: {args.output}")
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["decision"] == "pass" else 1


def command_plan_forks(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    selection_policy = load_candidate_policy(
        allowlist_path=args.allowlist,
        suppression_path=args.suppression,
    )
    plan = create_fork_plan(
        catalog,
        min_score=args.min_score,
        limit=args.limit,
        selection_policy=selection_policy,
        **fork_target_kwargs(args),
    )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as handle:
            json.dump(plan, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"wrote dry-run fork plan: {args.output}")
    else:
        for entry in plan["forks"]:
            print(
                f"{entry['source_full_name']} -> "
                f"{entry['target_full_name']} "
                f"(score {entry['score']})"
            )
            print(f"  {entry['dry_run_command']}")
    return 0


def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return payload


def read_optional_json(path: Path | None) -> dict | None:
    return read_json(path) if path else None


def write_json_file(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def select_fork_plan_entry(
    fork_plan: dict,
    *,
    source: str | None = None,
    target: str | None = None,
) -> dict:
    forks = fork_plan.get("forks") or []
    if not isinstance(forks, list):
        raise ValueError("Fork plan field 'forks' must be a list")

    matches = []
    for entry in forks:
        if not isinstance(entry, dict):
            continue
        if source and entry.get("source_full_name") != source:
            continue
        if target and entry.get("target_full_name") != target:
            continue
        matches.append(entry)

    if not source and not target and len(matches) != 1:
        raise ValueError(
            "Pass --source or --target when the fork plan does not contain exactly one fork"
        )
    if not matches:
        raise ValueError("No fork plan entry matched the requested source/target")
    if len(matches) > 1:
        raise ValueError(
            "Multiple fork plan entries matched; pass both --source and --target"
        )
    return matches[0]


def project_packet_markdown(packet: dict) -> str:
    lines = [
        "# Assured Downstream Fork Publication",
        "",
        f"Status: `{packet.get('status', 'unknown')}`",
        f"Upstream: `{packet.get('source_full_name', 'unknown')}`",
        f"Downstream: `{packet.get('target_full_name', 'unknown')}`",
        "",
    ]
    for key in ("proposal_summary_markdown", "fetch_instructions_markdown"):
        value = packet.get(key)
        if value:
            lines.extend([str(value).strip(), ""])
    return "\n".join(lines).rstrip() + "\n"


def liaison_packet_markdown(packet: dict) -> str:
    """Compatibility alias for the former Markdown renderer."""
    return project_packet_markdown(packet)


def command_apply_fork_plan(args: argparse.Namespace) -> int:
    with args.plan.open("r", encoding="utf-8") as handle:
        plan = json.load(handle)
    state = StateStore.load(args.state)
    result = apply_fork_plan(
        plan,
        state=state,
        execute=args.execute,
        account_boundary=(load_github_account_boundary() if args.execute else None),
    )
    state.save(args.state)

    mode = "executed" if args.execute else "dry-run"
    print(
        f"{mode} fork plan: "
        f"{result.succeeded} succeeded, "
        f"{result.failed} failed, "
        f"{result.skipped} skipped"
    )
    print(f"state: {args.state}")
    return 1 if result.failed else 0


def command_plan_sync(args: argparse.Namespace) -> int:
    with args.fork_plan.open("r", encoding="utf-8") as handle:
        fork_plan = json.load(handle)
    plan = create_sync_plan(fork_plan, workspace=args.workspace)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as handle:
            json.dump(plan, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"wrote dry-run sync plan: {args.output}")
    else:
        for repo in plan["repositories"]:
            print(f"{repo['target_full_name']} in {repo['local_path']}")
            for command in repo["commands"]:
                print(f"  {command['display']}")
    return 0


def command_apply_sync_plan(args: argparse.Namespace) -> int:
    with args.plan.open("r", encoding="utf-8") as handle:
        plan = json.load(handle)
    state = StateStore.load(args.state)
    result = apply_sync_plan(plan, state=state, execute=args.execute)
    state.save(args.state)
    mode = "executed" if args.execute else "dry-run"
    print(
        f"{mode} sync plan: "
        f"{result.succeeded} succeeded, "
        f"{result.failed} failed, "
        f"{result.review_required} need review"
    )
    print(f"state: {args.state}")
    if result.failed:
        return 1
    return 2 if result.review_required else 0


def top_repositories(catalog: dict, limit: int) -> list[dict]:
    repositories = sorted(
        catalog.get("repositories", []),
        key=lambda repo: (
            -repo.get("score", 0),
            repo["owner"].lower(),
            repo["name"].lower(),
        ),
    )
    return repositories[:limit]


if __name__ == "__main__":
    raise SystemExit(main())
