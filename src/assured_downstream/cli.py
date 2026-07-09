from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assured_downstream.behavior import compare_behavior_reports, normalize_trace
from assured_downstream.catalog import load_catalog, save_catalog, upsert_findings
from assured_downstream.custody import create_custodian_review
from assured_downstream.enrichment import enrich_catalog
from assured_downstream.evidence import (
    compare_evidence_manifests,
    create_evidence_manifest,
    verify_evidence_manifest,
)
from assured_downstream.fork_apply import apply_fork_plan
from assured_downstream.fork_plan import create_fork_plan
from assured_downstream.github_api import GitHubClient
from assured_downstream.lifecycle import StateStore
from assured_downstream.overlay import plan_overlay
from assured_downstream.overlay_render import render_overlay
from assured_downstream.pin_resolver import resolve_tooling_pins
from assured_downstream.pipeline import run_pilot_pipeline
from assured_downstream.recon import inspect_repository
from assured_downstream.scoring import score_catalog
from assured_downstream.seed import parse_seed_file
from assured_downstream.sync_apply import apply_sync_plan
from assured_downstream.sync_plan import create_sync_plan


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return args.func(args)
    except Exception as exc:  # noqa: BLE001 - CLI should print clean errors.
        print(f"error: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="saucetotal",
        description="SauceTotal assured downstream automation control-plane CLI.",
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
        type=Path,
        help="Path to an awesome list or markdown seed file. May be repeated.",
    )
    ingest.add_argument("--catalog", required=True, type=Path)
    ingest.set_defaults(func=command_ingest)

    pilot = subparsers.add_parser(
        "pilot",
        help="Run an observe-first SauceTotal pilot pipeline from seed files.",
    )
    pilot.add_argument("--seed", action="append", required=True, type=Path)
    pilot.add_argument("--org", required=True)
    pilot.add_argument("--run-dir", required=True, type=Path)
    pilot.add_argument("--limit", type=int, default=None)
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
    custody.set_defaults(func=command_custodian_review)

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
        choices=["Tracked", "Hardened", "Attested", "Reproducible", "Behavior-Reproducible", "Validated"],
        default="Attested",
    )
    create_evidence.add_argument("--artifact", action="append", type=Path, default=[])
    create_evidence.add_argument("--sbom", action="append", type=Path, default=[])
    create_evidence.add_argument("--attestation", action="append", type=Path, default=[])
    create_evidence.add_argument("--trace", action="append", type=Path, default=[])
    create_evidence.add_argument("--report", action="append", type=Path, default=[])
    create_evidence.add_argument("--output", required=True, type=Path)
    create_evidence.set_defaults(func=command_create_evidence)

    verify_evidence = subparsers.add_parser(
        "verify-evidence",
        help="Verify file digests recorded in an evidence manifest.",
    )
    verify_evidence.add_argument("--manifest", required=True, type=Path)
    verify_evidence.set_defaults(func=command_verify_evidence)

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

    plan_forks = subparsers.add_parser(
        "plan-forks",
        help="Create a dry-run fork plan for selected catalog entries.",
    )
    plan_forks.add_argument("--catalog", required=True, type=Path)
    plan_forks.add_argument("--org", required=True)
    plan_forks.add_argument("--min-score", type=int, default=None)
    plan_forks.add_argument("--limit", type=int, default=None)
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
        findings = parse_seed_file(seed_path)
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
        org=args.org,
        run_dir=args.run_dir,
        limit=args.limit,
        enrich=args.enrich,
        resolve_pins=args.resolve_pins,
        tooling_path=args.tooling,
        client=client,
    )
    print(f"pilot run complete: {args.run_dir}")
    print(f"summary: {summary['summary_path']}")
    print(f"candidates: {summary['repositories']}")
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
    packet = create_custodian_review(catalog, min_score=args.min_score)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        json.dump(packet, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"wrote custodian review packet: {args.output}")
    print(f"candidates: {len(packet['candidates'])}")
    return 0


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


def command_render_overlay(args: argparse.Namespace) -> int:
    with args.plan.open("r", encoding="utf-8") as handle:
        overlay = json.load(handle)
    pins = {}
    if args.pins:
        with args.pins.open("r", encoding="utf-8") as handle:
            pin_payload = json.load(handle)
        pins = pin_payload.get("pins", pin_payload)

    result = render_overlay(
        overlay,
        root=args.path,
        pins=pins,
        execute=args.execute,
        force=args.force,
    )
    mode = "wrote" if args.execute else "planned"
    print(
        f"{mode} overlay: "
        f"{len(result.written)} writable, "
        f"{len(result.skipped)} skipped"
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
    lock = resolve_tooling_pins(tooling_policy, client=client)
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
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"wrote evidence manifest: {args.output}")
    return 0


def command_verify_evidence(args: argparse.Namespace) -> int:
    with args.manifest.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    result = verify_evidence_manifest(manifest)
    if result["ok"]:
        print(f"verified evidence manifest: {args.manifest}")
        return 0
    print(f"evidence manifest verification failed: {args.manifest}")
    for failure in result["failures"]:
        print(f"  {failure}")
    return 1


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


def command_plan_forks(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    plan = create_fork_plan(
        catalog,
        org=args.org,
        min_score=args.min_score,
        limit=args.limit,
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


def command_apply_fork_plan(args: argparse.Namespace) -> int:
    with args.plan.open("r", encoding="utf-8") as handle:
        plan = json.load(handle)
    state = StateStore.load(args.state)
    result = apply_fork_plan(plan, state=state, execute=args.execute)
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
        f"{result.failed} failed"
    )
    print(f"state: {args.state}")
    return 1 if result.failed else 0


def top_repositories(catalog: dict, limit: int) -> list[dict]:
    repositories = sorted(
        catalog.get("repositories", []),
        key=lambda repo: (-repo.get("score", 0), repo["owner"].lower(), repo["name"].lower()),
    )
    return repositories[:limit]


if __name__ == "__main__":
    raise SystemExit(main())
