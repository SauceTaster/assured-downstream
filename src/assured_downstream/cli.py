from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assured_downstream.catalog import load_catalog, save_catalog, upsert_findings
from assured_downstream.enrichment import enrich_catalog
from assured_downstream.fork_apply import apply_fork_plan
from assured_downstream.fork_plan import create_fork_plan
from assured_downstream.github_api import GitHubClient
from assured_downstream.lifecycle import StateStore
from assured_downstream.overlay import plan_overlay
from assured_downstream.overlay_render import render_overlay
from assured_downstream.pin_resolver import resolve_tooling_pins
from assured_downstream.recon import inspect_repository
from assured_downstream.scoring import score_catalog
from assured_downstream.seed import parse_seed_file
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


def command_score(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    scored = score_catalog(catalog)
    output = args.output or args.catalog
    save_catalog(output, catalog)

    print(f"scored {scored} repositories")
    for repo in top_repositories(catalog, args.limit):
        print(f"{repo['score']:>4}  {repo['owner']}/{repo['name']}")
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


def top_repositories(catalog: dict, limit: int) -> list[dict]:
    repositories = sorted(
        catalog.get("repositories", []),
        key=lambda repo: (-repo.get("score", 0), repo["owner"].lower(), repo["name"].lower()),
    )
    return repositories[:limit]


if __name__ == "__main__":
    raise SystemExit(main())
