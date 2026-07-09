from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assured_downstream.catalog import load_catalog, save_catalog, upsert_findings
from assured_downstream.fork_plan import create_fork_plan
from assured_downstream.scoring import score_catalog
from assured_downstream.seed import parse_seed_file


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


def top_repositories(catalog: dict, limit: int) -> list[dict]:
    repositories = sorted(
        catalog.get("repositories", []),
        key=lambda repo: (-repo.get("score", 0), repo["owner"].lower(), repo["name"].lower()),
    )
    return repositories[:limit]


if __name__ == "__main__":
    raise SystemExit(main())
