from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from assured_downstream.agent_registry import (
    default_agent_registry_path,
    load_agent_registry,
    summarize_agent_registry,
)
from assured_downstream.catalog import utc_now
from assured_downstream.evidence import create_evidence_manifest, verify_evidence_manifest
from assured_downstream.policy_eval import evaluate_release
from assured_downstream.recon import inspect_repository
from assured_downstream.release_profile import plan_release_profile
from assured_downstream.release_render import render_release_workflow


DEFAULT_SELF_TEST_ECOSYSTEMS = ["go", "rust", "python", "java", "dotnet"]
FULL_SHA = "0123456789abcdef0123456789abcdef01234567"
SELF_TEST_PINS = {
    "actions/checkout": FULL_SHA,
    "actions/attest": FULL_SHA,
    "actions/upload-artifact": FULL_SHA,
    "anchore/sbom-action": FULL_SHA,
}


def run_self_test(
    *,
    output_dir: Path,
    fixtures_root: Path | None = None,
    ecosystems: list[str] | None = None,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    fixture_root = fixtures_root or default_fixtures_root()
    selected_ecosystems = ecosystems or DEFAULT_SELF_TEST_ECOSYSTEMS

    agent_system_result = run_agent_system_self_test(output_dir)
    ecosystem_results = [
        run_ecosystem_self_test(
            ecosystem=ecosystem,
            fixture_root=fixture_root,
            output_dir=output_dir,
        )
        for ecosystem in selected_ecosystems
    ]
    evidence_result = run_evidence_self_test(output_dir)

    checks = [
        *agent_system_result["checks"],
        *evidence_result["checks"],
        *[
            check
            for ecosystem_result in ecosystem_results
            for check in ecosystem_result["checks"]
        ],
    ]
    result = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": "passed" if all(check["ok"] for check in checks) else "failed",
        "ok": all(check["ok"] for check in checks),
        "fixtures_root": str(fixture_root),
        "agent_system": agent_system_result,
        "ecosystems": ecosystem_results,
        "evidence": evidence_result,
        "summary": {
            "checks": len(checks),
            "passed": sum(1 for check in checks if check["ok"]),
            "failed": sum(1 for check in checks if not check["ok"]),
        },
    }
    write_json(output_dir / "self-test-result.json", result)
    write_self_test_summary(output_dir / "SELF_TEST_SUMMARY.md", result)
    return result


def run_agent_system_self_test(output_dir: Path) -> dict[str, Any]:
    system_dir = output_dir / "agent-system"
    system_dir.mkdir(parents=True, exist_ok=True)
    registry_path = default_agent_registry_path()

    try:
        registry = load_agent_registry(registry_path)
        summary = summarize_agent_registry(registry)
        checks = [
            check("agent registry loads", True),
            check("required agents present", summary["agent_count"] >= summary["required_agent_count"]),
            check("handoff invariants declared", summary["handoff_invariants"] > 0),
            check("mutation-capable agents identifiable", bool(summary["mutation_capable_agents"])),
        ]
    except Exception as exc:  # noqa: BLE001 - self-test records validation failure details.
        registry = {}
        summary = {}
        checks = [check("agent registry loads", False, str(exc))]

    payload = {
        "registry_path": str(registry_path),
        "summary": summary,
        "checks": checks,
    }
    write_json(system_dir / "agent-system.json", payload)
    if registry:
        write_json(system_dir / "agent-registry.snapshot.json", registry)
    return {
        "output_dir": str(system_dir),
        **payload,
    }


def run_ecosystem_self_test(
    *,
    ecosystem: str,
    fixture_root: Path,
    output_dir: Path,
) -> dict[str, Any]:
    fixture = fixture_root / ecosystem
    ecosystem_dir = output_dir / "ecosystems" / ecosystem
    ecosystem_dir.mkdir(parents=True, exist_ok=True)

    if not fixture.exists():
        return {
            "ecosystem": ecosystem,
            "fixture": str(fixture),
            "checks": [check("fixture exists", False, f"missing fixture: {fixture}")],
        }

    recon = inspect_repository(fixture)
    profile = plan_release_profile(recon)
    render_result = render_release_workflow(
        profile,
        root=fixture,
        pins=SELF_TEST_PINS,
        execute=False,
        force=True,
    )

    render_payload = {
        "executed": False,
        "written": render_result.written,
        "skipped": render_result.skipped,
    }
    write_json(ecosystem_dir / "recon.json", recon)
    write_json(ecosystem_dir / "release-profile.json", profile)
    write_json(ecosystem_dir / "release-render-result.json", render_payload)

    workflows = recon.get("ci", {}).get("workflows", [])
    checks = [
        check("fixture exists", True),
        check("workflow parsed structurally", all(workflow.get("parsed") for workflow in workflows)),
        check("artifact candidates detected", bool(recon.get("artifact_candidates"))),
        check("release profile recognized ecosystem", profile["project"]["language_family"] != "unknown"),
        check("release workflow renderable", bool(render_result.written) and not render_result.skipped),
    ]

    return {
        "ecosystem": ecosystem,
        "fixture": str(fixture),
        "output_dir": str(ecosystem_dir),
        "language_family": profile["project"]["language_family"],
        "checks": checks,
        "artifacts": {
            "recon": str(ecosystem_dir / "recon.json"),
            "release_profile": str(ecosystem_dir / "release-profile.json"),
            "release_render_result": str(ecosystem_dir / "release-render-result.json"),
        },
    }

def run_evidence_self_test(output_dir: Path) -> dict[str, Any]:
    evidence_dir = output_dir / "evidence-smoke"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    artifact = evidence_dir / "tool.bin"
    sbom = evidence_dir / "sbom.spdx.json"
    attestation = evidence_dir / "build.intoto.json"
    artifact.write_text("self-test artifact\n", encoding="utf-8")
    sbom.write_text('{"spdxVersion":"SPDX-2.3","name":"self-test"}\n', encoding="utf-8")
    attestation.write_text('{"_type":"https://in-toto.io/Statement/v1"}\n', encoding="utf-8")

    manifest = create_evidence_manifest(
        project="assured-downstream/self-test",
        target_repo="assured-downstream/self-test",
        upstream_ref="self-test-upstream",
        overlay_ref="self-test-overlay",
        release_tag="secure-v0.0.0+self-test",
        assurance="Attested",
        files={
            "artifacts": [artifact],
            "sboms": [sbom],
            "attestations": [attestation],
            "traces": [],
            "reports": [],
        },
    )
    verification = verify_evidence_manifest(manifest)
    evaluation = evaluate_release(
        evidence=manifest,
        target="Attested",
        evidence_verification=verification,
    )

    write_json(evidence_dir / "evidence.json", manifest)
    write_json(evidence_dir / "verification.json", verification)
    write_json(evidence_dir / "release-evaluation.json", evaluation)

    return {
        "output_dir": str(evidence_dir),
        "checks": [
            check("evidence manifest verifies", verification["ok"]),
            check("attested gate passes", evaluation["decision"] == "pass"),
        ],
        "artifacts": {
            "evidence": str(evidence_dir / "evidence.json"),
            "verification": str(evidence_dir / "verification.json"),
            "release_evaluation": str(evidence_dir / "release-evaluation.json"),
        },
    }


def check(name: str, ok: bool, detail: str | None = None) -> dict[str, Any]:
    result = {"name": name, "ok": bool(ok)}
    if detail:
        result["detail"] = detail
    return result


def default_fixtures_root() -> Path:
    return Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "recon"


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_self_test_summary(path: Path, result: dict[str, Any]) -> None:
    lines = [
        "# Assured Downstream Self-Test",
        "",
        f"Status: `{result['status']}`",
        "",
        "## Summary",
        "",
        f"- checks: {result['summary']['checks']}",
        f"- passed: {result['summary']['passed']}",
        f"- failed: {result['summary']['failed']}",
        "",
        "## Agent System",
        "",
    ]
    agent_system = result["agent_system"]
    agent_summary = agent_system.get("summary") or {}
    lines.extend(
        [
            f"- registry: `{agent_system['registry_path']}`",
            f"- agents: {agent_summary.get('agent_count', 0)}",
            f"- handoff invariants: {agent_summary.get('handoff_invariants', 0)}",
        ]
    )
    for item in agent_system["checks"]:
        marker = "pass" if item["ok"] else "fail"
        detail = f" - {item['detail']}" if item.get("detail") else ""
        lines.append(f"- {marker}: {item['name']}{detail}")
    lines.extend(
        [
            "",
            "## Ecosystems",
            "",
        ]
    )
    for ecosystem in result["ecosystems"]:
        lines.append(f"### {ecosystem['ecosystem']}")
        lines.append("")
        lines.append(f"- fixture: `{ecosystem['fixture']}`")
        lines.append(f"- language family: `{ecosystem.get('language_family', 'unknown')}`")
        for item in ecosystem["checks"]:
            marker = "pass" if item["ok"] else "fail"
            detail = f" - {item['detail']}" if item.get("detail") else ""
            lines.append(f"- {marker}: {item['name']}{detail}")
        lines.append("")

    lines.extend(["## Evidence Smoke", ""])
    for item in result["evidence"]["checks"]:
        marker = "pass" if item["ok"] else "fail"
        lines.append(f"- {marker}: {item['name']}")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
