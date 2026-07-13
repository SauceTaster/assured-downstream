from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

from assured_downstream.agent_registry import (
    default_agent_registry_path,
    load_agent_registry,
    summarize_agent_registry,
)
from assured_downstream.catalog import utc_now
from assured_downstream.ecosystem_profile import plan_ecosystem_build_profile
from assured_downstream.evidence import (
    create_evidence_manifest,
    verify_evidence_manifest,
)
from assured_downstream.evidence_agents import run_release_evidence_agent_system
from assured_downstream.intake_agents import run_intake_agent_system
from assured_downstream.policy_eval import evaluate_release_candidate
from assured_downstream.recon import inspect_repository
from assured_downstream.release_profile import plan_release_profile
from assured_downstream.release_render import render_release_workflow


DEFAULT_SELF_TEST_ECOSYSTEMS = ["go", "rust", "python", "java", "dotnet"]
FULL_SHA = "0123456789abcdef0123456789abcdef01234567"
SELF_TEST_PINS = {
    "actions/checkout": FULL_SHA,
    "actions/attest": FULL_SHA,
    "actions/download-artifact": FULL_SHA,
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
    evidence_agent_result = run_evidence_agent_self_test(output_dir)

    checks = [
        *agent_system_result["checks"],
        *evidence_result["checks"],
        *evidence_agent_result["checks"],
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
        "evidence_agents": evidence_agent_result,
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
            check(
                "required agents present",
                summary["agent_count"] >= summary["required_agent_count"],
            ),
            check("handoff invariants declared", summary["handoff_invariants"] > 0),
            check(
                "mutation-capable agents identifiable",
                bool(summary["mutation_capable_agents"]),
            ),
        ]
    except Exception as exc:  # noqa: BLE001 - self-test records validation failure details.
        registry = {}
        summary = {}
        checks = [check("agent registry loads", False, str(exc))]

    replay = run_agent_replay_self_test(system_dir)
    checks.extend(replay["checks"])
    payload = {
        "registry_path": str(registry_path),
        "summary": summary,
        "replay": replay,
        "checks": checks,
    }
    write_json(system_dir / "agent-system.json", payload)
    if registry:
        write_json(system_dir / "agent-registry.snapshot.json", registry)
    return {
        "output_dir": str(system_dir),
        **payload,
    }


def run_agent_replay_self_test(system_dir: Path) -> dict[str, Any]:
    replay_dir = system_dir / "replay"
    seed_path = system_dir / "self-test-seed.md"
    seed_path.write_text(
        "- [cosign](https://github.com/sigstore/cosign) - signing security tooling\n",
        encoding="utf-8",
    )
    try:
        result = run_intake_agent_system(
            seed_sources=[seed_path],
            org="assured-self-test",
            run_dir=replay_dir,
            run_id="self-test-agent-replay",
            limit=1,
            codex_mode="off",
        )
        expected_events = [
            "DiscoveryRequested",
            "SeedBatchReady",
            "CatalogUpdated",
            "CandidateSelected",
            "GatePassed:CandidateSelected",
            "ForkPlanReady",
        ]
        checks = [
            check("agent replay succeeds", result["status"] == "succeeded"),
            check("agent replay drains all work", result["pending_count"] == 0),
            check(
                "agent replay artifacts verify", result["artifact_verification"]["ok"]
            ),
            check(
                "agent replay records five handoffs",
                result["summary"]["handoff_count"] == 5,
            ),
            check(
                "agent replay follows typed event chain",
                result["summary"]["event_types"] == expected_events,
            ),
            check(
                "agent replay creates fork plan",
                (replay_dir / "fork-plan.json").exists(),
            ),
        ]
        return {
            "run_id": result["run_id"],
            "database_path": result["database_path"],
            "summary_path": result["summary_path"],
            "checks": checks,
        }
    except Exception as exc:  # noqa: BLE001 - self-test records the failure.
        return {
            "run_id": "self-test-agent-replay",
            "checks": [check("agent replay succeeds", False, str(exc))],
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
    ecosystem_profile = None
    if ecosystem in {"java", "dotnet"}:
        ecosystem_profile = plan_ecosystem_build_profile(
            root=fixture,
            source_repository=f"assured-self-test/{ecosystem}",
            source_commit=FULL_SHA,
        )
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
    if ecosystem_profile is not None:
        write_json(
            ecosystem_dir / "ecosystem-build-profile.json",
            ecosystem_profile,
        )
    write_json(ecosystem_dir / "release-render-result.json", render_payload)

    workflows = recon.get("ci", {}).get("workflows", [])
    checks = [
        check("fixture exists", True),
        check(
            "workflow parsed structurally",
            all(workflow.get("parsed") for workflow in workflows),
        ),
        check("artifact candidates detected", bool(recon.get("artifact_candidates"))),
        check(
            "release profile recognized ecosystem",
            profile["project"]["language_family"] != "unknown",
        ),
        check(
            "release workflow renderable",
            bool(render_result.written) and not render_result.skipped,
        ),
    ]
    if ecosystem_profile is not None:
        checks.extend(
            [
                check(
                    "ecosystem build profile is recognized",
                    ecosystem_profile["profile_id"] is not None,
                ),
                check(
                    "development build profile fails closed",
                    ecosystem_profile["status"] == "blocked"
                    and not ecosystem_profile["execution_permitted"],
                ),
                check(
                    "isolated build plan requires no network and no shell",
                    ecosystem_profile["build_plan"]["network"] == "none"
                    and not ecosystem_profile["build_plan"]["shell"],
                ),
            ]
        )

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
            "ecosystem_build_profile": (
                str(ecosystem_dir / "ecosystem-build-profile.json")
                if ecosystem_profile is not None
                else None
            ),
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
    attestation.write_text(
        '{"_type":"https://in-toto.io/Statement/v1"}\n', encoding="utf-8"
    )

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
    evaluation = evaluate_release_candidate(
        evidence=manifest,
        target="Attested",
        evidence_verification=verification,
        attestation_verification={
            "ok": True,
            "verification_type": "sigstore-bundle",
            "issuer": "https://token.actions.githubusercontent.com",
            "signer": "self-test-fixture",
            "verified_subjects": [
                {"sha256": manifest["evidence"]["artifacts"][0]["sha256"]}
            ],
        },
        tooling_verification={
            "ok": True,
            "policy_sha256": "1" * 64,
            "lock_sha256": "2" * 64,
        },
        workflow_risk_verification={
            "ok": True,
            "analyzed_workflow_sha256": "3" * 64,
            "findings": [],
        },
    )

    write_json(evidence_dir / "evidence.json", manifest)
    write_json(evidence_dir / "verification.json", verification)
    write_json(evidence_dir / "release-evaluation.json", evaluation)

    return {
        "output_dir": str(evidence_dir),
        "checks": [
            check("evidence manifest verifies", verification["ok"]),
            check(
                "evidence candidate input shape is complete",
                evaluation["decision"] == "candidate",
            ),
        ],
        "artifacts": {
            "evidence": str(evidence_dir / "evidence.json"),
            "verification": str(evidence_dir / "verification.json"),
            "release_evaluation": str(evidence_dir / "release-evaluation.json"),
        },
    }


def run_evidence_agent_self_test(output_dir: Path) -> dict[str, Any]:
    root = output_dir / "evidence-agent-replay"
    source = root / "source"
    evidence_root = source / "evidence"
    for directory in ("dist", "sbom", "attestations", "traces", "reports"):
        (evidence_root / directory).mkdir(parents=True, exist_ok=True)
    artifact = evidence_root / "dist" / "fixture.bin"
    artifact.write_bytes(b"durable evidence fixture\n")
    (evidence_root / "sbom" / "fixture.spdx.json").write_text(
        '{"spdxVersion":"SPDX-2.3","name":"durable-fixture"}\n',
        encoding="utf-8",
    )
    for name in (
        "provenance.sigstore.json",
        "sbom.sigstore.json",
        "policy.sigstore.json",
    ):
        (evidence_root / "attestations" / name).write_text(
            '{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3"}\n',
            encoding="utf-8",
        )
    write_json(
        evidence_root / "traces" / "fixture-trace.json",
        {
            "schema_version": 1,
            "collector": {
                "name": "self-test-fixture",
                "version": "1",
                "platform": "linux",
            },
            "coverage": {
                "process": True,
                "file": True,
                "network": True,
                "syscall": True,
            },
            "events": [
                {
                    "kind": "process",
                    "parent_exe": "/usr/bin/env",
                    "exe": "/workspace/python",
                    "argv": ["python", "-m", "build"],
                },
                {
                    "kind": "file",
                    "operation": "write",
                    "path": "/workspace/dist/fixture.bin",
                },
                {
                    "kind": "network",
                    "host": "pypi.org",
                    "port": 443,
                    "outcome": "denied",
                },
                {
                    "kind": "syscall",
                    "name": "mount",
                    "outcome": "denied",
                },
            ],
        },
    )
    write_json(evidence_root / "reports" / "builder.json", {"fixture": True})
    build_result = source / "build-result.json"
    write_json(
        build_result,
        {
            "schema_version": 1,
            "status": "succeeded",
            "project": {
                "source_full_name": "assured-downstream/self-test",
                "target_full_name": "assured-downstream/self-test",
                "upstream_ref": "a" * 40,
                "overlay_ref": "b" * 40,
                "release_tag": "secure-v0.0.0+self-test",
            },
            "builder": {
                "mode": "test-fixture",
                "builder_id": "self-test-fixture-v1",
                "isolated": True,
                "secrets_exposed": False,
                "network_policy": "deny",
                "workspace_root": "/workspace",
            },
            "evidence": {
                "artifacts": ["dist/fixture.bin"],
                "sboms": ["sbom/fixture.spdx.json"],
                "attestations": [
                    "attestations/provenance.sigstore.json",
                    "attestations/sbom.sigstore.json",
                    "attestations/policy.sigstore.json",
                ],
                "raw_traces": ["traces/fixture-trace.json"],
                "reports": ["reports/builder.json"],
            },
        },
    )
    controls = source / "controls"
    write_json(
        controls / "release-verification-policy.json",
        {
            "schema_version": 1,
            "status": "self-test-fixture-only",
        },
    )
    write_json(
        controls / "tooling-verification.json",
        {
            "ok": True,
            "policy_sha256": "1" * 64,
            "lock_sha256": "2" * 64,
        },
    )
    write_json(
        controls / "workflow-risk-verification.json",
        {
            "ok": True,
            "analyzed_workflow_sha256": "3" * 64,
            "findings": [],
        },
    )
    run_dir = root / "run"
    try:
        with patch(
            "assured_downstream.evidence_agents.verify_release_attestations",
            side_effect=selftest_release_verifier,
        ):
            result = run_release_evidence_agent_system(
                build_result_path=build_result,
                evidence_root=evidence_root,
                release_verification_policy_path=(
                    controls / "release-verification-policy.json"
                ),
                tooling_verification_path=controls / "tooling-verification.json",
                workflow_risk_verification_path=(
                    controls / "workflow-risk-verification.json"
                ),
                run_dir=run_dir,
                run_id="self-test-evidence-agents",
                allow_test_fixture=True,
            )
        evaluation = json.loads(
            (run_dir / "release-evaluation.json").read_text(encoding="utf-8")
        )
        checks = [
            check("evidence agent replay succeeds", result["status"] == "succeeded"),
            check(
                "evidence agent replay drains all work", result["pending_count"] == 0
            ),
            check(
                "evidence agent artifacts verify", result["artifact_verification"]["ok"]
            ),
            check(
                "evidence agent replay records five handoffs",
                result["summary"]["handoff_count"] == 5,
            ),
            check(
                "evidence Governor emits a non-authoritative candidate",
                evaluation["decision"] == "candidate",
            ),
        ]
        return {
            "output_dir": str(run_dir),
            "run_id": result["run_id"],
            "checks": checks,
            "artifacts": {
                "evidence": str(run_dir / "evidence.json"),
                "verification_guide": str(run_dir / "VERIFY.md"),
                "release_evaluation": str(run_dir / "release-evaluation.json"),
            },
        }
    except Exception as exc:  # noqa: BLE001 - self-test records validation failure.
        return {
            "output_dir": str(run_dir),
            "run_id": "self-test-evidence-agents",
            "checks": [check("evidence agent replay succeeds", False, str(exc))],
        }


def selftest_release_verifier(*, evidence_path: Path, policy_path: Path) -> dict:
    del policy_path
    manifest = json.loads(evidence_path.read_text(encoding="utf-8"))
    project = manifest["project"]
    return {
        "schema_version": 1,
        "status": "verified",
        "ok": True,
        "authority": "test-fixture-non-authoritative",
        "verification_type": "sigstore-bundle",
        "issuer": "https://token.actions.githubusercontent.com",
        "signer": (
            f"{project['target_full_name']}/.github/workflows/"
            "assured-downstream-attested-release.yml"
        ),
        "verified_subjects": [
            {"sha256": entry["sha256"]} for entry in manifest["evidence"]["artifacts"]
        ],
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
        lines.append(
            f"- language family: `{ecosystem.get('language_family', 'unknown')}`"
        )
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
    lines.extend(["## Durable Evidence Agents", ""])
    for item in result["evidence_agents"]["checks"]:
        marker = "pass" if item["ok"] else "fail"
        detail = f" - {item['detail']}" if item.get("detail") else ""
        lines.append(f"- {marker}: {item['name']}{detail}")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
