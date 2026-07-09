from __future__ import annotations

from typing import Any

from assured_downstream.catalog import utc_now


ASSURANCE_ORDER = {
    "Hardened": 1,
    "Attested": 2,
    "Reproducible": 3,
    "Behavior-Reproducible": 4,
}


def plan_overlay(recon_report: dict[str, Any], *, target: str = "Hardened") -> dict[str, Any]:
    if target not in ASSURANCE_ORDER:
        raise ValueError(f"Unsupported assurance target: {target}")

    changes = []
    risk_signals = recon_report.get("risk_signals", [])
    ci = recon_report.get("ci") or {}
    controls = recon_report.get("security_controls") or {}
    release_signals = recon_report.get("release_signals") or {}

    if ci.get("provider") != "github-actions":
        changes.append(change(
            "gha-bootstrap",
            "Hardened",
            "add",
            [".github/workflows/saucetotal-ci.yml"],
            "Add a minimal GitHub Actions hardening workflow for projects without existing workflows.",
        ))
    else:
        if any(not workflow.get("has_permissions_block") for workflow in ci.get("workflows", [])):
            changes.append(change(
                "gha-minimal-permissions",
                "Hardened",
                "modify",
                workflow_paths_without_permissions(ci),
                "Set default workflow permissions to read-only and grant write access only in scoped release jobs.",
            ))
        if unpinned_action_risks(risk_signals):
            changes.append(change(
                "gha-pin-actions",
                "Hardened",
                "modify",
                workflow_paths_with_signal(risk_signals, "not pinned"),
                "Replace floating GitHub Action refs with full commit SHA pins from the approved tooling catalog.",
            ))
        if pull_request_target_risks(risk_signals):
            changes.append(change(
                "gha-pr-target-review",
                "Hardened",
                "review",
                workflow_paths_with_signal(risk_signals, "pull_request_target"),
                "Review pull_request_target usage and split untrusted build/test work onto pull_request where possible.",
                human_review_required=True,
            ))

    if not controls.get("has_dependabot"):
        changes.append(change(
            "dependabot-baseline",
            "Hardened",
            "add",
            [".github/dependabot.yml"],
            "Add dependency update monitoring for detected package ecosystems.",
        ))

    changes.append(change(
        "dependency-review",
        "Hardened",
        "add",
        [".github/workflows/saucetotal-dependency-review.yml"],
        "Block risky dependency changes in pull requests where GitHub dependency review supports the ecosystem.",
    ))

    if not controls.get("mentions_scorecard"):
        changes.append(change(
            "scorecard-evidence",
            "Hardened",
            "add",
            [".github/workflows/saucetotal-scorecard.yml"],
            "Generate OpenSSF Scorecard evidence as telemetry, not as a substitute for fixes.",
        ))

    if not controls.get("mentions_harden_runner"):
        changes.append(change(
            "harden-runner-audit",
            "Hardened",
            "modify",
            workflow_paths(ci),
            "Add approved runtime monitoring in audit mode before enforcing egress policy.",
        ))

    if target_at_least(target, "Attested"):
        add_attestation_changes(changes, controls, release_signals)

    if target_at_least(target, "Reproducible"):
        changes.append(change(
            "independent-rebuild",
            "Reproducible",
            "add",
            [".github/workflows/saucetotal-rebuild.yml"],
            "Run an independent rebuild lane and compare artifact, SBOM, and provenance digests.",
        ))

    if target_at_least(target, "Behavior-Reproducible"):
        changes.append(change(
            "behavior-trace",
            "Behavior-Reproducible",
            "add",
            [".github/workflows/saucetotal-trace.yml"],
            "Capture process, file, network, and syscall/security-event evidence for normalized behavior comparison.",
            human_review_required=True,
        ))

    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "target": target,
        "source_recon": {
            "path": recon_report.get("path"),
            "generated_at": recon_report.get("generated_at"),
        },
        "summary": summarize(changes),
        "proposed_changes": changes,
    }


def add_attestation_changes(
    changes: list[dict[str, Any]],
    controls: dict[str, Any],
    release_signals: dict[str, Any],
) -> None:
    if any(release_signals.values()):
        release_paths = [".github/workflows/saucetotal-release.yml"]
    else:
        release_paths = ["release workflow to be discovered or created"]

    if not controls.get("mentions_sbom"):
        changes.append(change(
            "sbom-generation",
            "Attested",
            "add",
            release_paths,
            "Generate SBOMs for release artifacts using approved tooling.",
        ))
    if not controls.get("mentions_slsa"):
        changes.append(change(
            "slsa-provenance",
            "Attested",
            "add",
            release_paths,
            "Generate SLSA provenance for release artifacts where the builder supports it.",
        ))
    if not controls.get("mentions_sigstore"):
        changes.append(change(
            "sigstore-signing",
            "Attested",
            "add",
            release_paths,
            "Sign release artifacts with keyless Sigstore identity when supported.",
        ))
    changes.append(change(
        "in-toto-evidence",
        "Attested",
        "add",
        ["evidence/saucetotal/"],
        "Publish in-toto statements binding source, build, test, package, trace, and release evidence.",
    ))


def summarize(changes: list[dict[str, Any]]) -> dict[str, int]:
    summary = {
        "total": len(changes),
        "human_review_required": 0,
    }
    for item in changes:
        summary[item["stage"]] = summary.get(item["stage"], 0) + 1
        if item.get("human_review_required"):
            summary["human_review_required"] += 1
    return summary


def change(
    identifier: str,
    stage: str,
    action: str,
    paths: list[str],
    rationale: str,
    *,
    human_review_required: bool = False,
) -> dict[str, Any]:
    return {
        "id": identifier,
        "stage": stage,
        "action": action,
        "paths": sorted(set(paths)),
        "rationale": rationale,
        "human_review_required": human_review_required,
    }


def target_at_least(target: str, stage: str) -> bool:
    return ASSURANCE_ORDER[target] >= ASSURANCE_ORDER[stage]


def workflow_paths(ci: dict[str, Any]) -> list[str]:
    paths = [workflow["path"] for workflow in ci.get("workflows", [])]
    return paths or [".github/workflows/"]


def workflow_paths_without_permissions(ci: dict[str, Any]) -> list[str]:
    return [
        workflow["path"]
        for workflow in ci.get("workflows", [])
        if not workflow.get("has_permissions_block")
    ]


def workflow_paths_with_signal(risks: list[dict[str, str]], signal: str) -> list[str]:
    return [
        risk["path"]
        for risk in risks
        if signal in risk.get("signal", "")
    ]


def unpinned_action_risks(risks: list[dict[str, str]]) -> bool:
    return any("not pinned" in risk.get("signal", "") for risk in risks)


def pull_request_target_risks(risks: list[dict[str, str]]) -> bool:
    return any("pull_request_target" in risk.get("signal", "") for risk in risks)

