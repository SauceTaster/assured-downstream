from __future__ import annotations

from typing import Any

from assured_downstream.command_runner import display_command


def create_verification_guide(evidence: dict[str, Any]) -> str:
    project = evidence.get("project") or {}
    target_repo = project.get("target_full_name", "OWNER/REPOSITORY")
    lines = [
        "# Assured Downstream Verification Guide",
        "",
        "Status: dev/idea-stage generated verification guide.",
        "",
        "## Release",
        "",
        f"- source: `{project.get('source_full_name', 'unknown')}`",
        f"- downstream: `{target_repo}`",
        f"- upstream ref: `{project.get('upstream_ref', 'unknown')}`",
        f"- overlay ref: `{project.get('overlay_ref', 'unknown')}`",
        f"- release tag: `{project.get('release_tag', 'unknown')}`",
        f"- assurance: `{project.get('assurance', 'unknown')}`",
        "",
        "## Local Digest Checks",
        "",
        "Run these commands from an environment that has the release files at the recorded paths.",
        "",
        "```bash",
    ]
    for entry in file_entries(evidence):
        lines.append(f"printf '%s  %s\\n' '{entry['sha256']}' '{entry['path']}' | shasum -a 256 -c -")
    if not file_entries(evidence):
        lines.append("# No files were recorded in the evidence manifest.")
    lines.extend(
        [
            "```",
            "",
            "## GitHub Attestation Verification",
            "",
            "These commands assume the release was attested through GitHub artifact attestations.",
            "",
            "```bash",
        ]
    )
    for entry in evidence.get("evidence", {}).get("artifacts", []):
        lines.append(display_command(["gh", "attestation", "verify", entry["path"], "-R", target_repo]))
    if not evidence.get("evidence", {}).get("artifacts"):
        lines.append("# No artifacts were recorded for GitHub attestation verification.")
    lines.extend(
        [
            "```",
            "",
            "## Assured Downstream Manifest Verification",
            "",
            "```bash",
            "assured-downstream verify-evidence --manifest evidence.json",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def file_entries(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    entries = []
    for role_entries in evidence.get("evidence", {}).values():
        entries.extend(role_entries)
    return [
        entry for entry in entries
        if entry.get("path") and entry.get("sha256")
    ]
