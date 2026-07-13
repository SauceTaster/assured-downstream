# Case Study 001: Pilot Cohort

Status: five pilot forks created, lineage-verified, locally reconciled, and
analyzed through durable agents. The exact upstream Bandit source now has a
verified build-evidence canary; the separate additive `secure/main` patch
remains local and unpublished.

## Objective

Validate Assured Downstream against real security projects across Go, Rust,
Python, Java, and .NET before enabling autonomous build or repository mutation
agents.

## Cohort

| Upstream | Downstream | Ecosystem | Role | License |
| --- | --- | --- | --- | --- |
| `securego/gosec` | [`SauceTaster/assured-gosec`](https://github.com/SauceTaster/assured-gosec) | Go | Compact release canary | Apache-2.0 |
| `epi052/feroxbuster` | [`SauceTaster/assured-feroxbuster`](https://github.com/SauceTaster/assured-feroxbuster) | Rust | Multi-platform release stress | MIT |
| `PyCQA/bandit` | [`SauceTaster/assured-bandit`](https://github.com/SauceTaster/assured-bandit) | Python | Package publication canary | Apache-2.0 |
| `google/tsunami-security-scanner` | [`SauceTaster/assured-tsunami-security-scanner`](https://github.com/SauceTaster/assured-tsunami-security-scanner) | Java | Mixed-repository Gradle canary | Apache-2.0 |
| `microsoft/DevSkim` | [`SauceTaster/assured-DevSkim`](https://github.com/SauceTaster/assured-DevSkim) | .NET | CLI and extension release canary | MIT |

`dnSpyEx/dnSpy`, `find-sec-bugs/find-sec-bugs`, and
`security-code-scan/security-code-scan` are stewardship challenge cases. They
are intentionally deferred until the first cohort proves Windows isolation,
fork-of-a-fork lineage, and copyleft obligation handling.

## Validation Performed

- ran Source Discovery against `sbilly/awesome-security`
- persisted 188 candidates through the durable intake agents
- honored the Luna `needs_human_review` result when seed metadata was
  insufficient for license and stewardship decisions
- queried current GitHub repository metadata and exact default-branch commits
- replayed the curated nomination seed through all five durable intake agents;
  exactly five projects were selected and `dnSpyEx/dnSpy` was suppressed
- shallow-cloned all five cohort repositories
- performed non-executing structural recon and Attested release planning
- parsed 19 of 19 cohort GitHub Actions workflows successfully
- identified release profiles for Go, Rust, Python, Java, and .NET
- found 11 upstream artifact candidates across the cohort
- created five prefixed public forks under the authenticated `SauceTaster`
  account and verified each direct upstream parent and initial fork commit
- replayed the durable agent lane with a personal target and prefix; all five
  existing forks were lineage-verified and skipped without duplicate mutation
- replayed the durable Fork And Sync -> Recon -> Overlay Planner lane over all
  five forks; three agent handoffs and 21 artifacts re-verified successfully
- reconciled the five managed checkouts repeatedly: all fork default SHAs
  matched upstream, all `secure/<default>` refs were preserved, and no remote
  pushes were executed
- analyzed detached worktrees pinned to each synchronized upstream SHA rather
  than the managed checkout's selected branch
- produced five Attested overlay plans with 46 proposed changes and five draft
  release profiles; one gosec overlay item and every release profile remain
  human-review-required
- resumed the completed managed-checkout run with the same run id and processed
  zero additional work
- resolved all eight approved GitHub Actions to fresh full-SHA pins bound to the
  tooling-policy digest
- policy-approved only three exact additive Bandit templates: dependency
  review, Scorecard telemetry, and the in-toto evidence directory
- created local Bandit commit `a509063a8b80b9c04e6bec990a0108b2f9a0043c`
  directly through Git objects with upstream commit `c45446e...` as its sole
  parent, then advanced `secure/main` by compare-and-swap
- replayed the approval in a fresh durable run and reused the exact commit;
  four patch/publication artifacts re-verified and same-run resume claimed zero
  work
- replayed once more after future-time, pin-freshness, actual tooling-policy
  coverage, and Publisher handoff checks were tightened; the exact commit was
  reused and publication stayed off
- recorded remote publication as not authorized and independently confirmed
  that GitHub has no `secure/main` ref
- built exact upstream Bandit commit `c45446e...` in a digest-pinned,
  no-network Python builder and retained wheel and source-distribution subjects
- captured 36,157 syscall records and 13 signal records across 14 raw trace
  files with zero unparsed records
- generated an SPDX 2.3 SBOM and SLSA provenance, SPDX, and custom build
  Sigstore bundles through separate build, permissionless inspection, and
  source-free attestation jobs
- independently verified all retained bundles against distinct caller and
  reusable-signer commits, exact certificate identity, hosted runner policy,
  artifact subjects, SPDX binding, and pinned Sigstore trust root
- retained the case as `verified-evidence-candidate`; no hardened-release or
  production `Attested` claim was made
- published the original evidence and durable verifier ledger as a development
  prerelease asset with SHA-256
  `b66d6c9712bf7e6d0e9adbf030e60a6b2d3bfc4f1288089a9bc9a517050a7524`

The machine-readable patch evidence is in [`patch-canary.json`](./patch-canary.json).
It deliberately makes no build, runtime, attestation, or hardened-release claim.
The live build result is in
[`bandit-build-canary.json`](./bandit-build-canary.json).

The real checkouts exposed and drove fixes for GitHub Actions YAML parsing, Go
semantic import version names, mixed-language release-profile priority, and
nested .NET project selection.

The initial run confirmed that GitHub metadata enrichment had to become part of
the durable catalog handoff. After adding `agent-run --enrich`, the final run
completed with live metadata, a required Luna review with no findings, all
Governor checks passed, and ten of ten persisted artifacts re-verified.

## Temporary Namespace

The pilot uses the authenticated personal account because organization creation
was not available in the current GitHub session. The `assured-` prefix reserves
a coherent downstream namespace and keeps the repositories easy to identify.
Fork lineage is preserved so transfer into a future organization can be tested
as a separate governed migration.

## Next Run

1. Separate collector-owned evidence from the hostile build UID and add a
   source fixture that actively attempts trace tampering.
2. Verify exact Git ancestry and signer workflow content through independent
   code before allowing production `Attested` to pass.
3. Rebuild the same source on a second independent host and compare artifact
   hashes, SBOMs, and normalized behavior.
4. Review the five unapproved Bandit changes separately; no workflow surgery or
   release logic should inherit the additive policy approval.
5. Redesign publication authorization inside the single-account boundary before
   any public `secure/main` mutation.
