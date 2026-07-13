# Case Study 001: Pilot Cohort

Status: five pilot forks are created, lineage-verified, locally reconciled, and
analyzed through durable agents. The v2 Bandit comparison correctly blocked on
archive and SPDX drift. The repaired v3 lane then produced byte-identical wheel,
canonical sdist, normalized SPDX, and normalized behavior evidence across two
freshly verified GitHub-hosted runs. That result is a same-provider development
candidate, not a production release or independence claim. The additive
`secure/main` patch remains local and unpublished.

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
- published `python-wheel-v2` only after an unprivileged hostile PEP 517 build
  failed to signal the collector, modify its entrypoint, inspect or write its
  evidence, or read its memory
- independently verified the exact v2 manifest's SLSA/in-toto Sigstore
  attestation and retained the canary, raw trace, and verification material as
  a prerelease asset with SHA-256
  `d8ad50210bb741be040a3452a9067266be1fa87ed263b36678cf1221dc7c306a`
- rebuilt the exact Bandit source through `python-wheel-v2`, retained its
  root-owned traces, SPDX document, and three keyless bundles, then had the
  separate Builder Verifier Agent reparse all 36,170 trace records and verify
  the distinct caller and reusable-signer identities
- retained the v2 result as `verified-evidence-candidate`; source ancestry,
  workflow approval, builder or collector resistance, reproducibility, and
  semantic safety remain explicitly unverified
- repeated the immutable Bandit source request in a second GitHub-hosted
  execution and freshly reverified all six retained Sigstore verification paths
  under one bounded two-caller policy
- ran the dedicated Repro Agent over content-addressed snapshots of both
  evidence sets; each parsed manifest was bound to the exact digest returned by
  its fresh Builder Verifier invocation
- confirmed the wheel, source inventory, stable builder projection, raw trace
  summary, SPDX package inventory, and normalized behavior digest match
- classified the sdist failure as payload-equivalent archive metadata drift:
  all 89 members, modes, sizes, and contents match, while gzip and tar member
  mtimes differ
- retained the SPDX mismatch separately: package inventory matches, while the
  sdist binding, creation time, and random document namespace differ
- routed `RebuildMismatch` to the Governor, which emitted `GateBlocked`, kept
  the durable run at `needs_human_review`, and recorded
  `promotion_authorized: false`
- reran the Luna security review after adding exact manifest-to-verifier digest
  binding and the Governor handoff; neither prior blocker remained and no new
  finding was reported
- published the original v2 evidence and durable verifier ledger as a
  development prerelease asset with SHA-256
  `dffa8dd08e6c3084e567c2cd2b33912ebf07941595217b5f58e023a0bbe2bde7`
- extracted that prerelease into a separate directory, reverified both signed
  evidence sets, and reproduced the two-agent `needs_human_review` outcome with
  all stored artifact integrity checks green
- activated `python-wheel-v3` only for the exact Bandit development request,
  with a pinned image, separate handoff, deterministic SPDX normalizer,
  `/build/v2` predicate, and bounded verifier policy
- completed GitHub-hosted runs `29261239215` and `29261279150` from the same
  pinned caller, called workflow, source, builder, handoff, and policy anchors
- freshly verified all six v3 Sigstore bundles, exact in-toto subject paths,
  signed run bindings, canonical archives, normalized SPDX, and all retained
  trace records through the portable v3 verifier
- confirmed exact wheel, canonical sdist, and normalized SPDX bytes; the raw
  sdist payloads were semantically identical before canonicalization
- compared both runs through the durable Repro and Governor v3 agents; exact
  artifacts and normalized behavior passed as same-provider candidates while
  `provider_independent` and `promotion_authorized` remained false
- moved the v3 policy, verifier, archive-validator, and module pins into a
  separate code trust root; the verifier now hashes full source bytes without a
  reciprocal or zeroed policy field
- reran three Luna review rounds to closure; the final focused review reported
  no actionable findings, and the hardened real replay passed all ten Governor
  checks while retaining the installed-control-plane trust assumption
- published a deterministic 163-entry v3 replay archive, verified all 162
  internal checksums after extraction, replayed it from the extracted package,
  and confirmed a fresh GitHub download matched SHA-256
  `dd58793059bded8c8074eb11da14b8fb6a87d0cc7df4fdf5ed6237561c84b356`
- recorded the parser limit explicitly: the retained trace does not independently
  prove the complete build invocation, process lifecycle, or collector resistance

The machine-readable patch evidence is in [`patch-canary.json`](./patch-canary.json).
It deliberately makes no build, runtime, attestation, or hardened-release claim.
The live build result is in
[`bandit-build-canary.json`](./bandit-build-canary.json).
The replacement v2 build result is in
[`bandit-build-canary-v2.json`](./bandit-build-canary-v2.json).
The two-run mismatch and durable Governor decision are in
[`bandit-reproducibility-v2.json`](./bandit-reproducibility-v2.json).
The corrected two-run development candidate is in
[`bandit-reproducibility-v3.json`](./bandit-reproducibility-v3.json).
Its complete evidence, policies, verifier sources, ledger, checksums, and replay
instructions are retained in the
[`case-study-001-bandit-reproducibility-v3`](https://github.com/SauceTaster/assured-downstream/releases/tag/case-study-001-bandit-reproducibility-v3)
development prerelease.
The portable evidence is retained in the
[`case-study-001-bandit-reproducibility-v2`](https://github.com/SauceTaster/assured-downstream/releases/tag/case-study-001-bandit-reproducibility-v2)
development prerelease.
The builder containment result is in
[`python-builder-v2-canary.json`](./python-builder-v2-canary.json).

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

1. Repeat the request on a genuinely independent executor with independent
   source acquisition before making any host-independence claim.
2. Verify exact Git ancestry and signer workflow content through separate code
   before allowing production `Attested` to pass.
3. Build real Java and .NET evidence profiles from the bounded v3 contract.
4. Review the five unapproved Bandit changes separately; no workflow surgery or
   release logic should inherit the additive policy approval.
5. Redesign publication authorization inside the single-account boundary before
   any public `secure/main` mutation.
