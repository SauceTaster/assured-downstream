# Assured Downstream WBS Execution Plan

Status: dev/idea-stage execution breakout. This turns the high-level WBS into
agent-sized work packages that can be built in parallel without widening the
MVP beyond a working assured downstream lane.

Synthesized from four read-only Codex worker reviews on 2026-07-09:

- control plane and operations
- recon, overlay, and release rendering
- reproducibility and behavior evidence
- stewardship and upstream liaison

## Operating Rules

- MVP first: prove one sandbox org can follow upstream, apply security overlay
  work, build an attested release, and publish verifiable evidence.
- Upstream remains authoritative while active; downstream work must be easy for
  maintainers to fetch, inspect, and adopt.
- Mutations stay behind explicit execution flags or reviewed workflow runs.
- Agent output must be both machine-readable JSON and human-readable Markdown.
- Security claims must be backed by evidence. Missing or unverifiable evidence
  blocks promotion.
- Custodian ownership language is forbidden until human governance approves it.
- Behavior-reproducible builds are the north star, not an MVP blocker.

## Agent Lanes

| Lane | Primary scope | First success signal |
| --- | --- | --- |
| Governor/Safety Agent | Policy gates, approved tooling, suppression state, run index | A blocked release or mutation exits nonzero with clear reasons |
| Control-Plane Agent | Candidate intake, fork lifecycle, sync lifecycle, run management | Repeated sandbox runs are idempotent and auditable |
| Patch/Release Agent | Structural recon, overlays, release profiles, workflow rendering | Go/Rust/Python fixtures render pinned draft workflows safely |
| Evidence/Repro Agent | Evidence manifests, verification, artifact comparison, trace normalization | Attested gate passes only after local manifest verification |
| Stewardship/Liaison Agent | Custodian packets, maintainer fetch instructions, proposal summaries | Maintainers get respectful optional adoption packets |

## Critical Path

1. Add persistent run index and candidate allow/suppress controls.
2. Make fork creation idempotent with org/auth preflight and existing-fork
   detection.
3. Make sync execution idempotent without clobbering secure branches.
4. Replace regex-only workflow recon with structural YAML parsing.
5. Harden approved tooling pin locks with coverage, expiry, and full-SHA
   enforcement.
6. Add release profile confirmation and artifact path confirmation before any
   tag-triggered release.
7. Ensure rendered release workflows upload artifacts, SBOMs, manifests,
   attestations, and verification guides.
8. Make `evaluate-release --target Attested` require verified local evidence and
   recorded attestation evidence.
9. Generate maintainer-facing liaison packets and fetch instructions.
10. Run the full sandbox MVP on one Go, one Rust, and one Python candidate.
11. Add artifact reproducibility as the next gate after Attested is real.
12. Add behavior trace collection only after artifact reproducibility is stable.

## Work Packages

### WP0 - Run Index And Selection Controls

Owner: Control-Plane Agent with Governor/Safety Agent.

WBS refs: 1.1.6, 1.1.7, 6.1.3, 6.2.

Purpose: make pilot runs resumable and explain why candidates were or were not
selected.

Inputs:

- seed references
- catalog and score output
- run directory paths
- optional allowlist and suppression files

Outputs:

- `runs/index.json`
- per-candidate selection reasons
- suppressed and allowlisted candidate records

Acceptance:

- Every pilot appends run id, timestamp, seed refs, org, output paths, counts,
  status, and failures.
- Suppressed repos never enter fork plans.
- Allowlisted repos can enter the plan with an explicit reason trail.
- Failed runs are recorded without corrupting prior index entries.

Tests:

- temp-directory pilot run tests
- allowlist and suppression precedence tests
- malformed state recovery tests

Do not scope creep:

- no scheduler
- no dashboard
- no live GitHub mutation in this package

### WP1 - Fork Lifecycle Idempotence

Owner: Control-Plane Agent.

WBS refs: 1.2.4, 1.2.5, 1.2.6, 1.2.7.

Purpose: make fork creation safe to re-run against a sandbox org.

Inputs:

- fork plan
- lifecycle state file
- GitHub org and token

Outputs:

- preflight report
- lifecycle state transitions
- existing-fork detection records

Acceptance:

- Missing auth or org access fails before mutation.
- Existing forks record `ForkExists` instead of failing.
- `--execute` is still required for mutation.
- Dry runs never call mutating GitHub APIs.
- Sandbox smoke path proves one fork can be created or detected repeatedly.

Tests:

- fake GitHub client unit tests
- dry-run mutation guard tests
- sandbox smoke test gated by environment variables

Do not scope creep:

- no org-wide branch protection rollout until sandbox fork lifecycle works
- no production org execution path

### WP2 - Sync Lifecycle Idempotence

Owner: Control-Plane Agent.

WBS refs: 1.3.4, 1.3.5, 1.3.6, 1.3.7.

Purpose: keep downstream forks tracking upstream without overwriting security
branches or losing conflict evidence.

Inputs:

- sync plan
- fork lifecycle state
- local workspace root
- upstream and downstream remotes

Outputs:

- idempotent sync command plan
- sync state transitions
- conflict review packet on failure

Acceptance:

- Existing checkouts fetch and update remotes cleanly.
- Secure overlay branches are never force-reset or recreated.
- Upstream tag/release detection is recorded.
- Conflicts route to human review with repo, branch, command, and stderr.

Tests:

- temp git repositories with repeated sync runs
- existing-branch safety tests
- conflict packet generation tests

Do not scope creep:

- no auto-conflict resolution
- no merge bot behavior

### WP3 - Structural Recon And Fixtures

Owner: Patch/Release Agent.

WBS refs: 2.1.5, 2.1.6, 2.1.7.

Purpose: replace fragile workflow detection with structured GitHub Actions
analysis.

Inputs:

- local checkout
- `.github/workflows/*.yml`
- package manager files

Outputs:

- structural recon JSON for workflows, permissions, jobs, steps, actions,
  artifact paths, release triggers, and workflow risks
- Go, Rust, and Python fixture coverage

Acceptance:

- One Go, one Rust, and one Python fixture produces accurate recon.
- Existing regex-derived signals are preserved or intentionally replaced.
- Workflow `uses` entries and release triggers are represented structurally.
- Artifact candidates are surfaced for release profile review.

Tests:

- workflow parser unit tests
- fixture-based recon tests
- malformed YAML handling tests

Do not scope creep:

- no structural editing of existing upstream workflows yet
- no broad package manager support beyond first-lane fixtures

### WP4 - Approved Tooling Pin Hardening

Owner: Governor/Safety Agent with Patch/Release Agent.

WBS refs: 3.1.3, 3.1.4, 3.1.5, 6.2.4.

Purpose: make generated workflows depend only on approved, pinned tooling.

Inputs:

- `policies/approved-tooling.json`
- resolved pin lockfile
- generated workflow action requirements

Outputs:

- enriched pin lock entries with coverage, resolved ref, timestamp, and expiry
- block decisions for stale, missing, or incomplete pins

Acceptance:

- Every generated workflow action is pinned to a full 40-character SHA.
- Rendering fails on missing, stale, failed, or incomplete pin records.
- Lockfile includes enough metadata to audit when and why a pin was used.

Tests:

- stale lockfile tests
- missing-action coverage tests
- renderer full-SHA enforcement tests

Do not scope creep:

- no private mirror of tooling yet
- no binary reproducibility for tools yet

### WP5 - Release Profile Confirmation Gate

Owner: Patch/Release Agent.

WBS refs: 3.2.5, 3.2.6, 3.2.7.

Purpose: prevent draft release workflows from accidentally publishing or
tag-triggering before a human confirms the build shape.

Inputs:

- recon output
- release profile
- artifact candidate paths

Outputs:

- release profile fields for review status, artifact path confirmation, and
  unresolved notes
- draft workflow mode until confirmed

Acceptance:

- Draft profiles render manual-only workflows.
- Tag triggers are emitted only after explicit confirmation.
- Artifact paths must be confirmed before Attested release promotion.
- Review notes survive render and appear in summaries.

Tests:

- release profile serialization tests
- manual-only draft renderer tests
- confirmed tag-trigger renderer tests

Do not scope creep:

- no GitHub release publishing in this package
- no container release path

### WP6 - Attested Workflow Evidence Production

Owner: Patch/Release Agent with Evidence/Repro Agent.

WBS refs: 3.3.2, 3.3.3, 3.3.4, 3.3.5, 3.4.6, 3.4.7.

Purpose: make the rendered release workflow produce the evidence needed to
verify the claim it is making.

Inputs:

- confirmed release profile
- approved pins
- build outputs
- SBOM output
- GitHub attestation metadata

Outputs:

- artifacts
- SBOM
- evidence manifest
- in-toto statements
- attestation references
- Markdown verification guide
- uploaded evidence bundle

Acceptance:

- Workflow uploads artifacts, SBOM, manifest, attestations, and verification
  guide.
- Evidence manifest records upstream ref, overlay ref, release tag, artifact
  digests, SBOM digests, and attestation references.
- Verification guide can be generated from downloaded evidence alone.

Tests:

- workflow renderer artifact upload assertions
- evidence manifest completeness tests
- sandbox workflow smoke test after WP5

Do not scope creep:

- no public release asset publishing yet
- no release signing UX beyond existing attestation path

### WP7 - Attested Gate Enforcement

Owner: Governor/Safety Agent with Evidence/Repro Agent.

WBS refs: 3.4.2, 3.4.5, 6.2.1, 6.2.4, 6.2.5.

Purpose: make `Attested` mean something enforceable.

Inputs:

- evidence manifest
- verification result
- tooling policy result
- workflow risk result

Outputs:

- release evaluation JSON
- block decision with reasons

Acceptance:

- `evaluate-release --target Attested` passes only after local manifest
  verification succeeds.
- Required artifact, SBOM, and attestation evidence must be present.
- Unapproved tooling and unsafe workflow signals block promotion.
- CLI exits nonzero on block decisions.

Tests:

- missing evidence tests
- digest mismatch tests
- missing attestation tests
- unsafe workflow risk tests
- CLI nonzero exit tests

Do not scope creep:

- no Reproducible target changes until Attested is enforced
- no external transparency log policy yet

### WP8 - Maintainer Liaison Packet

Owner: Stewardship/Liaison Agent.

WBS refs: 2.2.5, 5.2.1, 5.2.2, 5.2.3, 5.2.4, 5.2.5.

Purpose: make downstream work easy and respectful for upstream maintainers to
fetch, inspect, and adopt.

Inputs:

- fork plan entry
- checkout analysis outputs
- overlay plan
- render results
- release profile notes
- maintainer preference or suppression state

Outputs:

- liaison JSON packet
- Markdown maintainer fetch instructions
- proposal summary
- respectful PR description draft

Acceptance:

- Packet generation is pure local output with no network mutation.
- Fetch instructions include concrete `git remote add`, `git fetch`, and local
  review branch commands.
- Proposal summary lists affected paths, rationale, skipped items, and
  human-review-required notes.
- PR draft states upstream remains authoritative.
- Suppressed repos do not get outreach drafts.

Tests:

- fixture packet tests
- suppression/preference tests
- Markdown command rendering tests

Do not scope creep:

- no automatic PR creation
- no repeated outreach automation

### WP9 - Custodian Governance Packet

Owner: Stewardship/Liaison Agent with Governor/Safety Agent.

WBS refs: 5.1.4, 5.1.5, 5.1.6.

Purpose: keep eventual custodian mode possible without implying ownership too
early.

Inputs:

- custodian review packet
- repo activity evidence
- license evidence
- maintainer contact evidence

Outputs:

- expanded custodian packet with contact tracking, naming/trademark checklist,
  and human approval gate

Acceptance:

- Packet includes `maintainer_contact`.
- Packet includes `naming_trademark_review`.
- Packet includes `custodian_claim_gate.status = human-approval-required`.
- No generated text implies official upstream ownership or endorsement.

Tests:

- custody packet field tests
- stale and archived repo tests
- wording guard tests for ownership language

Do not scope creep:

- no public custody claims
- no project transfer automation

### WP10 - Sandbox MVP Run

Owner: all lanes, coordinated by Control-Plane Agent.

WBS refs: MVP Definition Of Done.

Purpose: prove the whole MVP on a sandbox org before broad automation.

Inputs:

- one real awesome-list seed
- sandbox GitHub org
- one Go, one Rust, and one Python candidate
- approved tooling lockfile

Outputs:

- run index
- fork and sync states
- checkout analysis bundles
- rendered overlays and draft release workflows
- at least one completed attested release evidence bundle
- release evaluation
- liaison packet

Acceptance:

- Ingests one real seed.
- Chooses a small first-lane candidate set.
- Forks or detects forks idempotently.
- Syncs without clobbering secure branches.
- Analyzes Go/Rust/Python checkouts.
- Renders pinned hardened CI and draft attested-release workflows.
- Runs at least one attested release workflow successfully.
- Collects evidence manifests and verification guides.
- Evaluates the `Attested` gate.
- Leaves every mutation behind an explicit execution flag or reviewed workflow.

Tests:

- normal unit suite
- sandbox org smoke run gated by environment variables
- artifact download plus `verify-evidence` plus `evaluate-release`

Do not scope creep:

- no production org rollout
- no maintainer outreach by default

### WP11 - Artifact Reproducibility Stage 1

Owner: Evidence/Repro Agent.

WBS refs: 4.1.4, 4.1.5, 4.1.6, 6.2.2.

Purpose: add reproducible artifact claims after the Attested path is real.

Inputs:

- release profile build commands
- two rebuild host results
- evidence manifests

Outputs:

- host A evidence manifest
- host B evidence manifest
- comparison report
- mismatch review packet
- `Reproducible` release evaluation

Acceptance:

- Reproducible sandbox run produces two manifests.
- Artifact and SBOM roles are compared deterministically.
- Mismatches block promotion and create a concise review packet.
- `evaluate-release --target Reproducible` passes only on matching evidence.

Tests:

- matching and mismatching manifest tests
- deterministic report ordering tests
- renderer tests for two rebuild lanes
- CLI integration test with temp evidence files

Do not scope creep:

- no behavior trace gate yet
- no claim that GitHub-hosted runners are truly independent hosts

### WP12 - Behavior Reproducibility Stage 1

Owner: Evidence/Repro Agent with Governor/Safety Agent.

WBS refs: 4.2.3, 4.2.4, 4.2.5, 4.2.6, 6.2.3.

Purpose: begin syscall and runtime behavior evidence without blocking the MVP.

Inputs:

- raw build traces
- workspace root
- divergence allowlist
- normalized behavior reports

Outputs:

- normalized trace reports
- behavior comparison report
- behavior mismatch review packet
- `Behavior-Reproducible` release evaluation

Acceptance:

- One Linux-only trace collector path exists for build commands.
- Workspace and temp paths normalize deterministically.
- Allowed divergence rules are explicit and reviewed.
- Non-allowed process, file, network, or syscall/security deltas block the
  behavior gate.

Tests:

- path normalization tests
- allowed divergence tests
- syscall/network delta tests
- mismatch packet tests

Do not scope creep:

- no universal collector support
- no validated pentest claim
- no behavior gate before artifact reproducibility is stable

## Immediate Parallel Build Split

These are safe to run as separate Codex implementation agents because their
primary files should overlap only at CLI registration and docs.

| Agent | Package | Primary files | Depends on |
| --- | --- | --- | --- |
| A | WP0 | pipeline/run index, catalog selection, tests | none |
| B | WP3 | recon parser, fixtures, recon tests | none |
| C | WP4 and WP5 | pin locks, release profile, release renderer tests | B for best artifact hints, but can start now |
| D | WP8 and WP9 | custody, liaison module, liaison tests | WP0 suppression shape |
| E | WP6 and WP7 | evidence, release evaluation, workflow evidence upload | C |
| F | WP1 and WP2 | GitHub client, fork/sync lifecycle, temp git tests | WP0 useful but not blocking |
| G | WP11 | reproducibility renderer and mismatch packets | E |
| H | WP12 | trace collector and behavior mismatch packets | G |

## Next Five Implementation Tasks

1. Implement WP0: run index plus allow/suppress controls.
2. Implement WP3: structural workflow recon with Go/Rust/Python fixtures.
3. Implement WP4 and WP5: pin lock hardening plus release confirmation gate.
4. Implement WP8 and WP9: maintainer liaison and safe custodian governance
   packets.
5. Implement WP1 and WP2: sandbox-safe fork and sync idempotence.

After those land, run WP6/WP7 to make the Attested lane real, then execute WP10
against the sandbox org. WP11 and WP12 should wait until the Attested path has a
green sandbox run.

## Suggested Worker Prompts

Control-Plane Agent:

```text
You are working in Assured Downstream. Implement WP0 from docs/WBS_EXECUTION_PLAN.md:
persistent run index plus candidate allow/suppress controls. Keep mutations
behind existing flags, add focused unittest coverage, and avoid touching release
or liaison code except for CLI/docs wiring that is required.
```

Patch/Release Agent:

```text
You are working in Assured Downstream. Implement WP3 from docs/WBS_EXECUTION_PLAN.md:
structural GitHub Actions recon and first-lane Go/Rust/Python fixtures. Preserve
existing recon behavior where practical, add parser tests, and do not implement
workflow editing.
```

Governor/Safety Agent:

```text
You are working in Assured Downstream. Implement WP4 and WP5 from
docs/WBS_EXECUTION_PLAN.md: approved tooling pin lock hardening plus release
profile confirmation gates. Rendering must fail on stale or incomplete pins, and
draft release workflows must remain manual-only until confirmed.
```

Stewardship/Liaison Agent:

```text
You are working in Assured Downstream. Implement WP8 and WP9 from
docs/WBS_EXECUTION_PLAN.md: local maintainer liaison packets, fetch instructions,
proposal summaries, and safer custodian governance fields. No network mutation,
no automatic PR creation, and no ownership claims.
```

Evidence/Repro Agent:

```text
You are working in Assured Downstream. After WP4/WP5 land, implement WP6 and WP7
from docs/WBS_EXECUTION_PLAN.md: release workflow evidence upload and Attested
gate enforcement. Attested must require verified local evidence and recorded
attestation evidence.
```
