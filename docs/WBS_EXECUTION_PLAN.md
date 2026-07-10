# Assured Downstream WBS Execution Plan

Status: dev/idea-stage execution breakout. This turns the high-level WBS into
agent-sized work packages that can be built in parallel without widening the
MVP beyond a working assured downstream lane.

Synthesized from four read-only Codex worker reviews on 2026-07-09:

- control plane and operations
- recon, overlay, and release rendering
- reproducibility and behavior evidence
- passive fork publication and stewardship

## Implementation Snapshot

As of the 2026-07-09 prototype pass:

- WP0 core is implemented: pilot runs write a run index, selection reasons, and
  allow/suppress policy decisions.
- WP3 is implemented: recon parses GitHub Actions workflows structurally without
  a runtime YAML dependency and has Go/Rust/Python/Java/.NET fixture coverage.
- WP4/WP5 are partially implemented: pin locks carry freshness metadata, stale
  lock entries block rendering, and draft release workflows remain manual-only
  until review fields confirm workflow and artifact paths.
- WP7 is partially implemented: the Attested gate requires local evidence
  verification plus artifact, SBOM, and attestation evidence.
- WP8/WP9 are implemented locally: passive fork publication packets, optional
  fetch instructions, and custodian governance fields exist.
- A local `self-test` command now exercises first-lane fixtures plus Attested
  evidence verification without network access.

Current critical path:

1. Local multi-agent replay from discovery through passive fork publication.
2. WP1 and WP2: repeat-safe default-branch fork/sync against a sandbox org.
3. WP6: workflow-produced evidence bundle, attestation metadata capture, and
   verification guide upload.
4. WP10: full sandbox MVP run.
5. WP11: artifact reproducibility once Attested has a green sandbox run.

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
| Control-Plane Agent | Candidate intake, default-branch fork/sync reconciliation, run management | Repeated sandbox runs are safe and auditable |
| Patch/Release Agent | Structural recon, overlays, release profiles, workflow rendering | Go/Rust/Python/Java/.NET fixtures render pinned draft workflows safely |
| Evidence/Repro Agent | Evidence manifests, verification, artifact comparison, trace normalization | Attested gate passes only after local manifest verification |
| Publication/Stewardship Agent | Fork metadata, evidence links, optional fetch instructions, custodian packets | Each fork explains itself without outbound contact |

## Critical Path

1. Add persistent run index and candidate allow/suppress controls.
2. Reconcile an existing or new fork with org/auth preflight and existing-fork
   detection.
3. Follow the detected upstream `main` or `master` branch without clobbering the
   corresponding `secure/<default>` branch.
4. Replace regex-only workflow recon with structural YAML parsing.
5. Harden approved tooling pin locks with coverage, expiry, and full-SHA
   enforcement.
6. Add release profile confirmation and artifact path confirmation before any
   tag-triggered release.
7. Ensure rendered release workflows upload artifacts, SBOMs, manifests,
   attestations, and verification guides.
8. Make `evaluate-release --target Attested` require verified local evidence and
   recorded attestation evidence.
9. Generate passive fork publication packets and optional fetch instructions.
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

### WP1 - Default-Branch Fork Reconciliation

Owner: Control-Plane Agent.

WBS refs: 1.2.4, 1.2.5, 1.2.6, 1.2.7.

Purpose: create or detect one fork safely against a sandbox org. This is a
repeat-safe reconciliation operation, not a general branch-management service.

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

### WP2 - Default-Branch Sync Reconciliation

Owner: Control-Plane Agent.

WBS refs: 1.3.4, 1.3.5, 1.3.6, 1.3.7.

Purpose: keep the detected upstream default branch, normally `main` or `master`,
and its `secure/<default>` counterpart current without losing conflict evidence.

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
- Upstream default-branch and tag/release detection is recorded.
- Conflicts route to human review with repo, branch, command, and stderr.

Tests:

- temp git repositories with repeated sync runs
- existing-branch safety tests
- conflict packet generation tests

Do not scope creep:

- no auto-conflict resolution
- no merge bot behavior
- no generalized multi-branch synchronization in the MVP

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
- local Sigstore bundle paths emitted by `actions/attest`

Outputs:

- artifacts
- SBOM
- evidence manifest
- in-toto statements
- attestation references
- Markdown verification guide
- uploaded evidence bundle

Acceptance:

- Workflow uploads artifacts, SBOM, manifest, signed in-toto/Sigstore bundles,
  and verification guide.
- Workflow creates SLSA provenance, SBOM, and Assured Downstream policy
  attestations through the pinned `actions/attest` backend.
- Evidence manifest records upstream ref, overlay ref, release tag, artifact
  digests, SBOM digests, and attestation references.
- Verification guide can be generated from downloaded evidence alone.

Tests:

- workflow renderer artifact upload assertions
- evidence manifest completeness tests
- sandbox workflow smoke test after WP5

Do not scope creep:

- no public release asset publishing yet
- no separate signing service beyond the GitHub/Sigstore attestation path

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

### WP8 - Passive Fork Publication Packet

Owner: Fork Publication Agent.

WBS refs: 2.2.5, 5.2.1, 5.2.2, 5.2.3, 5.2.4, 5.2.5.

Purpose: make each downstream fork self-explanatory and independently useful
without contacting upstream maintainers.

Inputs:

- fork plan entry
- checkout analysis outputs
- overlay plan
- render results
- release profile notes

Outputs:

- project publication JSON packet
- Markdown fork landing content
- upstream lineage and proposal summary
- evidence links and optional secure-branch fetch instructions

Acceptance:

- Packet generation is pure local output with no network mutation or outbound
  contact.
- Fetch instructions include concrete `git remote add`, `git fetch`, and local
  review branch commands.
- Proposal summary lists affected paths, rationale, skipped items, and
  human-review-required notes.
- Packet states upstream remains authoritative and GitHub's fork network is the
  discovery mechanism.
- No PR, issue, comment, email, or other outreach draft is produced.

Tests:

- fixture packet tests
- no-outbound-contact tests
- Markdown command rendering tests

Do not scope creep:

- no automatic PR or issue creation
- no maintainer contact or notification service

### WP9 - Custodian Governance Packet

Owner: Publication/Stewardship Agent with Governor/Safety Agent.

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
- passive fork publication packet

Acceptance:

- Ingests one real seed.
- Chooses a small first-lane candidate set.
- Forks or detects forks idempotently.
- Syncs without clobbering secure branches.
- Analyzes Go/Rust/Python/Java/.NET checkouts.
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
- no maintainer outreach

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
| D | WP8 and WP9 | custody, fork publication module, publication tests | WP0 catalog shape |
| E | WP6 and WP7 | evidence, release evaluation, workflow evidence upload | C |
| F | WP1 and WP2 | GitHub client, fork/sync lifecycle, temp git tests | WP0 useful but not blocking |
| G | WP11 | reproducibility renderer and mismatch packets | E |
| H | WP12 | trace collector and behavior mismatch packets | G |

## Next Implementation Tasks

1. Implement WP1 and WP2: sandbox-safe default-branch fork and sync
   reconciliation.
2. Finish WP6: release workflow evidence bundle and attestation metadata
   capture.
3. Finish WP7: add tooling/workflow risk inputs to release gate evaluation.
4. Run WP10: full sandbox MVP over one first-lane seed and fixture-like real
   candidates across the supported language set.
5. Start WP11 only after WP10 produces a green Attested run.

WP12 should still wait until artifact reproducibility is stable.

## Suggested Worker Prompts

Control-Plane Agent:

```text
You are working in Assured Downstream. Implement WP0 from docs/WBS_EXECUTION_PLAN.md:
persistent run index plus candidate allow/suppress controls. Keep mutations
behind existing flags, add focused unittest coverage, and avoid touching release
or fork publication code except for CLI/docs wiring that is required.
```

Patch/Release Agent:

```text
You are working in Assured Downstream. Implement WP3 from docs/WBS_EXECUTION_PLAN.md:
structural GitHub Actions recon and first-lane Go/Rust/Python/Java/.NET
fixtures. Preserve existing recon behavior where practical, add parser tests,
and do not implement workflow editing.
```

Governor/Safety Agent:

```text
You are working in Assured Downstream. Implement WP4 and WP5 from
docs/WBS_EXECUTION_PLAN.md: approved tooling pin lock hardening plus release
profile confirmation gates. Rendering must fail on stale or incomplete pins, and
draft release workflows must remain manual-only until confirmed.
```

Publication/Stewardship Agent:

```text
You are working in Assured Downstream. Implement WP8 and WP9 from
docs/WBS_EXECUTION_PLAN.md: passive fork publication packets, optional fetch
instructions, evidence summaries, and safer custodian governance fields. No
outbound maintainer contact, network mutation, or ownership claims.
```

Evidence/Repro Agent:

```text
You are working in Assured Downstream. After WP4/WP5 land, implement WP6 and WP7
from docs/WBS_EXECUTION_PLAN.md: release workflow evidence upload and Attested
gate enforcement. Attested must require verified local evidence and recorded
attestation evidence.
```
