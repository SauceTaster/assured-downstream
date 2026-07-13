# Assured Downstream WBS Execution Plan

Status: dev/idea-stage execution breakout. This turns the high-level WBS into
agent-sized work packages that can be built in parallel without widening the
MVP beyond a working assured downstream lane.

Synthesized from four read-only Codex worker reviews on 2026-07-09 and updated
through the Java/.NET ecosystem-profile threat reviews on 2026-07-13:

- control plane and operations
- recon, overlay, and release rendering
- reproducibility and behavior evidence
- passive fork publication and stewardship

## Implementation Snapshot

As of the 2026-07-13 prototype pass:

- WP0 core is implemented: pilot runs write a run index, selection reasons, and
  allow/suppress policy decisions.
- WP1 is live in a temporary prefixed personal namespace: five forks were
  created, direct-parent verified, and then detected repeat-safely.
- WP2 is implemented locally: five managed checkouts were reconciled repeatedly
  without moving `secure/<default>` or pushing remotes, then handed durably to
  exact-SHA recon and overlay planning.
- WP3 is implemented: recon parses GitHub Actions workflows structurally without
  a runtime YAML dependency and has Go/Rust/Python/Java/.NET fixture coverage.
- WP3B is implemented structurally: a durable Ecosystem Profiler handoff now
  emits fail-closed Java Maven and .NET profiles, explicit blocker ownership,
  trusted tmpfs preparation, and canary requirements without executing source.
  A separate Material Resolver role owns dependency closure. Both policies deny
  execution until digest-pinned builders and offline material locks exist.
- WP3A is implemented locally: digest-bound policy approval selected three
  exact additive Bandit files, the Patch Agent created a deterministic
  single-parent secure commit by CAS, and the Publisher correctly refused an
  unauthorized remote mutation.
- WP4/WP5 are partially implemented: pin locks carry freshness metadata, stale
  lock entries block rendering, locks bind the source tooling-policy digest,
  and draft release workflows remain manual-only until workflow, artifact,
  isolated-builder, and lineage review fields are confirmed. Renderer-level
  validation rejects path traversal and profile-to-YAML injection.
- WP7 is partially implemented: the v3 Builder Verifier cryptographically
  validates retained Sigstore bundles, exact subject coverage, certificates,
  run-bound workflow provenance, deterministic SPDX, archive transforms, and
  the custom policy predicate. Its policy and full-byte verifier sources are
  pinned by a separate code trust root. A durable Source Reacquirer now performs
  canonical GitHub branch acquisition and exact tree-inventory comparison, with
  the real Bandit case matching 298 entries. Upstream ancestry, workflow
  implementation, the wider operating-system toolchain, provider-independent
  acquisition, and builder isolation remain untrusted. Production `Attested`
  remains deliberately blocked.
- WP6 now renders separate build, unprivileged inspection/SBOM, and privileged
  attestation jobs, portable evidence bundles, and durable evidence lanes. The
  Python v2 path has completed real GitHub-hosted executions and fresh retained
  Sigstore verification; other ecosystems remain.
- WP11 stage 1 is implemented and exercised on two v2 and two v3 Bandit evidence
  sets. The v2 mismatch was retained and blocked. The repaired v3 path freshly
  reverifies both manifests and produces exact wheel, canonical sdist, and
  normalized SPDX matches through a durable Repro/Governor candidate gate. It
  does not authorize promotion or claim provider independence. Three hostile
  review rounds closed the candidate-gate and verifier-anchor findings.
  The deterministic package is now retained outside Actions artifact expiry;
  an extracted copy and a fresh GitHub download both passed integrity checks,
  and the extracted copy reproduced the bounded candidate decision.
- WP12 diagnostics have advanced without becoming a production gate: both v3
  Bandit runs retained 36,170 parseable trace records and produced the same
  normalized behavior digest. Full invocation, lifecycle, and collector
  resistance are not independently derived from that trace.
- Python v3 is active only for the exact Bandit development case. Its separate
  handoff, normalized SPDX, `/build/v2` predicate, reusable workflow, strict
  verifier, and durable Builder Verifier/Repro/Governor agents passed runs
  `29261239215` and `29261279150` against the pinned image. The broader Python
  profile remains inactive, and the frozen v2 lane is unchanged.
- WP8/WP9 are implemented locally: passive fork publication packets, optional
  fetch instructions, and custodian governance fields exist.
- A local `self-test` command now exercises first-lane fixtures, Java/.NET
  profile denial, Attested candidate evidence verification, and the five-agent
  durable evidence lane without network access or upstream-code execution.

Current critical path:

1. Add an independent executor and rerun the implemented exact-source
   reacquisition through a genuinely separate host/provider before granting any
   host- or provider-independence claim.
2. WP7: implement code-anchored lineage, builder, tooling, and workflow-content
   verifiers. Signed workflow claims are not yet separate proof of ancestry or
   isolation.
3. Implement Java/.NET material resolution and digest-pinned builders, then run
   the already-defined profiles through the v3 evidence contract.
4. Redesign remote authorization inside the single-account boundary, then test
   public secure-ref publication separately from build safety.
5. Add organization replay, branch protection, and scheduled upstream detection.

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
| Ecosystem/Material Agents | Build target decisions and sealed dependency closure | A blocked profile names every owner; a closed profile consumes only digest-locked offline materials |
| Evidence/Repro Agent | Evidence manifests, verification, artifact comparison, trace normalization | A non-authoritative evidence candidate is emitted only after local consistency checks |
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
8. Make the evidence-candidate validator require locally consistent evidence
   and recorded attestation input shape without granting assurance.
9. Add a code-anchored Sigstore verifier before the production `Attested` gate
   or any release route can pass. Implemented; the gate remains blocked on
   lineage, builder, tooling, and workflow-content authority.
10. Generate passive fork publication packets and optional fetch instructions.
11. Run the full sandbox MVP on one Go, one Rust, and one Python candidate.
12. Add artifact reproducibility as the next gate after Attested is real.
13. Add behavior trace collection only after artifact reproducibility is stable.

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
- GitHub organization or authenticated personal owner and token

Outputs:

- preflight report
- lifecycle state transitions
- existing-fork detection records

Acceptance:

- Missing auth or target-owner access fails before mutation.
- Personal targets require the authenticated `gh` user to match the plan.
- Existing forks record `ForkVerified` only after direct-parent verification.
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

Status: implemented and live-validated locally against the five-fork pilot.

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
- Recon analyzes a detached worktree pinned to the synchronized upstream SHA.
- Validated remote transports are used directly with explicit refspecs, so Git
  remote fetch configuration cannot redirect managed refs.

Tests:

- temp git repositories with repeated sync runs
- existing-branch safety tests
- conflict packet generation tests
- stale-default-branch versus synchronized-snapshot regression test
- five-repository live replay, artifact re-hash, and zero-work resume

Do not scope creep:

- no auto-conflict resolution
- no merge bot behavior
- no generalized multi-branch synchronization in the MVP
- no remote push in this package

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

### WP3A - Governed Additive Patch And Secure Ref

Owner: Patch/Release Agent with Governor/Safety Agent.

Status: implemented locally and validated on the Bandit canary; production
publication approval remains.

WBS refs: 1.0.8, 1.3.8, 2.3.8, 2.3.9, 2.3.10.

Purpose: turn immutable analysis into the smallest policy-approved local secure
commit without executing upstream code or silently widening approval.

Inputs:

- analysis index with transitive overlay digests
- fresh pin lock with action/ref coverage verified against the digest-bound
  tooling-policy file
- repository-scoped expiring patch approval
- managed checkout and recorded secure/upstream SHAs

Outputs:

- patch gate decision
- exact rendered-file manifest
- deterministic single-parent patch commit and CAS result
- secure-branch publication plan or verified exact-ref result

Acceptance:

- Policy approval covers only known additive ID/action/path/template contracts
  with `human_review_required: false` and cannot authorize a push.
- Existing paths with different blobs, stale secure bases, wrong remotes,
  incomplete pins, or artifact drift block before ref mutation.
- Reduced pin coverage or refs that differ from the supplied tooling policy block
  automated approval.
- Patch construction uses Git objects and a temporary index, not a source
  checkout, hooks, filters, or target-code execution.
- Local and remote ref changes use compare-and-swap/explicit lease semantics.
- The Publisher revalidates approval at execution time, isolates Git transport
  configuration, and names the approved commit object directly.
- Normal runtime and CLI execution remain blocked until an authenticated
  publication authorization verifier exists.
- Retry after local commit or remote push recognizes the exact approved state.

Tests:

- real bare-repository patch and publication tests
- deterministic commit and fresh-run reconciliation tests
- stale-upstream ancestry and existing-path conflict tests
- nested artifact tamper and exact policy-contract tests
- plan-only and unauthorized-publication tests

Do not scope creep:

- no structural edits to upstream workflows under additive policy
- no policy-authorized remote push
- no claim that a local secure commit is a hardened or attested release

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

- release profile fields for review status, artifact path confirmation,
  digest-pinned isolated builder confirmation, and unresolved notes
- draft workflow mode until confirmed

Acceptance:

- Draft profiles render manual-only workflows.
- Tag triggers are emitted only after explicit confirmation.
- Artifact paths must be confirmed before Attested release promotion.
- Source repository and exact upstream lineage must be confirmed before tag
  triggers are rendered.
- Upstream code is never rendered as a host-run shell command. Execution
  requires a reviewed builder image digest, argv-only command, read-only source
  mount, dropped capabilities, and network-disabled container.
- Java/.NET execution additionally requires an Ecosystem Profiler decision with
  no blockers, an approved canary-only policy, a trusted inventory-verified
  tmpfs copy, and a source-bound offline material bundle.
- Review notes survive render and appear in summaries.

Tests:

- release profile serialization tests
- manual-only draft renderer tests
- confirmed tag-trigger renderer tests

Do not scope creep:

- no GitHub release publishing in this package
- no container-image release publishing path

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

Purpose: make evidence-candidate completeness enforceable without confusing
caller-supplied claims with verified assurance or release authorization.

Inputs:

- evidence manifest
- verification result
- tooling policy result
- workflow risk result

Outputs:

- release evaluation JSON
- block decision with reasons

Acceptance:

- the evidence-candidate event is emitted only after local manifest consistency
  checks succeed, and it grants no promoted assurance.
- Required artifact, SBOM, and attestation evidence must be present.
- Unapproved tooling and unsafe workflow signals block promotion.
- the production `evaluate-release --target Attested` CLI remains blocked until
  code-anchored lineage, builder, tooling, and workflow-content results are
  composed with the implemented Sigstore result.
- CLI exits nonzero on production block decisions.

Tests:

- missing evidence tests
- digest mismatch tests
- missing attestation tests
- unsafe workflow risk tests
- CLI nonzero exit tests

Do not scope creep:

- no Reproducible target changes until production Attested is enforced
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

Status: comparator, durable Repro/Governor handoff, mismatch packet, and portable
replay are implemented. The v2 real Bandit case blocked; the corrected v3 case
passed as a same-provider artifact reproducibility candidate. No production
`Reproducible` or promotion claim has passed. Its complete durable package was
downloaded, checksum-verified, extracted, and replayed successfully.

WBS refs: 4.1.4, 4.1.5, 4.1.6, 6.2.2.

Purpose: add reproducible artifact claims after the Attested path is real.

Inputs:

- release profile build commands
- two retained rebuild results with explicit provider-independence status
- evidence manifests

Outputs:

- evidence set A manifest
- evidence set B manifest
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

Status: Linux trace collection, independent raw-record parsing, and diagnostic
normal form v2 are implemented for the Python builder. A same-provider v3
behavior candidate passed; no production behavior gate or independence claim is
enabled.

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

## Parallel Build Split Record

This was the initial parallel split. WP0, WP1's personal-owner path, WP2, WP3,
WP8, and WP9 now have working local implementations; the remaining packages
retain these ownership boundaries.

| Agent | Package | Primary files | Depends on |
| --- | --- | --- | --- |
| A | WP0 | pipeline/run index, catalog selection, tests | none |
| B | WP3 | recon parser, fixtures, recon tests | none |
| C | WP4 and WP5 | pin locks, release profile, release renderer tests | B for best artifact hints, but can start now |
| D | WP8 and WP9 | custody, fork publication module, publication tests | WP0 catalog shape |
| E | WP6 and WP7 | evidence, release evaluation, workflow evidence upload | C |
| F | WP1 and WP2 follow-up | org replay, branch policy, remote publication, scheduler | local reconciliation complete |
| G | WP11 | reproducibility renderer and mismatch packets | E |
| H | WP12 | trace collector and behavior mismatch packets | G |

## Next Implementation Tasks

1. Schedule a genuinely provider-independent rebuild using Source Reacquirer v3
   and a separate collector trust boundary.
2. Implement code-anchored lineage, builder, tooling-lock, and workflow-content
   verification before enabling production `Attested`.
3. Implement the quarantined Material Resolver and hostile-tested Java/.NET
   builders, then run the checked-in profiles on JSON Sanitizer and DevSkim.
4. Redesign publication approval inside the GitHub account boundary.
5. Replay WP1 against the eventual organization and add downstream branch
   protection plus scheduled upstream-change ingestion.
6. Run WP10: full sandbox MVP over one first-lane seed and fixture-like real
   candidates across the supported language set.

WP12 remains diagnostic until independent execution and collector trust are
demonstrated.

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
