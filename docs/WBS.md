# Assured Downstream WBS

Status: dev/idea-stage work breakdown. This is scoped to a working MVP first,
then the hardening path after the MVP is operating on real forks.

See [WBS_EXECUTION_PLAN.md](./WBS_EXECUTION_PLAN.md) for the agent-sized
implementation split, dependencies, acceptance criteria, and immediate parallel
work packages.

## 1. MVP Control Plane

### 1.0 Durable Agent Runtime

Status: single-host runtime plus intake, managed-checkout, governed additive
patch request, authorization verification, and fail-closed publication mechanics
built; remote authorization is disabled, and distributed execution plus later
evidence lanes remain.

- 1.0.1 Persist typed events, work items, attempts, artifacts, and handoffs
- 1.0.2 Add idempotency keys, leased claims, retries, and dead letters
- 1.0.3 Separate enqueue, worker, status, and replay commands
- 1.0.4 Add constrained `gpt-5.6-luna` Codex profile and structured driver
- 1.0.5 Run discovery through dry-run fork planning as five durable agents
- 1.0.6 Add no-network agent replay to self-test
- 1.0.7 Add multi-host backend after measured need; evaluate Dapr at that gate
- 1.0.8 Host recon, overlay planning, additive Patch, Publication Request,
  Publication Authorization, and Secure Branch Publisher agents on the same
  contracts (built); external build-result ingestion, Trace, Attestation, and
  evidence Governor now use those contracts too; isolated execution,
  repository-specific patch, repro, release, and watch remain
- 1.0.9 Fence work completion by worker, attempt id, and unexpired lease (built)
- 1.0.10 Add durable authorization-run polling and artifact collection
- 1.0.11 Host external Build-result, Trace, Attestation, and evidence Governor
  handlers with immutable input snapshots (built)

### 1.1 Candidate Intake

Status: MVP built; live tuning and scheduler integration remain.

- 1.1.1 Ingest local awesome-list seeds
- 1.1.2 Ingest remote URL seeds
- 1.1.3 Extract and deduplicate GitHub repositories
- 1.1.4 Enrich repositories with GitHub metadata
- 1.1.5 Score candidates with explainable heuristics
- 1.1.6 Add candidate suppression/allowlist controls
- 1.1.7 Add persistent run history across pilot runs
- 1.1.8 Host GitHub metadata and license enrichment in the durable Catalog
  Ingestion handoff before the Governor selection gate

### 1.2 Fork Lifecycle

Status: live and repeat-safe in the temporary prefixed personal namespace;
organization bootstrap and branch protection remain.

- 1.2.1 Generate dry-run fork plans
- 1.2.2 Record lifecycle state
- 1.2.3 Guard fork creation behind `--execute`
- 1.2.4 Add GitHub org bootstrap checks
- 1.2.5 Add live fork creation smoke test against a sandbox owner (five-fork
  personal-namespace case built; organization replay remains)
- 1.2.6 Add fork existence detection and idempotent re-runs (built with direct
  upstream-parent verification)
- 1.2.7 Add branch protection/bootstrap policy for downstream forks

### 1.3 Sync Lifecycle

Status: local reconciliation, durable recon, governed secure commits,
authorization verification, and exact-lease publication mechanics are
implemented. Remote authorization is disabled; a replacement account-isolated
gate, governed public-ref mutation, and scheduling remain.

- 1.3.1 Generate clone/sync plans
- 1.3.2 Record sync lifecycle state
- 1.3.3 Guard git execution behind `--execute`
- 1.3.4 Avoid clobbering secure overlay branches (built)
- 1.3.5 Add idempotent local workspace sync (built)
- 1.3.6 Add upstream release/tag detection (built)
- 1.3.7 Add conflict routing to human review (built)
- 1.3.8 Publish reviewed `upstream/<default>` and `secure/<default>` refs to the
  downstream remote (authorization and secure-ref implementation built; first
  governed public-ref canary pending)
- 1.3.9 Add scheduled and GitHub-event-driven upstream reconciliation

## 2. Repository Analysis And Overlay

### 2.1 Recon

Status: structural first pass built with fixtures and exact-SHA detached
analysis worktrees in the durable managed-checkout lane.

- 2.1.1 Detect languages and package managers
- 2.1.2 Detect CI workflows and release signals
- 2.1.3 Detect existing security controls
- 2.1.4 Detect common workflow risks
- 2.1.5 Parse workflow YAML structurally instead of regex-only
- 2.1.6 Detect artifact outputs more accurately
- 2.1.7 Add Go/Rust/Python/Java/.NET repo fixtures from real projects

### 2.2 Overlay Planning

Status: first pass built and hosted after durable managed-checkout recon.

- 2.2.1 Plan hardened CI overlays
- 2.2.2 Plan attestation/reproducibility overlays
- 2.2.3 Emit human-review-required markers
- 2.2.4 Add policy reasons for skipped or blocked patches
- 2.2.5 Keep the MVP overlay on `secure/<default>`; add proposal branches only
  when a project requires them

### 2.3 Overlay Rendering

Status: governed additive rendering, Git-object commit application, canonical
publication requests, and Sigstore authorization verification are built. The
live authorization deployment is disabled and the Bandit patch remains local.

- 2.3.1 Render Dependabot baseline
- 2.3.2 Render dependency review workflow
- 2.3.3 Render Scorecard evidence workflow
- 2.3.4 Render evidence directory
- 2.3.5 Require full SHA pins for generated workflows
- 2.3.6 Render Harden-Runner audit mode safely
- 2.3.7 Add structural workflow editing for existing workflows
- 2.3.8 Bind patch approval to analysis, overlay, pin-lock, tooling-policy,
  repository, branch, base SHA, expiration, and exact change IDs (built)
- 2.3.9 Build deterministic single-parent commits through a temporary Git index
  and advance `secure/<default>` by compare-and-swap (built)
- 2.3.10 Add authenticated human approvals before production remote mutation
  (verification and replay controls built; deployment disabled pending an
  account-isolated approval design)
- 2.3.11 Add immutable authorization input snapshots and cross-run replay
  rejection (built)
- 2.3.12 Anchor the publication policy in code, derive the replay ledger from
  the OS account, and enforce mutation deadlines at push time (built)
- 2.3.13 Enforce the GitHub account-boundary policy at every mutation adapter
  and revalidate the external approval design without cross-account delegation

## 3. Attested Release MVP

### 3.1 Approved Tooling

Status: action pin lockfiles carry freshness, coverage, resolved-ref, and source
tooling-policy digests; binary verification and mirroring remain.

- 3.1.1 Maintain approved tooling policy
- 3.1.2 Resolve approved GitHub Actions to full commit SHAs
- 3.1.3 Store pin lockfiles
- 3.1.4 Add expiry/refresh policy for pins
- 3.1.5 Verify release tooling binaries before use
- 3.1.6 Mirror or rebuild critical tooling where practical

### 3.2 Release Profile

Status: draft planner built with human confirmation gates and artifact candidate
review.

- 3.2.1 Generate release profiles from recon
- 3.2.2 Support first-lane Go builds
- 3.2.3 Support first-lane Rust builds
- 3.2.4 Support first-lane Python builds
- 3.2.5 Require human review before enabling release workflows
- 3.2.6 Add artifact path confirmation
- 3.2.7 Add project-specific build matrix support

### 3.3 Release Workflow Rendering

Status: split-job renderer built. Untrusted build jobs have read-only
permissions; only the evidence job receives OIDC/attestation writes and produces
a portable evidence bundle.

- 3.3.1 Render pinned attested-release workflow
- 3.3.2 Generate SBOM with approved SBOM tooling
- 3.3.3 Generate provenance with `actions/attest`
- 3.3.4 Generate SBOM attestation with `actions/attest`
- 3.3.5 Upload evidence artifact
- 3.3.6 Add GitHub release asset publishing
- 3.3.7 Add container-image release path

### 3.4 Evidence And Verification

Status: portable manifest verification and durable evidence agents are built.
The bounded Python v3 lane independently reverifies retained keyless Sigstore
bundles, exact in-toto subjects, normalized SPDX, archive transforms, signed run
binding, raw trace parseability, and full-byte verifier sources against a
separate code trust root. Production `Attested` remains blocked until
separate code also verifies upstream ancestry, workflow content, tooling, source
reacquisition, and builder or collector isolation.

- 3.4.1 Create evidence manifests
- 3.4.2 Verify local evidence manifests
- 3.4.3 Generate in-toto statements
- 3.4.4 Generate Markdown verification guides
- 3.4.5 Evaluate release policy gates
- 3.4.6 Pull GitHub attestation metadata into evidence manifests
- 3.4.7 Attach verification guides to downstream releases

## 4. Reproducibility

### 4.1 Artifact Reproducibility

Status: durable Repro/Governor comparison is implemented. The v2 Bandit case
correctly blocked on sdist and SPDX drift; the repaired v3 lane then produced
byte-identical wheel, canonical sdist, and normalized SPDX subjects across two
freshly reverified GitHub-hosted runs. This is a same-provider reproducibility
candidate with no promotion authority. Provider-independent runners remain.
The hardened comparison and Governor bindings passed a final focused Luna
review with no actionable findings.

- 4.1.1 Compare evidence manifests
- 4.1.2 Compare artifact hashes across hosts
- 4.1.3 Compare SBOMs across hosts
- 4.1.4 Add independent rebuild runner abstraction
- 4.1.5 Add two-host sandbox rebuild workflow
- 4.1.6 Route mismatches to human review

### 4.2 Behavior Reproducibility

Status: Linux strace collection, raw-record replay, and trace normal form v2 are
built. Two Bandit observations each retained 36,170 parseable records and match
after enumerated volatile-path normalization. This is diagnostic behavior
evidence only: the retained trace does not yet prove the complete invocation or
lifecycle, collector tamper resistance, or independent-host execution.

- 4.2.1 Normalize JSON trace events
- 4.2.2 Compare behavior digests
- 4.2.3 Integrate a real process/file/network collector
- 4.2.4 Integrate syscall/security-event collection
- 4.2.5 Define stable allowed divergence rules
- 4.2.6 Add behavior mismatch reports
- 4.2.7 Separate collector-owned evidence from the hostile build UID
- 4.2.8 Add adversarial trace-tampering canaries

## 5. Stewardship And Custody

### 5.1 Custodian Review

Status: packet generation built with governance fields; public custodian claims
remain human-gated.

- 5.1.1 Detect archived/stale repositories
- 5.1.2 Generate custodian review packets
- 5.1.3 Record license and activity evidence
- 5.1.4 Add maintainer contact tracking
- 5.1.5 Add naming/trademark review checklist
- 5.1.6 Add human approval gate before custodian claims

### 5.2 Passive Fork Publication

Status: local publication packet generation built; outbound contact is disabled
by design.

- 5.2.1 Generate fork landing metadata
- 5.2.2 Publish upstream lineage and overlay summaries
- 5.2.3 Publish evidence and verification links
- 5.2.4 Generate optional secure-branch fetch instructions
- 5.2.5 Assert that no outbound contact operations exist

## 6. Operations

### 6.1 Run Management

Status: SQLite event/work/handoff ledger, pilot summaries, run index, and local
workers built; recurring scheduler and dashboards remain.

- 6.1.1 Produce pilot run directories
- 6.1.2 Produce checkout analysis run directories
- 6.1.3 Add machine-readable run index
- 6.1.4 Add recurring scheduler on top of resumable leased workers
- 6.1.5 Add failure dashboards or reports

### 6.2 Safety Gates

Status: first release gates built.

- 6.2.1 Block missing evidence
- 6.2.2 Block failed reproducibility checks
- 6.2.3 Block behavior divergence
- 6.2.4 Block unapproved tooling
- 6.2.5 Block unsafe workflow patterns
- 6.2.6 Add signed policy bundle

## MVP Definition Of Done

The MVP is done when Assured Downstream can, against a sandbox GitHub org:

- ingest one real awesome-list seed
- choose a small set of first-lane candidate repos
- fork or detect forks idempotently
- sync upstream without clobbering secure branches
- analyze one Go, one Rust, one Python, one Java, and one .NET checkout
- render pinned hardened CI and draft attested-release workflows
- run at least one attested release workflow successfully
- collect evidence manifests and verification guides
- evaluate an `Attested` release policy gate
- leave all mutations behind explicit execution flags or reviewed workflow runs

## Post-MVP North Star

After the MVP is real, the priority order is:

- independent rebuilds
- behavior trace collection
- behavior-reproducible comparison
- validated security review workflows
- custodian mode governance
