# Assured Downstream WBS

Status: dev/idea-stage work breakdown. This is scoped to a working MVP first,
then the hardening path after the MVP is operating on real forks.

See [WBS_EXECUTION_PLAN.md](./WBS_EXECUTION_PLAN.md) for the agent-sized
implementation split, dependencies, acceptance criteria, and immediate parallel
work packages.

## 1. MVP Control Plane

### 1.1 Candidate Intake

Status: mostly built.

- 1.1.1 Ingest local awesome-list seeds
- 1.1.2 Ingest remote URL seeds
- 1.1.3 Extract and deduplicate GitHub repositories
- 1.1.4 Enrich repositories with GitHub metadata
- 1.1.5 Score candidates with explainable heuristics
- 1.1.6 Add candidate suppression/allowlist controls
- 1.1.7 Add persistent run history across pilot runs

### 1.2 Fork Lifecycle

Status: planned and guarded, live execution still pending.

- 1.2.1 Generate dry-run fork plans
- 1.2.2 Record lifecycle state
- 1.2.3 Guard fork creation behind `--execute`
- 1.2.4 Add GitHub org bootstrap checks
- 1.2.5 Add live fork creation smoke test against a sandbox org
- 1.2.6 Add fork existence detection and idempotent re-runs
- 1.2.7 Add branch protection/bootstrap policy for downstream forks

### 1.3 Sync Lifecycle

Status: planned and guarded, live execution still pending.

- 1.3.1 Generate clone/sync plans
- 1.3.2 Record sync lifecycle state
- 1.3.3 Guard git execution behind `--execute`
- 1.3.4 Avoid clobbering secure overlay branches
- 1.3.5 Add idempotent local workspace sync
- 1.3.6 Add upstream release/tag detection
- 1.3.7 Add conflict routing to human review

## 2. Repository Analysis And Overlay

### 2.1 Recon

Status: first pass built.

- 2.1.1 Detect languages and package managers
- 2.1.2 Detect CI workflows and release signals
- 2.1.3 Detect existing security controls
- 2.1.4 Detect common workflow risks
- 2.1.5 Parse workflow YAML structurally instead of regex-only
- 2.1.6 Detect artifact outputs more accurately
- 2.1.7 Add Go/Rust/Python repo fixtures from real projects

### 2.2 Overlay Planning

Status: first pass built.

- 2.2.1 Plan hardened CI overlays
- 2.2.2 Plan attestation/reproducibility overlays
- 2.2.3 Emit human-review-required markers
- 2.2.4 Add policy reasons for skipped or blocked patches
- 2.2.5 Split maintainer-friendly proposal overlays from downstream-only overlays

### 2.3 Overlay Rendering

Status: safe additive rendering exists.

- 2.3.1 Render Dependabot baseline
- 2.3.2 Render dependency review workflow
- 2.3.3 Render Scorecard evidence workflow
- 2.3.4 Render evidence directory
- 2.3.5 Require full SHA pins for generated workflows
- 2.3.6 Render Harden-Runner audit mode safely
- 2.3.7 Add structural workflow editing for existing workflows

## 3. Attested Release MVP

### 3.1 Approved Tooling

Status: first pass built.

- 3.1.1 Maintain approved tooling policy
- 3.1.2 Resolve approved GitHub Actions to full commit SHAs
- 3.1.3 Store pin lockfiles
- 3.1.4 Add expiry/refresh policy for pins
- 3.1.5 Verify release tooling binaries before use
- 3.1.6 Mirror or rebuild critical tooling where practical

### 3.2 Release Profile

Status: draft planner built.

- 3.2.1 Generate release profiles from recon
- 3.2.2 Support first-lane Go builds
- 3.2.3 Support first-lane Rust builds
- 3.2.4 Support first-lane Python builds
- 3.2.5 Require human review before enabling release workflows
- 3.2.6 Add artifact path confirmation
- 3.2.7 Add project-specific build matrix support

### 3.3 Release Workflow Rendering

Status: draft renderer built.

- 3.3.1 Render pinned attested-release workflow
- 3.3.2 Generate SBOM with approved SBOM tooling
- 3.3.3 Generate provenance with `actions/attest`
- 3.3.4 Generate SBOM attestation with `actions/attest`
- 3.3.5 Upload evidence artifact
- 3.3.6 Add GitHub release asset publishing
- 3.3.7 Add container-image release path

### 3.4 Evidence And Verification

Status: first pass built.

- 3.4.1 Create evidence manifests
- 3.4.2 Verify local evidence manifests
- 3.4.3 Generate in-toto statements
- 3.4.4 Generate Markdown verification guides
- 3.4.5 Evaluate release policy gates
- 3.4.6 Pull GitHub attestation metadata into evidence manifests
- 3.4.7 Attach verification guides to downstream releases

## 4. Reproducibility

### 4.1 Artifact Reproducibility

Status: comparison primitives built, runners pending.

- 4.1.1 Compare evidence manifests
- 4.1.2 Compare artifact hashes across hosts
- 4.1.3 Compare SBOMs across hosts
- 4.1.4 Add independent rebuild runner abstraction
- 4.1.5 Add two-host sandbox rebuild workflow
- 4.1.6 Route mismatches to human review

### 4.2 Behavior Reproducibility

Status: normalization primitives built, collectors pending.

- 4.2.1 Normalize JSON trace events
- 4.2.2 Compare behavior digests
- 4.2.3 Integrate a real process/file/network collector
- 4.2.4 Integrate syscall/security-event collection
- 4.2.5 Define stable allowed divergence rules
- 4.2.6 Add behavior mismatch reports

## 5. Stewardship And Custody

### 5.1 Custodian Review

Status: packet generation built.

- 5.1.1 Detect archived/stale repositories
- 5.1.2 Generate custodian review packets
- 5.1.3 Record license and activity evidence
- 5.1.4 Add maintainer contact tracking
- 5.1.5 Add naming/trademark review checklist
- 5.1.6 Add human approval gate before custodian claims

### 5.2 Upstream Liaison

Status: pending.

- 5.2.1 Generate maintainer fetch instructions
- 5.2.2 Generate proposal branch summaries
- 5.2.3 Draft respectful PR descriptions
- 5.2.4 Track maintainer preferences
- 5.2.5 Suppress noisy repeat outreach

## 6. Operations

### 6.1 Run Management

Status: basic pilot summaries built.

- 6.1.1 Produce pilot run directories
- 6.1.2 Produce checkout analysis run directories
- 6.1.3 Add machine-readable run index
- 6.1.4 Add resumable scheduler
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
- analyze one Go, one Rust, and one Python checkout
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
