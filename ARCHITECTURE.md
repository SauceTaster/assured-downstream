# Assured Downstream Architecture

Status: early idea/dev stage. This architecture is the working blueprint for the
automation system, not a claim that every control already exists.

## System Shape

The system is an agent-driven control plane for a public assured downstream
organization.

It ingests project seeds, selects candidates, creates and syncs forks, applies
security overlays, builds in quarantined environments, publishes hardened
releases, emits signed evidence, and keeps tracking upstream.

The system has three major surfaces:

- the public org where hardened forks and releases live
- the approved tooling and policy catalog used by every fork
- the control plane that schedules agents and enforces gates

## Trust Domains

### Upstream

The original project repository. Upstream is the source of source truth when it
is active, but it is not assumed to be secure.

### Downstream Fork

The org-owned fork that tracks upstream and applies a declared security overlay.

### Approved Tooling

The trusted internal catalog of tools, reusable workflows, actions, containers,
runner images, policies, and cryptographic identities. Forks should consume from
this catalog rather than pulling arbitrary tooling from the internet.

### Build Environment

An isolated, ephemeral build environment. It should start with no ambient trust,
no long-lived secrets, least-privilege tokens, restricted network access, and
runtime monitoring.

### Evidence Store

The public and machine-readable store for attestations, reports, signatures,
SBOMs, trace summaries, rebuild comparisons, and validation outcomes.

## Organization Layout

The target GitHub organization should contain:

- `approved-tooling`: pinned tools, action SHAs, container digests, signing
  identities, and allowed versions
- `secure-workflows`: reusable workflows for build, release, SBOM, SLSA,
  Sigstore, in-toto, tracing, and verification
- `runner-images`: hardened runner images with provenance and SBOMs
- `policies`: OPA/Rego policies, Falco rules, egress policies, workflow lint
  policies, and dependency rules
- `catalog`: inventory of tracked upstreams, fork status, assurance tier, and
  evidence links
- `control-plane`: agents, scheduler, state machine, and API integration
- `reports`: rendered human-readable reports and machine-readable summaries
- project forks: one fork per tracked upstream project

## Fork Branch Model

Each fork should use a predictable branch and tag scheme:

- `upstream/<default>`: exact mirror of the upstream default branch
- `secure/<default>`: upstream plus the current security overlay
- `secure/release/<version>`: hardened release branch
- `proposal/<topic>`: maintainer-friendly branch that upstream can fetch or
  cherry-pick
- `upstream-vX.Y.Z`: tag matching the upstream release
- `secure-vX.Y.Z+org.N`: tag for the downstream hardened release

## Assurance Levels

### Tracked

The upstream project is known, monitored, mirrored, and inventoried.

### Hardened

A security overlay has been applied. This generally includes minimal GitHub
token permissions, pinned actions, safer pull request workflows, dependency
review, and workflow linting.

### Attested

Artifacts are built with signed provenance, SBOMs, in-toto statements, and
Sigstore or equivalent signatures.

### Reproducible

Independent rebuilds on separate hosts produce matching artifact hashes and
matching declared materials.

### Behavior-Reproducible

Independent rebuilds produce matching normalized build behavior evidence:
process graph, file boundaries, network behavior classes, privileged syscall
profile, and policy outcome.

### Validated

A scoped security review, fuzzing campaign, or penetration-style assessment has
been completed and published with retest evidence.

## Lifecycle State Machine

```text
Seeded
  -> Candidate
  -> Selected
  -> Forked
  -> Mirrored
  -> Reconned
  -> OverlayPlanned
  -> Patched
  -> Built
  -> Traced
  -> Attested
  -> Released
  -> Watched
```

Failure and maintenance states:

```text
Blocked
NeedsHumanReview
UpstreamChanged
OverlayConflict
BuildFailed
PolicyFailed
RebuildMismatch
BehaviorMismatch
Deprecated
CustodianReview
CustodianFork
AdoptedProject
```

## Agent Roles

### Seed Agent

Ingests awesome lists and other seed sources, extracts repositories, deduplicates
them, and records source attribution.

### Triage Agent

Scores project relevance, maintenance health, release shape, language, package
ecosystem, security impact, and likelihood that hardening can be automated.

### Fork Agent

Creates forks, configures remotes, syncs from upstream, manages branch naming,
and records fork lineage.

### Recon Agent

Detects language, package managers, CI workflows, release workflows, build
commands, test commands, artifact paths, container builds, and existing security
controls.

### Overlay Planner

Chooses the smallest viable hardening overlay for the repository. It should
prefer incremental improvements over broad rewrites.

### Patch Agent

Applies approved templates and repository-specific edits. It should preserve
local style and avoid unrelated churn.

### Tooling Curator

Maintains the approved tooling catalog. It pins versions, verifies upstream
tooling, rebuilds mirrored tools when practical, signs approved artifacts, and
rotates tools through policy review.

### Build Agent

Runs builds in quarantined environments. It must assume target code is hostile
and avoid exposing long-lived secrets.

### Trace Agent

Captures process, file, network, and syscall evidence. It produces raw trace
artifacts for audit and normalized summaries for reproducibility comparisons.

### Repro Agent

Runs independent rebuilds on separate hosts and compares artifacts, materials,
SBOMs, provenance, and normalized behavior.

### Attestation Agent

Emits SBOMs, SLSA provenance, in-toto statements, signatures, verification
summary attestations, and evidence manifests.

### Release Agent

Publishes hardened releases, attaches evidence, signs artifacts, and maintains
release notes describing upstream source and downstream overlay.

### Report Agent

Writes human-readable and machine-readable reports for each project and release.

### Upstream Liaison Agent

Prepares optional pull requests, issue comments, fetch instructions, and small
proposal branches. It must avoid noisy automation and respect maintainer
preferences.

### Watch Agent

Monitors upstream commits, releases, advisories, CVEs, tooling updates, policy
changes, and failed downstream syncs.

### Governor Agent

Owns policy decisions. It blocks unsafe releases, enforces approved tooling,
requires evidence before claims, and routes ambiguous custody or security issues
to human review.

## Approved Tooling Policy

Forks should not casually pull unreviewed actions, containers, or install
scripts.

Approved tooling entries should include:

- source repository
- pinned commit SHA or image digest
- version
- license
- SBOM
- provenance
- signature verification policy
- allowed usage contexts
- known risks
- refresh schedule

## Evidence Manifest

Every release should produce an evidence manifest that links:

- upstream source commit
- downstream overlay commit
- artifact names and digests
- SBOM documents
- SLSA provenance
- in-toto build, test, package, and trace statements
- signatures and certificates
- runtime trace summaries
- raw trace artifact references when publishable
- rebuild comparison result
- behavior comparison result
- validation report
- remaining risk notes

## Behavior Digest

Raw syscall traces are expected to differ across hosts. The system should
normalize traces into a behavior digest.

Initial normalization fields:

- executable path class and hash when available
- process parent-child graph
- package manager activity
- compiler, linker, archiver, and packager activity
- file read/write paths after workspace-relative normalization
- file writes outside expected directories
- network destination classes and resolved hosts
- privileged syscall categories
- environment variable access classes
- secret-like file and token access attempts
- container, namespace, and privilege escalation attempts

The behavior digest is not a proof of safety. It is a reproducibility and
anomaly signal that can force review when behavior diverges.

## Policy Gates

A release must not advance when:

- upstream source lineage is unclear
- approved tooling verification fails
- artifact signing fails
- provenance is missing for required artifacts
- SBOM generation fails
- dependency resolution uses undeclared sources
- a build attempts unexpected credential access
- egress violates policy
- independent rebuild hashes diverge at a tier requiring reproducibility
- normalized behavior diverges at a tier requiring behavior reproducibility
- a custodian claim lacks required evidence
