# Assured Downstream Roadmap

Status: early idea/dev stage. The roadmap tracks the path from design prototype
to useful automation.

## MVP Boundary

The first useful system should be narrow and real.

Target public GitHub projects with:

- permissive or clearly reusable licenses
- active or historically important security relevance
- GitHub-hosted source
- existing release artifacts or a clear build output
- Go, Rust, Python, Java, or .NET as the first language families
- GitHub Actions as the first CI target

The MVP should not try to solve every ecosystem, every build system, or full
behavior-reproducible builds immediately.

## Phase 0: Foundation

Goals:

- capture project intent, architecture, and roadmap
- define assurance levels and stewardship modes
- define the initial evidence model
- define the first candidate project shape

Exit criteria:

- docs are present and specific enough to guide implementation
- the first implementation slice is obvious

## Phase 1: Catalog and Seed Ingestion

Build:

- seed source model
- awesome-list parser
- GitHub repository extractor
- deduplication
- project catalog file or database
- candidate scoring fields

Initial scoring dimensions:

- upstream activity
- stars, dependents, package downloads, or ecosystem importance
- security relevance
- license compatibility
- release presence
- workflow presence
- apparent hardening gaps
- automation difficulty

Exit criteria:

- a command can ingest one or more awesome lists
- a catalog of candidate repositories is produced
- candidates are ranked with explainable scores

Current prototype status:

- local seed ingestion exists
- remote URL seed ingestion exists
- local catalog writing exists
- GitHub metadata enrichment exists
- explainable heuristic scoring exists
- observe-first pilot runs produce catalog, fork plan, lifecycle state, sync
  plan, and Markdown summary artifacts
- first machine-readable agent registry exists at `policies/agent-registry.json`

## Phase 2: Fork and Sync Control Plane

Build:

- GitHub auth integration
- fork creation
- upstream remote tracking
- branch scheme creation
- sync scheduler
- fork state recording

Exit criteria:

- selected repos can be forked into the org
- `upstream/<default>` mirrors upstream
- sync events are recorded
- failures move to explicit states

Current prototype status:

- dry-run fork plans exist
- fork-plan application records lifecycle state
- GitHub fork mutation is guarded behind `--execute`
- personal-owner preflight, direct-parent verification, existing-fork
  detection, and repeat-safe replay are live against five prefixed pilot forks
- local clone/sync plan generation exists
- sync-plan application performs guarded repeat-safe reconciliation and records
  exact SHAs, tags, divergence, and lifecycle state
- git sync execution is guarded behind `--execute`
- `upstream/<default>` advances without resetting `secure/<default>`
- validated remote transports are fetched with explicit refspecs; exact-ref
  publication exists behind separate approval and execution gates
- the durable Fork And Sync lane hands exact-SHA snapshots to Recon and Overlay
  Planner agents with digest-verified artifacts
- publication verification and exact-ref mechanics are implemented locally;
  remote authorization is disabled pending an account-isolated gate design
- remaining: authorization redesign, first governed public secure-ref mutation,
  organization replay, downstream branch protection, and scheduled/event-driven
  sync

## Phase 3: Repository Recon

Build:

- language detection
- package manager detection
- CI workflow parser
- release workflow detection
- artifact path inference
- dependency and lockfile inventory
- current security control detection

Exit criteria:

- recon report exists for each selected repo
- the system can identify build and release candidates
- repos without enough signal are routed to review instead of guessed through

Current prototype status:

- local checkout recon exists
- language, package manager, build system, workflow, release signal, security
  control, and risk signal detection exists
- checkout analysis pipeline exists for recon-to-overlay and recon-to-release
  run artifacts
- managed recon uses a detached worktree pinned to the synchronized upstream
  commit, independent of the checkout's selected branch

## Phase 4: Hardened CI Overlay

Build:

- approved workflow templates
- workflow permission minimizer
- action pinning plan
- dependency review workflow
- workflow lint workflow
- safe pull request workflow patterns
- passive fork publication metadata and optional secure-branch fetch instructions

Exit criteria:

- the system can create a small hardening branch
- changes are explainable and scoped
- CI hardening can be tested without publishing a release

Current prototype status:

- overlay planning from recon reports exists
- hardened, attested, reproducible, and behavior-reproducible target levels are
  represented in plans
- approved tooling policy scaffold exists at `policies/approved-tooling.json`
- patch rendering exists for safe additive files
- workflow rendering requires full commit SHA pins
- approved GitHub Action refs can be resolved into a fresh pin lockfile bound to
  the tooling-policy digest
- patch approval verifies the lock's complete action/ref coverage against that
  actual digest-verified tooling-policy file
- separate durable Patch -> Publication Request and Publication Authorization ->
  Secure Branch Publisher runs consume expiring, digest-bound,
  repository-scoped approvals
- automated approval is limited to exact additive template contracts and cannot
  authorize remote publication
- publication code requires a protected-workflow Sigstore/in-toto bundle
  verified against an exact signer/source commit and a one-time consumption
  ledger; the live policy is disabled
- patch commits are built through Git objects with one approved parent and move
  `secure/<default>` only by compare-and-swap
- the Bandit canary produced a three-file local secure commit, replayed
  idempotently, and remained absent from GitHub because publication was not
  authorized
- account-boundary policy now forbids authentication switching and cross-account
  delegation; unavailable independent approval fails closed
- repository-specific release patching is still pending

## Phase 5: Attested Release

Build:

- SBOM generation
- SLSA provenance generation
- in-toto statement generation
- Sigstore signing for artifacts or containers
- release evidence manifest
- human-readable release report

Exit criteria:

- one project can produce a hardened release
- artifacts are signed
- SBOM and provenance are attached
- evidence is linked from the release

Current prototype status:

- evidence manifest creation exists
- evidence manifest verification exists
- file roles include artifacts, SBOMs, attestations, traces, and reports
- generic in-toto statement generation exists
- release policy gate evaluation exists for attested, reproducible,
  behavior-reproducible, and validated targets
- Markdown verification guide generation exists for release evidence manifests
- draft release profile planning exists for first-lane Go, Rust, Python, Java,
  and .NET checkouts
- pinned attested-release workflow rendering exists using `actions/attest` for
  SLSA provenance, SBOM, and a custom Assured Downstream in-toto predicate
- rendered workflows capture local Sigstore bundle outputs for evidence upload
- generated workflows now separate untrusted build execution, unprivileged
  artifact inspection/SBOM generation, and privileged OIDC attestation; artifact
  inventories are checked across both handoffs
- the durable Build-result -> Trace -> Attestation -> Release Verifier ->
  Governor lane snapshots external evidence, cryptographically verifies retained
  Sigstore bundles and SPDX artifact references, and validates
  tooling/workflow-risk input shape without granting assurance; upstream
  ancestry remains a signed workflow claim until independently checked
- a live Bandit source canary completed the digest-pinned no-network build,
  complete strace parser pass, permissionless SPDX generation, three keyless
  Sigstore attestations, and portable evidence assembly
- the Bandit source canary now runs on `python-wheel-v2`, with a root-owned
  collector and evidence boundary and an unprivileged UID 65532 build process
- the code-anchored Builder Verifier Agent independently verified the retained
  signer/caller identities, subjects, SPDX binding, predicates, and transparency
  timestamps while correctly retaining `Evidence-candidate` status
- the v2 Bandit evidence and durable verifier ledger are retained in a
  digest-recorded development prerelease

## Phase 6: Reproducible Release

Build:

- independent rebuild runner abstraction
- rebuild material capture
- artifact hash comparison
- SBOM comparison
- provenance comparison
- mismatch report

Exit criteria:

- at least two independent hosts rebuild the same release
- matching artifacts promote the release to `Reproducible`
- mismatches produce actionable reports

Current prototype status:

- evidence manifests can be compared across independent builds
- comparison matches evidence files by role, name, size, and SHA-256
- mismatch reports are machine-readable and CLI-visible

## Phase 7: Runtime and Behavior Evidence

Build:

- process tracing
- file boundary tracing
- network tracing
- syscall or security-event tracing
- raw trace retention policy
- normalized behavior digest
- behavior comparison report

Exit criteria:

- builds produce trace summaries
- obvious unexpected network and file behavior can fail policy
- matching independent behavior can promote a release to
  `Behavior-Reproducible`

Current prototype status:

- generic JSON trace normalization exists
- behavior digests cover process, file, network, and syscall/security-event
  categories
- behavior reports can be compared across independent builds
- the first Linux strace collector runs in the digest-pinned Python builder and
  requires a complete parser pass before attestation
- collector/build UID separation and an enumerated hostile-source tamper canary
  are complete for `python-wheel-v2`
- a second independent collector host and broader kernel/runtime resistance
  testing are still pending

## Phase 8: Validation Workflows

Build:

- fuzzing integrations
- static analysis integrations
- container and binary scanning
- scoped manual review packet support
- retest evidence workflow

Exit criteria:

- a release can be promoted to `Validated`
- reports distinguish automated validation from human-reviewed assessment
- scope is explicit and legally safe

## Phase 9: Custodian Mode

Build:

- abandonment signal collector
- maintainer contact tracker
- license and naming review checklist
- custodian evidence packet
- continuation fork naming policy
- governance bootstrap templates

Exit criteria:

- inactive projects can be proposed for custody
- human review is required before public custody claims
- custodian releases preserve upstream lineage

Current prototype status:

- custodian review packet generation exists
- archived and stale repositories can be routed to human review
- packets include license, activity, popularity, and required review criteria

## First Implementation Slice

The first code should implement:

- a local project catalog
- seed ingestion from awesome lists
- GitHub repository extraction
- candidate scoring
- a dry-run fork plan

Suggested first command shape:

```text
assured-downstream ingest --seed awesome-security.md --catalog catalog.json
assured-downstream score --catalog catalog.json
assured-downstream plan-forks --catalog catalog.json --org <org>
```

No repository mutation should happen until dry-run planning is useful.
