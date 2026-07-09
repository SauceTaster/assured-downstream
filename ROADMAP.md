# SauceTotal Roadmap

Status: early idea/dev stage. The roadmap tracks the path from design prototype
to useful automation.

## MVP Boundary

The first useful system should be narrow and real.

Target public GitHub projects with:

- permissive or clearly reusable licenses
- active or historically important security relevance
- GitHub-hosted source
- existing release artifacts or a clear build output
- Go, Rust, or Python as the first language families
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
- local clone/sync plan generation exists
- sync-plan application records lifecycle state
- git sync execution is guarded behind `--execute`

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

## Phase 4: Hardened CI Overlay

Build:

- approved workflow templates
- workflow permission minimizer
- action pinning plan
- dependency review workflow
- workflow lint workflow
- safe pull request workflow patterns
- maintainer-fetchable proposal branch generation

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
- approved GitHub Action refs can be resolved into a pin lockfile
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
- actual SBOM/provenance/signature generation is still pending

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
- real trace collector integrations are still pending

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
saucetotal ingest --seed awesome-security.md --catalog catalog.json
saucetotal score --catalog catalog.json
saucetotal plan-forks --catalog catalog.json --org <org>
```

No repository mutation should happen until dry-run planning is useful.
