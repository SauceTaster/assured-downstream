# Assured Downstream

Assured Downstream is an early-stage idea/dev project for an agentic DevOps
assured downstream for open source software.

Status: executable design prototype. Durable intake, managed-checkout, and
governed local patch lanes work, but this is not production-ready. Expect
names, schemas, command interfaces, and trust boundaries to change while the
core automation takes shape.

The goal is to maintain an organization of hardened forks that continuously
track upstream projects, rebuild and release them under stronger security
controls, and publish verifiable evidence for every meaningful claim.

This is not a scorecard farm. The system should fix, rebuild, attest, sign,
trace, compare, publish, and keep following upstream.

## Core Idea

For important open source projects, especially security tools, libraries,
packages, and applications, the org provides a trusted downstream lane:

- upstream remains the source of truth when it is active
- forks track upstream automatically
- security overlays are applied in small, reviewable deltas
- hardened releases are built from known source commits
- artifacts are signed and attested
- SBOMs, SLSA provenance, in-toto statements, runtime evidence, and validation
  reports are published
- maintainers can fetch branches or opt into deeper support
- inactive projects can eventually move into custodian maintenance

## Key Documents

- [INTENT.md](./INTENT.md): mission, social contract, stewardship modes, and
  boundaries.
- [ARCHITECTURE.md](./ARCHITECTURE.md): trust domains, lifecycle, agents,
  assurance levels, evidence model, and policy gates.
- [docs/AGENT_OPERATING_MODEL.md](./docs/AGENT_OPERATING_MODEL.md): full
  project-finding, ingestion, agent, event, tool, and handoff model.
- [docs/AGENT_RUNTIME.md](./docs/AGENT_RUNTIME.md): implemented SQLite runtime,
  Luna worker contract, commands, failure semantics, and Dapr migration gate.
- [ROADMAP.md](./ROADMAP.md): staged implementation plan from catalog and fork
  sync to behavior-reproducible releases.
- [docs/WBS.md](./docs/WBS.md): work breakdown for what remains before and
  after the MVP.
- [docs/WBS_EXECUTION_PLAN.md](./docs/WBS_EXECUTION_PLAN.md): agent-sized work
  packages, dependencies, acceptance criteria, and implementation order.
- [docs/RESEARCH.md](./docs/RESEARCH.md): implementation-shaping research notes.
- [docs/VALIDATION_PLAN.md](./docs/VALIDATION_PLAN.md): self-test, case-study
  tiers, and proof required before making stronger assurance claims.
- [case-studies/001-pilot-cohort](./case-studies/001-pilot-cohort/README.md):
  first real Go/Rust/Python/Java/.NET security-project cohort and exact upstream
  commits.

## Current Prototype Commands

The current CLI defaults to observe-first behavior. Explicit flags can create
forks or mutate managed local refs. Exact-lease remote publication is implemented
and locally tested, but the durable runtime refuses executed publication until
an authenticated approval backend exists. The CLI is a local tool adapter for
the agent system, not the system boundary.

```text
assured-downstream codex-preflight
assured-downstream agent-run --seed awesome-security.md --org <org> \
  --run-dir ./runs/intake-001 --enrich
assured-downstream agent-run --seed awesome-security.md --user <github-user> \
  --name-prefix assured- --run-dir ./runs/intake-personal --enrich
assured-downstream agent-run --seed awesome-security.md --org <org> \
  --run-dir ./runs/intake-002 --enqueue-only
assured-downstream agent-worker \
  --database ./runs/intake-002/agent-control-plane.sqlite3
assured-downstream agent-status \
  --database ./runs/intake-002/agent-control-plane.sqlite3
assured-downstream checkout-run --fork-plan fork-plan.json --state state.json \
  --workspace ./worktrees --run-dir ./runs/checkout-sync-001 --execute-sync
assured-downstream prepare-patch-approval --analysis-index analysis-index.json \
  --pins pins.json --tooling-policy policies/approved-tooling.json \
  --repository org/repo --output patch-approval.json \
  --auto-approve-safe
assured-downstream patch-run --analysis-index analysis-index.json --pins pins.json \
  --tooling-policy policies/approved-tooling.json \
  --approval patch-approval.json --workspace ./worktrees \
  --run-dir ./runs/patch-001
assured-downstream patch-run --analysis-index analysis-index.json --pins pins.json \
  --tooling-policy policies/approved-tooling.json \
  --approval patch-approval.json --workspace ./worktrees \
  --run-dir ./runs/patch-apply-001 --execute-patch
assured-downstream pilot --seed awesome-security.md --org <org> --run-dir ./runs/pilot-001
assured-downstream pilot --seed https://example.com/awesome-security.md --org <org> \
  --run-dir ./runs/pilot-remote
assured-downstream pilot --seed awesome-security.md --org <org> --run-dir ./runs/pilot-001 \
  --allowlist first-lane.json --suppress do-not-touch.json --run-index ./runs/index.json
assured-downstream self-test --output-dir ./runs/self-test
assured-downstream analyze-checkout --path /path/to/checkout --run-dir ./runs/checkout-001 \
  --target Attested
assured-downstream plan-release --recon recon.json --output release-profile.json
assured-downstream render-release-workflow --profile release-profile.json \
  --path /path/to/checkout --pins pins.json
assured-downstream ingest --seed awesome-security.md --catalog catalog.json
assured-downstream enrich --catalog catalog.json
assured-downstream score --catalog catalog.json
assured-downstream custodian-review --catalog catalog.json --output custody-review.json
assured-downstream recon --path /path/to/checkout --output recon.json
assured-downstream plan-overlay --recon recon.json --target Attested --output overlay-plan.json
assured-downstream resolve-pins --tooling policies/approved-tooling.json --output pins.json
assured-downstream render-overlay --plan overlay-plan.json --path /path/to/checkout --pins pins.json
assured-downstream plan-forks --catalog catalog.json --org <org>
assured-downstream plan-forks --catalog catalog.json --user <github-user> \
  --name-prefix assured-
assured-downstream apply-fork-plan --plan fork-plan.json --state state.json
assured-downstream plan-sync --fork-plan fork-plan.json --workspace ./worktrees
assured-downstream apply-sync-plan --plan sync-plan.json --state state.json
assured-downstream create-evidence --project owner/repo --target-repo org/repo \
  --upstream-ref <sha> --overlay-ref <sha> --release-tag secure-v1.0.0+org.1 \
  --artifact ./dist/tool --sbom ./dist/sbom.json --output evidence.json
assured-downstream create-attestation --predicate-type https://assured-downstream.dev/attestation/build/v1 \
  --subject ./dist/tool --predicate build-predicate.json --output build.intoto.json
assured-downstream verify-evidence --manifest evidence.json
assured-downstream write-verification-guide --evidence evidence.json --output VERIFY.md
assured-downstream evaluate-release --evidence evidence.json --target Attested \
  --output release-evaluation.json
assured-downstream create-project-packet --fork-plan fork-plan.json --source owner/repo \
  --checkout-analysis recon.json --overlay-plan overlay-plan.json --render-result render-result.json \
  --release-profile release-profile.json --output project.json --markdown-output PROJECT.md
assured-downstream compare-evidence --left host-a-evidence.json --right host-b-evidence.json
assured-downstream normalize-trace --trace raw-trace.json --workspace-root /workspace \
  --output behavior.json
assured-downstream compare-behavior --left host-a-behavior.json --right host-b-behavior.json
```

`enrich` uses public GitHub API access by default and reads `GITHUB_TOKEN` when
available. Fork targets may be an organization (`--org`) or the personal
account authenticated in `gh` (`--user`), with an optional `--name-prefix`.
`apply-fork-plan` is dry-run unless `--execute` is passed. Before personal
account mutation it verifies the active GitHub identity; existing targets are
accepted only when GitHub confirms the requested upstream parent. Overlay
planning is also non-mutating; it turns recon evidence into a structured set of
proposed hardening changes. Overlay rendering is dry-run unless `--execute` is
passed, and generated workflows require full commit SHA pins supplied through
`--pins`.

`checkout-run` is the second durable agent lane: Fork And Sync -> Recon ->
Overlay Planner. It digest-binds its fork plan, lifecycle state, and every
handoff artifact in SQLite. With `--execute-sync`, it validates remote identity,
preserves each validated SSH/HTTPS transport, fetches with explicit refspecs,
updates only `upstream/<default>`, creates `secure/<default>` once, and never
pushes a remote branch. Recon runs from a detached worktree pinned to the exact
synchronized upstream commit, not whichever branch happens to be checked out.

`prepare-patch-approval` creates a digest-bound decision for one repository.
Its automated policy can select only exact supported additive templates with an
explicit false review marker, a complete fresh pin lock whose action/ref coverage
matches the supplied digest-verified tooling policy, and no overwrite.
`patch-run` then hosts Patch and Secure Branch Publisher agents. The Patch Agent
constructs a deterministic Git commit through the object database, proves its
secure base contains the analyzed upstream commit, and advances only
`secure/<default>` with compare-and-swap. The Publisher plans by default; a
network push names the approved commit object directly, isolates Git transport
configuration, revalidates approval at the handoff, and uses an exact expected
remote SHA lease. That primitive is exercised only against local test remotes;
the CLI and normal workers block execution until they can verify an externally
authenticated publication authorization. No outbound maintainer contact is
created.

Seeds can be local files or URLs. `agent-run` is the current durable
observe-first entrypoint. It persists typed events, leased work, attempts,
artifact digests, and agent handoffs in SQLite, and writes `catalog.json`,
`fork-plan.json`, `selection-reasons.json`, `state.json`, and `sync-plan.json`.
The intake lane is dry-run only. `agent-worker` can resume any durable lane
from its database. `pilot` remains the single-process tool path and writes a run
directory with `catalog.json`, `fork-plan.json`,
`selection-reasons.json`, `state.json`, `sync-plan.json`, and `RUN_SUMMARY.md`,
and appends to a machine-readable run index.

`self-test` runs local no-network validation against first-lane Go, Rust,
Python, Java, and .NET fixtures, replays the five-agent intake lane, then
verifies an Attested evidence smoke test.

`analyze-checkout` is the local Patch Agent cockpit. It writes `recon.json`,
`overlay-plan.json`, `render-result.json`, `release-profile.json`,
`release-render-result.json`, and `CHECKOUT_SUMMARY.md`, and only writes overlay
or release workflow files into the checkout when `--render` is passed.

`plan-release` and `render-release-workflow` are the current attested-release
MVP path. They draft a human-review-required release profile and render a pinned
GitHub Actions workflow that builds artifacts, generates an SBOM, uses
`actions/attest` for SLSA provenance, SBOM, and a custom Assured Downstream
in-toto predicate, and uploads the resulting Sigstore bundles with the evidence.
Draft release workflows are manual-only until the release workflow and artifact
paths are confirmed in the profile.

`create-project-packet` produces passive fork metadata, lineage, an overlay
summary, and optional fetch commands. Assured Downstream does not create pull
requests, issues, comments, email, or other outbound maintainer contact.

## North Star

The highest assurance target is not only reproducible builds. It is
behavior-reproducible builds.

Two independent hosts should produce matching artifacts and matching normalized
build behavior evidence: dependency materials, process graph, file boundaries,
network behavior classes, privileged syscall profile, provenance, SBOMs, and
policy outcome.

Raw traces will vary. Normalized behavioral digests should make meaningful
divergence visible.

## Public Promise

For every supported release, the system should be able to answer:

- Which upstream commit or release is this based on?
- What security overlay was applied?
- What artifacts were produced?
- Were artifacts signed?
- What SBOM, SLSA, and in-toto evidence exists?
- What did the build do at runtime?
- Did independent rebuilds match?
- What risks remain?
- How can upstream fetch or adopt the hardening work?
