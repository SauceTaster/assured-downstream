# SauceTotal

SauceTotal is an early-stage idea/dev project for an agent-driven assured
downstream for open source software.

Status: design prototype. Not production-ready. Expect names, schemas, command
interfaces, and trust boundaries to change while the core automation takes
shape.

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
- [ROADMAP.md](./ROADMAP.md): staged implementation plan from catalog and fork
  sync to behavior-reproducible releases.

## Current Prototype Commands

The current CLI is intentionally observe-first. It can build a catalog, enrich
candidate metadata, inspect local checkouts, score candidates, and generate
dry-run fork plans.

```text
saucetotal pilot --seed awesome-security.md --org <org> --run-dir ./runs/pilot-001
saucetotal pilot --seed https://example.com/awesome-security.md --org <org> \
  --run-dir ./runs/pilot-remote
saucetotal analyze-checkout --path /path/to/checkout --run-dir ./runs/checkout-001 \
  --target Attested
saucetotal ingest --seed awesome-security.md --catalog catalog.json
saucetotal enrich --catalog catalog.json
saucetotal score --catalog catalog.json
saucetotal custodian-review --catalog catalog.json --output custody-review.json
saucetotal recon --path /path/to/checkout --output recon.json
saucetotal plan-overlay --recon recon.json --target Attested --output overlay-plan.json
saucetotal resolve-pins --tooling policies/approved-tooling.json --output pins.json
saucetotal render-overlay --plan overlay-plan.json --path /path/to/checkout --pins pins.json
saucetotal plan-forks --catalog catalog.json --org <org>
saucetotal apply-fork-plan --plan fork-plan.json --state state.json
saucetotal plan-sync --fork-plan fork-plan.json --workspace ./worktrees
saucetotal apply-sync-plan --plan sync-plan.json --state state.json
saucetotal create-evidence --project owner/repo --target-repo org/repo \
  --upstream-ref <sha> --overlay-ref <sha> --release-tag secure-v1.0.0+org.1 \
  --artifact ./dist/tool --sbom ./dist/sbom.json --output evidence.json
saucetotal verify-evidence --manifest evidence.json
saucetotal compare-evidence --left host-a-evidence.json --right host-b-evidence.json
saucetotal normalize-trace --trace raw-trace.json --workspace-root /workspace \
  --output behavior.json
saucetotal compare-behavior --left host-a-behavior.json --right host-b-behavior.json
```

`enrich` uses public GitHub API access by default and reads `GITHUB_TOKEN` when
available. `apply-fork-plan` is dry-run unless `--execute` is passed. Overlay
planning is also non-mutating; it turns recon evidence into a structured set of
proposed hardening changes. Overlay rendering is dry-run unless `--execute` is
passed, and generated workflows require full commit SHA pins supplied through
`--pins`.

Seeds can be local files or URLs. `pilot` is the current observe-first
entrypoint. It writes a run directory with `catalog.json`, `fork-plan.json`,
`state.json`, `sync-plan.json`, and `RUN_SUMMARY.md`.

`analyze-checkout` is the local Patch Agent cockpit. It writes `recon.json`,
`overlay-plan.json`, `render-result.json`, and `CHECKOUT_SUMMARY.md`, and only
writes overlay files into the checkout when `--render` is passed.

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
