# Assured Downstream Agent Operating Model

Status: dev/idea-stage operating model. This document is the system shape that
the prototype CLI should grow into.

## Correction

Assured Downstream is not a single command-line tool.

The CLI in this repository is a local harness and tool adapter layer. The actual
system is an agentic DevOps network of reconcilers, model-assisted agents,
policies, queues, evidence stores, tools, schedulers, and human gates working
together to maintain an assured downstream organization.

The important unit is not "run one command." The important unit is "move a
project through an evidence-backed lifecycle without losing provenance, safety,
or upstream respect."

## System Boundary

The system includes:

- source discovery feeds and project finding agents
- catalog ingestion and enrichment
- candidate scoring, allowlists, suppressions, and human review queues
- fork and sync lifecycle agents
- checkout recon and release-shape inference
- overlay planning and patch rendering
- approved tooling curation
- build, trace, attestation, release, and reproducibility agents
- passive fork publication and custodian review agents
- watch agents for upstream changes, advisories, and tool refreshes
- governor gates that decide what can advance
- public evidence stores and human-readable reports

The CLI should eventually be one of several tool surfaces. Other surfaces may
include scheduled workers, GitHub Apps, queue consumers, dashboards, policy
engines, workflow runners, and human review UIs.

## Agentic DevOps Thesis

Most agents are DevOps reconcilers, not chat personas. They observe GitHub and
evidence state, compare it with policy, plan a change, execute through scoped
tools, verify the result, and record a handoff. Model reasoning is most useful
for ambiguous triage, repository-specific recon, patch planning, and failure
analysis. Deterministic tools and Governor decisions remain authoritative.

The fork organization is the managed environment. Agents continuously reconcile
upstream default branches, security overlays, workflow definitions, build
outputs, attestations, releases, and watch state.

## Machine-Readable Registry

The first registry lives at
[`policies/agent-registry.json`](../policies/agent-registry.json). It defines
the agents, their owned artifacts, input and output events, tools, and human
gates.

`assured-downstream self-test` validates that the registry loads, required
agents are present, handoff invariants exist, and mutation-capable agents are
identifiable.

## Project Finding And Intake

Project finding is a continuous process, not a one-shot seed parse.

Discovery sources:

- awesome lists
- package indexes
- security advisory feeds
- GitHub search and topic queries
- maintainer or user nominations
- existing downstream demand
- abandoned but important project lists
- internal case-study targets

The Source Discovery Agent turns those sources into seed batches with
attribution. The Catalog Ingestion Agent normalizes repositories, deduplicates
identity, enriches metadata, and records freshness. The Triage Agent scores
projects and explains selection, suppression, or review decisions.

The output of intake is not "a list." It is a catalog with enough evidence for
the Governor Agent to decide whether a project may enter the downstream lane.

## Event Model

Agents communicate through state transitions and artifacts. The event names can
change, but the shape should stay explicit.

```text
DiscoveryRequested
  -> SeedBatchReady
  -> CatalogUpdated
  -> RepoCandidateReady
  -> CandidateSelected | CandidateSuppressed | NeedsHumanReview
  -> ForkReady
  -> SyncReady
  -> CheckoutAnalyzed
  -> OverlayProposed
  -> ToolPinsReady
  -> PatchRendered
  -> PatchReady
  -> PublicationAuthorizationRequested
  -> SecureBranchPublicationAuthorized
  -> SecureBranchPublished
  -> ReleaseProfileDrafted
  -> ReleaseConfirmed
  -> BuildArtifactsReady
  -> TraceReady
  -> ReleaseEvidenceReady
  -> GatePassed | GateBlocked
  -> ReleasePublished
  -> ForkPresentationReady
  -> ProjectWatched
```

Recurring events:

```text
UpstreamChanged
AdvisoryFound
ToolRefreshDue
PolicyRefreshDue
RebuildRequested
```

Failure events:

```text
SyncConflict
InsufficientSignal
PatchNeedsReview
BuildFailed
TracePolicyFailed
EvidenceVerificationFailed
RebuildMismatch
BehaviorMismatch
ForkPresentationFailed
```

## Agent Lanes

### Discovery Lane

Agents:

- Source Discovery Agent
- Catalog Ingestion Agent
- Triage Agent
- Governor Agent

Core artifacts:

- seed batch
- catalog
- score report
- selection reasons
- run index

The lane answers: "What projects should we spend downstream assurance work on,
and why?"

### Fork And Sync Lane

Agents:

- Fork And Sync Agent
- Watch Agent
- Governor Agent

Core artifacts:

- fork plan
- sync plan
- lifecycle state
- branch lineage
- conflict packets

The lane answers: "Can we safely track upstream without clobbering our secure
branches or pretending to own upstream?"

### Analysis And Patch Lane

Agents:

- Recon Agent
- Overlay Planner Agent
- Patch Agent
- Tooling Curator Agent
- Governor Agent

Core artifacts:

- recon report
- artifact candidates
- workflow risk signals
- overlay plan
- render result
- pin lockfile
- release profile

The lane answers: "What is the smallest useful hardening delta, and can it be
rendered safely?"

### Publication Authorization Lane

Agents:

- Publication Request Agent
- Publication Authorization Agent
- Secure Branch Publisher Agent

Core artifacts:

- canonical publication request
- protected-workflow dispatch record
- Sigstore/in-toto authorization bundle
- authorization verification record
- one-time consumption ledger entry
- exact-lease remote transition evidence

The lane answers: "Did an independent protected identity authorize this exact
patch, target, ref, old remote state, and evidence set, and can that authority be
consumed only once?"

### Build And Evidence Lane

Agents:

- Build Agent
- Trace Agent
- Attestation Agent
- Repro Agent
- Release Agent
- Governor Agent

Core artifacts:

- build logs
- artifacts
- SBOMs
- in-toto statements
- SLSA provenance
- signatures
- trace reports
- evidence manifest
- verification guide
- release evaluation
- reproducibility comparison

The lane answers: "What was built, from what, by whom, under what controls, and
can the claim be independently checked?"

### Publication And Stewardship Lane

Agents:

- Fork Publication Agent
- Watch Agent
- Governor Agent
- Triage Agent

Core artifacts:

- fork landing metadata
- upstream lineage and overlay summaries
- evidence links and optional fetch instructions
- custodian review packet
- externally supplied custody contact evidence when applicable
- naming and trademark review

The lane answers: "How do we make the fork self-explanatory and useful without
contacting maintainers or overclaiming authority?"

## Tool Surfaces

Current local CLI tools are early adapters:

- `agent-run`, `checkout-run`, `patch-run`, `publication-run`, `agent-worker`,
  `agent-status`
- `ingest`, `enrich`, `score`, `pilot`
- `plan-forks`, `apply-fork-plan`
- `plan-sync`, `apply-sync-plan`
- `recon`, `analyze-checkout`
- `plan-overlay`, `render-overlay`
- `prepare-patch-approval`
- `dispatch-publication-authorization`, `verify-publication-authorization`
- `resolve-pins`
- `plan-release`, `render-release-workflow`
- `create-evidence`, `create-attestation`, `verify-evidence`
- `evaluate-release`
- `compare-evidence`, `normalize-trace`, `compare-behavior`
- `custodian-review`, `create-project-packet`
- `self-test`

Future system tools should include:

- queue consumers and schedulers
- GitHub App event handlers
- project nomination intake
- policy evaluation service
- evidence indexer
- public report renderer
- sandbox org smoke runner
- independent rebuild runner manager
- trace collector integrations

## Handoff Invariants

Every agent handoff should include:

- run id
- source repository
- upstream ref when known
- downstream fork/ref when known
- input artifact digests
- output artifact paths
- policy decision or next required gate
- human-review-required notes
- immutable approval scope and expected old ref for every mutation

Mutation-capable agents must support dry-run planning. Release-claim agents must
produce evidence before publishing language that implies assurance.

## Full-System Self-Test

The local self-test should grow in layers:

1. Agent registry validation.
2. Fixture ecosystem validation.
3. Evidence gate validation.
4. Local multi-agent replay from seed to passive fork publication packet.
5. Sandbox org replay from project discovery to attested release.
6. Upstream update replay to prove resync and rerun behavior.

The current `self-test` covers the first three and replays the durable intake
lane. Case Study 001 separately proves repeat-safe live fork detection plus the
durable Fork And Sync -> Recon -> Overlay Planner lane over five repositories.
It also proves Patch -> Publication Request and Publication Authorization ->
Secure Branch Publisher locally on Bandit, including policy scope,
deterministic commit creation, CAS, artifact verification, invalid-attestation
refusal, and cross-run replay rejection. Remote authorization is disabled until
the independent gate can operate without authentication switching or
cross-account delegation. The next self-test increment should bring both update
and patch replay into the no-network bundle before the first governed build case
study.

## Validated Case Study

A credible case study should demonstrate the whole system, not just a rendered
workflow.

Minimum case-study path:

1. Source Discovery Agent finds or receives the project.
2. Catalog Ingestion Agent normalizes and enriches it.
3. Triage Agent selects it with explicit reasons.
4. Governor Agent approves onboarding to a sandbox org.
5. Fork And Sync Agent creates or detects the fork and syncs upstream.
6. Recon Agent analyzes the checkout.
7. Overlay Planner and Patch Agent produce the hardening delta.
8. Tooling Curator Agent resolves and validates pins.
9. Human review confirms release workflow and artifact paths.
10. Build, Trace, and Attestation Agents produce evidence.
11. Governor Agent evaluates `Attested`.
12. Release Agent publishes only if the gate passes.
13. Fork Publication Agent writes lineage, overlay, evidence, and optional fetch
    metadata into the downstream fork without outbound contact.
14. Watch Agent detects a simulated or real upstream update and requeues the
    project.

The case study succeeds only if an outside reviewer can follow the artifacts
without trusting the agent transcript.
