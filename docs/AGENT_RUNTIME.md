# Agent Runtime

Status: executable dev/idea-stage runtime. It supports dry-run intake, guarded
checkout reconciliation, governed local secure-branch commits, and durable
release-evidence ingestion. It is not ready for production GitHub branch
mutation or in-process execution of upstream build scripts.

## What Exists

The durable intake lane is:

```text
DiscoveryRequested
  -> Source Discovery Agent -> SeedBatchReady
  -> Catalog Ingestion Agent -> CatalogUpdated
  -> Triage Agent -> CandidateSelected
  -> Governor Agent -> GatePassed:CandidateSelected
  -> Fork And Sync Agent -> ForkPlanReady
```

Each arrow is persisted in SQLite as an immutable event. Each agent invocation
is a leased work item with an attempt record. Successful work atomically writes
its output events, content-addressed artifact records, and a handoff containing
input and output digests. Output events durably bind the producer agent and exact
successful attempt. Failed work is retried up to its declared attempt limit and
then dead-lettered.

The intake lane produces dry-run fork and sync plans only. It cannot mutate
GitHub.

The managed-checkout lane is:

```text
UpstreamChanged
  -> Fork And Sync Agent -> SyncReady
  -> Recon Agent -> CheckoutAnalyzed
  -> Ecosystem Profiler Agent -> BuildProfilesPlanned
  -> Overlay Planner Agent -> AnalysisBundleReady
```

This lane consumes a digest-pinned fork plan and fork lifecycle state. Explicit
`--execute-sync` permits clone/fetch and local ref mutation after lineage gates
pass. It preserves `secure/<default>`, mirrors the fetched upstream commit at
`upstream/<default>`, records tag and divergence evidence, and performs no
remote pushes. Recon inspects a detached analysis worktree pinned to the SHA in
the sync handoff. Managed artifacts live beneath an attempt-specific directory.
Run creation records the run root's device/inode identity; persistence,
verification, reads, and writes reopen each path component through no-following
directory descriptors anchored to that identity. Recon and profiling hold a
pinned analysis-directory descriptor and inspect source from that directory
object. Every downstream consumer requires the artifact reference attempt to
match the durable producing event, then verifies the artifact digest before
reading it.

Patch creation and remote publication are separate durable runs so a protected
approval can arrive later without changing immutable run configuration:

```text
PatchApprovalRecorded
  -> Patch Agent -> PatchReady
  -> Publication Request Agent -> PublicationAuthorizationRequested

PublicationAuthorizationRecorded (external Sigstore bundle)
  -> Publication Authorization Agent -> SecureBranchPublicationAuthorized
  -> Secure Branch Publisher Agent
       -> SecureBranchPublicationPlanned | SecureBranchPublished
```

The approval binds the analysis index, nested overlay digest, fresh pin lock,
tooling-policy digest, repository, upstream SHA, secure base, exact change IDs,
 expiration, and publication decision. The patch-side agents verify the lock's complete
action/ref coverage against the supplied digest-verified tooling-policy file.
Automated policy approval is limited to known additive templates with exact
action/path contracts and no review marker; it cannot authorize a push. The
Patch Agent writes Git objects through a
temporary index, creates a deterministic single-parent commit, and advances
`secure/<default>` with compare-and-swap. It never checks out or executes
upstream files. Publication Request creates an expiring canonical request that
also binds the patch result and publication-policy digests, but cannot mutate a
remote. The remote authorization deployment is disabled. Its verifier and
publisher mechanics remain fail-closed until an account-isolated gate replaces
it.

Publication Authorization snapshots every input once and verifies the pinned
`gh` binary, build-anchored policy digest, exact certificate SAN, signer/source
commit, source ref, GitHub OIDC issuer, GitHub-hosted runner, predicate type,
subject digest, predicate scope, transparency timestamp, and expiry. Publisher
accepts only its typed event, rechecks the immutable authorization record,
reserves the request in a code-derived per-account one-time ledger, and uses an
exact ref plus expected remote SHA. It rechecks authorization and worker
deadlines immediately before a timeout-bounded push, isolates Git configuration,
rejects repository URL rewrites, and pushes the approved object ID rather than a
mutable local ref. A crash after the push can reconcile only the same
run/work/request tuple; cross-run replay is blocked.

The release-evidence lane treats build execution as a separate trust domain:

```text
BuildResultRecorded (external builder declaring isolation)
  -> Build Agent -> BuildArtifactsReady
  -> Trace Agent -> TraceReady
  -> Attestation Agent -> ReleaseEvidenceReady
  -> Release Verifier Agent -> ReleaseAttestationsVerified
  -> Governor Agent -> EvidenceCandidateReady | blocked
```

The Build Agent snapshots the build result, artifacts, SBOMs, signed bundles,
raw traces, reports, a digest-anchored release-verification policy, and two
caller-supplied policy documents. It
rejects path escape, symlinks, mutable snapshots, and builder declarations that
do not state isolation, no secret exposure, and denied network. These
declarations are not independent proof of containment. Trace records measured
collector coverage and blocks
successful network activity under deny policy, privileged syscalls, and
host-sensitive file mutation. Attestation creates a portable evidence manifest,
an unsigned local binding statement, and a verification guide. Release Verifier
uses the pinned `gh` binary to validate the retained provenance, SPDX, and custom
Sigstore bundles plus their exact certificate, artifact-subject, SPDX-reference,
and statement bindings. Upstream ancestry in the custom predicate is retained as
a signed workflow claim, not independent lineage proof. Governor then requires
internally complete tooling and workflow-risk input shapes before it emits a
non-authoritative evidence candidate. That event has no Release Agent route;
code-anchored lineage, builder, tooling, and workflow verification remain
required for production promotion.

## Why Custom SQLite First

The MVP needs durable replay, idempotency, leases, retry history, and auditable
handoffs. Python and SQLite provide those properties without another runtime,
broker, sidecar, container, or operational dependency. The implementation uses
WAL mode, full synchronous writes, foreign keys, immediate transactions, and
payload hashes.

Before a run is marked successful, every recorded artifact is re-hashed. Agent
outputs are immutable snapshots; later agents write new artifacts rather than
editing earlier handoff files. Selection policy is also copied into the event
stream before the Governor decision so policy files cannot drift mid-run.

This is deliberately a backend, not the architecture. `AgentBackend` is the
boundary between handlers and durable orchestration. Agent handlers do not
depend on SQLite directly.

SQLite is appropriate while workers run on one host and throughput is modest.
It is not the multi-host queue. A distributed backend must replace it before
several machines can claim work concurrently.

## Dapr Decision

Dapr is deferred, not rejected. Its workflow engine is attractive for durable
multi-application workflows, retries, child workflows, and long-running state.
Its self-hosted mode still adds a sidecar per service and normally brings
supporting services such as Redis and Zipkin; Kubernetes adds the Dapr control
plane. That is too much machinery for proving the first lane.

Reconsider Dapr when any two of these are true:

- workers must claim work across multiple hosts
- the system is deployed on Kubernetes
- workflows routinely wait days for human approval
- per-agent scaling and service identity are operational requirements
- SQLite write contention is measured rather than hypothetical
- a broker is already operated for other organization services

The relevant upstream documentation is the
[self-hosted overview](https://docs.dapr.io/operations/hosting/self-hosted/self-hosted-overview/),
[sidecar model](https://docs.dapr.io/concepts/dapr-services/sidecar/), and
[workflow architecture](https://docs.dapr.io/developing-applications/building-blocks/workflow/workflow-architecture/).

## Codex And Luna

Codex runs behind a constrained driver for judgment-heavy work. The default
profile is `assured-downstream-luna`, configured for `gpt-5.6-luna` with high
reasoning effort. In Codex CLI, `-p` selects a named profile; noninteractive
workers use `codex exec`.

The repository profile template is
`config/codex/assured-downstream-luna.config.toml`. Install it as
`$CODEX_HOME/assured-downstream-luna.config.toml`, or under `~/.codex` when
`CODEX_HOME` is unset.

Every invocation uses:

- approval policy `never`
- ephemeral session state
- read-only sandbox
- a 90-second default timeout
- a closed JSON output schema
- a fresh output file

The current Triage Agent uses Luna as an advisory reviewer over compact typed
candidate data. Repository text is treated as untrusted data. Luna cannot
change selection, pass a gate, or mutate a repository. Deterministic scoring,
selection policy, the Governor Agent, and tool adapters remain authoritative.

Modes:

- `off`: deterministic execution only; used by self-test and replay
- `advisory`: continue if Luna is unavailable, recording the failure
- `required`: retry and eventually dead-letter if Luna cannot return a valid
  structured result

## Commands

Run the complete local lane:

```text
assured-downstream agent-run \
  --seed awesome-security.md \
  --org <org> \
  --run-dir ./runs/intake-001 \
  --enrich
```

Target the currently authenticated personal account with prefixed repository
names:

```text
assured-downstream agent-run \
  --seed awesome-security.md \
  --user <github-user> \
  --name-prefix assured- \
  --run-dir ./runs/intake-personal \
  --enrich
```

Separate enqueueing from workers:

```text
assured-downstream agent-run \
  --seed awesome-security.md \
  --org <org> \
  --run-dir ./runs/intake-002 \
  --enqueue-only

assured-downstream agent-worker \
  --database ./runs/intake-002/agent-control-plane.sqlite3 \
  --run-id <run-id>
```

Reconcile verified forks and continue through recon and overlay planning:

```text
assured-downstream checkout-run \
  --fork-plan ./runs/intake-personal/fork-plan.json \
  --state ./runs/intake-personal/state.json \
  --workspace ./worktrees \
  --run-dir ./runs/checkout-sync-001 \
  --run-id checkout-sync-001 \
  --execute-sync
```

Repeating the command with the same run id and exact configuration resumes the
durable run. A completed run claims no new work.

Prepare and apply a policy-approved additive patch locally:

```text
assured-downstream prepare-patch-approval \
  --analysis-index ./runs/checkout-sync-001/analysis-index.json \
  --pins ./runs/pins.json \
  --tooling-policy ./policies/approved-tooling.json \
  --repository <owner/repo> \
  --output ./runs/patch-approval.json \
  --auto-approve-safe

assured-downstream patch-run \
  --analysis-index ./runs/checkout-sync-001/analysis-index.json \
  --pins ./runs/pins.json \
  --tooling-policy ./policies/approved-tooling.json \
  --approval ./runs/patch-approval.json \
  --publication-policy ./policies/publication-authorization.json \
  --workspace ./worktrees \
  --run-dir ./runs/patch-001 \
  --execute-patch
```

Omitting `--execute-patch` plans without moving the local secure ref. There is
no patch-run publication switch. A human-record patch approval can request
publication, but only the separate protected-workflow authorization lane can
route work to Publisher.

```text
assured-downstream dispatch-publication-authorization \
  --request ./runs/patch-001/publication-request.json \
  --publication-policy ./policies/publication-authorization.json \
  --output ./runs/patch-001/authorization-dispatch.json \
  --execute

assured-downstream publication-run \
  --request ./runs/patch-001/publication-request.json \
  --bundle ./authorization.sigstore.json \
  --publication-policy ./policies/publication-authorization.json \
  --checkout ./worktrees/repository \
  --workspace ./worktrees \
  --run-dir ./runs/publication-001 \
  --execute
```

Inspect the durable state or verify the model profile:

```text
assured-downstream agent-status \
  --database ./runs/intake-002/agent-control-plane.sqlite3

assured-downstream codex-preflight
```

## Current Limits

- intake, fork-sync/recon/overlay-planning, governed additive patch request,
  authorization verification, one-time secure publication mechanics, and
  build-result/trace/attestation/Governor evidence ingestion are hosted by the
  runtime; remote authorization is disabled, and isolated builder execution,
  repository-specific patching, release, and watch adapters remain
- discovery currently accepts local or HTTPS awesome-list style sources;
  remote responses are size-bounded and obvious local/private targets are
  rejected
- GitHub metadata enrichment can run inside the Catalog Ingestion handoff with
  `--enrich`; tokens are read from an environment variable and never persisted
- live fork creation remains a separately guarded adapter; managed checkout and
  local secure commits are live; authorization verification and exact-lease
  publication are locally validated but remote authorization is disabled and no
  public secure ref has moved
- SQLite is single-host orchestration
- deterministic policy owns additive patch approval; Luna remains advisory and
  later repository-specific patch agents will
  use the same driver where deterministic tools cannot resolve ambiguity

The next runtime increment is an external disposable Linux builder adapter for
the retained Bandit commit. Publication authorization remains a separate
account-isolation design problem and is not a prerequisite for build evidence.
Scheduled upstream-change ingestion follows once that pilot path is proven.
