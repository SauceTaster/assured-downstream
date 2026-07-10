# Agent Runtime

Status: executable dev/idea-stage runtime. It is safe for local dry-run intake
and planning, not production GitHub mutation.

## What Exists

The first live agent lane is:

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
input and output digests. Failed work is retried up to its declared attempt
limit and then dead-lettered.

The lane produces dry-run fork and sync plans only. It cannot mutate GitHub.

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

Inspect the durable state or verify the model profile:

```text
assured-downstream agent-status \
  --database ./runs/intake-002/agent-control-plane.sqlite3

assured-downstream codex-preflight
```

## Current Limits

- only the discovery-to-dry-run-fork-plan lane is hosted by the runtime
- discovery currently accepts local or HTTPS awesome-list style sources;
  remote responses are size-bounded and obvious local/private targets are
  rejected
- GitHub metadata enrichment can run inside the Catalog Ingestion handoff with
  `--enrich`; tokens are read from an environment variable and never persisted
- live fork creation, syncing, and repository mutation remain outside this lane
- SQLite is single-host orchestration
- Luna advisory is implemented for triage; later recon and patch agents will
  use the same driver where deterministic tools cannot resolve ambiguity

The next runtime increment is idempotent sandbox-org fork detection and live
sync behind a reviewed mutation capability, followed by recon and overlay
agents over the resulting checkout.
