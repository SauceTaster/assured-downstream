# Build Evidence Contract

Status: development-stage contract for the first isolated builder integration.

## Trust Boundary

The control plane does not execute upstream build scripts. An external,
disposable builder produces a build result and evidence directory. The Build
Agent snapshots those inputs once, validates their boundaries, and hands them to
Trace, Attestation, Release Verifier, and Governor agents through the durable
SQLite runtime.

The production CLI accepts only the declaration `builder.mode =
external-isolated`. That value and the isolation fields are untrusted builder
claims until a code-anchored builder verifier is added. Synthetic
`test-fixture` builders are available only to in-process tests and `self-test`.
Generated workflows also fail closed until their release profile confirms a
digest-pinned builder image and argv-only command. They never interpolate the
repository's suggested shell build commands into the host runner.

The central Python build service is a reusable workflow with three permission
domains. Its build job accepts only repository, commit, tree, version, and case
metadata; executes a fixed image entrypoint under a no-network container; and
has no OIDC or attestation permission. A token-permissionless inspection job
generates and binds the SPDX document. A final job receives keyless attestation
permission but never checks out or executes source. Each handoff is revalidated
by code fetched from an immutable control-plane commit and checked against
hardcoded file digests.

The caller workflow identity, exact built source identity, upstream lineage
claim, reusable workflow signer identity, handoff-verifier commit, and builder
image digest are distinct fields. A successful workflow does not collapse
these into one authority. The first Bandit source canary deliberately builds
the exact upstream commit because the governed downstream overlay remains
unpublished.

The development reusable workflow is allowlisted to that exact caller workflow
and Bandit request. General agent dispatch remains disabled until a signed,
replay-resistant build-request verifier replaces the static allowlist. The
pinned image entrypoint invokes strace; the parser recognizes syscall, signal,
and process-termination records while failing closed on any other line. The
handoff verifier requires retained raw trace files and a complete parser pass
before evidence can reach attestation. This demonstrates observed collection,
not independent proof that the collector or container boundary was
uncompromised.

The development image currently runs its collector supervisor and build child
under the same unprivileged UID. The child can therefore discover and attempt
to modify collector-owned paths on the shared writable output mount. Exact
inventory and parser checks catch accidental corruption but do not establish
tamper resistance against hostile source. Production builder verification must
separate the collector and build identities, make raw evidence inaccessible to
the build identity, and exercise an adversarial tamper canary before promoting
this collector beyond a builder declaration.

## Build Result

```json
{
  "schema_version": 1,
  "status": "succeeded",
  "project": {
    "source_full_name": "owner/project",
    "target_full_name": "SauceTaster/assured-project",
    "upstream_ref": "40-hex source commit",
    "overlay_ref": "40-hex built commit",
    "release_tag": "secure-v1.0.0+downstream.1"
  },
  "builder": {
    "mode": "external-isolated",
    "builder_id": "pinned-builder-image-or-workflow-identity",
    "isolated": true,
    "secrets_exposed": false,
    "network_policy": "deny",
    "workspace_root": "/workspace"
  },
  "evidence": {
    "artifacts": ["dist/project.whl"],
    "sboms": ["sbom/project.spdx.json"],
    "attestations": ["attestations/project.sigstore.json"],
    "raw_traces": ["traces/raw.json"],
    "reports": ["reports/builder.json"]
  }
}
```

Every evidence path is relative to `--evidence-root`. Absolute paths, parent
traversal, symlinks, missing files, changed snapshots, and builder declarations
that do not state isolation, no secret exposure, and denied network fail closed.

## Verification Inputs

`evidence-run` requires one code-anchored policy and two caller-supplied claim
documents:

- release-verification policy that pins the verifier and exact allowed GitHub
  signer namespace, workflow, tags, predicates, issuer, and runner class
- approved-tooling claim binding the tooling-policy and pin-lock digests
- workflow-risk claim binding the analyzed workflow digest and findings

The Release Verifier derives Sigstore results by executing the pinned verifier;
the tooling and workflow-risk documents remain untrusted and cannot promote
`Attested`.

## Agent Flow

```text
BuildResultRecorded
  -> Build Agent -> BuildArtifactsReady
  -> Trace Agent -> TraceReady
  -> Attestation Agent -> ReleaseEvidenceReady
  -> Release Verifier Agent -> ReleaseAttestationsVerified
  -> Governor Agent -> EvidenceCandidateReady | blocked
```

Trace coverage is explicit per process, file, network, and syscall category.
Observed successful network activity under a deny policy, successful privileged
syscalls, or host-sensitive file mutation blocks the lane. Missing collector
coverage is retained as a limitation; it is never presented as proof of absence.

## Non-Claims

Completing this lane verifies the retained GitHub/Sigstore attestations but does
not claim independent upstream ancestry, builder isolation, SLSA Build L3,
reproducibility, independent builders, behavior parity, complete syscall
visibility, semantic safety, or a validated security assessment. Upstream
lineage in the custom predicate is a signed workflow claim until a separate
code-anchored lineage and workflow verifier confirms it. The locally generated
in-toto statement binds the evidence but is not itself a Sigstore signature.
The evidence-candidate event cannot route to Release Agent and grants no
assurance. Production promotion still requires code-anchored lineage, builder,
tooling, and workflow verification.
