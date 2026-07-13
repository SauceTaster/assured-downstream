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

The first `python-wheel-v1` canary ran its collector and build child under the
same unprivileged UID. Exact inventory and parser checks caught corruption but
could not establish tamper resistance against hostile source. The published
`python-wheel-v2` profile replaces that boundary: a root supervisor owns
mode-0700 collector output and invokes only the tracee as UID/GID 65532. Build
artifacts land in a separate disposable tree and are copied through bounded,
no-follow, identity-checked snapshots after strace has reaped the traced process
tree.

The supervisor receives only `CHOWN`, `KILL`, `SETGID`, `SETUID`, and `SYS_PTRACE`
inside the container's private PID namespace. The tracee must report zero
effective capabilities and `NoNewPrivs: 1`. A custom PEP 517 fixture attempts
to signal PID 1, modify the immutable entrypoint, list and write `/out`, and
read `/proc/1/mem`. Run `29221499094` denied every operation during both backend
invocations, observed zero tracee capabilities, `NoNewPrivs: 1`, seccomp mode 2,
and 9,129 parsed trace lines with no parser misses. Registry authentication,
push, and attestation happened only afterward; the pulled registry digest
resolved to the same tested image ID. Independent Sigstore verification bound
the published manifest digest to the expected workflow, source commit, hosted
runner, in-toto statement, and SLSA provenance. This narrows the known same-UID
weakness; it still does not prove resistance to a kernel, runtime, or collector
exploit. The v1 Bandit caller remains disabled during migration.

Because a tracee can request `CLONE_UNTRACED`, `-f` is not treated as a
quiescence guarantee. After strace returns, the PID 1 supervisor kills and
reaps every remaining process in the private namespace before reading the
build-owned artifact tree. Each artifact then requires two identical content
passes plus stable inode, size, mtime, ctime, and link-count metadata.

`python-wheel-v3` is a separate, inactive bootstrap path. It does not modify or
replace the v2 sources. After the same quiescence barrier, it snapshots raw
build output into root-owned `raw-artifacts` and applies the versioned
`python-sdist-pax-v1` transform into root-owned `dist`. Source distributions
are parsed without path extraction. PAX, GNU, sparse, and global extension
headers are rejected or bounded before their bodies are read; gzip/tar/path,
member, payload, and output totals are independently bounded. Release artifacts
must occupy a flat, case-fold-unique namespace. Regular-member and extension
padding must be zero, two tar end-marker blocks are required, and trailing bytes
are drained through the tar stream wrapper so its read-ahead buffer is checked.
The builder retains per-artifact input/output identities and reparses the
canonical output before success. Its publication workflow is restricted to
SauceTaster as both actor and triggering actor and must compare final artifacts
from two complete hostile-fixture executions before registry authentication and
push.

The v3 bootstrap policy intentionally contains no image digest, reusable
workflow, handoff verifier, custom predicate, or build-verification policy.
Those controls remain disabled until the canary-tested registry digest is
published and independently verified. Deterministic SPDX and signed workflow
run claims belong to that second activation phase, not to the bootstrap image.

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
