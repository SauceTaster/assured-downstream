# Build Evidence Contract

Status: development-stage contract for the first isolated builder integration.

## Trust Boundary

The control plane does not execute upstream build scripts. An external,
disposable builder produces a build result and evidence directory. The Build
Agent snapshots those inputs once, validates their boundaries, and hands them to
Trace, Attestation, and Governor agents through the durable SQLite runtime.

The production CLI accepts only the declaration `builder.mode =
external-isolated`. That value and the isolation fields are untrusted builder
claims until a code-anchored builder verifier is added. Synthetic
`test-fixture` builders are available only to in-process tests and `self-test`.
Generated workflows also fail closed until their release profile confirms a
digest-pinned builder image and argv-only command. They never interpolate the
repository's suggested shell build commands into the host runner.

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

`evidence-run` currently requires three separate caller-supplied documents:

- attestation verification naming the Sigstore verification type, issuer,
  signer, and every verified artifact SHA-256 subject
- approved-tooling claim binding the tooling-policy and pin-lock digests
- workflow-risk claim binding the analyzed workflow digest and findings

An `ok` boolean without those bindings cannot complete even the input-shape
check. The documents remain untrusted and cannot promote `Attested`.

## Agent Flow

```text
BuildResultRecorded
  -> Build Agent -> BuildArtifactsReady
  -> Trace Agent -> TraceReady
  -> Attestation Agent -> ReleaseEvidenceReady
  -> Governor Agent -> EvidenceCandidateReady | blocked
```

Trace coverage is explicit per process, file, network, and syscall category.
Observed successful network activity under a deny policy, successful privileged
syscalls, or host-sensitive file mutation blocks the lane. Missing collector
coverage is retained as a limitation; it is never presented as proof of absence.

## Non-Claims

Completing this lane does not claim attestation verification, builder isolation,
SLSA Build L3, reproducibility, independent builders, behavior parity, complete
syscall visibility, semantic safety, or a validated security assessment. The
locally generated in-toto statement binds the evidence but is not itself a
Sigstore signature.
The evidence-candidate event cannot route to Release Agent and grants no
assurance. Production promotion requires a future code-anchored verifier to
create the cryptographic and builder verification inputs.
