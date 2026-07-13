# Build Verification Contract

Status: development-stage contract exercised by the Bandit source canary.

## Identity Model

Reusable GitHub Actions attestations have distinct caller and signer
identities. The Builder Verifier Agent preserves all of them:

- caller repository, workflow path, protected ref, and a bounded allowlist of
  exact caller commits
- reusable signer workflow path, signer commit, and exact certificate SAN
- exact upstream source repository, commit, and Git tree in the signed custom
  predicate
- claimed downstream target repository and case identifier
- digest-pinned builder image and immutable handoff-verifier commit

The GitHub certificate proves the caller and reusable signer identities. The
custom predicate signs the upstream source and downstream target fields, but
those fields remain workflow-authored claims until separate lineage and
workflow-content verifiers compose their results.

Policy schema v2 permits repeated executions by listing at most eight sorted,
unique caller commits. The verifier selects the effective caller only from the
retained custom predicate, requires it in that code-anchored allowlist, and uses
the same digest for Sigstore verification, certificate validation, SLSA
provenance validation, and the durable output record. The reusable signer
workflow and certificate identity remain singular.

## Verification

`verify-build-attestations` snapshots and rehashes the evidence manifest,
code-anchored build policy, code-anchored Sigstore trust policy, and pinned
`gh` executable. It uses a clean temporary home with credentials and inherited
loader variables removed. Each retained bundle is verified from disk with:

- exact reusable-workflow certificate identity
- distinct signer-workflow and caller-source commits
- exact protected source ref and GitHub Actions OIDC issuer
- GitHub-hosted runner enforcement
- pinned Sigstore trusted root and transparency timestamp
- exact provenance, SPDX 2.3, or Assured Downstream build predicate type
- exact artifact subject name and SHA-256 set

The verifier separately binds the SPDX document to every artifact, compares the
signed custom predicate with the retained build reports, and independently
reparses every retained raw strace record. Recomputed syscall, signal, exit,
parsed-line, and raw-file totals must exactly match the signed trace summary.

```text
assured-downstream verify-build-attestations \
  --evidence evidence.json \
  --policy policies/build-verification.json \
  --trust-policy policies/release-verification.json \
  --output build-verification.json

assured-downstream build-verification-run \
  --evidence evidence.json \
  --policy policies/build-verification.json \
  --trust-policy policies/release-verification.json \
  --run-dir runs/build-verification
```

The second command first rejects symlinked or multiply linked manifests, then
snapshots the manifest and complete evidence bundle into content-addressed
inputs. It routes `BuildVerificationRequested` through the leased SQLite agent
runtime. Success and rejection are durable terminal events.

## Promotion Boundary

A successful record has status `verified-evidence-candidate`. It does not grant
`Attested`. Promotion remains blocked until independent code verifies source
lineage, approved workflow implementation, builder containment, tooling, and
the collector's resistance to hostile-source tampering. Reproducibility and
semantic safety require separate evidence.
