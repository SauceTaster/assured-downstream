# Release Verification Contract

Status: development-stage contract for code-anchored verification of retained
GitHub/Sigstore bundles.

## Trust Root

`policies/release-verification.json` is digest-anchored in the verifier code. It
pins the verifier executable and limits accepted attestations to:

- `SauceTaster/assured-*` target repositories
- the generated Assured Downstream release workflow path
- GitHub Actions OIDC certificates on GitHub-hosted runners
- `secure-v*` tag refs
- SLSA provenance, SPDX 2.3 SBOM, and Assured Downstream release predicates
- the retained Sigstore public-good trusted root embedded in the same policy

Changing that policy or verifier binary requires an explicit code change to the
embedded policy digest.

## Per-Release Binding

The verifier derives the following values from the locally verified evidence
manifest rather than from a separate caller-authored verification document:

- target repository and exact signer workflow
- overlay commit as both signer and source digest
- secure release tag and exact `refs/tags/...` source ref
- every artifact subject name and SHA-256
- the local SPDX SBOM document, including a SHA-256 reference for every release
  artifact
- source repository, upstream commit, overlay commit, workflow ref, and lineage
  assertion in the custom predicate, explicitly classified as workflow-authored
  claims

Every retained bundle is verified from disk with `gh attestation verify
--bundle` inside an isolated temporary home. The command also enforces the exact
certificate identity, OIDC issuer, source ref, source digest, signer digest,
predicate type, pinned custom trusted root, GitHub hostname, and hosted-runner
policy. `gh` makes exact
certificate identity and signer-workflow selectors mutually exclusive, so the
verifier uses the stronger exact certificate SAN and independently checks the
parsed certificate's workflow fields.

The verifier independently parses the JSON result and requires at least one
verified transparency timestamp. All three signed statements must contain
exactly the artifact name/digest set recorded in the evidence manifest.

## Claim Boundary

The verification record separates certificate-backed controls from signed
predicate content. The target repository, signer workflow SAN, hosted-runner
class, source overlay commit, tag ref, transparency timestamp, and artifact
subjects are certificate or signature backed. The upstream repository, upstream
commit, and ancestor assertion are authored by the signing workflow. They are
retained and checked for consistency with the evidence manifest, but
`independently_verified.upstream_lineage` remains `false` until a separate
lineage and workflow-content verifier proves the check actually ran in an
approved workflow implementation.

## Non-Claims

This verifies cryptographic bundle integrity and the GitHub workflow identity.
It does not independently prove upstream ancestry, that the builder was
isolated, that the workflow implementation was approved, that the tooling lock
was current, or that the artifacts are safe. Production `Attested` promotion
remains blocked until those additional code-anchored checks are composed in the
Governor path.

The development policy currently pins one local Homebrew `gh` path and digest.
Deployment packaging must replace that workstation-specific pin with a
portable, reviewed verifier artifact and update the embedded policy digest.
Trusted-root rotation likewise requires a reviewed policy update and embedded
digest change. Verification uses no inherited environment, GitHub credentials,
attestation API lookup, or network-fetched trust root, and every `gh` invocation
has a hard timeout.
