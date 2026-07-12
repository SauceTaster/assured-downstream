# Assured Downstream Research Notes

Status: dev/idea-stage notes. These notes record implementation-shaping
research, not final security claims.

## 2026-07-09: MVP Release Attestation Lane

Question: what should the first working attested-release lane render?

Decision: keep the MVP on GitHub Actions public repositories and render a draft
workflow around `actions/attest@v4`, not the older provenance/SBOM wrapper
actions.

Why:

- GitHub's current artifact attestation docs show `actions/attest@v4` as the
  attestation step for build provenance, with required `id-token`, `contents`,
  and `attestations` permissions.
- `actions/attest` supports provenance, SBOM, and custom-predicate modes through
  one action surface.
- `actions/attest-sbom` is documented as being deprecated in favor of
  `actions/attest`.
- GitHub's SLSA Level 3 guidance emphasizes reusable workflows plus artifact
  attestations. Assured Downstream should not jump straight to that for the first MVP;
  the immediate lane should produce useful attested evidence and leave reusable
  workflow isolation as the next hardening step.
- Syft remains a reasonable SBOM engine for the MVP, and Anchore's action exposes
  `format` and `output-file` inputs that fit Assured Downstream's evidence manifest
  model.

MVP implication:

- Add a draft release profile planner from recon evidence.
- Render one pinned `assured-downstream-attested-release.yml` workflow.
- Mark generated release workflows as human-review-required.
- Require full SHA pins for `actions/checkout`, `actions/attest`,
  `actions/upload-artifact`, and `anchore/sbom-action`.
- Treat `actions/attest` as the first attestation backend instead of building a
  separate signing service. It already emits signed in-toto statements in
  Sigstore bundles, uploads them to GitHub, and supports SLSA provenance, SBOM,
  and custom predicate modes.
- Capture each generated bundle through the action's `bundle-path` output and
  upload it with the release evidence.
- Add an Assured Downstream custom predicate for the applied release policy.
- Do not publish releases automatically in this slice.
- Do not claim SLSA Build L3 in this slice. Builder/attester isolation and
  reusable workflow hardening remain a separate assurance improvement.

Sources:

- GitHub artifact attestations:
  https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations
- GitHub SLSA Level 3 with artifact attestations:
  https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/increase-security-rating
- `actions/attest`:
  https://github.com/actions/attest
- `actions/attest-sbom` deprecation note:
  https://github.com/actions/attest-sbom
- SLSA GitHub Generator:
  https://github.com/slsa-framework/slsa-github-generator
- Syft:
  https://github.com/anchore/syft
- Anchore SBOM Action:
  https://github.com/anchore/sbom-action
- Sigstore Cosign quickstart:
  https://docs.sigstore.dev/quickstart/quickstart-cosign/

## 2026-07-11: Publication Authorization Trust Boundary

Question: how can a local agent prove that a human gate authorized one exact
secure-branch transition without treating a local boolean or unsigned JSON as
authority?

Decision: split patch creation and publication into separate durable runs. A
public control repository hosts a static, SHA-pinned `actions/attest@v4`
workflow behind a protected GitHub environment. The exact publication request
is the attestation subject; a custom predicate repeats the critical target,
branch, patch, request id, request digest, decision, and environment.

Verification policy:

- require the exact certificate SAN for the control workflow and source ref
- pin both signer and source repository commit digests
- require the GitHub Actions OIDC issuer and reject self-hosted runners
- require the custom predicate type and one exact request subject digest
- require a verified transparency timestamp
- revalidate request target scope, patch/base/upstream SHAs, expected remote
  state, evidence/policy digests, canonical request id, and expiry
- snapshot request, bundle, policy, and verifier binary once before parsing or
  execution
- anchor the accepted policy SHA-256 in the installed code so a caller cannot
  nominate both a verifier binary and its digest
- derive the one-time consumption ledger from the operating-system account,
  rather than accepting a caller-selected path
- recheck authorization and work-lease deadlines immediately before a
  timeout-bounded exact-lease push

GitHub environments can require reviewers, prevent the dispatcher from
approving its own run, and disallow administrator bypass. A deployment must also
satisfy the repository's account-boundary policy. `gh attestation verify`
exposes the required certificate identity, signer/source digest, source ref,
predicate, OIDC issuer, hosted-runner, offline bundle, and JSON-output controls.
Its identity selector flags are mutually exclusive, so the implementation uses
the exact certificate SAN rather than simultaneously passing the weaker signer
repository/workflow selectors.

## 2026-07-12: GitHub Account Isolation

Decision: one workspace operates through one explicitly configured GitHub
actor. Agents must verify that actor before mutation, must never switch
authentication, and must not manufacture independent approval by adding or
using another user account. If a required approval cannot be implemented inside
that boundary, publication fails closed.

The development publication policy is disabled and no live control deployment
is retained. Re-enabling it requires a new account-isolated approval design and
a fresh validation case.

## 2026-07-12: Build And Attestation Separation

Decision: upstream build code must not execute in the control-plane process or
in the same permission domain as OIDC attestation. Generated workflows use a
read-only build job, an unprivileged artifact-inspection/SBOM job, and a final
job with attestation permissions. Checkout credentials are not persisted into
the builder's source mount, and artifact inventories are verified after SBOM
generation and again before attestation.
The durable runtime ingests immutable outputs from an external builder that
declares isolation instead of treating local command execution as isolation.
That declaration remains untrusted until builder identity is verified.
Draft workflows refuse to execute until a digest-pinned builder image and
argv-only command are reviewed. Confirmed execution uses a read-only source
mount, no network, dropped capabilities, no-new-privileges, resource limits, and
an unprivileged user; the privileged attestation job never checks out source or
runs a third-party artifact parser.

The evidence-candidate validator requires the local manifest to verify, every
artifact digest to appear in a represented Sigstore subject set,
approved-tooling policy and lock digests, and a workflow-risk result bound to
the analyzed workflow. Those documents and builder-isolation fields remain
untrusted declarations. Production `Attested` remains blocked until a
code-anchored verifier creates those results and verifies builder identity.
Trace coverage is recorded by
category and remains an observational non-claim until a real Linux collector
and independent comparisons exist.

Sources:

- GitHub deployment environments:
  https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments
- GitHub deployment environment REST API:
  https://docs.github.com/en/rest/deployments/environments
- GitHub CLI attestation verification:
  https://cli.github.com/manual/gh_attestation_verify
- `actions/attest` custom predicates and bundle output:
  https://github.com/actions/attest
