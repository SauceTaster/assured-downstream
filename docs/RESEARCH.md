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
