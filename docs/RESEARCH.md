# Assured Downstream Research Notes

Status: dev/idea-stage notes. These notes record implementation-shaping
research, not final security claims.

## 2026-07-12: Central Reusable Builder Boundary

Question: how should a controlled build service represent a downstream caller,
the source being built, and the workflow that is authorized to sign evidence?

Decision: model them as separate identities. The caller repository and commit
select a job, an exact source repository/commit/tree identifies the input, and
the immutable reusable workflow plus image digest identify the builder. GitHub
OIDC exposes the caller through ordinary workflow claims and the called builder
through `job_workflow_ref` and `job_workflow_sha`; neither substitutes for
independent source-lineage verification.

The first profile is intentionally narrow: Linux/amd64, CPython 3.12, and
pure-Python setuptools/PBR wheel and sdist output. The base image is pinned by
OCI index digest, Python build wheels are exact-version/hash locked, and the
Debian strace and libunwind runtime packages are downloaded by exact version
and verified by SHA-256.
The runtime accepts metadata only, copies a read-only source mount into an
ephemeral workspace, executes one fixed argv under strace, and runs without
network, capabilities, secrets, or a writable root filesystem.

This is a staged bootstrap, not a circular trust claim. The image publication
workflow first produces a GHCR digest and GitHub/Sigstore attestation. A later
commit must pin that resulting digest into the reusable build workflow before
upstream source can execute. Hermetic bootstrap, independent image rebuilds,
and trace equivalence remain later gates.

Sources:

- GitHub reusable workflow OIDC claims:
  https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows
- GitHub artifact attestations with reusable workflows:
  https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/increase-security-rating
- Docker default seccomp profile:
  https://docs.docker.com/engine/security/seccomp/
- Debian bookworm package index and package pool:
  https://deb.debian.org/debian/dists/bookworm/main/binary-amd64/Packages.xz
- Docker Registry HTTP API for the Python base manifest:
  https://registry-1.docker.io/v2/library/python/manifests/3.12.11-slim-bookworm
- PyPI JSON API for locked build wheels:
  https://pypi.org/pypi/build/json

## 2026-07-09: MVP Release Attestation Lane

Question: what should the first working attested-release lane render?

Decision: keep the MVP on GitHub Actions public repositories and render a draft
workflow around `actions/attest@v4`, not the older provenance/SBOM wrapper
actions.

Why:

- GitHub's current artifact attestation docs show `actions/attest@v4` as the
  attestation step for build provenance. Its top-level usage lists
  `artifact-metadata: write`, but the action source uses that permission for
  optional OCI storage records. The file-subject MVP keeps only `id-token`,
  `contents`, and `attestations`; a future container lane must add artifact
  metadata permission explicitly if it enables storage records.
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
predicate, OIDC issuer, hosted-runner, local bundle, and JSON-output controls.
Its identity selector flags are mutually exclusive, so the implementation uses
the exact certificate SAN rather than simultaneously passing the weaker signer
repository/workflow selectors.

Sources:

- GitHub deployment environments:
  https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments
- GitHub deployment environment REST API:
  https://docs.github.com/en/rest/deployments/environments
- GitHub CLI attestation verification:
  https://cli.github.com/manual/gh_attestation_verify
- `actions/attest` custom predicates and bundle output:
  https://github.com/actions/attest

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
untrusted declarations. The code-anchored Sigstore verifier now replaces the
attestation claim document; production `Attested` remains blocked until
separate lineage, workflow, tooling, and builder verifiers are composed. Trace
coverage is recorded by category and remains an observational non-claim until a
real Linux collector and independent comparisons exist.

## 2026-07-12: Retained Sigstore Bundle Verification

Question: which release facts can the control plane establish from retained
GitHub artifact-attestation bundles without trusting a caller-authored `ok`
document?

Decision: execute a digest-pinned `gh attestation verify` against each local
bundle, with an isolated home, blank credentials, forced `github.com` hostname,
exact certificate SAN, GitHub OIDC issuer, hosted-runner requirement, source and
signer commit, tag ref, predicate type, and artifact subject. Parse the JSON
result again in Assured Downstream and require exact certificate fields, a
transparency timestamp, the complete artifact subject set, expected provenance,
the exact retained SBOM, and the custom predicate content.

`--bundle` prevents attestation lookup from becoming the authority. The current
Sigstore public-good trusted root is retained inside the digest-anchored policy
and passed through `--custom-trusted-root`, so the verifier does not discover or
refresh signing authority at runtime. Root rotation requires a reviewed policy
and embedded digest update.

Implementation lessons:

- `--cert-identity` and `--signer-workflow` are mutually exclusive in current
  `gh`; exact SAN plus independent certificate-field checks is the selected
  contract. A live CLI grammar test guards this boundary.
- GitHub documents predicate content as workflow-controlled. A valid signature
  therefore proves who signed a lineage assertion, not that upstream ancestry
  is true. The output record marks upstream lineage as not independently
  verified until a code-anchored lineage and workflow-content check exists.
- An SPDX attestation that merely signs an arbitrary SPDX document is not enough
  to bind release subjects. The generated workflow adds every inventoried
  artifact SHA-256 as an SPDX file and `DESCRIBES` relationship; the verifier
  requires the exact subject name and digest on a file directly described by the
  signed document.
- Test doubles are no longer accepted through the production orchestration API.
  Unit tests patch the verifier symbol explicitly, while the production worker
  always constructs the real verifier.

Sources:

- GitHub CLI attestation verification and JSON policy notes:
  https://cli.github.com/manual/gh_attestation_verify
- GitHub artifact attestation verification:
  https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations
- `actions/attest` retained bundle and SBOM inputs:
  https://github.com/actions/attest
- SPDX 2.3 file checksums and relationships:
  https://spdx.github.io/spdx-spec/v2.3/

## 2026-07-13: Collector And Hostile Build Identity Separation

Question: how can the MVP prevent untrusted build code from editing or killing
its own syscall collector without introducing a privileged sidecar platform?

Decision: version the Python profile instead of silently changing the v1 trust
model. `python-wheel-v2` runs a trusted root supervisor in the container's
private PID namespace and uses strace's `-u` option to launch only the build
tracee as UID/GID 65532. The container drops every capability and restores only
`CHOWN`, `KILL`, `SETGID`, `SETUID`, and `SYS_PTRACE` for the supervisor. The root
filesystem is read-only, `no-new-privileges` remains enabled, source is
read-only, and `/out` is a root-owned mode-0700 bind mount. Untrusted artifacts
are first written to a separate tmpfs and then copied into `/out` through
bounded, no-follow snapshots after the traced process tree exits.

Because Linux permits a tracee to request `CLONE_UNTRACED`, `-f` alone is not a
quiescence guarantee. The root supervisor is PID 1 in a private PID namespace;
after strace returns it kills and reaps every other remaining process before
opening the artifact tree. Artifact snapshots include ctime in their identity
check and require two matching content hashes around the copy.

The profile includes a PEP 517 source fixture that attempts collector signaling,
entrypoint modification, evidence directory listing and writing, and root
process memory access. Its own `/proc/self/status` must show UID/GID 65532, zero
effective capabilities, seccomp filtering, and `NoNewPrivs: 1`. The workflow
does not authenticate to GHCR until the local image passes; after push, it pulls
the registry digest and requires the same image ID before attesting.

Run `29221499094` passed that gate and published manifest
`sha256:18916b853d240d87c653175368bd9a8f54edac8f77553d7c0e2b23abb87d5221`.
Independent verification required its exact workflow certificate identity,
source commit `81ada239c2ea4cb0460e37100ee9dd0b0bc13959`, protected main ref,
GitHub-hosted runner, SLSA v1 predicate, in-toto v1 statement, subject digest,
and Rekor timestamp. The canary, raw traces, Sigstore bundle, trusted-root
snapshot, verification result, and internal checksums are retained in a
development prerelease with archive SHA-256
`d8ad50210bb741be040a3452a9067266be1fa87ed263b36678cf1221dc7c306a`.

This is an MVP containment improvement, not the final observer model. A second
host-level or sidecar collector remains desirable because an in-container root
collector still shares the kernel and container runtime with hostile source.

Sources:

- Docker runtime capabilities and `--cap-add`/`--cap-drop`:
  https://docs.docker.com/engine/containers/run/
- Docker `no-new-privileges` and runtime security options:
  https://docs.docker.com/reference/cli/docker/container/run
- Docker default seccomp profile:
  https://docs.docker.com/engine/security/seccomp/
- Linux Yama ptrace policy and parent/child restrictions:
  https://docs.kernel.org/admin-guide/LSM/Yama.html
- strace `-u` tracee identity option:
  https://man7.org/linux/man-pages/man1/strace.1.html

## 2026-07-13: Deterministic Python Artifact Bootstrap

Question: how should the next Python profile remove the real Bandit sdist and
SPDX drift without rewriting the published v2 evidence or inventing a v3 image
identity before that image exists?

Decision: preserve every v2 source, workflow, and policy pin and build v3 in
parallel. `python-wheel-v3` retains the v2 tracee/collector boundary, snapshots
the build-owned output into root-only `raw-artifacts`, and only after process
quiescence parses and rewrites source distributions into root-owned `dist`.
The parser never extracts archive paths. It spools regular-file payloads under
numeric root-only names, bounds compressed bytes, uncompressed stream bytes,
members, payload, paths, output totals, and PAX metadata, and rejects traversal,
path aliases, case-fold collisions, file/directory prefix collisions, sparse
members, links, special files, special mode bits, global PAX headers, and
malformed gzip/tar. Release output is flat and case-fold unique.

An independent phase-one review found that a post-parse PAX limit was too late:
Python's streaming tar reader could consume the declared extension body first.
The reviewed parser now intercepts PAX, GNU long-name/link, sparse, global, and
Solaris extension types before standard-library body processing. PAX bodies are
limited to 64 KiB, framed and decoded by the strict parser, restricted to one
unchained `path`/`mtime` header set, and only then applied to the following
member. The same review found the publication job lacked the repository's exact
account boundary; both the dispatch actor and rerun triggering actor are now
required to be `SauceTaster` before write permissions can be used.

A follow-up review reported no blocker, high, or medium findings and requested a
complete static extension/rerun test matrix. That matrix now covers GNU
long-name, GNU long-link, old GNU sparse, global PAX, Solaris PAX, chained PAX,
malformed PAX framing/padding, stream and payload limits, and pre-open/mid-copy
artifact mutation. The workflow gate is evaluated for all four combinations of
trusted/untrusted initial and rerun actors without crossing GitHub accounts.

Running that suite under the image's exact CPython 3.12.11 exposed a real
compatibility error: `_fromtarfile` exists in newer `tarfile` implementations
but not 3.12. The parser now reads exactly one 512-byte following header, uses
the public `TarInfo.frombuf` on 3.12, uses the newer dircheck-aware parser when
available, sets the stream offset, and redispatches through
`StrictTarInfo._proc_member`. It also validates regular-member padding, requires
two zero tar end blocks, and drains trailing bytes through `tarfile`'s stream
wrapper so buffered read-ahead cannot hide data. The 16-test/27-subtest v3 suite
passes on CPython 3.12.11 and 3.14.6. The real PyPI Bandit 1.9.4 sdist
canonicalizes on both to 340 members, 5,104,389 payload bytes, and canonical
archive SHA-256
`0ee347951edcca56803fb97271394a14647be70fd1ed9501c735ed8a15dc18f8`.

The canonical output is sorted by UTF-8 path bytes and written as POSIX pax
with fixed `SOURCE_DATE_EPOCH`, root metadata, `0644`/`0755` modes, gzip level
9, no filename field, flags 0, XFL 2, and OS 255. The builder reparses its own
output and requires identical payload semantics plus exact canonical metadata
before exposing it. Original/final digest, size, layout, member count, payload
size, payload digest, and transformation policy are retained per artifact.

The current Bandit sdist is a legacy `setup.py` layout without
`pyproject.toml`, despite carrying Metadata-Version 2.4. The canonicalizer
preserves and labels that legacy layout rather than adding synthetic source
content. Modern sdists must contain `pyproject.toml`; both layouts require one
top-level directory and `PKG-INFO`.

Syft 1.42.3 itself uses the wall clock for `creationInfo.created` and a random
UUID for `documentNamespace`. Phase two will therefore normalize SPDX in a
separate v3 handoff, derive the namespace from canonical semantic document
content, require ISO-8601 UTC creation time derived from `SOURCE_DATE_EPOCH`,
and bind exact artifact paths rather than basenames. The same phase will add a
custom `/build/v2` predicate and label GitHub run, attempt, caller workflow,
and called workflow fields as signed workflow claims until a separate verifier
cross-checks them.

The bootstrap remains non-circular. Run `29230841506` passed the exact-account
gate, hostile identity canary, two same-image exact-artifact executions,
registry pull/image-ID check, and Sigstore attestation. The published manifest
is `sha256:5f52c4bfe05c4947877d6d80f2124062b79a46764cc2161dc4caaa631d65833a`;
online and downloaded-bundle verification bind it to source commit
`e446fd3af7f0ae50acac1f950adcee595eb0edbd`, the expected workflow, GitHub OIDC,
a GitHub-hosted runner, in-toto Statement v1, SLSA provenance v1, and Rekor.

The two raw sdist digests differed while both canonical outputs matched at
`464cd8cd782b552e2f2b6aed14afba625cf9c781c42609ffd8d1389f46b0ffc6`.
The complete final artifact manifest matched at
`598b1b541cc7e5de8a6c25b44cb500abb57a30b16a9f3bb4af7feeaae14ae653`.
The durable 47-file evidence package was downloaded from its prerelease and
replayed successfully; its SHA-256 is
`b6e025db126210da7bffb694376e327bd2f0b1d861de065bca793d8fa087dbae`.
Activation remains disabled. A later phase may reference this exact digest from
a separate v3 handoff and reusable workflow only after deterministic SPDX,
`/build/v2`, and their verifiers are reviewed.

Sources:

- Python source distribution format and POSIX pax requirement:
  https://packaging.python.org/en/latest/specifications/source-distribution-format/
- Python gzip deterministic `mtime` control:
  https://docs.python.org/3/library/gzip.html
- Syft 1.42.3 SPDX creation timestamp implementation:
  https://github.com/anchore/syft/blob/v1.42.3/syft/format/common/spdxhelpers/to_format_model.go
- Syft 1.42.3 random SPDX namespace implementation:
  https://github.com/anchore/syft/blob/v1.42.3/syft/format/internal/spdxutil/helpers/document_namespace.go
- SPDX document namespace and creation-time requirements:
  https://spdx.github.io/spdx-spec/v2.3/document-creation-information/
- GitHub caller, run, attempt, and called-workflow contexts:
  https://docs.github.com/en/actions/reference/workflows-and-actions/contexts
