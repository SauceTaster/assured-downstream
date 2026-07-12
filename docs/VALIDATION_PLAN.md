# Assured Downstream Validation Plan

Status: dev/idea-stage validation plan. The goal is to prove the model works
before making strong public assurance claims.

## Validation Thesis

Assured Downstream is useful if it can repeatedly take an upstream project,
follow it without becoming the authority, add a small hardening overlay, produce
a release with verifiable evidence, and explain the result well enough that a
maintainer or downstream user can independently inspect it.

The first validation target is not "all open source." It is one honest,
evidence-backed case study.

## Validation Tiers

### T0 - Local System Self-Test

Purpose: prove the local agent registry, control plane assumptions, recon,
release planning, rendering, and evidence gates still compose.

Command:

```text
assured-downstream self-test --output-dir ./runs/self-test
```

What it checks:

- the agent registry is loadable and includes required system agents
- agent handoff invariants are declared
- Go, Rust, Python, Java, and .NET fixtures parse structurally.
- Fixture workflows expose artifact candidates.
- Release profiles resolve to known language families.
- Draft attested-release workflows are renderable with pinned actions.
- A local evidence manifest verifies.
- `evaluate-release --target Attested` passes only with verified artifact, SBOM,
  and attestation evidence.

Pass condition: all self-test checks pass and `SELF_TEST_SUMMARY.md` plus
`self-test-result.json` are written.

### T1 - Local Candidate Dry Run

Purpose: prove the agent system can analyze real cloned repositories without
network mutation.

Inputs:

- one awesome-list seed
- an allowlist of 3 to 5 first-lane repositories
- local checkouts of those repositories

Outputs:

- pilot run index
- selection reasons
- agent assignment/handoff record
- recon reports
- overlay plans
- release profiles
- dry-run render results
- passive fork publication packet drafts

Pass condition: every selected candidate has a clear agent-owned next action:
renderable, blocked-with-reason, or human-review-required. No candidate should
fail with an unexplained exception or orphaned handoff.

### T1.5 - Managed Fork Reconciliation

Purpose: prove verified forks can be followed repeat-safely before any build or
release claim is attempted.

Inputs:

- verified fork plan and lifecycle state
- sandbox organization or prefixed personal namespace
- managed local workspace

Outputs:

- durable Fork And Sync, Recon, and Overlay Planner handoffs
- exact upstream, fork-default, mirror, and secure-branch SHAs
- namespaced upstream tags and divergence decision
- exact-SHA recon snapshots, overlay plans, and draft release profiles
- artifact digest verification and same-run resume evidence

Pass condition: repeated reconciliation preserves secure refs, analyzes the
synchronized upstream commit, performs no unapproved remote push, and either
finishes with verified artifacts or routes an explicit conflict to review.

Case Study 001 passed this tier for five Go/Rust/Python/Java/.NET forks on
2026-07-10. This validates reconciliation mechanics, not build safety.

### T1.75 - Governed Local Secure Patch

Purpose: prove immutable analysis can become a narrowly approved secure commit
without executing upstream code or widening approval.

Inputs:

- analysis index with transitive artifact digests
- complete fresh action pin lock whose action/ref coverage matches the supplied,
  digest-verified tooling-policy file
- expiring repository/base/change-scoped approval
- managed secure and synchronized upstream SHAs

Outputs:

- durable Patch, Publication Request, Publication Authorization, and Secure
  Branch Publisher handoffs across two immutable runs
- gate decision and exact rendered-file manifest
- single-parent local secure commit and compare-and-swap result
- canonical publication request, Sigstore authorization verification, one-time
  consumption record, and publication plan or explicit not-requested decision

Pass condition: only exact approved files enter the commit, the secure base
contains the analyzed upstream commit, retries converge on the same commit, all
artifacts re-verify, and no remote ref changes without an authenticated external
authorization revalidated at the Publisher handoff. Executed publication now
requires a pinned protected-workflow Sigstore bundle and shared replay ledger;
exact-lease pushes are still tested only against local bare remotes.

Case Study 001 passed the local portion for Bandit on 2026-07-10. Commit
`a509063a8b80b9c04e6bec990a0108b2f9a0043c` contains three policy-approved
additions and remains unpublished. This is not a build or hardening claim.
External authorization is disabled. Its next validation must prove the approval
gate without authentication switching, cross-account delegation, or an
unapproved access principal before any public ref can move.

### T2 - Sandbox Owner Attested Case Study

Purpose: prove an end-to-end downstream fork can produce evidence.

Inputs:

- a sandbox GitHub organization or temporary prefixed personal namespace
- one small, permissively licensed project with a simple release shape
- approved tooling lockfile
- explicit human confirmation of release workflow and artifact paths

Outputs:

- discovery, catalog, triage, governor, fork/sync, recon, patch, build,
  attestation, release, fork publication, and watch agent handoffs
- idempotent fork or existing-fork detection
- idempotent sync state
- hardened overlay branch
- passive fork metadata and optional secure-branch fetch instructions
- completed attested-release workflow
- artifacts, SBOM, attestations, evidence manifest, and verification guide
- release evaluation showing `Attested` pass
- a case-study report with failure modes and residual risks

Pass condition: a fresh reviewer can verify the released artifact evidence from
the published bundle and reconstruct which agent owned each transition without
trusting the agent transcript.

### T3 - External Review

Purpose: learn whether this is useful and socially acceptable.

Inputs:

- one case-study report
- one public fork publication packet
- one downstream-user verification guide

Pass condition: at least one outside reviewer can answer what changed, what was
verified, what was not verified, and how upstream could fetch the work. Any
confusion becomes a product bug.

## First Case Study Shape

The first case study should be intentionally boring:

- small enough to inspect in one sitting
- active enough that upstream authority is clear
- permissively licensed
- one primary language from the first-lane set
- deterministic or close-to-deterministic build output
- no production secrets or release credentials needed
- reviewers can fetch the secure branch without being asked to trust it

Good candidates are simple CLI tools, small libraries, or applications with
plain GitHub Actions releases. More complex projects like large .NET desktop
applications are useful soon, but they should come after the sandbox path proves
the evidence story.

## Case Study Report Checklist

Every validated case study should include:

- source repository and upstream commit
- downstream repository and overlay branch
- exact files changed by the hardening overlay
- generated workflow pins and pin freshness
- artifact list and SHA-256 digests
- SBOM digest
- attestation references
- local verification command output
- release gate decision
- optional secure-branch fetch commands
- known limitations
- what broke or needed human review
- time and cost to refresh after an upstream update

## Metrics

Track these per case study:

- time from upstream update to downstream evidence bundle
- number of agent interventions
- number of human-review-required items
- number of unsafe workflow findings
- number of failed or stale pins
- number of evidence verification failures
- artifact reproducibility pass/fail once WP11 exists
- behavior reproducibility pass/fail once WP12 exists
- external reviewer comprehension issues

## Claim Discipline

Do not call a project "approved," "safe," "maintained by us," or "validated"
until the matching evidence level is actually met. The earliest public claim
should be narrow: "Assured Downstream produced an attested downstream build for
this upstream commit, with this overlay, and here is how to verify it."
