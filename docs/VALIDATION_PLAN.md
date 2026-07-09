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
- liaison packet drafts

Pass condition: every selected candidate has a clear agent-owned next action:
renderable, blocked-with-reason, or human-review-required. No candidate should
fail with an unexplained exception or orphaned handoff.

### T2 - Sandbox Org Attested Case Study

Purpose: prove an end-to-end downstream fork can produce evidence.

Inputs:

- a sandbox GitHub org
- one small, permissively licensed project with a simple release shape
- approved tooling lockfile
- explicit human confirmation of release workflow and artifact paths

Outputs:

- discovery, catalog, triage, governor, fork/sync, recon, patch, build,
  attestation, release, liaison, and watch agent handoffs
- idempotent fork or existing-fork detection
- idempotent sync state
- hardened overlay branch
- draft maintainer fetch instructions
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
- one maintainer-facing liaison packet
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
- maintainers can fetch the proposal branch without being asked to trust it

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
- maintainer fetch commands
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
- maintainer or external reviewer comprehension issues

## Claim Discipline

Do not call a project "approved," "safe," "maintained by us," or "validated"
until the matching evidence level is actually met. The earliest public claim
should be narrow: "Assured Downstream produced an attested downstream build for
this upstream commit, with this overlay, and here is how to verify it."
