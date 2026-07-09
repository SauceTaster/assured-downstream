# SauceTotal Intent

Status: early idea/dev stage. This document defines the intended direction and
social contract before the automation is mature enough for production use.

## Mission

Build a public, security-first maintenance network for open source software.

The organization should continuously track upstream projects, produce hardened
downstream releases, publish verifiable build and runtime evidence, and provide
long-term stewardship paths for projects whose maintainers opt in or disappear.

## Ideal

The org acts like an assured downstream distribution for libraries, packages,
CLIs, desktop applications, containers, and security tools.

It should feel closer to a public-interest security foundation than a scanner:
it follows upstream, fixes what can be fixed, rebuilds under stricter controls,
signs artifacts, publishes evidence, and keeps doing the maintenance work.

## Intent

The system exists to make security work happen automatically, respectfully, and
repeatably.

It should:

- help users consume safer versions of important open source software
- help maintainers fetch or merge hardening work without adopting the whole
  system
- preserve upstream as the source of truth when upstream is active
- become a custodian only when maintainers opt in or upstream maintenance has
  meaningfully disappeared
- publish evidence instead of vague trust claims
- prefer small, understandable deltas over invasive rewrites
- treat every target repository and dependency as potentially hostile
- maintain security work continuously, like a downstream distribution

## Anti-Intent

The system should not become:

- a substitute for active, legitimate upstream ownership
- fork squatting
- a noisy pull-request bot
- a vanity scorecard farm
- a release channel that hides downstream patches
- a project that claims "secure" without inspectable evidence
- a scanner that finds issues but never fixes anything

## Stewardship Modes

### Downstream Assured Mode

Upstream is active.

The org tracks upstream, applies security overlays, builds hardened releases,
publishes evidence, and offers fetchable deltas. It does not claim to be the
official upstream.

### Maintainer-Aware Mode

Upstream maintainers acknowledge the downstream work, fetch from it, or use
parts of it, but ownership remains upstream.

### Opt-In Supported Mode

Maintainers explicitly ask the org to provide release, build, or security
support. The org may own some automation while the project remains upstream-led.

### Custodian Mode

Upstream is archived, abandoned, unresponsive, or unable to keep up with known
security needs.

The org maintains a clearly named continuation fork, publishes the reason for
custody, preserves upstream lineage, and remains open to coordination if
upstream resumes.

### Adopted Project Mode

Maintainers transfer ownership or delegate long-term stewardship. The project
becomes an official project under the org with governance, maintainers, release
policy, and security policy.

## Custodian Criteria

Before moving a project into Custodian Mode, the system should produce a public
evidence packet covering:

- last upstream commit and release dates
- maintainer response attempts
- unresolved critical vulnerabilities or high-impact maintenance gaps
- stale pull requests or issue queue evidence
- license compatibility
- naming and trademark risk
- user demand or ecosystem relevance
- a clear statement of what the downstream fork changes and does not change

## Language Rules

Use careful language until a project opts in.

Preferred terms:

- hardened fork
- assured downstream
- security-maintained distribution
- continued fork
- custodian fork

Reserved terms:

- official
- upstream
- project owner

Those reserved terms are only appropriate when maintainers transfer or delegate
that status.

## Public Promise

For each supported project and release, the org should make the following clear:

- upstream source commit or release
- downstream security overlay
- produced artifacts and hashes
- SBOMs
- SLSA provenance
- in-toto attestations
- Sigstore signatures or equivalent signatures
- runtime trace summary
- reproducibility status
- validation status
- remaining risks
- fetch instructions for maintainers
