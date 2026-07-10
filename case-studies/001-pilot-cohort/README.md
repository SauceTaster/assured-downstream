# Case Study 001: Pilot Cohort

Status: vetted and ready to fork after GitHub organization creation.

## Objective

Validate Assured Downstream against real security projects across Go, Rust,
Python, Java, and .NET before enabling build or repository mutation agents.

## Cohort

| Repository | Ecosystem | Role | License |
| --- | --- | --- | --- |
| `securego/gosec` | Go | Compact release canary | Apache-2.0 |
| `epi052/feroxbuster` | Rust | Multi-platform release stress | MIT |
| `PyCQA/bandit` | Python | Package publication canary | Apache-2.0 |
| `google/tsunami-security-scanner` | Java | Mixed-repository Gradle canary | Apache-2.0 |
| `microsoft/DevSkim` | .NET | CLI and extension release canary | MIT |

`dnSpyEx/dnSpy`, `find-sec-bugs/find-sec-bugs`, and
`security-code-scan/security-code-scan` are stewardship challenge cases. They
are intentionally deferred until the first cohort proves Windows isolation,
fork-of-a-fork lineage, and copyleft obligation handling.

## Validation Performed

- ran Source Discovery against `sbilly/awesome-security`
- persisted 188 candidates through the durable intake agents
- honored the Luna `needs_human_review` result when seed metadata was
  insufficient for license and stewardship decisions
- queried current GitHub repository metadata and exact default-branch commits
- replayed the curated nomination seed through all five durable intake agents;
  exactly five projects were selected and `dnSpyEx/dnSpy` was suppressed
- shallow-cloned all five cohort repositories
- performed non-executing structural recon and Attested release planning
- parsed 19 of 19 cohort GitHub Actions workflows successfully
- identified release profiles for Go, Rust, Python, Java, and .NET
- found 11 upstream artifact candidates across the cohort
- executed no upstream code, builds, forks, or GitHub repository mutations

The real checkouts exposed and drove fixes for GitHub Actions YAML parsing, Go
semantic import version names, mixed-language release-profile priority, and
nested .NET project selection.

The initial run confirmed that GitHub metadata enrichment had to become part of
the durable catalog handoff. After adding `agent-run --enrich`, the final run
completed with live metadata, a required Luna review with no findings, all
Governor checks passed, and ten of ten persisted artifacts re-verified.

## Blocker

GitHub CLI does not provide organization creation. The authenticated
`SauceTaster` account has no current organization, and the in-app GitHub web
session is signed out. Create the free `assured-downstream-labs` organization
through GitHub's organization setup page, owned by `SauceTaster`. After that,
the Fork And Sync Agent can create the five forks idempotently.

## Next Run

1. Verify `SauceTaster` is an owner of `assured-downstream-labs`.
2. Re-run the cohort seed with that organization as the target.
3. Detect any existing forks before mutation.
4. Apply the reviewed fork plan.
5. Verify fork lineage, default branches, and upstream remotes.
6. Start checkout recon and overlay planning from the fork SHAs recorded in
   `cohort.json`.
