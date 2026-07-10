# Case Study 001: Pilot Cohort

Status: five pilot forks created and lineage-verified in the temporary
`SauceTaster/assured-*` namespace.

## Objective

Validate Assured Downstream against real security projects across Go, Rust,
Python, Java, and .NET before enabling autonomous build or repository mutation
agents.

## Cohort

| Upstream | Downstream | Ecosystem | Role | License |
| --- | --- | --- | --- | --- |
| `securego/gosec` | [`SauceTaster/assured-gosec`](https://github.com/SauceTaster/assured-gosec) | Go | Compact release canary | Apache-2.0 |
| `epi052/feroxbuster` | [`SauceTaster/assured-feroxbuster`](https://github.com/SauceTaster/assured-feroxbuster) | Rust | Multi-platform release stress | MIT |
| `PyCQA/bandit` | [`SauceTaster/assured-bandit`](https://github.com/SauceTaster/assured-bandit) | Python | Package publication canary | Apache-2.0 |
| `google/tsunami-security-scanner` | [`SauceTaster/assured-tsunami-security-scanner`](https://github.com/SauceTaster/assured-tsunami-security-scanner) | Java | Mixed-repository Gradle canary | Apache-2.0 |
| `microsoft/DevSkim` | [`SauceTaster/assured-DevSkim`](https://github.com/SauceTaster/assured-DevSkim) | .NET | CLI and extension release canary | MIT |

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
- created five prefixed public forks under the authenticated `SauceTaster`
  account and verified each direct upstream parent and initial fork commit
- replayed the durable agent lane with a personal target and prefix; all five
  existing forks were lineage-verified and skipped without duplicate mutation
- executed no upstream code or builds; GitHub mutations were limited to the
  five reviewed fork creations and one case-only name alignment

The real checkouts exposed and drove fixes for GitHub Actions YAML parsing, Go
semantic import version names, mixed-language release-profile priority, and
nested .NET project selection.

The initial run confirmed that GitHub metadata enrichment had to become part of
the durable catalog handoff. After adding `agent-run --enrich`, the final run
completed with live metadata, a required Luna review with no findings, all
Governor checks passed, and ten of ten persisted artifacts re-verified.

## Temporary Namespace

The pilot uses the authenticated personal account because organization creation
was not available in the current GitHub session. The `assured-` prefix reserves
a coherent downstream namespace and keeps the repositories easy to identify.
Fork lineage is preserved so transfer into a future organization can be tested
as a separate governed migration.

## Next Run

1. Bootstrap managed checkouts from the fork SHAs recorded in `cohort.json`.
2. Add explicit `upstream` remotes and verify fast-forward sync planning.
3. Generate per-project hardening overlays without enabling release mutation.
4. Run the first isolated builds and capture in-toto, SLSA, Sigstore, SBOM, and
   syscall evidence.
5. Compare reproducibility and normalized behavior across two independent
   builders before promoting any hardened release.
