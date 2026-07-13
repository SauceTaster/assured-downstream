# Ecosystem Build Profiles

Status: development-stage Java and .NET profiling contract. No policy in this
document authorizes source execution or a release claim.

## Purpose

The Ecosystem Profiler Agent turns exact-source recon into a machine-readable
answer to a narrow question: what would have to be fixed, selected, pinned, and
verified before this repository may enter an isolated build canary?

It is one agent in the system, not a replacement for the system:

```text
Source Reacquirer / Fork And Sync
  -> Recon
  -> Ecosystem Profiler
  -> Overlay Planner
  -> Material Resolver + Tooling Curator
  -> Governor
  -> isolated Build canary
  -> Trace + Attestation + Builder Verifier
  -> Repro + Governor
```

Recon and overlay work may continue when a profile is blocked. A blocked
profile may not enter the build execution plane.

## Decision Contract

Each `ecosystem-build-profile.json` binds the source repository, full commit,
Git tree, and complete filesystem inventory; hashes the source manifests it
read; names one policy pack; records structural signals; and emits:

- `blockers`: requirements that forbid even a target-specific build canary
- `canary_requirements`: facts that only isolated execution can establish
- `review_items`: source behavior that must remain visible but is not itself an
  execution authorization
- `next_handoffs`: the exact agent responsible for each blocker
- `canary_admission_candidate`: true only when no blocker remains and an
  independently reviewed policy permits asking Governor for one exact canary
- `execution_permitted`: always false in a structural profile; only a separate
  digest-bound Governor admission may authorize execution
- `release_eligible`: always false at this stage

A drafted argv is an inert proposal. Build must reject a profile by itself even
when `build_plan.steps` is populated; it must consume a separate, one-request
Governor admission bound to the profile, source, materials, and builder.

## Trust Boundaries

The profiler never invokes Maven, Gradle, `dotnet`, MSBuild, a wrapper, a
project script, or source code. It uses bounded descriptor reads, rejects
symlinked profile inputs, refuses XML entities, and records file digests.

The future builder must not run directly from a read-only source mount because
Maven and MSBuild write project-local outputs. A trusted supervisor must:

1. Verify the accepted source inventory.
2. Copy it into private tmpfs with only root-confined relative symlinks.
3. Verify the copy before changing ownership to the unprivileged build UID.
4. Verify and copy sealed dependency materials into a private writable cache.
5. Keep collector output inaccessible to the build UID.
6. Run the fixed argv with no network, no ambient credentials, and an allowlisted
   environment.
7. Quiesce the build process tree before a trusted collector snapshots outputs.

The original source and material bundles remain read-only evidence inputs.

## Material Resolution

Dependency resolution is a separate, quarantined networked phase owned by the
Dependency Material Resolver Agent. It must produce a source-bound lock and an
immutable offline bundle containing every dependency, plugin, analyzer, build
task, POM, SDK/runtime pack, and transitive material needed by the selected
profile.

The resolver may not pass credentials into the build. Authenticated or
non-public feeds, insecure repositories, missing content hashes, signature
exceptions, or source-controlled credentials block for review. Offline build
failure never falls back to the network.

## Java Maven v1

`policies/ecosystems/java-maven-v1.json` supports a single root Maven project.
Multi-module reactors and Gradle remain blocked in this first increment.

The proposed Maven invocation:

- uses an absolute Maven path from a future digest-pinned builder
- supplies sealed user and global settings
- uses strict checksums and offline mode
- uses a copied, digest-verified local repository
- fixes locale, timezone, home, Java home, and PATH
- forces release activation false and tests enabled
- excludes signing, staging, deployment, site deployment, and source/Javadoc
  release attachments
- selects one exact primary JAR or WAR name when the POM makes that possible

Project `.mvn/maven.config`, `.mvn/jvm.config`, and `.mvn/extensions.xml` files
are blocked because they can inject arguments or code outside the fixed argv.
Parent POMs, profile-level build output overrides, and plugin configuration that
can rename, relocate, replace, or attach artifacts block selection until the
Material Resolver supplies a digest-bound effective model and collector
contract. Root-level nonliteral names and non-default directories also block.
Maven build extensions, JDK-conditional models, random tests, and archive
timestamps remain explicit canary or reproducibility concerns.

## .NET v1

`policies/ecosystems/dotnet-v1.json` requires explicit selection when a source
tree has multiple projects, target frameworks, runtime identifiers, or both
`pack` and `publish` outputs. Publish also requires an explicit
self-contained/framework-dependent decision.

The proposed .NET invocation:

- uses an absolute `dotnet` path from a future digest-pinned SDK image
- restores with `--locked-mode` from a generated offline NuGet configuration
- requires `packages.lock.json` and package content hashes for the full selected
  project and test closure
- disables failed-source fallback and network access
- runs tests with `--no-restore`
- sets continuous-integration, deterministic, and path-map properties
- requires an exact recursive output manifest before release eligibility

Source-controlled NuGet credentials and MSBuild response files are blockers.
Target frameworks and runtime identifiers must be bounded literal CLI tokens;
option-like, expression-bearing, whitespace, and control values produce no build
steps.
Conditional MSBuild elements, package-provided build tasks, and source `Exec`
tasks require isolated trace evidence. External Azure templates and signing or
publishing jobs are recon evidence only; the downstream profile does not call
them or receive their credentials.

## Real Repository Decisions

Structural profiles were generated at exact commits without executing source:

- `OWASP/json-sanitizer@fc612ab...`: selected as the first Maven specimen. It
  has one exact primary JAR, but remains blocked on a builder digest, complete
  Maven material lock, and policy promotion. Its Nexus build extension and
  legacy JDK-conditional target require canaries; release/sign/deploy scripts
  are explicitly excluded.
- `microsoft/DevSkim@17706a8...`: the CLI publish profile explicitly selects
  `net10.0`, `linux-x64`, and self-contained output. It remains blocked on a
  builder digest, NuGet/package locks, a sealed material bundle, and its
  authenticated Azure feed. External pipeline templates and first-party
  signing are not reused.
- `google/tsunami-security-scanner@363ba87...`: remains the Gradle stress case,
  not the first Java execution canary. It has no wrapper, dependency locks, or
  closed builder and includes an external source-control dependency.

These are useful blocked results. They validate that repository selection and
profiling can discover the work without silently converting uncertainty into a
build.

## CLI

```text
assured-downstream plan-build-profile \
  --path /path/to/checkout \
  --source-repository owner/repo \
  --source-commit <full-commit> \
  --source-git-tree <full-tree> \
  --output ecosystem-build-profile.json

assured-downstream plan-build-profile \
  --path /path/to/dotnet-checkout \
  --source-repository owner/repo \
  --source-commit <full-commit> \
  --source-git-tree <full-tree> \
  --target path/to/Tool.csproj \
  --operation publish --target-framework net10.0 \
  --runtime-identifier linux-x64 --self-contained \
  --portable --output ecosystem-build-profile.json
```

Retained case-study profiles additionally pass a fixed `--generated-at` value,
which makes a future byte-comparison replay well-defined. Canonical network
reacquisition is still required because source bytes are not copied into this
repository. This case study does not retain an independently reacquired second
run and makes no byte-identical real-case replay claim.

## Next Increment

1. Implement the quarantined Material Resolver and signed material-lock schema.
2. Publish and hostile-test digest-pinned JDK/Maven and .NET SDK builders.
3. Run JSON Sanitizer and DevSkim target-specific canaries with complete syscall
   and network-denial evidence.
4. Bind exact output manifests, SPDX, SLSA/in-toto predicates, and Sigstore
   bundles into the existing v3 verifier contract.
5. Rebuild each accepted artifact on a genuinely separate executor before any
   host-independence or reproducibility claim.
