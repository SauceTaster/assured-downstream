# Assured Downstream Control

> Development / idea-stage control repository. No project or release is assured
> merely because it appears in this system.

This directory contains the protected authorization workflow template for
Assured Downstream secure-branch publication. No live control deployment is
retained, and the checked-in publication policy is disabled. The template does
not build upstream code and must hold no downstream repository credentials.

`authorize-publication.yml` accepts one canonical publication request, verifies
its supplied SHA-256 digest, waits at the `secure-publication` GitHub environment,
and emits a Sigstore-signed in-toto authorization predicate. The downstream
publisher separately verifies the bundle, exact workflow identity and commit,
GitHub OIDC issuer, source ref, GitHub-hosted runner, request digest, target,
branch, patch commit, expiry, and one-time consumption ledger before a push.

A future gate must satisfy `policies/github-account-boundary.json`, prevent
self-review, disallow administrator bypass, and fail closed when independent
approval cannot be provided without cross-account delegation. Changes to the
workflow require rotating the signer and source commit pins in the downstream
publication policy.
