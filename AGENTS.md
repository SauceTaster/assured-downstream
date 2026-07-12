# Repository Agent Rules

## GitHub Account Boundary

- The only GitHub identity authorized to mutate resources from this workspace is
  `SauceTaster`.
- Before every `gh` mutation or remote Git mutation, verify the active identity
  with `gh api user --jq .login` and fail closed unless it is exactly
  `SauceTaster`.
- Never run `gh auth switch`, authenticate as another GitHub user, accept an
  invitation through another user, or use another user's credentials.
- Never add an outside user account as a collaborator, environment reviewer,
  release approver, or other access principal on a SauceTaster repository.
- Mutate only owners allowed by `policies/github-account-boundary.json`.
- If a control requires an independent identity that is unavailable within this
  boundary, leave the control disabled and ask for a new design. Do not create
  separation by crossing accounts.
- Read-only access to public upstream repositories is allowed. These rules apply
  to authentication, authorization, invitations, approvals, and mutations.

