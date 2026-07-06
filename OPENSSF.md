# OpenSSF Readiness

This repository follows the Lightning IT shared OpenSSF readiness model generated from `lightning-it/shared-assets-lit`.

## Repository

- Repository: `modulix-validation-lit`
- Visibility: `private`
- Type: `private_infrastructure`
- Release type: `none`
- Artifact type: `validation_evidence`

## Scorecard

Not enabled by default for this private repository. Private repositories require GitHub Advanced Security or an explicit local exception before publishing Scorecard results.

The Scorecard badge is included in `README.md` only for public repositories where the workflow is synced.

## Best Practices Badge

Not applicable unless this private repository is intentionally published as an open-source product.

Do not add a passing OpenSSF Best Practices badge until the repository is actually enrolled and passing.

## Security Policy

`SECURITY.md` describes supported versions, vulnerability reporting, coordinated disclosure, supported artifact scope, and the distinction between public repository content and private customer or infrastructure data.

## Branch Protection And Release Integrity

- `main` is the protected release branch.
- `develop` is the integration branch for normal work, Renovate, and shared-assets-lit PRs.
- `develop` to `main` promotion PRs require manual review.
- Renovate and shared-assets-lit PRs may auto-merge only into `develop` after required checks pass.
- Releases and publishing happen only from trusted `main` workflows after validation.
- Release evidence is generated for repositories with release artifacts.

## Dependency Automation

Dependency automation must target `develop` and must not bypass required checks. Coverage should include GitHub Actions, language dependencies, Ansible content, container base images, pre-commit hooks, and documentation tooling where applicable.

## Security Scanning

Secret-safe validation only; no private inventory values or customer data may be exposed.

## Exceptions

Repository-specific exceptions must be documented in this file or in `.lit/repository.yml`. Exceptions must not expose secrets, private infrastructure details, customer data, or credential-bearing examples.
