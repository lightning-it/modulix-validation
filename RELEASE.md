# Release Model

This repository follows the Lightning IT shared release and quality model.

## Repository Classification

- Repository: `modulix-validation-lit`
- Type: `private_infrastructure`
- Release type: `none`
- Artifact type: `validation_evidence`
- Visibility: `private`
- Release evidence: `disabled`
- Heavy Incus release validation: `required`

## Branch Flow

- `develop` is the integration branch for normal work, Renovate updates, and shared-assets-lit synchronization.
- `main` is the protected release branch.
- This repository does not publish release artifacts; `main` still represents the protected stable branch.
- A `develop` to `main` promotion PR is created automatically when releasable changes exist.
- The `develop` to `main` PR may auto-merge only after current-revision Copilot review, required checks, and conversation resolution.
- After `main` changes, a `main` to `develop` backmerge PR is created or updated automatically.
- Backmerge PRs may auto-merge only when required checks are green and there are no conflicts.

## Mandatory Quality Gates

- Required profiles: `pre-commit, validation-matrix, integration-incus, secret-safe-validation`.
- OS matrix: `ubuntu-latest, rhel-9, rhel-10`.
- Product/runtime matrix: `aap-2.6, aap-2.7, incus`.
- Fork pull requests run validation without publishing credentials.
- Publishing secrets are available only to trusted `main` release workflows.
- GitHub token permissions must stay least-privilege for each workflow.

## Private Infrastructure Safety

- Do not copy secrets or private inventory values into public repositories.
- Release and testing documentation must stay generic.
- CI must avoid printing host-specific or credential-bearing inventory values.
- Shared workflows may be consumed only when they protect private data by default.

## Release Evidence

Release evidence is disabled because this repository does not publish release artifacts. Evidence records the repository name, repository type, version, tag, commit SHA, workflow run, tested matrix combinations, passed/failed/skipped jobs, built artifacts, published artifacts, changelog link, security scan result, and SBOM/provenance/signature links when available.

Evidence files must not contain tokens, credentials, private inventory values, or secret material.
