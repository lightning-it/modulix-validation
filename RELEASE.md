# Release Model

This repository follows the Lightning IT shared release and quality model.

## Repository Classification

- Repository: `modulix-validation`
- Type: `generic_managed`
- Release type: `none`
- Artifact type: `validation_evidence`
- Visibility: `public`
- Release evidence: `disabled`
- Heavy Incus release validation: `required`

## Branch Flow

- `develop` is the integration branch for normal work, Renovate updates, and centrally managed synchronization.
- `main` is the protected release branch.
- This repository does not publish release artifacts; `main` still represents the protected stable branch.
- A `develop` to `main` promotion PR is created automatically when releasable changes exist.
- The `develop` to `main` PR is a manual gate and must never be auto-merged.
- After `main` changes, a `main` to `develop` backmerge PR is created or updated automatically.
- When a promotion creates a `main`-only merge commit, the backmerge must preserve
  that commit's ancestry even if the `main` and `develop` trees already match;
  otherwise strict up-to-date protection keeps the next promotion PR behind.
- Integration and backmerge PRs may auto-merge only after required checks pass, all review conversations are resolved, and there are no conflicts.

## Mandatory Quality Gates

- Required profiles: `pre-commit, validation-matrix, integration-incus, secret-safe-validation`.
- OS matrix: `ubuntu-latest, rhel-9, rhel-10`.
- Product/runtime matrix: `aap-2.6, aap-2.7, incus`.
- Fork pull requests run validation without publishing credentials.
- Publishing secrets are available only to trusted `main` release workflows.
- GitHub token permissions must stay least-privilege for each workflow.

## Managed Repository Release

- CI validates repository structure and file formats appropriate to the repository contents.
- Generated documentation is maintained by shared-assets-lit.
- Artifact/version behavior is documented in repository-specific files when artifacts are published.

## Release Evidence

Release evidence is disabled because this repository does not publish release artifacts. When release evidence is enabled for a publishing repository, its records include the repository name, repository type, version, tag, commit SHA, workflow run, tested matrix combinations, passed/failed/skipped jobs, built artifacts, published artifacts, changelog link, security scan result, and SBOM/provenance/signature links when available.

Evidence files must not contain tokens, credentials, private inventory values, or secret material.
