# modulix-validation-lit

<!-- BEGIN LIT_SHARED_RELEASE_MODEL -->

## Release and Quality Model

This repository follows the Lightning IT shared release and quality model.

See [RELEASE.md](./RELEASE.md) for:

- branch and release flow
- required quality checks
- test matrix
- release evidence
- artifact publishing
- supported repository-specific release behavior

Repository classification: **Private Infrastructure Repository**.
Required test profiles: `pre-commit, validation-matrix, integration-incus, secret-safe-validation`.
Publishing targets: `none`.

## Supported and Tested Platforms

| Platform / Product | Status | Validation |
|---|---:|---|
| ubuntu-latest | Supported | Molecule / Incus |
| rhel-9 | Supported | Molecule / Incus |
| rhel-10 | Supported | Molecule / Incus |
| aap-2.6 | Tested where applicable | Molecule / Incus |
| aap-2.7 | Tested where applicable | Molecule / Incus |
| incus | Tested where applicable | Molecule / Incus |

Private repository note: generated docs must stay generic and secret-safe.
<!-- END LIT_SHARED_RELEASE_MODEL -->

<!-- BEGIN LIT_QUALITY_BADGES -->

No public badges are shown for this private repository. Quality status is reported through internal GitHub checks and `RELEASE.md` / `TESTING.md`.

<!-- END LIT_QUALITY_BADGES -->

# Internal Use Only

Private Lightning IT validation harnesses for ModuLix.

This repository owns real nightly and integration validation workflows. It is
separate from:

- `modulix-automation`: public reusable runbooks and orchestration code
- `ansible-collection-*`: role implementation and collection-level tests
- `modulix-operations-lit`: internal operator documentation and procedures

## Current Validation

- AAP Incus Nightly Matrix

## Layout

```text
.github/workflows/                         GitHub Actions workflows
.github/scripts/                           workflow runner scripts
inventories/nightly/                       validation inventory and matrices
docs/                                      validation documentation
```

## Required Secrets

Set these secrets on `lightning-it/modulix-validation-lit`:

- `MODULIX_REPO_READ_TOKEN`: token that can read private Lightning IT
  repositories used by the workflow.
- `RH_AUTOMATION_HUB_TOKEN`: Red Hat offline token for certified collection
  installation.

Optional:

- `RHSM_ORG_ID`: overrides the validation inventory RHSM org.
- `AAP_CI_ADMIN_PASSWORD`: fixed test admin password.
- `VAULT_TOKEN`: only needed when a validation runbook reads Vault-backed values.
- `AAP_26_BUNDLE_URL` / `AAP_26_BUNDLE_SHA256`: AAP 2.6 bundle artifact.
- `AAP_27_BUNDLE_URL` / `AAP_27_BUNDLE_SHA256`: AAP 2.7 bundle artifact.
- `RHEL_9_INCUS_METADATA_URL` / `RHEL_9_INCUS_METADATA_SHA256`: RHEL 9 Incus metadata artifact.
- `RHEL_9_INCUS_QCOW2_URL` / `RHEL_9_INCUS_QCOW2_SHA256`: RHEL 9 Incus qcow2 artifact.
- `RHEL_10_INCUS_METADATA_URL` / `RHEL_10_INCUS_METADATA_SHA256`: RHEL 10 Incus metadata artifact.
- `RHEL_10_INCUS_QCOW2_URL` / `RHEL_10_INCUS_QCOW2_SHA256`: RHEL 10 Incus qcow2 artifact.

## License

This repository is proprietary and private. Do not redistribute.

## Security

See [SECURITY.md](./SECURITY.md) for supported versions and vulnerability reporting.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for contribution and review expectations.

<!-- BEGIN LIT_RELEASE_QUALITY_MODEL -->

## Release and Quality Model

This repository follows the Lightning IT shared release and quality model.
The README shows the current supported and tested matrix.
Exact per-version validation proof is stored with each GitHub Release as `release-evidence.md` and `release-evidence.json`.
Releases are created from the protected `main` branch after a reviewed `develop -> main` release promotion.
Repository checks validate the managed structure, documentation, and release model for this repository type.

See:

- [RELEASE.md](./RELEASE.md)
- [TESTING.md](./TESTING.md)
- [GitHub Releases](../../releases)

Repository classification: **Private Infrastructure Repository**.
Required test profiles: `pre-commit, validation-matrix, integration-incus, secret-safe-validation`.
Publishing targets: `none`.

Private repository note: generated docs must stay generic and secret-safe.
<!-- END LIT_RELEASE_QUALITY_MODEL -->

<!-- BEGIN LIT_COMPATIBILITY_MATRIX -->

## Compatibility Matrix

| Platform / Product | Status | Validation |
|---|---:|---|
| ubuntu-latest | Supported | Molecule / Incus |
| rhel-9 | Supported | Molecule / Incus |
| rhel-10 | Supported | Molecule / Incus |
| aap-2.6 | Tested where applicable | Molecule / Incus |
| aap-2.7 | Tested where applicable | Molecule / Incus |
| incus | Tested where applicable | Molecule / Incus |

Validation proof for each released version is stored in the corresponding GitHub Release evidence.

<!-- END LIT_COMPATIBILITY_MATRIX -->

## Release Evidence

This repository does not publish release artifacts by default; release evidence is recorded when artifact releases are enabled.
The evidence records:

- tested matrix combinations
- GitHub Actions run links
- artifact references
- publish status
- security scan status

See [GitHub Releases](../../releases), [RELEASE.md](./RELEASE.md), and [TESTING.md](./TESTING.md) for the release process and validation model.
