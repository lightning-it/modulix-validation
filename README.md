# modulix-validation-lit

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

## License

This repository is proprietary and private. Do not redistribute.
