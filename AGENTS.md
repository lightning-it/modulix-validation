# Agent Instructions

## Repository Purpose

This private repository contains Lightning IT validation harnesses for ModuLix.

Use it for:

- GitHub Actions workflows that run real integration tests
- validation inventories and matrices
- runner-specific preflight contracts
- private artifact references needed by tests

Do not put reusable automation logic here. Reusable runbooks belong in
`modulix-automation`. Role implementation belongs in the collection
repositories. Human operational procedures belong in `modulix-operations-lit`.

## Boundaries

- Keep this repository private unless all environment-specific values have been
  removed.
- Keep secrets out of Git. Use GitHub Secrets, Vault, or short-lived tokens.
- Keep Red Hat downloads, signed URLs, AAP manifests, and RHSM credentials out
  of Git.
- Keep test matrices explicit and reviewable under `inventories/`.
- Prefer copy-paste-ready docs for manual validation commands.

## AAP Incus Nightly

The AAP Incus nightly workflow owns its matrix in:

```text
inventories/nightly/host_vars/ciwkr01.prd.dmz.corp.l-it.io/aap_ci_matrix.yml
```

The workflow must:

- run only on runners with `self-hosted`, `linux`, `x64`, `ubuntu`, `incus`, and
  `nested-virt`
- use short guest hostnames for AAP EDA safety
- keep `hub_seed_collections: false` by default for compatibility tests
- unregister RHEL guests before destroying Incus VMs
- destroy temporary Incus instances by default
- fail early on stale `aap-ci-*` instances

If `rhel_teardown.yml` succeeds, do not run a second RHSM unregister through
`incus exec` during destroy. Incus VM agent availability is not reliable during
late teardown.

## Validation

For workflow and shell changes, run:

```bash
shellcheck .github/scripts/*.sh
git diff --check
```

When `actionlint` is available, run:

```bash
actionlint
```
