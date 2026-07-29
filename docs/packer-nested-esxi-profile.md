# Packer nested ESXi Heavy profile

The reusable `packer-nested-esxi-profile.yml` workflow owns the GitHub Actions
orchestration for real Packer builds on nested ESXi. The caller supplies an
exact 40-character candidate commit, the exact 40-character
`modulix-validation` commit used by the caller's reusable-workflow pin, one
supported build target, a protected environment, and explicitly mapped
secrets.

The Packer templates and deterministic Heavy entry point remain in the caller
repository. The central workflow owns the runner selection, immutable checkout,
pinned infrastructure dependency, execution gate, and normalized evidence.
It checks out the validation toolchain and its hash lockfile at the supplied
validation commit; caller and validation revisions must never be inferred from
the same GitHub context because they belong to different repositories.
The component entry point must perform exact-name, owner-scoped cleanup in an
`EXIT` trap.

A run can pass only after the real component entry point exits successfully and
`evidence/heavy-result.json` identifies its candidate SHA, `heavy` profile,
`nested-esxi` scenario, and target platform. Skipped or missing execution fails
the aggregate profile job.
