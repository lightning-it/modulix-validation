# Generic collection infrastructure profile

The reusable `collection-molecule-profile.yml` workflow is the versioned
execution contract for repository-owned Heavy and Application Acceptance
Molecule scenarios. It implements the accepted
[Modulix test execution ownership ADR](https://wiki.cloud.l-it.io/wiki/spaces/LIT/pages/2886566105).

Collection repositories retain scenarios, assertions, fixtures, and candidate
builds. `modulix-validation` owns protected execution, runner selection,
concurrency, lifecycle finalization, owner-scoped Incus reconciliation, and
normalized evidence.

## Caller contract

Callers pin the reusable workflow to a full commit SHA and provide:

- `profile`: `heavy` or `application_acceptance`;
- `matrix-json`: a non-empty object with an `include` array;
- `candidate-artifact`: an artifact containing exactly one collection archive
  and `candidate-SHA256SUMS`;
- `source-sha`: the exact 40- or 64-character commit represented by the archive;
- `collection-namespace` and `collection-name` from `galaxy.yml`; and
- `environment-name`: the protected runtime environment.

Every matrix cell contains:

```yaml
runner: [self-hosted, linux, x64, incus]
scenario: example-service_heavy
target: ubuntu-24.04
infrastructure: incus
image: images:ubuntu/24.04
instance_type: container
roles: [example_service]
success_marker: assertions/example-service-heavy.passed
```

`infrastructure` is `incus`, `external`, or `local`. Incus cells must provide
`image` and `instance_type`. The `(scenario, target)` pair must be unique.

The scenario receives `MOLECULE_TEST_OWNER`, run identity, target, image,
instance type, bounded run-unique instance and network names, and
`MOLECULE_TEST_SUCCESS_MARKER`. Its final meaningful verification step must
write non-empty content to the marker. A zero Molecule exit code without that
marker fails the cell, so required validation cannot pass through an internal
skip.

Protected legacy scenarios also receive the same bounded instance as
`INCUS_INSTANCE_NAME`. `INCUS_MODE`, `INCUS_RHEL9_IMAGE`, and
`INCUS_RHEL10_IMAGE` are derived from the validated matrix cell. This keeps
resource and image selection centrally controlled while those component
scenarios migrate to the generic `MOLECULE_TEST_*` names.

## Lifecycle and evidence

The central action runs the scenario with automatic destruction disabled,
captures scenario evidence, destroys resources, and then reconciles only Incus
objects whose `user.molecule-owner` exactly matches the current run owner.
Cleanup is idempotent and never uses a broad name prefix.

Each successful cell uploads a checksum-protected manifest and JUnit document.
The manifest identifies repository, candidate SHA, profile, scenario, target,
infrastructure, image, instance type, roles, owner, run, attempt, lifecycle
exit codes, marker presence, and final result. Raw command logs are not
uploaded because generic logs cannot be proven secret-free.
