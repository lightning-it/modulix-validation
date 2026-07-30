# Testing

This repository uses the Lightning IT shared test model.

## Test Profiles

- `pre-commit`
- `validation-matrix`
- `integration-incus`
- `secret-safe-validation`

## Supported Matrix

Operating systems and runners:

- `ubuntu-latest`
- `rhel-9`
- `rhel-10`

Products and runtimes:

- `aap-2.6`
- `aap-2.7`
- `incus`

## When Tests Run

- Normal pull requests run the declared test profiles relevant to changed files.
- Renovate and verified shared-assets or repository-quality synchronization pull requests target `develop` and may auto-merge only after required checks pass.
- `develop` to `main` promotion pull requests run the strongest validation profile for this repository.
- Trusted `main` release workflows build and publish artifacts only after validation succeeds.

## Local Commands

From a clean committed checkout with `origin/develop` available, run the exact
local/CI profile:

```bash
scripts/lit-ci-profile.sh repository-quality
```

This requires Docker or Podman. Before pushing, also run the push-ready gate
with authenticated Copilot and Codex CLIs:

```bash
python3 scripts/lit-push-ready.py push-ready
```

`pre-commit run --all-files` remains an optional fast feedback loop; it is not
the CI-parity boundary. The repository-specific command in
`.lit/push-ready.json` and both required CI workflows invoke the exact profile
above. Do not substitute unrelated toolchains.

Heavy Incus tests require an Ubuntu host or runner with Incus available, suitable images, and repository-specific scenario configuration. They must use sanitized inputs and must not rely on private inventory values.

## Interpreting GitHub Actions

The GitHub Actions matrix is the primary dashboard. Job names should expose the repository class, OS/runtime where applicable, and profile, for example `repository / quality`.

Release evidence is generated during trusted release workflows and attached to or linked from GitHub Releases where the repository publishes release artifacts.
