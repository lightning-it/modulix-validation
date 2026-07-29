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

- Normal pull requests run pre-commit, linting, syntax checks, and light tests relevant to changed files.
- Renovate and verified shared-assets or repository-quality synchronization pull requests target `develop` and may auto-merge only after required checks pass.
- `develop` to `main` promotion pull requests run the strongest validation profile for this repository.
- A reviewed temporary backmerge branch synchronizes protected `main` ancestry before promoting a diverged `develop` branch.
- Trusted `main` release workflows build and publish artifacts only after validation succeeds.

## Local Commands

Run pre-commit locally:

```bash
pre-commit run --all-files
```

Run repository-specific light checks from the checked-out repository:

```bash
bash scripts/wunder-devtools-ee.sh true
```

Heavy Incus tests require an Ubuntu host or runner with Incus available, suitable images, and repository-specific scenario configuration. Heavy tests must use sanitized inputs and must not rely on private inventory values.

## Packer Runtime Lock

The reusable Packer Heavy profile installs its Python 3.11 runtime from
`.github/requirements/collection-quality-profile.lock` with
`--require-hashes`. Regenerate that lock for the workflow's target interpreter,
not the maintainer's local Python version:

```bash
uv pip compile \
  --python-version 3.11 \
  --generate-hashes \
  --no-emit-index-url \
  --output-file .github/requirements/collection-quality-profile.lock \
  .github/requirements/collection-quality-profile.in
```

The `validation / Packer runtime lock` CI job verifies a clean installation in
a new Python 3.11 virtual environment. It must pass before a revised lock can
be used by a protected Heavy run.

## Interpreting GitHub Actions

The GitHub Actions matrix is the primary dashboard. Job names should expose the repository class, OS/runtime, and profile, for example `ansible / rhel9 / molecule-heavy-incus` or `container / ubuntu / build-smoke`.

Release evidence is generated during trusted release workflows and attached to or linked from GitHub Releases where the repository publishes release artifacts.
