# Public Workbench Acceptance

## Purpose

The private `Workbench Public Acceptance` workflow verifies the application
state of `wbn01.prd.edge.pub.l-it.io` from a GitHub-hosted Ubuntu controller.
The physical Workbench is always the managed target and is never used as the
GitHub Actions runner.

This harness composes automation owned by `modulix-automation`; it does not
copy reusable deployment or validation logic into this repository.

## Safety Boundary

The workflow has three independent execution guards:

1. The job uses the protected `workbench-public-acceptance` GitHub Environment.
2. The dispatcher must type the exact target FQDN.
3. The Python harness accepts only the checked-in public inventory, exact
   target FQDN, public address, SSH port, `svc_ansible` SSH user, and exclusive
   `ubuntu_workbenches` membership.

The harness also requires `GITHUB_ACTIONS=true` and
`RUNNER_ENVIRONMENT=github-hosted`. It always passes one literal
`--limit wbn01.prd.edge.pub.l-it.io`; a host pattern or group limit cannot be
supplied through workflow inputs.

The inventory preflight rejects local/non-SSH connections, password-based
Ansible credentials, extra hosts in the Workbench group, and any target alias,
address, port, or deploy-user drift. The controller also forces the SSH
transport and strict host-key checking.

Cross-repository checkouts are pinned to `develop`. Arbitrary repository refs,
playbook paths, inventories, targets, tags, or extra variables are not workflow
inputs. The playbook locations remain explicit and reviewable in
`inventories/acceptance/workbench-public.yml` and must resolve beneath the
checked-out automation repository.
The harness additionally requires the exact repository root names and all four
fixed Workbench playbook paths; the matrix cannot redirect execution to a
different checked-out playbook.

## Execution Sequence

Before any deployment, the harness requires all configured files and runs
syntax checks for:

- `20-ubuntu-setup.yml`
- `30-validate.yml`
- `40-acceptance.yml`
- `50-cleanup.yml`

It then runs this fixed lifecycle:

1. Complete deployment playbook in check mode.
2. Complete deployment playbook normally.
3. Complete deployment playbook a second time; aggregate `changed` must be
   exactly zero.
4. Strictly read-only validation; aggregate `changed` must be zero.
5. Selected `tiny`, `heavy`, or `application` acceptance profiles against the
   already-built Workbench.
6. Ownership- and run-ID-checked cleanup for every selected profile.

Every non-syntax phase must return exactly one Ansible Runner host statistic
for the declared Workbench. Missing statistics or statistics for any other
host fail closed before an idempotence result can be accepted.

Acceptance profiles are not deployment tags. Each profile is passed only as
`workbench_acceptance_profile`, together with the sanitized
`workbench_acceptance_run_id`. The `application` profile requires a declared
repository URL, exact commit, and Molecule scenario, then executes the pinned
repository lint, smoke, and Molecule gates. Missing or invalid declarations
fail closed.

Cleanup runs from the Python harness `finally` path. A separate GitHub Actions
`always()` step repeats the idempotent cleanup contract to cover a failed or
interrupted main step before controller credentials are removed. Each cleanup
profile has its own 15-minute limit, so one stuck cleanup cannot consume the
attempts reserved for the remaining selected profiles; the final workflow step
also has a bounded 55-minute budget.

## Protected Environment

Create the private GitHub Environment `workbench-public-acceptance` with
required reviewers and deployment-branch restrictions. Add these Environment
Secrets:

- `LIT_REPOSITORY_READ_TOKEN`: read-only access to the automation, inventory,
  and Ubuntu collection repositories.
- `WORKBENCH_DEPLOY_SSH_PRIVATE_KEY`: the existing `svc_ansible` deployment
  private key accepted by the Workbench.
- `WORKBENCH_SSH_KNOWN_HOSTS`: a pre-verified known-hosts entry for
  `[195.201.173.85]:1905`.

The workflow materializes the SSH files with mode `0600` only for the job and
deletes them in an unconditional final step. Secret environment variables are
scoped to the materialization step. The harness additionally purges
secret-shaped variables before importing or invoking `ansible-runner`, then
passes an explicit nonsecret environment allowlist to Ansible.

## Evidence Contract

The workflow uploads only the two sanitized JSON summaries produced by the
main run and the final cleanup. A summary contains:

- phase status and return code
- host-aggregate Ansible recap counters
- bounded static labels for `assert` and `command` tasks
- selected profiles, safe run ID, timestamps, and matrix digest
- cleanup status and a stable error code

It never contains raw inventory, host variables, module results, stdout,
stderr, credentials, private keys, known-hosts content, or raw Ansible Runner
events. Runner artifacts exist only in mode-`0700` temporary directories and
are removed after each phase. Raw controller logs must not be uploaded.

## Dispatch

From GitHub Actions, select `Workbench Public Acceptance`, choose one profile
or `all`, enter `wbn01.prd.edge.pub.l-it.io`, and request the run. An
Environment reviewer must inspect and approve the deployment before secrets
are available.

## Local Validation

Local tests never connect to or modify the Workbench:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m py_compile .github/scripts/workbench-public-acceptance.py
python3 scripts/lit-repository-quality.py
actionlint .github/workflows/workbench-public-acceptance.yml
git diff --check
```

The harness intentionally refuses a real local execution because only a
protected GitHub-hosted controller is authorized.
