# Ansible runbook Heavy profile

The reusable `ansible-runbook-heavy-profile.yml` workflow centrally
orchestrates an infrastructure-backed component runbook on an authorized
self-hosted runner. Callers provide an exact candidate SHA, a protected
absolute inventory path, one exact inventory hostname, and fixed
repository-relative acceptance and cleanup playbooks.

The component repository owns its runbook, assertions, fixtures, and cleanup
implementation. The central workflow owns the immutable checkout, bounded run
identity, Heavy invocation, recovery-cleanup attempt, protected environment,
and normalized evidence. A missing or skipped Heavy job fails the aggregate
profile.

The normalized artifact records the candidate SHA, `heavy` profile, scenario,
target platform, and passed status. It is created only after the component
runbook completes successfully.
