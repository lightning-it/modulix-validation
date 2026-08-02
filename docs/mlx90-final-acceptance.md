# MLX-90 finalizer library (inert core)

## Current stage

B1 adds an uninvoked library above A: no workflow, eligible profile, network,
signing, upload, promotion, or callback. B2 adds tests; C activates it.

## Fail-closed library contract

The library validates bounded strict JSON, immutable evidence, exact variants,
run-owned receipts, OCI/BuildKit bindings, reports, and terminal documents.

Raw OCI bytes are hashed before decoding. Outputs are create-new and path-free
in diagnostics. Atomic publication, cleanup, and paired rollback are
device/inode-bound. Receipt snapshots, digests, run identity, freshness, and
revocation state are cross-bound and fail closed.

Digest-bound inputs use one non-following, bounded regular-file snapshot for
digest, size, and parsing, with device/inode/time stability checks. Downloaded
release assets, including the collection, are capped at 10 MiB; other
OCI/BuildKit inputs are capped at 64 MiB. Symlinks, FIFOs, devices, oversized
or changing inputs fail with fixed value-free diagnostics.

## Verification

```bash
python3 -m unittest \
  tests.test_mlx90_delivery tests.test_mlx90_finalizer_smoke \
  tests.test_mlx90_finalizer
python3 scripts/lit-repository-quality.py
```

## References

- MLX-90 ADR: <https://wiki.cloud.l-it.io/wiki/spaces/LIT/pages/2894659587>
- REL-20 implementation status:
  <https://wiki.cloud.l-it.io/wiki/spaces/LIT/pages/2894790704>
- Governance issue:
  <https://github.com/lightning-it/github-management-lit/issues/267>
- Producer repair:
  <https://github.com/lightning-it/ansible-collection-supplementary/pull/595>
