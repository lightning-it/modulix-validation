# MLX-90 final acceptance contract (inert foundation)

## Current stage

This branch is the first, deliberately inert part of the MLX-90 final-acceptance
stack. It defines data contracts only. It does **not** contain the MLX-90
finalizer library, a GitHub Actions workflow, a workflow shell implementation,
or workflow-contract tests. Nothing in this stage can contact GitHub, execute a
container acceptance command, publish evidence, dispatch promotion, or change a
release.

The operational workflow described by the MLX-90 ADR is forward-looking here.
It will be introduced only after the inert finalizer library has landed and the
separate activation change has passed review.

## Contract files present now

| Path | Current purpose |
| --- | --- |
| `acceptance/mlx90/profiles.json` | Declarative allowlist contract for the later finalizer library |
| `scripts/validate-mlx90-delivery.py` | Offline validator for an already-created terminal acceptance document |
| `tests/test_mlx90_delivery.py` | Positive and negative tests for that offline delivery-document validator |
| `docs/mlx90-final-acceptance.md` | Staged contract and ownership documentation |

### Acceptance profile contract

`acceptance/mlx90/profiles.json` defines the fixed command allowlist that the
inert finalizer library in stack stage B will load explicitly through its
`--profiles` argument. Stage A intentionally has no runtime profile consumer.
The file is present now so that the identifier, schema, eligibility flag, and
argument-vector boundary are reviewed before any execution path exists.

The only current entry is
`lit.supplementary/mlx90-fixture`. It is historical test data with
`releaseEligible: false` and `containerCommand: ["/bin/false"]`. It cannot
authorize a release. A future release-eligible profile will require a separate
review tied to authoritative producer evidence and a fixed, nonsecret command
vector.

### Delivery-document validator

`scripts/validate-mlx90-delivery.py` validates a terminal JSON document passed
on the command line:

```bash
python3 scripts/validate-mlx90-delivery.py path/to/acceptance.json
```

It accepts only the exact `lit.security-release.acceptance/v1` contract. For a
`delivered` document it validates the producer, consumer, three container
variants, acceptance identity, required checks, receipt-bundle binding, and
finalizer run identity. It also validates the exact reduced schemas for
terminal `blocked` and `revoked` results. Unknown fields, mutable identities,
invalid digests, inconsistent versions, false checks, and malformed URLs fail
closed.

Its timestamp contract is a strict, lossless RFC3339 profile: uppercase `T`,
complete seconds, and uppercase `Z` or a colon-delimited numeric offset are
mandatory. Fractions may be omitted or contain 1–6 decimal digits. Alternate
separators, missing seconds or zones, longer fractions, comma fractions,
lowercase `t`/`z`, invalid calendar values, and leap seconds fail closed.
Only after that grammar check, the parser converts a terminal `Z` to `+00:00`
and right-pads a present 1–6 digit fraction to six digits. This lossless parser
representation makes every permitted precision work on Python 3.9 and later
without broadening the accepted input grammar.

Producer collection versions and container release tags use the complete
SemVer 2.0.0 grammar. Major, minor, patch, and numeric prerelease identifiers
reject leading zeroes except for the single identifier `0`; prerelease and
build metadata are nonempty, dot-separated ASCII identifiers containing only
letters, digits, and hyphens. Numeric build identifiers may retain leading
zeroes. Every semantic-version value is limited to 255 ASCII characters before
the full grammar is evaluated, which bounds work for adversarial invalid
prerelease strings. Malformed, overlong, or Unicode lookalike versions fail
closed.

All contract strings reject every ASCII control character (`U+0000` through
`U+001F` and `U+007F`) before URL parsing or other semantic interpretation.
The delivery CLI strictly rejects duplicate object keys at every nesting level,
control-bearing keys, non-standard or non-finite numeric values, oversized
numbers, and excessive nesting. Its UTF-8 input must be a regular, non-symlink
file no larger than 10 MiB. Parse errors report only the failure class and do
not echo untrusted keys, values, tokens, or secret material.

Acceptance profile IDs are limited to 255 ASCII characters and contain exactly
one slash separating two grammar-validated segments. Additional or empty
segments, dot segments, and trailing slashes fail closed.

The validator checks the syntax and evidence binding of the profile recorded in
an already-created result; it does not choose or execute a profile and therefore
does not read `profiles.json`. Profile selection belongs to the stage-B
finalizer library. Keeping those responsibilities separate prevents an output
validator from becoming an execution mechanism.

## Forward contract for later stack stages

Stage B will add an inert local finalizer library and tests. That library will
be the explicit consumer of `profiles.json`, reject the current
non-release-eligible fixture, validate signed evidence and typed receipts, and
create terminal
documents only when called with complete local inputs. It will still have no
workflow caller.

Stage C will separately add the protected workflow and shell orchestration. Only
that activation stage may perform live GitHub, OCI, signature, persistence, and
callback checks. It must remain fail-closed on the exact producer central-CI
attempt, release tags and assets, immutable evidence persistence, and protected
promotion boundary. Neither this document nor stage A is evidence that those
future checks have run successfully.

## Verification available in this stage

Only checks backed by files present in stage A are listed here:

```bash
python3 -m unittest tests.test_mlx90_delivery
python3 scripts/lit-repository-quality.py
git diff --check
```

Do not invoke MLX-90 finalizer, workflow-contract, ShellCheck, or actionlint
commands from this stage: the corresponding MLX-90 files do not exist yet.

## References

- MLX-90 ADR: <https://wiki.cloud.l-it.io/wiki/spaces/LIT/pages/2894659587>
- REL-20 implementation status:
  <https://wiki.cloud.l-it.io/wiki/spaces/LIT/pages/2894790704>
- Governance issue:
  <https://github.com/lightning-it/github-management-lit/issues/267>
- Producer repair:
  <https://github.com/lightning-it/ansible-collection-supplementary/pull/595>
