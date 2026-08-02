# MLX-90 finalizer library (inert foundation)

## Current stage

This branch is stage B2, the third and still deliberately inert part of the
MLX-90 final-acceptance stack. It contains the reviewed data contracts from
stage A, the local finalizer library from stage B1, and the complete dedicated
finalizer test suite. It does **not** contain the MLX-90 GitHub Actions
workflow, workflow shell implementation, or workflow-contract tests. No
existing workflow calls the library. B2 retains B1's core behavior block and
shared fixtures, then extends that same test module with the full adversarial,
BuildKit, boundary, leakage, CLI, and cross-binding matrix without duplicating
the fixture layer. B2 also adds the independent delivery validator's
malformed-URL sanitization and its parser/CLI leakage regression.

The library can validate explicitly supplied local files and can write local
receipt, report, and terminal-evidence files when invoked manually. It cannot
fetch GitHub or registry state, verify a live workflow run, execute the profile
command, sign or upload evidence, publish a Release, or dispatch promotion by
itself. Those operations remain absent until the separate activation stage C.

## Contract files present now

| Path | Current purpose |
| --- | --- |
| `acceptance/mlx90/profiles.json` | Fixed profile allowlist consumed by the finalizer library |
| `scripts/finalize-mlx90-delivery.py` | Local parsing, evidence, receipt, report, and terminal-result library |
| `scripts/validate-mlx90-delivery.py` | Independent offline validator for an already-created terminal result |
| `tests/test_mlx90_finalizer_smoke.py` | CI-discovered import/compile and no-clobber writer smoke tests |
| `tests/test_mlx90_finalizer.py` | B1 core behavior plus B2 adversarial, BuildKit, boundary, CLI, tampering, and cross-binding expansion |
| `tests/test_mlx90_delivery.py` | Positive and negative tests for the terminal-result validator |
| `docs/mlx90-final-acceptance.md` | Current inert-library contract and ownership documentation |

## Profile ownership and use

`scripts/finalize-mlx90-delivery.py` is now the explicit consumer of
`acceptance/mlx90/profiles.json`. Commands that validate evidence, write a
receipt or report, or finalize a result receive the file through the required
`--profiles` argument. `load_profiles()` enforces the exact schema and
`eligible_profile()` requires the evidence-selected profile to exist and have
`releaseEligible: true`. The `profile-command` subcommand returns only the
reviewed fixed argument vector; it does not execute it.

The only current profile is
`lit.supplementary/mlx90-fixture`, with `releaseEligible: false` and
`containerCommand: ["/bin/false"]`. Finalizer preflight therefore rejects it as
non-release-eligible. A future real profile must be added in a separate review
tied to authoritative producer evidence, use a fixed nonsecret argument
vector, and be suitable for both collection-bearing variants.

The independent `scripts/validate-mlx90-delivery.py` remains an output
validator. It validates the syntax and evidence binding of the profile recorded
in a terminal result but deliberately does not select or execute a command and
does not read the allowlist.

## Finalizer contract implemented in this stage

The local library validates exact dispatch identities, producer and container
evidence schemas, immutable URLs and digests, the three variant identities,
CycloneDX and provenance bindings, OCI index structure, BuildKit SPDX/SLSA
subjects, installed collection observations, and the exact typed receipt set.
It rejects unknown fields, duplicate receipts, stale or foreign run bindings,
variant substitution, changed evidence digests, and cross-receipt disagreement.

`verify-index` hashes the bounded raw file bytes and requires the exact signed
variant `manifestDigest` before JSON decoding or semantic index acceptance.
Whitespace or any other byte change therefore fails even when platform digests
are unchanged. The BuildKit verifier uses the same digest-bound loader.

Both the finalizer and the independent delivery validator enforce the same
strict, lossless RFC3339 timestamp profile before parsing: uppercase `T`,
complete seconds, and uppercase `Z` or a colon-delimited numeric offset are
mandatory. Fractions may be omitted or contain 1–6 decimal digits. Alternate
separators, missing seconds or zones, longer fractions, comma fractions,
lowercase `t`/`z`, invalid calendar values, and leap seconds fail closed.
Only after that grammar check, the parser converts a terminal `Z` to `+00:00`
and right-pads a present 1–6 digit fraction to six digits. This lossless parser
representation makes every permitted precision work on Python 3.9 and later
without broadening the accepted input grammar.

Producer collection versions, producer affected/fixed versions, and container
release tags use the complete SemVer 2.0.0 grammar in both libraries. Major,
minor, patch, and numeric prerelease identifiers reject leading zeroes except
for the single identifier `0`; prerelease and build metadata are nonempty,
dot-separated ASCII identifiers containing only letters, digits, and hyphens.
Numeric build identifiers may retain leading zeroes. Every semantic-version
value is limited to 255 ASCII characters before the full grammar is evaluated,
which bounds work for adversarial invalid prerelease strings. Malformed,
overlong, or Unicode lookalike versions fail closed, including in the
installed-version helper.

All contract strings reject every ASCII control character (`U+0000` through
`U+001F` and `U+007F`) before URL parsing or other semantic interpretation.
Both libraries reject duplicate object keys at every nesting level,
control-bearing keys, non-standard or non-finite numeric values, oversized
numbers, and excessive nesting. The finalizer additionally accepts only LF or
CRLF JSONL records. UTF-8 inputs must be regular, non-symlink files bounded to
10 MiB in the delivery CLI and 64 MiB in the finalizer. Parse errors report only
the contract field and failure class and do not echo untrusted keys, values,
tokens, malformed URL parser details, observed/expected collection versions, or
secret material.

Digest-bound inputs use one non-following, nonblocking regular-file snapshot
for digest, size, and parsing, with device/inode/size/mtime/ctime stability
checks. Downloaded release assets, including the collection, are capped at
10 MiB; other OCI/BuildKit inputs are capped at 64 MiB. Symlinks, FIFOs,
devices, oversized inputs, and files that change during the read fail with
fixed value-free diagnostics.

Every JSON evidence output uses the same no-clobber writer. Existing regular
files and symlinks are rejected, the temporary file is created exclusively,
and an atomic hard link fails closed if a target appears during publication.
The temporary file is removed after success or failure; no output is an
in-place update target.

`finalize` publishes delivered and acceptance as a create-new pair: both
targets are preflighted and both documents serialized into exclusive temporary
files first. A first-link failure writes no second output. A second-link failure
removes the first only when its device/inode matches the owned temporary hard
link, never a foreign replacement; all owned temporaries are cleaned.

Acceptance profile IDs are limited to 255 ASCII characters and contain exactly
one slash separating two grammar-validated segments. Additional or empty
segments, dot segments, and trailing slashes fail closed.

Producer provenance must contain canonical positive run and attempt strings.
The typed `producer-central-ci` receipt must bind that provenance digest to the
exact `Collection CI` workflow run and attempt and to exactly one completed,
successful `Collection / Release Validation` job. The library does not query
that run; stage C's shell must produce the observation from live paginated REST
responses before the library will accept it.

Each initial producer/container revocation receipt binds an exact canonical
snapshot of the consumed release assets and its independently recomputed
digest. The library validates the correct repository and numeric release ID,
the exact consumed URL set, numeric asset IDs, filenames, uploaded state, byte
sizes, canonical URL order, and digest. The final revocation receipt binds both
release tag commits, both final snapshots, and separate initial/final snapshot
digest fields. Receipt-set validation cross-binds those initial fields and
snapshots to the initial receipts, recomputes the final digests, and requires
initial and final observations to match. Live tag resolution, pagination,
receipt-file readback, and asset downloads remain responsibilities of stage C.

Only a complete, current, run-owned receipt set can produce a verification
report and terminal `delivered` evidence. The resulting
`mlx90-final-acceptance.json` must also pass the independent delivery validator.
No signed or durable live evidence exists merely because these local functions
and tests are present.

## Forward activation contract

Stage C will separately add the protected workflow and shell orchestration. It
must acquire only scoped short-lived credentials, verify live producer central
CI, releases, tags, OCI state and signatures, download consumed assets again by
numeric ID, and persist exactly six verified assets in a Release whose REST
response says `immutable: true`. It must expose no callback output until every
check succeeds. Governance enablement, Producer PR #595, promotion, container
release, and final acceptance remain external prerequisites rather than claims
made by this inert branch.

## Verification available in this stage

Only checks backed by files present through stage B2 are listed here:

```bash
python3 -m unittest \
  tests.test_mlx90_delivery tests.test_mlx90_finalizer_smoke \
  tests.test_mlx90_finalizer
python3 scripts/lit-repository-quality.py
```

Do not invoke the MLX-90 workflow-contract, ShellCheck, or actionlint commands
from this stage: the corresponding MLX-90 activation files do not exist yet.

## References

- MLX-90 ADR: <https://wiki.cloud.l-it.io/wiki/spaces/LIT/pages/2894659587>
- REL-20 implementation status:
  <https://wiki.cloud.l-it.io/wiki/spaces/LIT/pages/2894790704>
- Governance issue:
  <https://github.com/lightning-it/github-management-lit/issues/267>
- Producer repair:
  <https://github.com/lightning-it/ansible-collection-supplementary/pull/595>
