# Prevalidated Candidate Evidence (v1)

This repository performs a **semantic** contract check, rather than fabricating
validation evidence or cryptographically trusting it. It implements the
contract introduced by
[MLX-70](https://wiki.cloud.l-it.io/wiki/spaces/LIT/pages/2893119515) and
specializes the centrally executed Heavy/Application Acceptance responsibilities
from [MLX-10](https://wiki.cloud.l-it.io/wiki/spaces/LIT/pages/2886566105) and
the release-evidence requirements from
[MLX-40](https://wiki.cloud.l-it.io/wiki/spaces/LIT/pages/2886926524).

It is the first safe contract stage of
[modulix-validation#134](https://github.com/lightning-it/modulix-validation/issues/134).
It does **not** move a source repository's branch protection or mark a Heavy
or Application Acceptance run successful.

## Contract

The machine-readable entry point is
[`schemas/validation-evidence-v1.schema.json`](../schemas/validation-evidence-v1.schema.json).
The fail-closed semantic verifier is
[`validation-evidence.py`](../.github/scripts/validation-evidence.py); its
checks are deliberately stricter than the portable JSON Schema.

A release-eligible v1 document must contain all of the following:

- exact candidate `repository`, full `source_sha`, and either its full
  `git_tree` or immutable `sha256:` artifact digest;
- a canonical, sorted component BOM (including the exact candidate), whose
  entries are each commit- or digest-bound, plus its deterministic SHA-256
  digest; when the candidate has an artifact digest, its single BOM entry must
  contain that exact digest too;
- full policy, matrix, and validation-workflow SHAs;
- selected Heavy/Application Acceptance profile, non-empty target/cell set and
  a successful structured result, log, and evidence reference for every cell;
- start, end, expiry and successful cleanup evidence;
- the central GitHub Actions run ID, attempt, repository, URL and workflow SHA;
- an attestation/provenance reference, immutable subject digest and the same
  candidate source SHA (the subject digest must equal a supplied candidate
  artifact digest); and
- a current `not_revoked` check.

The default maximum age is 36 hours. A policy may lower, but never increase,
that limit. Evidence expires sooner when its declared expiry is earlier. The
verifier rejects incomplete, skipped, non-successful, revoked, expired,
cleanup-failed, or identity-mismatched evidence.

## Semantic verification only

The expected source SHA, one or both immutable candidate identities, and all
control identities must be supplied independently of the document. If both Git
tree and artifact digest are supplied, **both** must match:

```bash
python3 .github/scripts/validation-evidence.py semantic-verify \
  --evidence /secure/path/evidence.json \
  --repository lightning-it/ansible-collection-supplementary \
  --source-sha <full-commit-sha> \
  --git-tree "<full-tree-sha>" \
  --policy-sha "<full-policy-sha>" \
  --matrix-sha "<full-matrix-sha>" \
  --validation-workflow-sha "<full-workflow-sha>" \
  --bom-digest "sha256:<canonical-bom-digest>"
```

For artifact-built candidates, use `--artifact-digest sha256:<64-lowercase-hex>`
instead of, or alongside, `--git-tree`. Do not put a signed URL, credential,
private inventory value, token, generated secret, or raw infrastructure log in
the evidence document or workflow input. References must point to an approved
sanitized artifact or GitHub record.

The `bom_digest` is `sha256:` plus the SHA-256 of the UTF-8/ASCII canonical JSON
representation of `components.bom`: list items are sorted by `(repository,
source_sha, artifact_digest)` with absent values as empty strings; every object
uses lexicographically sorted keys, `ensure_ascii=true`, and `(',', ':')`
separators. The verifier recomputes this value before comparing it to the
independently supplied expected digest.

This command does **not** verify a signature, an in-toto statement, a GitHub
attestation bundle, its issuer, its subject or its transparency-log inclusion.
Consequently it must not be configured as a release-required check and its
success must never be described as trusted release eligibility.

## Shadow workflow

`Validation evidence shadow contract (not a release check)` is callable,
manually dispatchable and scheduled. Its schedule is explicitly guarded to run
only from the default branch and uses `ubuntu-latest` with read-only contents
permissions. It has no protected environment, secret, self-hosted runner, or
pull-request trigger.

Without an input document it writes a `mode: shadow`,
`release_eligible: false`, `outcome: not_executed` manifest. That artifact
proves only that the default-branch schedule and contract plumbing work; the
release verifier rejects it. With a supplied document, the workflow performs
only the semantic verification above. It never starts Heavy infrastructure,
runs Application Acceptance, or turns skipped work into a pass.

## Next adapter (not implemented in this stage)

The central Heavy/Application controller must produce v1 evidence only after
all selected cells finish successfully and the unconditional cleanup finalizer
has succeeded. It must obtain the candidate tree/digest, control identities and
component BOM from the trusted build, bind `validation_workflow_sha` to the
reusable workflow identity, upload sanitized per-cell results, and create a
provenance attestation. A separate protected trust adapter must verify the
attestation cryptographically (issuer, subject, digest, workflow identity and
transparency evidence) before a release may use this semantic result.

Until that adapter exists, release branch protection must not require this
workflow and source repositories must retain their current required checks.
