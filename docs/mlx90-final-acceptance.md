# MLX-90 immutable final acceptance

`mlx90-final-acceptance.yml` is the protected, fail-closed finalizer for the
MLX-90 collection-to-container delivery chain. It can create a `delivered`
claim only after independently verifying the signed producer evidence, the
signed container evidence, the live GitHub identities, every required OCI
digest, and an immutable acceptance profile specific to the security fix.

The workflow and profile allowlist are foundations, not evidence that a release
has passed. The historical `lit.supplementary/mlx90-fixture` profile remains
`releaseEligible: false` with a non-success command. The separately reviewed
`lit.supplementary/forgejo-manifest-secret-permissions-v1` profile is the only
release-eligible profile. It cannot produce a `delivered` result without the
matching authoritative producer evidence, immutable container evidence, and
all live finalizer checks.

## Dispatch contract

The release automation GitHub App dispatches the workflow on protected `main`
with these required string inputs:

| Input | Exact meaning |
| --- | --- |
| `correlation_id` | Run-unique nonsecret correlation identifier |
| `producer_evidence_url` | Stable GitHub Release URL of `security-release-evidence.json` |
| `producer_evidence_bundle_url` | The preceding URL plus `.sigstore.json` |
| `producer_evidence_sha256` | Lowercase SHA-256 of the producer evidence without a prefix |
| `consumer_pr` | Merged consumer pull-request number |
| `consumer_head_sha` | Exact reviewed pull-request head SHA |
| `consumer_merge_sha` | Exact merge SHA and container source SHA |
| `container_release_id` | Numeric GitHub Release ID |
| `container_release_tag` | Exact v-prefixed semantic release tag |
| `container_release_run_id` | Container Build & Publish run ID bound by the signed evidence |
| `container_publish_run_attempt` | Successful attempt of that run which published the immutable release |

The workflow rejects any other actor, repository, ref, mutable SHA, release
binding, or evidence URL. It does not accept an arbitrary shell command. The
only executed acceptance command comes from the reviewed
`acceptance/mlx90/profiles.json` allowlist.

The App needs `Actions: write` to call the workflow-dispatch endpoint and
`Actions: read` to inspect the resulting run. The protected verification job
mints a one-hour installation token from the existing organization-managed
`RELEASE_AUTOMATION_APP_CLIENT_ID` variable and
`RELEASE_AUTOMATION_APP_PRIVATE_KEY` secret. It first rejects every dispatch
whose actor, ref, or repository differs from the exact MLX-90 contract. The
token creation is then fail-closed on App slug
`lightning-it-release-automation`, installation ID `148019054`, and exactly
these four read-only evidence repositories:

- `lightning-it/ansible-collection-supplementary`
- `lightning-it/container-ee-wunder-ansible-ubi9`
- `lightning-it/modulix-validation`
- `lightning-it/shared-assets-lit`

The minted token requests only `Actions: read`, `Checks: read`,
`Contents: read`, and `Pull requests: read`, is revoked automatically at the
end of the job, and is used for private cross-repository API reads, immutable
policy checkout, and authenticated GitHub Release asset downloads. The
`Checks: read` permission is required only for the exact current-head
`check-runs` lookup. It is not a personal token and does not introduce a new
secret. The same-repository persistence job continues to use only its
repository-scoped `GITHUB_TOKEN`. Job permissions are:

The least-privilege choice for merge-event lookup was reverified on 2026-08-06
against GitHub's versioned REST permission table for
[`List issue events`](https://docs.github.com/en/rest/issues/events?apiVersion=2026-03-10#list-issue-events):
the endpoint accepts either `Issues: read` or `Pull requests: read` for a
fine-grained GitHub App installation token. MLX-90 uses the latter because all
queried issue numbers are already identity-validated pull requests. The live
event request fails closed before any delivered claim if GitHub ever rejects
that documented scope; `Issues` permission is intentionally not requested.

| Job | Actions | Contents | OIDC | Other permissions |
| --- | --- | --- | --- | --- |
| `verify` | read | read | write, for keyless evidence signing | App token: Checks read; Pull requests read |
| `persist` | read | write, for the immutable evidence release | none | none |

The `verify` and callback jobs run in the dedicated protected
`mlx90-final-acceptance` environment. Governance configures that environment
without required reviewers only for the evidence-bound Security release path.
The `persist` job receives only the signed same-run artifact and cannot create
a result unless all prior verification succeeded.

## Required evidence

Producer evidence must satisfy the canonical
`lit.security-release/v1` policy from `lightning-it/shared-assets-lit`, pinned
in the workflow to commit
`1c6a1d43af638d081108d820b3576e401d9f0857`. The producer evidence and its
Sigstore bundle must be immutable assets of the matching producer release.

The container release must expose exactly one
`mlx90-container-evidence.json` and one matching
`mlx90-container-evidence.json.sigstore.json`. The signed JSON binds:

- the Security/Evidence ID and producer evidence URL plus digest;
- producer source SHA, collection version, and collection digest;
- consumer pull request, pre-merge base SHA, reviewed head SHA, and two-parent
  merge SHA;
- container release ID, tag, source SHA, workflow run ID, and run attempt;
- distinct `public`, `certified`, and `bootstrap` images;
- each OCI manifest digest and exact `linux/amd64` and `linux/arm64` platform
  digest;
- immutable signature, SBOM, and provenance references for every variant; and
- an explicit `not_revoked` observation and timestamp.

The finalizer re-resolves the producer and container tags, the merged consumer
pull request, and the successful container workflow run through GitHub. It
then verifies the collection archive's signature and checks its CycloneDX SBOM
and provenance against the producer SHA, version, and digest. For the container
it verifies OCI index contents, including exactly one BuildKit attestation
manifest for each exact platform manifest, and verifies the index signature
against the exact container workflow identity and workflow SHA. It also hashes
the raw index bytes against the evidence manifest digest. Only after that
raw-byte check may `verify-index` apply semantic JSON acceptance; the BuildKit
path uses the same digest-bound loader. Cosign verification then gates fetching
each attestation manifest by the
descriptor digest covered by the signed index and each in-toto layer by the
digest covered by that manifest. The layer bytes and sizes must match their
descriptors, and every SPDX and SLSA in-toto subject must name exactly the
attempt-bound
`mlx90-candidate-<consumer-merge-sha>-<publisher-run-id>-<publisher-attempt>`
reference created by the Security build for its platform and carry that
platform manifest's exact SHA-256 digest. The finalizer separately resolves
that one unique candidate tag and requires the accepted, signed index digest.
The Security path does not create or retarget release, bare-version,
`sha-<12>`, or `latest` aliases because Quay does not provide an atomic
create-if-absent alias operation. The durable callback revalidates the accepted
digests and identities but performs no Quay tag mutation.

MLX-90 additionally binds the original and rerun-triggering App actors before
any secret or token use. The evidence and publisher attempts must share the
exact run identity; only an earlier successful build and a later successful
attach-only retry are accepted. The merge-SHA workflow blob must bind the
`build`, `upload-trivy-sarif`, and `attach-release-evidence` IDs to their exact,
unique live job names and fail-closed DAG semantics. Numeric ID and tag must
resolve to the same immutable App-authored release at that SHA. REST reads pin
[`X-GitHub-Api-Version: 2026-03-10`](https://docs.github.com/en/rest/about-the-rest-api/api-versions?apiVersion=2026-03-10).

The current container workflow does not publish separate Cosign signatures for
these SPDX and SLSA layers. `cosign verify-attestation` would therefore not
establish their trust.
The enforced cryptographic chain is instead the keyless Cosign signature over
the immutable multiarch index, then
`index -> attestation manifest -> in-toto layer -> platform subject`. The live
SPDX predicate must be SPDX 2.3, identify Syft and BuildKit, and contain real
packages, files, and relationships. The live SLSA v1 predicate must bind the
variant profile, Dockerfile, repository, protected release tag, merge SHA,
platform, workflow, run ID, and run attempt. Its builder and timestamps are
validated as well. Registry blobs are fetched anonymously from the fixed Quay
host over HTTPS. Public blobs use the direct anonymous path. A `401` is accepted
only when its single Bearer challenge exactly names Quay's fixed token endpoint,
the `quay.io` service, and the validated repository's pull-only scope. The
resulting short-lived anonymous pull token is bounded and passed to curl only
through standard input; it is never persisted, logged, or placed in process
arguments. Curl's default cross-origin credential stripping remains in force
(`--location-trusted` is forbidden) while following at most the registry's
single HTTPS CDN redirect. Downloads are capped at 64 MiB and checked against
both the signed descriptor digest and exact size. Every downloaded byte
sequence remains an ephemeral runner input rather than published evidence.

The separately signed container evidence binds all release-asset digests to
that same workflow identity and SHA. The referenced Cosign signature receipt
must also be present byte-for-byte in the live cryptographic verification.
Each referenced Trivy CycloneDX SBOM must identify the exact
`image@manifestDigest`. The referenced release provenance must bind the
repository, tag, source SHA, workflow run, immutable image, signature receipt
digest, and SBOM digest. Malformed or unrelated referenced assets therefore
fail even when their file digest is listed in the signed container evidence.
The finalizer then pulls every image by manifest digest, confirms the pulled
digest, checks
that the exact collection version is installed in `public` and `certified`,
and runs the fixed profile in both collection-bearing variants. The existing
`bootstrap` product contract intentionally contains no collections; acceptance
therefore proves that `lit.supplementary` is absent and records a null installed
version instead of manufacturing a false version claim. Its manifest,
platform, signature, SBOM, provenance, and immutable-pull checks remain
mandatory.

Every evidence timestamp uses the strict RFC3339 profile enforced by both the
finalizer and the independent delivery validator: an uppercase `T`, complete
hours/minutes/seconds, and either uppercase `Z` or a colon-delimited numeric
timezone offset are mandatory. Fractional seconds may be omitted or contain
exactly 1–6 decimal digits, matching the parser's lossless microsecond
precision. Alternate separators, missing seconds or zones, longer fractions,
comma fractions, lowercase `t`/`z`, invalid calendar values, and leap seconds
fail closed rather than being normalized or truncated.
Only after that grammar check, the Python parser input converts a terminal `Z`
to `+00:00` and right-pads a present 1–6 digit fraction to six digits. This is
lossless and preserves the accepted grammar while making every permitted
fractional precision work consistently on Python 3.9 and later.

BuildKit-authored SLSA `runDetails.metadata.startedOn` and `finishedOn` values
use a separate RFC3339 profile because BuildKit serializes Go timestamps with
up to nine fractional digits. For those two fields only, the finalizer accepts
either no fractional part or exactly 1–9 digits when a fraction is present and
preserves the final three nanosecond digits when it checks strict
start-before-finish ordering. The 1–6 digit limit for all MLX-90-authored
evidence remains unchanged.

Every producer collection version, producer affected/fixed version, and
container release tag uses the complete SemVer 2.0.0 grammar. Major, minor,
patch, and numeric prerelease identifiers reject leading zeroes except for the
single identifier `0`; prerelease and build metadata are nonempty,
dot-separated ASCII identifiers containing only letters, digits, and hyphens.
Numeric build identifiers may retain leading zeroes as required by SemVer.
Every semantic-version value is limited to 255 ASCII characters. The Python
and shell validators enforce that bound before evaluating the full grammar,
which also bounds work for adversarial invalid prerelease strings. Malformed,
overlong, or Unicode lookalike versions fail closed in the dispatch identity,
producer evidence, finalizer helpers, callback, and independent delivery
validator.

All contract strings reject every ASCII control character (`U+0000` through
`U+001F` and `U+007F`) before URL parsing or other semantic interpretation.
All untrusted JSON and JSONL inputs use a duplicate-key-rejecting object hook
at every nesting level and reject control-bearing object keys, non-standard or
non-finite numeric values, oversized numbers, excessive nesting, and non-LF
JSONL separators. Reads are restricted to regular, non-symlink UTF-8 files and
bounded to 10 MiB in the delivery validator and 64 MiB in the finalizer. Parse
errors identify only the contract field and failure class; they do not echo
untrusted keys, values, tokens, or secret material.

Files whose bytes are bound by a digest use one non-following, nonblocking
descriptor read. The finalizer requires a regular file and enforces a 10 MiB
cap for release assets by default, including the collection archive. Only the
four exact container CycloneDX names (`sbom.cdx.json` and the `bootstrap`,
`certified`, and `public` variants) use the 64 MiB SBOM cap; other OCI/BuildKit
inputs are likewise capped at 64 MiB. It compares device, inode, byte size,
modification time, and change time before and after the bounded read.
Digest, size, and JSON/JSONL parsing are all derived from that same immutable
byte snapshot. A symlink, FIFO, device, oversized input, or file that changes
during the read fails with a fixed value-free diagnostic.

Acceptance profile IDs are limited to 255 ASCII characters and contain exactly
one slash separating two grammar-validated segments. Additional or empty
segments, dot segments, and trailing slashes fail closed.

The producer provenance run ID and attempt must be canonical positive decimal
values. The finalizer resolves that exact historical attempt through GitHub,
requires the `Collection CI` workflow at `.github/workflows/collection-ci.yml`
to be a successful protected-`main` push for the producer source SHA, and reads
the complete paginated job set for the same attempt. Exactly one job may be
named `Collection / Release Validation`, and that one job must be completed
successfully. A dedicated typed receipt binds the provenance digest, run,
attempt, workflow, source identity, and central gate job. A skipped transition
adapter or a successful run without that exact central gate cannot satisfy
producer acceptance.

Every successful live check emits one typed
`lit.security-release.verification-receipt/v1` document. The exact receipt set
covers producer evidence and identity, initial producer/container revocation,
producer and container Cosign verification, producer/container materials, the
exact producer central-CI attempt and validation gate, consumer and
container-release identity, and for every variant the OCI index, the exact
immutable candidate tag, live image signature, release materials, BuildKit
attestations, pull by digest, and installed collection state. `public` and
`certified` additionally require a receipt for the exact reviewed profile
command; `bootstrap` must not have one. Every receipt carries the correlation
ID, both evidence-file digests, finalizer workflow SHA, run ID, run attempt,
timestamp, receipt type, and type-specific observations. Receipts never contain
tokens, private keys, or secret values.

The receipt set also contains one `ZeroTouch` receipt whose `humanActions`
object is deliberately scoped to
`environment-approval-reviews-on-evidence-bound-runs` and records `count: 0`.
This is not an unverifiable claim that no human ever interacted with GitHub.
It is the narrower durable claim GitHub can prove: the release-automation App
authored both protected merge events and the bound workflow transitions, while
the producer, current-head review, container, and finalizer runs have empty
Actions environment-approval histories. The current-head review is accepted
only when `.github/workflows/copilot-review.yml` at the candidate head has the
same Git blob and SHA-256 content digest as the workflow at the protected
`main` base SHA recorded for that PR. A candidate-modified self-attesting gate,
human environment approval, foreign App identity, changed run ID, non-current
review gate, or missing API evidence stops the finalizer before durable
acceptance is created. The evidence token is scoped to the four repositories
required for these reads and retains only `Actions: read`, `Checks: read`,
`Contents: read`, and `Pull requests: read`.

Every finalizer JSON output uses one no-clobber writer. It rejects an existing
regular file or symlink, creates its temporary file exclusively, and publishes
through an atomic hard link that fails if another writer created the target in
the meantime. The temporary file is cleaned after success or failure. Evidence,
receipt, report, bundle, delivered, and acceptance paths are never treated as
in-place update targets.

`finalize` publishes delivered and acceptance as one create-new pair. It
preflights both targets, serializes both documents, and creates both temporary
files exclusively before linking either output. If the acceptance link fails,
the delivered link from that invocation is removed only when its device and
inode still equal the owned temporary hard link; a foreign replacement is
never removed. A delivered-link failure never writes acceptance, and all owned
temporary links are cleaned on success or failure.

The collector accepts only the exact filename/type set, rejects duplicates,
foreign run bindings, stale timestamps, changed evidence digests, variant
substitution, and cross-receipt digest disagreement. It derives the report's
checks and variant observations only from that validated receipt set. Supplying
the producer and container evidence documents without receipts cannot create a
report. Each initial producer/container revocation receipt contains the exact
canonical metadata snapshot of every release asset whose bytes were consumed
and its independently calculated digest. The receipt validator checks the
correct repository and numeric release ID, the exact consumed URL set, numeric
asset IDs, filenames, uploaded state, byte sizes, URL ordering, and canonical
digest before that initial observation becomes durable.

Immediately before report creation, the workflow fetches both releases again
and emits the final receipt only when neither live release contains an
applicable revocation asset. The same boundary resolves both release tags to
their required commits again and obtains each complete paginated REST asset
list. It reads the trusted initial snapshot digests back from the newly written
receipt files, rather than relying only on mutable shell variables, and compares
the final canonical snapshots against that durable readback. Every selected
asset is then downloaded again by numeric asset ID and byte-compared with every
local file used for verification. The workflow fetches both releases and their
complete asset lists once more after those downloads; tag commits and snapshot
digests must remain unchanged. The final typed receipt binds both final
snapshots, both initial/final snapshot digests, and both final tag commits.
Receipt-set validation cross-binds its initial digest fields and snapshots to
the two initial revocation receipts, recomputes the final snapshot digests, and
requires initial and final values to match. The final receipt must be the latest
observation.

## Durable result

After every check passes, the workflow creates:

- `security-release-delivered.json`, compatible with the canonical producer
  evidence policy;
- `mlx90-final-acceptance.json`, containing the complete three-variant
  acceptance matrix;
- `mlx90-verification-report.json`, binding the correlation ID and exact
  producer/container evidence digests to every observed check;
- `mlx90-verification-receipts.json`, the exact run-owned typed receipt bundle;
- `SHA256SUMS`; and
- `SHA256SUMS.sigstore.json`, a keyless signature bundle bound to the exact
  finalizer workflow SHA.

The six-file set is uploaded as a same-run artifact, verified again in a
separate least-privilege job, and persisted without replacement in a GitHub
Release whose tag is derived from the acceptance digest. Persistence first
creates an owned draft through the REST API and binds every subsequent write,
paginated asset read, and asset download to its positive numeric release or
asset ID. It uploads only missing assets through the release's ID-bound upload
URL, accepts a partial draft on retry only when its run marker, target SHA,
metadata, and every existing byte match the current signed evidence, and never
overwrites an asset. The complete draft must contain exactly six unique assets
in `uploaded` state. All six are downloaded by asset ID, byte-compared,
checksum-verified, and signature-verified before publication. The published
durable copy is then independently listed with full REST pagination and all six
assets are downloaded by ID and verified again before the workflow reports
success.

Publication is successful only when the numeric Release REST response exposes
`immutable: true` and the exact six-asset metadata snapshot remains unchanged
after the final downloads. Until immutable releases are enabled for
`lightning-it/modulix-validation` by Governance, persistence therefore fails
closed and exposes no callback outputs. The workflow neither requests nor adds
repository-administration permission to change that setting itself.

The final report and final acceptance document bind the receipt bundle by its
exact asset name, full SHA-256, and byte size, together with the finalizer run
and attempt already bound by those documents. Persistence includes the bundle
in `SHA256SUMS`, byte-compares it during draft recovery and after publication,
and recomputes the digest and size referenced by the acceptance document. A
direct durable download URL cannot be embedded in the self-hashed acceptance
document because its release tag is derived from that document's digest. After
publication, the persistence step therefore exposes the actual release tag,
the Release REST response's `html_url`, and the exact `browser_download_url`
values returned by the paginated asset API for final acceptance, final report,
and receipt bundle, together with their digests, as separate run outputs. It
validates those live URLs against the expected repository, evidence tag, and
asset names instead of constructing substitutes. Those external-evidence
outputs are created only after all six published assets have been downloaded
and verified byte-for-byte.

Only after that published `delivered` copy passes the local delivery validator,
checksum verification, byte comparison, and Cosign verification does the
persistence job expose callback outputs. A dependent protected job then mints
a short-lived App token scoped only to
`lightning-it/container-ee-wunder-ansible-ubi9` with `Actions: write`. It
rejects any App slug other than `lightning-it-release-automation`, any
installation ID other than `148019054`, and any token repository set other
than that single consumer repository. The callback dispatches
`security-release-promote-tags.yml` on consumer `main` with exactly these four
inputs:

- `final_acceptance_url`;
- `final_acceptance_sha256`;
- `consumer_merge_sha`; and
- `container_release_tag`.

The acceptance URL's immutable release tag must derive from the first 16 hex
characters of its full SHA-256 digest. No mutable image tag is changed by the
finalizer itself. The consumer workflow reauthenticates the durable acceptance
before its protected promotion job can move convenience tags.

## Enabling a real security profile

A regular pull request may add a release-eligible profile only after the
producer owns an authoritative Security/Evidence ID and a concrete acceptance
procedure for that exact fix. The profile must use a fixed argument vector,
must be safe for all three published variants, and must not depend on a mutable
tag, a free-form dispatch input, a private credential, or an unreviewed remote
script.

Before merging such a profile, verify that the producer and container evidence
contracts are live, the dispatch actor is the release automation App, and the
protected environment reviewers can validate the exact workflow SHA. Do not
dispatch the foundation against the historical fixture and do not interpret a
blocked preflight as delivery evidence.

The Forgejo profile is fixed to a container-local command that first requires
the separately reviewed verifier digest
`sha256:8095f617bb27f26043715d3b4466c75ea061f2277276e592809d256d8b456675`
and only then executes it:

```bash
script=/usr/share/ansible/collections/ansible_collections/lit/supplementary/scripts/verify-forgejo-manifest-security.py
test -f "$script"
test ! -L "$script"
test "$(sha256sum "$script" | cut -d' ' -f1)" = "8095f617bb27f26043715d3b4466c75ea061f2277276e592809d256d8b456675"
exec python3 "$script"
```

The verifier is shipped by the exact collection artifact under test, but the
candidate cannot substitute its own verifier: any content change fails the
independently pinned SHA-256 check before Python executes. The reviewed verifier
must then fail unless the Forgejo Pod-manifest template task is uniquely
identifiable, runs with `no_log: true`, and writes the secret-bearing manifest
as `root:root` with mode `0600`. The profile does not fetch code, accept a
free-form command, or read a credential. Its successful exit is one required
observation; it is never a substitute for signed producer/container evidence
or the final revocation check.

## Local verification

Run the repository-owned test and lint profile before pushing a change. The
focused checks are:

```bash
python3 -m unittest \
  tests.test_mlx90_delivery \
  tests.test_mlx90_finalizer_smoke \
  tests.test_mlx90_finalizer \
  tests.test_mlx90_workflow_contract
shellcheck .github/scripts/mlx90-final-acceptance.sh
actionlint .github/workflows/mlx90-final-acceptance.yml
git diff --check
```

The mandatory clean, committed acceptance boundary remains:

```bash
python3 scripts/lit-push-ready.py push-ready
```
