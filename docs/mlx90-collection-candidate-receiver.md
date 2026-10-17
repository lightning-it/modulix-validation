# MLX-90 collection candidate receiver

LI-359 owns the paired receiver for Supplementary's v2 validation request.
The workflow `mlx90-collection-candidate-validation.yml` implements the paired
request boundary, authenticated exact-byte Nexus readback, real supported
Heavy/Application matrices and keyless v2 receipt signing. Its controller
adapters are `scripts/collection_candidate_request.py` and
`scripts/collection_candidate_receiver.py`. Code delivery and independent
checks proceed under the owner's workflow-first decision. Runtime activation,
Nexus/Galaxy cutover and operational acceptance remain later work under
LI-371/LI-118; code presence is not an operational or release-eligible result.

The request adapter validates canonical compact JSON and its SHA-256 before
using request fields. It rejects duplicate keys, unexpected fields, boolean
integer substitutions, unsafe names, foreign identities, human action counts,
and a Nexus endpoint that differs from protected controller configuration.
The independent producer-run check binds both App actors, exact source SHA,
workflow, run and attempt; the producer must still be in progress while it
waits for the receiver.

## Confirmed infrastructure and remaining configuration

On 2026-10-17, the existing Protected Incus runner group allowed this
repository and contained five online Incus runners. The repository-level
runner inventory alone omits those organization runners.

The existing `mlx90-final-acceptance` environment already permits only `main`
and has no required human reviewers. Reusing this environment needs no change
to its protection rules. The separate collection runtime environments have
human reviewers and must retain them.

On 2026-10-17, the owner confirmed directly that Nexus has not yet been
provisioned. There is consequently no existing service endpoint or reader
configuration to discover. Foundation or host provisioning is outside LI-359.
The upstream service must deliver the Nexus target before runtime acceptance;
it does not block fail-closed workflow code delivery.

Repository, organization, and all seven existing environment metadata lists
contained no Nexus endpoint or reader credential configuration. No existing
workflow references a Nexus reader. A runner-local credential or a separately
approved external secret source has not been established by that inspection.
An App token is not a Nexus reader credential.

This is not evidence that the worker needs broader GitHub rights, nor proof
that a service is unreachable. There is no confirmed endpoint to probe. The
authoritative deployment record
[Nexus PRD Target](https://lit.atlassian.net/wiki/spaces/LIT/pages/2897838457)
(version 11) describes a planned target, without an installed or accepted
service, FQDN, TLS, repository, or credential baseline. The
[service project](https://lit.atlassian.net/wiki/spaces/LIT/pages/2897969321)
(version 14) likewise keeps applicability, design, and installation open.
The accepted
[MLX-70 ADR](https://lit.atlassian.net/wiki/spaces/LIT/pages/2893119515)
(version 7) explicitly keeps Nexus cutover and technical acceptance open.
The smallest missing prerequisite is now the actual provisioned service,
followed by its as-built repository reference and approved reader delivery
mechanism. There is no further secret or endpoint search in this increment.
Deploying a new service is outside this paired receiver increment.

The concrete configuration decision for the existing environment is:

| Type | Proposed reference | Exact boundary |
| --- | --- | --- |
| Variable | `NEXUS_GALAXY_READ_REPOSITORY` | One existing hosted ansiblegalaxy repository |
| Variable | `NEXUS_GALAXY_READ_REPOSITORY_URL` | Its credential-free HTTPS repository URL |
| Secret | `NEXUS_GALAXY_READ_USERNAME` | A dedicated reader for that repository |
| Secret | `NEXUS_GALAXY_READ_PASSWORD` | Its password or user-token secret |

These are proposed references, not configured or granted credentials. An
existing approved external-secret delivery path can replace these proposed
GitHub Secret references without changing the exact repository-read scope.
No secret value should be requested or copied into the chat. The
reader requires only browse/read on the exact existing repository. It must
have no upload, delete, redeploy, or administration privilege. Provisioning or
delegating this access requires the authorized credential custodian; no
publisher credential, anonymous fallback, or new App permission is allowed.
No secret value belongs in this document, Jira, or generated evidence.

## Native code path and later runtime acceptance

The workflow exposes exactly `request_id` and `request_json`, binds
the protected controller SHA and App identity, and validates the fresh producer
run before reading a protected credential. Empty configuration fails before
credential, download or publication effects. Authenticated Nexus readback
rejects redirects and proves exact size and digest without rebuilding or
changing the candidate. Existing read-only Release App scope retrieves the
exact producer-run/attempt stage artifact and tested runtime dependency bundle;
checksums bind staged and independently downloaded candidate bytes. No new App
permission or personal token is needed.

Matrices come from the exact protected source registry. The immutable
validation-owned quality action executes real scenarios with owned cleanup,
JUnit/Allure and strict evidence gates. Signing requires every prior native job
to have completed successfully in the same run/attempt, including actual Heavy
and Application Acceptance cells. Missing, failed, skipped, duplicate or
foreign-attempt results cannot authorize a receipt. There is no no-op fallback.
Only the protected main workflow receives the signing OIDC permission.

Local validation stays deterministic in read-only pinned Devtools. Protected
runtime readback explicitly enables network and workspace output; receipt
construction enables workspace output only. A trap removes the temporary
reader file, which is excluded from every artifact. The final receipt artifact
contains exactly the canonical JSON and its Sigstore bundle.

Supplementary remains responsible for verifying that receipt and publishing
the same candidate bytes to Galaxy. Its existing #1167/#1168 integration is
prepared separately against current protected develop; it has no operational
receiver acceptance merely because local integration tests pass.

The transition workflow and existing release functions remain until the paired
runtime path is accepted. Code delivery requires current-head native review and
normal protected integration. Later LI-371/LI-118 runtime evidence must prove
real infrastructure/configuration, real profiles and the exact signed receipt
before Galaxy cutover. LI-360 retains the separately recorded native workflow
and release acceptance boundary. Local tests and code delivery are not runtime
acceptance.
