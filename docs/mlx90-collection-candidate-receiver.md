# MLX-90 collection candidate receiver preparation

LI-359 owns the paired receiver for Supplementary's v2 validation request.
This branch currently supplies the request and live producer-run validation
boundary in `scripts/collection_candidate_request.py`. It does not yet expose
the dispatch workflow, execute infrastructure profiles, or issue a receipt.
It must not be reported as an operational or release-eligible receiver.

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
The smallest missing input is an as-built service and exact repository
reference plus its approved reader delivery mechanism. If that service has
since been installed, its custodian can supply those nonsecret references.
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

## Remaining paired implementation and acceptance

The final workflow must expose exactly `request_id` and `request_json`, bind
the protected controller SHA and App identity, and validate the fresh producer
run before reading a protected credential. Authenticated Nexus readback must
reject redirects and prove exact size and digest without rebuilding or
changing the candidate. Profile matrices must come from the protected source
registry, with real Heavy and Application Acceptance execution, owned cleanup,
and no skipped required result. Only their successful current-run evidence
may authorize the exact v2 receipt and keyless signature from protected main.

Supplementary remains responsible for verifying that receipt and publishing
the same candidate bytes to Galaxy. Its existing #1167/#1168 integration is
prepared separately against current protected develop; it has no operational
receiver acceptance merely because local integration tests pass.

The transition workflow and existing caller remain until the paired path is
delivered and accepted. No new workflow is deployed by this preparatory
increment. LI-360 retains the real release and native acceptance criteria.
