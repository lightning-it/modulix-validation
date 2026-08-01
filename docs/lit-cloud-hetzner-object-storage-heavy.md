# lit.cloud Hetzner Object Storage Heavy acceptance

The workflow `.github/workflows/lit-cloud-hetzner-object-storage-heavy.yml` is
the only supported executor for the protected Hetzner Object Storage Heavy
scenario. It requires an exact 40-character candidate SHA, builds and
checksums that collection artifact, and executes the repository-owned scenario
through the central `collection-molecule-profile.yml` lifecycle. The executor
checks out `lightning-it/ansible-collection-cloud` explicitly at the candidate
SHA; generic callers continue to default to their caller repository.

The versioned matrix is
`inventories/heavy/hetzner-object-storage.yml`. It declares deterministic,
run-owned isolated resources; Plan, Audit, and Reconcile; private bucket,
versioning, Object Lock, Governance retention, and multipart cleanup checks;
separate-project principals; and positive/negative Admin, Writer, Reader, and
Reviewer authorization tests. The same-project default full-rights behavior is
a mandatory regression guard and must never be reported as least privilege.

The protected environment supplies separate administration and role secrets.
They are exposed only to the scenario process and must not be printed or
written to artifacts. The central action uploads only normalized JUnit,
candidate-bound manifests, and checksums. Raw logs and object bodies are not
artifacts.

Each identity consists of an access key, secret key, and project ID. The
bucket-owning Admin project and the Writer, Reader, and Reviewer projects must
be four distinct Hetzner projects; the scenario fails closed otherwise.

The scenario must clean run-owned mutable fixtures idempotently. Governance-
locked fixtures that cannot yet be removed retain explicit ownership and
expiry metadata for the scheduled collector; cleanup must never select by a
broad prefix. The aggregate check
`lit.cloud / Hetzner Object Storage / Heavy` can be consumed as protected
release evidence only when every matrix cell and cleanup finalizer passes.
