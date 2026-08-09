# Wunderbox governed execution binding

`root-of-trust-policy.json` is the versioned, environment-neutral action
contract for one Wunderbox Root-of-Trust build. It fixes each action's record
prefix, gate, impact, inventory, playbook, tags, timeout, output bound,
extra-variable allowlist and evidence prerequisites. The adapter
`scripts/wbx-governed-exec.py` exposes no target, playbook, gate, impact or
arbitrary command option.

`gate-manifest.template.json` is deliberately non-executable. A real engagement
manifest must be created outside Git in an owner-only directory, completed with
the exact target/controller identity, all six frozen repository commits,
digest-pinned runtime images, collection attestation, gate state and one
authorization entry for every policy action. Unselected actions remain
`NOT_APPROVED`; each selected action receives a time-bounded `APPROVED` entry.
The manifest must retain
`safety_hold: true` until the relevant gate conditions and execution approval
are independently accepted.

The reviewed manifest is signed as an SSH signature with identity
`lit-wbx-approver` and namespace `lit-wbx-gate-manifest`. The allowed-signers
file, detached signature and manifest are owner-only inputs to the adapter.
Their presence does not itself accept evidence or advance a gate: recorder
outputs remain Candidate Evidence until independently reviewed and externally
anchored.

`scripts/render-wbx-gate-manifest-template.py` writes a complete skeleton to
stdout with the current policy hash and one `NOT_APPROVED` entry for every
action. Redirect it only into the owner-only external directory, complete and
review the selected authorizations, then sign that exact byte sequence. The
renderer never signs, approves or writes a manifest itself.

The pinned Ansible toolbox and execution environment are Linux runtimes. They
can mount the controller's SSH agent socket, but they cannot use the macOS
1Password Desktop CLI integration. Mounting only part of that trust path would
create an unverified half-integration, so `recovery_metadata_plan`, both
`prepare_installimage` actions and `bootstrap_unlock` are fail-closed with
`implementation_status: blocked` and blocker
`blocked_missing_desktop_integrated_onepassword_controller_runtime`.

`installimage_plan` is secret-free in isolation, but it is not independently
valid: the verified Dropbear hook it evaluates must first be staged by the
blocked `prepare_installimage` action. It therefore carries the same blocker.
The actions remain in the policy as reviewed interface contracts, but the
recorder rejects them before gate, authorization or process evaluation. Syntax
actions remain available because they require neither the Desktop session nor
an external mutation.

The runtime blocker may be removed only after independent review of either a
dedicated macOS adapter that uses the authenticated Desktop integration without
exposing secrets to the Linux execution environment, or a separate signed
bootstrap phase whose output is a secret-free, integrity-bound input to the
Linux phase. A socket-only, partial or implicit bridge is not acceptable.

The destructive `installimage_apply` action has the additional blocker
`dedicated_secret_safe_onepassword_installimage_orchestrator_missing`. Its
future consumer must resolve the exact pinned Password item without returning
the secret to an Ansible variable, fact, callback, file or command argument.
The generic recovery resolver and the installed-host LUKS/Tang workflows keep
their existing Ansible Vault/HashiCorp Vault contracts; selecting
`onepassword_cli` does not silently replace those Day-2 paths.

The bootstrap-unlock authorization carries the foundational plugin's
short-lived approval mapping only as signed-manifest transport metadata. The
recorder binds it to the exact attempt, all six frozen repository commits, the
approved Dropbear fingerprint, the exact dedicated known-hosts file digest and
the manifest time window, then atomically consumes its nonce independently of
the plugin payload. The mapping contains an armored signature from the pinned
foundational Approval Authority. The recorder validates only its transport
shape; the foundational action plugin must verify that signature against its
full inventory- and destination-bound payload before it consumes a secret.
Neither the unsigned mapping shape nor the outer transport alone replaces that
plugin verification.

Retries never reuse an execution ID. Increment the attempt from `001` to `002`
and retain the earlier Started/Result records, including interrupted or failed
attempts.
