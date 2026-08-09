# Wunderbox governed execution binding

`root-of-trust-policy.json` is the public, environment-neutral Recorder-v2
action contract for one Wunderbox Root-of-Trust build. Its top-level schema is
exact: it declares the policy identity, required repositories and collections,
the collection-to-repository mapping, target contract and action matrix. It no
longer contains signing configuration. The policy path, policy digest, manifest
signer, runtime-attestation signer and approval authority are pinned by the
root/admin-owned controller trust descriptor at
`/Library/Application Support/Lightning IT/Governed Ansible/controller-trust.json`;
an adapter caller cannot replace them.

Each action fixes its record prefix, gate, impact, playbook or projection mode,
timeout, output bound, extra-variable contract and evidence prerequisites. Every
callback artifact that may be persisted has an exact schema which types every
projected field and binds target identity fields to the signed manifest. The
adapter `scripts/wbx-governed-exec.py` exposes no policy, allowed-signers,
target, inventory, playbook, gate, impact or arbitrary command option.

`gate-manifest.template.json` and the renderer use manifest schema version 2.
The runtime section binds only digest-pinned toolbox and run-EE images plus the
absolute path, SHA-256 and detached signature path of the separate runtime
attestation. That signed attestation records the source commits and measured
installed collection trees. Collection metadata stated only by the manifest is
not accepted as runtime provenance.

A real engagement manifest is created outside Git in an owner-only directory.
It binds the exact target/controller identity, all six frozen repository
commits, runtime attestation, gate states and one exact authorization entry for
every action. Unselected and blocked actions remain `NOT_APPROVED`. A selected
action additionally needs a time-bounded outer authorization and a separate,
cryptographically signed Foundational execution approval. The execution
approval binds the exact recorder execution ID, repository commits, target,
controller, action, policy, runtime and outer approval and is consumed once by
the recorder before Ansible starts.

Signed approvals used by an Ansible consumer are a separate trust event. The
manifest contains only `consumer_approval_contracts[variable]` with the exact
operation, target and consumer binding. The corresponding signed transport is
supplied only through that action's owner-only extra-vars input. It uses a
different nonce and replay identity from the recorder execution approval; the
recorder verifies it before execution but leaves its one-time claim to the
pinned Foundational consumer immediately before the secret-bearing operation.
Successful execution is accepted only after the recorder verifies that the
consumer created the expected canonical replay marker.

Run the renderer to produce the complete non-approved skeleton:

```bash
python3 scripts/render-wbx-gate-manifest-template.py
```

The renderer adds exactly the evidence and authorization fields required by
each policy action. It gives every action a distinct placeholder execution ID
and nonce so reuse is visible, but it never signs or approves anything. The
output remains non-executable because `manifest_status` is `TEMPLATE`, safety
hold is enabled and every signature is an explicit replacement marker. Replace
all placeholders, independently review the resulting bytes and sign that exact
manifest according to the fixed controller trust descriptor.

The pinned Ansible toolbox and execution environment are Linux runtimes. They
cannot use the macOS 1Password Desktop CLI integration. A socket-only or
partially mounted bridge would leave an unverified trust transition. Therefore
the following seven actions remain fail-closed:

- `recovery_metadata_plan`
- `prepare_installimage_plan`
- `installimage_plan`
- `prepare_installimage_apply`
- `installimage_apply`
- `first_encrypted_boot`
- `bootstrap_unlock`

Six of these actions depend on the Desktop-integrated preparation or unlock
path and use
`blocked_missing_desktop_integrated_onepassword_controller_runtime`.
`installimage_apply` instead requires a dedicated secret-safe orchestrator and
uses
`dedicated_secret_safe_onepassword_installimage_orchestrator_missing`. The
actions remain in the policy as reviewed interface contracts, and the recorder
rejects them before gate, authorization or process evaluation. Syntax actions
remain available because they neither consume the Desktop session nor mutate an
external target.

The blockers may be removed only after independent review of a dedicated macOS
adapter which uses the authenticated Desktop integration without exposing
secrets to the Linux execution environment, or a separately signed bootstrap
phase whose output is a secret-free, integrity-bound Linux input. The
installimage consumer must resolve the exact pinned Password item without
returning the secret to an Ansible variable, fact, callback, file or command
argument.

Retries never reuse an execution ID, execution approval, consumer approval or
nonce. Increment the attempt from `001` to `002` and retain the earlier
Started/Result records, including interrupted or failed attempts. Recorder
outputs remain Candidate Evidence until independently reviewed and externally
anchored; they never advance a gate by themselves.
