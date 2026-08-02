import hashlib
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "mlx90-final-acceptance.yml"
SCRIPT_PATH = ROOT / ".github" / "scripts" / "mlx90-final-acceptance.sh"
PROFILE_PATH = ROOT / "acceptance" / "mlx90" / "profiles.json"


class FinalAcceptanceWorkflowContractTests(unittest.TestCase):
    def setUp(self):
        self.workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.workflow = yaml.safe_load(self.workflow_text)
        self.script = SCRIPT_PATH.read_text(encoding="utf-8")

    def _run_quay_blob_download(
        self,
        challenge=None,
        direct=False,
        token_json='{"token":"synthetic.jwt_token"}',
    ):
        blob = b"verified-buildkit-blob\n"
        digest = "sha256:" + hashlib.sha256(blob).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            driver = root / "driver.sh"
            driver.write_text(
                self.script[: self.script.index("\nverify_mode() {")]
                + '\ndownload_quay_blob "$@"\n',
                encoding="utf-8",
            )
            fake_curl = root / "fake-curl.sh"
            fake_curl.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
count=0
if [ -f "${QUAY_TEST_CALLS:?}" ]; then
  read -r count <"$QUAY_TEST_CALLS"
fi
count=$((count + 1))
printf '%s\n' "$count" >"$QUAY_TEST_CALLS"
printf 'call-%s\n' "$count" >>"${QUAY_TEST_ARGV:?}"
output=""
headers=""
service=""
scope=""
config_stdin=false
arguments=("$@")
for ((index = 0; index < ${#arguments[@]}; index++)); do
  argument="${arguments[$index]}"
  printf '%s\n' "$argument" >>"$QUAY_TEST_ARGV"
  case "$argument" in
    --output)
      index=$((index + 1))
      output="${arguments[$index]}"
      printf '%s\n' "$output" >>"$QUAY_TEST_ARGV"
      ;;
    --dump-header)
      index=$((index + 1))
      headers="${arguments[$index]}"
      printf '%s\n' "$headers" >>"$QUAY_TEST_ARGV"
      ;;
    --data-urlencode)
      index=$((index + 1))
      value="${arguments[$index]}"
      printf '%s\n' "$value" >>"$QUAY_TEST_ARGV"
      case "$value" in
        service=*) service="${value#service=}" ;;
        scope=*) scope="${value#scope=}" ;;
      esac
      ;;
    --config)
      index=$((index + 1))
      [ "${arguments[$index]}" = "-" ] || exit 91
      printf '%s\n' - >>"$QUAY_TEST_ARGV"
      config_stdin=true
      ;;
  esac
done

case "$count" in
  1)
    [ -n "$headers" ] && [ -n "$output" ] || exit 92
    if [ "${QUAY_TEST_DIRECT:?}" = 1 ]; then
      printf 'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n' \
        >"$headers"
      printf 'verified-buildkit-blob\n' >"$output"
      exit 0
    fi
    printf 'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: %s\r\n\r\n' \
      "${QUAY_TEST_CHALLENGE-}" >"$headers"
    exit 22
    ;;
  2)
    [ "$service" = "quay.io" ] || exit 93
    [ "$scope" = "repository:lightning-it/ee-wunder:pull" ] || exit 94
    [ "${arguments[${#arguments[@]} - 1]}" = "https://quay.io/v2/auth" ] \
      || exit 95
    [ -z "$output" ] || exit 96
    printf '%s\n' "${QUAY_TEST_TOKEN_JSON:?}"
    ;;
  3)
    $config_stdin || exit 97
    config="$(cat)"
    [ "$config" = 'oauth2-bearer = "synthetic.jwt_token"' ] || exit 98
    [[ "$*" != *synthetic.jwt_token* ]] || exit 99
    [ -n "$output" ] || exit 100
    printf 'verified-buildkit-blob\n' >"$output"
    printf 'authenticated\n' >"${QUAY_TEST_AUTH_SEEN:?}"
    ;;
  *) exit 101 ;;
esac
""",
                encoding="utf-8",
            )
            bash_env = root / "bash-env.sh"
            bash_env.write_text(
                'curl() { bash "${QUAY_TEST_FAKE_CURL:?}" "$@"; }\n',
                encoding="utf-8",
            )
            output = root / "blob.json"
            calls = root / "calls.txt"
            argv_log = root / "argv.txt"
            auth_seen = root / "auth-seen.txt"
            env = {
                **os.environ,
                "BASH_ENV": str(bash_env),
                "QUAY_TEST_ARGV": str(argv_log),
                "QUAY_TEST_AUTH_SEEN": str(auth_seen),
                "QUAY_TEST_CALLS": str(calls),
                "QUAY_TEST_CHALLENGE": challenge or "",
                "QUAY_TEST_DIRECT": "1" if direct else "0",
                "QUAY_TEST_FAKE_CURL": str(fake_curl),
                "QUAY_TEST_TOKEN_JSON": token_json,
                "RUNNER_TEMP": str(root),
            }
            completed = subprocess.run(
                [
                    "bash",
                    str(driver),
                    "quay.io/lightning-it/ee-wunder",
                    digest,
                    str(len(blob)),
                    str(output),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            return {
                "completed": completed,
                "output_exists": output.exists(),
                "output": output.read_bytes() if output.exists() else None,
                "calls": int(calls.read_text(encoding="utf-8").strip()),
                "argv": argv_log.read_text(encoding="utf-8"),
                "auth_seen": auth_seen.exists(),
                "blob": blob,
            }

    def test_dispatch_contract_is_exact_and_has_no_implicit_trigger(self):
        trigger = self.workflow.get("on", self.workflow.get(True))
        self.assertEqual({"workflow_dispatch"}, set(trigger))
        self.assertEqual(
            {
                "correlation_id",
                "producer_evidence_url",
                "producer_evidence_bundle_url",
                "producer_evidence_sha256",
                "consumer_pr",
                "consumer_head_sha",
                "consumer_merge_sha",
                "container_release_id",
                "container_release_tag",
                "container_release_run_id",
            },
            set(trigger["workflow_dispatch"]["inputs"]),
        )
        for value in trigger["workflow_dispatch"]["inputs"].values():
            self.assertIs(value["required"], True)
            self.assertEqual("string", value["type"])

    def test_job_permissions_are_minimal_and_explicit(self):
        self.assertEqual({}, self.workflow["permissions"])
        self.assertEqual(
            {"actions": "read", "contents": "read", "id-token": "write"},
            self.workflow["jobs"]["verify"]["permissions"],
        )
        self.assertEqual(
            {"actions": "read", "contents": "write"},
            self.workflow["jobs"]["persist"]["permissions"],
        )
        callback = self.workflow["jobs"]["post-delivery"]
        self.assertEqual("persist", callback["needs"])
        self.assertEqual({"contents": "read"}, callback["permissions"])
        self.assertEqual(
            {"name": "ansible-collection-runtime-protected"},
            callback["environment"],
        )
        token_step = next(
            step
            for step in self.workflow["jobs"]["verify"]["steps"]
            if step.get("id") == "evidence-app"
        )
        self.assertEqual(
            {
                "client-id": "${{ vars.RELEASE_AUTOMATION_APP_CLIENT_ID }}",
                "private-key": "${{ secrets.RELEASE_AUTOMATION_APP_PRIVATE_KEY }}",
                "owner": "${{ github.repository_owner }}",
                "repositories": (
                    "ansible-collection-supplementary\n"
                    "container-ee-wunder-ansible-ubi9\n"
                    "shared-assets-lit\n"
                ),
                "permission-actions": "read",
                "permission-contents": "read",
                "permission-pull-requests": "read",
            },
            token_step["with"],
        )
        self.assertIn(
            'test "$APP_INSTALLATION_ID" = "148019054"',
            self.workflow_text,
        )
        self.assertIn(
            'test "$APP_SLUG" = "lightning-it-release-automation"',
            self.workflow_text,
        )
        self.assertNotIn("LIT_REPOSITORY_READ_TOKEN", self.workflow_text)
        self.assertNotIn("--slurp", self.workflow_text)
        self.assertIn(
            "jq -sc '[.[].repositories[].full_name] | sort | unique'",
            self.workflow_text,
        )
        for forbidden in (
            "administration:",
            "checks:",
            "deployments:",
            "environments:",
            "workflows:",
            "permission-administration:",
            "permission-checks:",
            "permission-deployments:",
            "permission-environments:",
            "permission-secrets:",
            "permission-workflows:",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.workflow_text)

        persist = self.workflow["jobs"]["persist"]
        self.assertEqual(
            {
                "final_acceptance_url": (
                    "${{ steps.persistence.outputs.final_acceptance_url }}"
                ),
                "final_acceptance_sha256": (
                    "${{ steps.persistence.outputs.final_acceptance_sha256 }}"
                ),
                "evidence_release_tag": (
                    "${{ steps.persistence.outputs.evidence_release_tag }}"
                ),
                "evidence_release_url": (
                    "${{ steps.persistence.outputs.evidence_release_url }}"
                ),
                "verification_report_url": (
                    "${{ steps.persistence.outputs.verification_report_url }}"
                ),
                "verification_report_sha256": (
                    "${{ steps.persistence.outputs.verification_report_sha256 }}"
                ),
                "receipt_bundle_url": (
                    "${{ steps.persistence.outputs.receipt_bundle_url }}"
                ),
                "receipt_bundle_sha256": (
                    "${{ steps.persistence.outputs.receipt_bundle_sha256 }}"
                ),
                "consumer_merge_sha": (
                    "${{ steps.persistence.outputs.consumer_merge_sha }}"
                ),
                "container_release_tag": (
                    "${{ steps.persistence.outputs.container_release_tag }}"
                ),
            },
            persist["outputs"],
        )
        promotion_token = next(
            step for step in callback["steps"] if step.get("id") == "promotion-app"
        )
        self.assertEqual(
            {
                "client-id": "${{ vars.RELEASE_AUTOMATION_APP_CLIENT_ID }}",
                "private-key": ("${{ secrets.RELEASE_AUTOMATION_APP_PRIVATE_KEY }}"),
                "owner": "${{ github.repository_owner }}",
                "repositories": "container-ee-wunder-ansible-ubi9",
                "permission-actions": "write",
            },
            promotion_token["with"],
        )

    def test_external_actions_and_policy_are_immutably_pinned(self):
        action_uses = re.findall(r"(?m)^\s+uses:\s+([^\s#]+)", self.workflow_text)
        self.assertTrue(action_uses)
        for action in action_uses:
            with self.subTest(action=action):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")
        self.assertIn(
            "ref: 1c6a1d43af638d081108d820b3576e401d9f0857",
            self.workflow_text,
        )
        self.assertIn(
            "name: ansible-collection-runtime-protected",
            self.workflow_text,
        )

    def test_script_fails_closed_before_claiming_delivery(self):
        for required in (
            '[ "$GITHUB_REF" = "refs/heads/main" ]',
            '[ "$GITHUB_ACTOR" = "lightning-it-release-automation[bot]" ]',
            'python3 "$POLICY_VALIDATOR"',
            "cosign verify-blob",
            "verify-container-materials",
            "verify-buildkit-attestations",
            '--certificate-github-workflow-sha "$INPUT_CONSUMER_MERGE_SHA"',
            "docker buildx imagetools inspect --raw",
            "\"${image}:${immutable_tag}\" --format '{{ .Manifest.Digest }}'",
            '"$INPUT_CONTAINER_RELEASE_TAG"',
            '"$container_version"',
            '"sha-$short_consumer_sha"',
            '"${image}@${attestation_digest}"',
            '"https://quay.io/v2/${repository}/blobs/${digest}"',
            "--max-filesize 67108864",
            "--proto-redir '=https'",
            "--max-redirs 1",
            'docker pull "$image_ref"',
            "verify-installed",
            'docker run --rm "$image_ref" "${profile_command[@]}"',
            "--require-delivered",
            "sha256sum --check SHA256SUMS",
            '[ "$APP_INSTALLATION_ID" = "148019054" ]',
            '[ "$APP_SLUG" = "lightning-it-release-automation" ]',
            "security-release-promote-tags.yml/dispatches",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.script)
        self.assertIn("download_release_asset", self.script)
        self.assertIn("Accept: application/octet-stream", self.script)
        self.assertIn(
            "repos/${repository}/releases/assets/${asset_id}",
            self.script,
        )
        self.assertIn("validate_quay_bearer_challenge", self.script)
        self.assertIn("'https://quay.io/v2/auth'", self.script)
        self.assertIn("oauth2-bearer", self.script)
        self.assertIn('"$layer_digest" "$layer_size"', self.script)
        self.assertNotIn("Authorization:", self.script)
        self.assertNotIn("--location-trusted", self.script)
        self.assertIn("immutable reference digest mismatch", self.script)
        self.assertNotIn(
            'immutable reference digest mismatch: ${url}', self.script
        )
        self.assertEqual(2, self.script.count("--location"))
        signed_index = self.script.index(
            '      "$image_ref" >"$INPUT_ROOT/${variant}-signature-live.json"'
        )
        immutable_alias = self.script.index(
            '        "${image}:${immutable_tag}" --format'
        )
        attached_payload = self.script.index("        download_quay_blob \\")
        self.assertLess(signed_index, immutable_alias)
        self.assertLess(immutable_alias, attached_payload)
        self.assertNotIn(
            'docker buildx imagetools inspect "${image}:latest"',
            self.script,
        )
        raw_index = self.script.index(
            'docker buildx imagetools inspect --raw "$image_ref" >"$index_path"'
        )
        raw_digest = self.script.index('sha256sum "$index_path"', raw_index)
        library_index = self.script.index(
            'python3 "$FINALIZER" verify-index', raw_digest
        )
        semantic_read = self.script.index(
            'platform_digests="$(jq -ec', library_index
        )
        self.assertLess(raw_index, raw_digest)
        self.assertLess(raw_digest, library_index)
        self.assertLess(library_index, semantic_read)
        durable_validation = self.script.index(
            '    "$release_dir/mlx90-final-acceptance.json"'
        )
        callback_output = self.script.index(
            '    echo "final_acceptance_url=$durable_acceptance_url"'
        )
        self.assertLess(durable_validation, callback_output)
        self.assertIn(
            '(keys | sort) == ["inputs", "ref"]',
            self.script,
        )
        for callback_input in (
            "consumer_merge_sha",
            "container_release_tag",
            "final_acceptance_sha256",
            "final_acceptance_url",
        ):
            with self.subTest(callback_input=callback_input):
                self.assertEqual(1, self.script.count(f"{callback_input}:"))
        for forbidden in (
            "ACCEPTANCE_COMMAND",
            "--clobber",
            "eval ",
            "github_pat_",
            "ghp_",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.script)

    def test_quay_blob_download_supports_direct_anonymous_access(self):
        result = self._run_quay_blob_download(direct=True)
        completed = result["completed"]
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(1, result["calls"])
        self.assertEqual(result["blob"], result["output"])
        self.assertFalse(result["auth_seen"])

    def test_quay_blob_download_uses_exact_anonymous_bearer_exchange(self):
        challenge = (
            'Bearer service="quay.io", '
            'scope="repository:lightning-it/ee-wunder:pull",'
            'realm="https://quay.io/v2/auth"'
        )
        result = self._run_quay_blob_download(challenge=challenge)
        completed = result["completed"]
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(3, result["calls"])
        self.assertEqual(result["blob"], result["output"])
        self.assertTrue(result["auth_seen"])
        for captured in (completed.stdout, completed.stderr, result["argv"]):
            self.assertNotIn("synthetic.jwt_token", captured)

    def test_quay_blob_download_rejects_untrusted_bearer_challenges(self):
        challenges = (
            'Bearer realm="https://evil.example/token",service="quay.io",'
            'scope="repository:lightning-it/ee-wunder:pull"',
            'Bearer realm="https://quay.io/v2/auth",service="registry.example",'
            'scope="repository:lightning-it/ee-wunder:pull"',
            'Bearer realm="https://quay.io/v2/auth",service="quay.io",'
            'scope="repository:lightning-it/other:pull"',
            'Bearer realm="https://quay.io/v2/auth",service="quay.io",'
            'scope="repository:lightning-it/ee-wunder:pull,push"',
            'Bearer realm="https://quay.io/v2/auth",service="quay.io",'
            'scope="repository:lightning-it/ee-wunder:pull",account="someone"',
            'Bearer realm="https://quay.io/v2/auth",'
            'realm="https://quay.io/v2/auth",service="quay.io",'
            'scope="repository:lightning-it/ee-wunder:pull"',
            'Bearer realm="https://quay.io/v2/auth",service="quay.io",'
            'scope="repository:lightning-it/ee-wunder:pull",',
            'Bearer realm="https://quay.io/v2/auth",service="quay.io",'
            'scope="repository:lightning-it/ee-wunder:pull"\r\n'
            'WWW-Authenticate: Bearer realm="https://quay.io/v2/auth",'
            'service="quay.io",'
            'scope="repository:lightning-it/ee-wunder:pull"',
            "",
        )
        for challenge in challenges:
            with self.subTest(challenge=challenge):
                result = self._run_quay_blob_download(challenge=challenge)
                completed = result["completed"]
                self.assertNotEqual(0, completed.returncode)
                self.assertEqual(1, result["calls"])
                self.assertFalse(result["output_exists"])
                self.assertFalse(result["auth_seen"])
                self.assertNotIn("synthetic.jwt_token", completed.stdout)
                self.assertNotIn("synthetic.jwt_token", completed.stderr)
                self.assertNotIn("synthetic.jwt_token", result["argv"])
                if challenge:
                    self.assertNotIn(challenge, completed.stdout)
                    self.assertNotIn(challenge, completed.stderr)

    def test_quay_blob_download_rejects_unsafe_token_content(self):
        challenge = (
            'Bearer realm="https://quay.io/v2/auth",service="quay.io",'
            'scope="repository:lightning-it/ee-wunder:pull"'
        )
        result = self._run_quay_blob_download(
            challenge=challenge,
            token_json='{"token":"unsafe token"}',
        )
        completed = result["completed"]
        self.assertNotEqual(0, completed.returncode)
        self.assertEqual(2, result["calls"])
        self.assertFalse(result["output_exists"])
        self.assertFalse(result["auth_seen"])
        self.assertNotIn("unsafe token", completed.stdout)
        self.assertNotIn("unsafe token", completed.stderr)
        self.assertNotIn("unsafe token", result["argv"])

    def test_persistence_recovers_only_matching_drafts_before_publish(self):
        for required in (
            "draft: true",
            "{draft: false, make_latest: \"false\"}",
            "existing draft asset differs",
            "draft evidence release ownership changed",
            "downloaded draft evidence asset set is not exact",
            "canonical_release_asset_metadata",
            "download_release_assets_and_compare",
            "upload_release_asset_by_id",
            "https://uploads.github.com/repos/${repository}/",
            '"repos/${FINALIZER_REPOSITORY}/releases/${release_id}"',
            '"$FINALIZER_REPOSITORY" "$release_id"',
            ".immutable == true",
            "sha256sum --check SHA256SUMS",
            '"$verified_draft_dir/SHA256SUMS.sigstore.json"',
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.script)
        persistence = self.script[
            self.script.index("persist_mode()") : self.script.index("callback_mode()")
        ]
        create = persistence.index(
            '"repos/${FINALIZER_REPOSITORY}/releases"'
        )
        upload = persistence.index("        upload_release_asset_by_id")
        publish = persistence.index("        --method PATCH")
        self.assertLess(create, upload)
        self.assertLess(upload, publish)
        self.assertNotIn("gh release view", persistence)
        self.assertNotIn("gh release download", persistence)
        self.assertNotIn("gh release create", persistence)
        self.assertNotIn("gh release upload", persistence)
        self.assertNotIn("gh release edit", persistence)
        self.assertNotIn("--json assets", persistence)
        self.assertEqual(
            6,
            len(
                re.findall(
                    r"(?m)^    (?:SHA256SUMS|SHA256SUMS\.sigstore\.json|"
                    r"mlx90-final-acceptance\.json|"
                    r"mlx90-verification-receipts\.json|"
                    r"mlx90-verification-report\.json|"
                    r"security-release-delivered\.json)$",
                    persistence,
                )
            ),
        )

    def test_persistence_uses_live_asset_urls_only_after_id_downloads(self):
        persistence = self.script[
            self.script.index("persist_mode()") : self.script.index("callback_mode()")
        ]
        for required in (
            'release_assets="$(list_release_assets',
            "gh api --paginate",
            "repos/${repository}/releases/${release_id}/assets?per_page=100",
            "repos/${repository}/releases/assets/${asset_id}",
            'published_asset_metadata="$(canonical_release_asset_metadata',
            'release_asset_metadata="$(canonical_release_asset_metadata',
            'durable_release_url="$(jq -er \'.html_url\'',
            "then .[0].url",
            "live final acceptance asset URL is not canonical",
            "immutable evidence release assets changed during verification",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.script)
        download = persistence.index("  download_release_assets_and_compare")
        stable_metadata = persistence.index(
            '  [ "$release_asset_metadata" = "$published_asset_metadata" ]'
        )
        actual_urls = persistence.index('  durable_release_url="$(jq -er')
        outputs = persistence.index(
            '    echo "final_acceptance_url=$durable_acceptance_url"'
        )
        self.assertLess(download, stable_metadata)
        self.assertLess(stable_metadata, actual_urls)
        self.assertLess(actual_urls, outputs)

    def test_final_receipt_rebinds_tags_and_every_consumed_asset_snapshot(self):
        for required in (
            "canonical_consumed_asset_snapshot",
            "asset_snapshot_digest",
            "redownload_snapshot_and_compare",
            "producer_initial_asset_snapshot_digest",
            "container_initial_asset_snapshot_digest",
            "final_producer_asset_snapshot_digest",
            "final_container_asset_snapshot_digest",
            'final_producer_tag_commit="$(resolve_tag_commit',
            'final_container_tag_commit="$(resolve_tag_commit',
            "producerTagCommit",
            "containerTagCommit",
            "producerInitialAssetSnapshotDigest",
            "producerFinalAssetSnapshotDigest",
            "containerInitialAssetSnapshotDigest",
            "containerFinalAssetSnapshotDigest",
            "producerAssets",
            "containerAssets",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.script)
        producer_redownload = self.script.index(
            '    "$INPUT_ROOT/final-producer-assets"'
        )
        container_redownload = self.script.index(
            '    "$INPUT_ROOT/final-container-assets"'
        )
        final_receipt = self.script.index("write_receipt final-revocation")
        self.assertLess(producer_redownload, final_receipt)
        self.assertLess(container_redownload, final_receipt)

        producer_initial = self.script[
            self.script.index("write_receipt producer-revocation-initial") :
            self.script.index("write_receipt producer-cosign")
        ]
        container_initial = self.script[
            self.script.index("write_receipt container-revocation-initial") :
            self.script.index("write_receipt container-cosign")
        ]
        for block, snapshot, digest in (
            (
                producer_initial,
                "producer_initial_asset_snapshot",
                "producer_initial_asset_snapshot_digest",
            ),
            (
                container_initial,
                "container_initial_asset_snapshot",
                "container_initial_asset_snapshot_digest",
            ),
        ):
            with self.subTest(initial_snapshot=snapshot):
                self.assertIn(f'--argjson asset_snapshot "${snapshot}"', block)
                self.assertIn(
                    f'--arg asset_snapshot_digest "${digest}"', block
                )
                self.assertIn("assetSnapshot: $asset_snapshot", block)
                self.assertIn(
                    "assetSnapshotDigest: $asset_snapshot_digest", block
                )

        producer_readback = self.script.index(
            'stored_producer_initial_asset_snapshot_digest="$(jq -er'
        )
        container_readback = self.script.index(
            'stored_container_initial_asset_snapshot_digest="$(jq -er'
        )
        first_final_comparison = self.script.index(
            '[ "$final_producer_asset_snapshot_digest"', producer_readback
        )
        self.assertLess(producer_readback, first_final_comparison)
        self.assertLess(container_readback, first_final_comparison)
        self.assertLess(producer_readback, final_receipt)
        self.assertLess(container_readback, final_receipt)
        self.assertIn(
            '"$RECEIPT_ROOT/producer-revocation-initial.json"', self.script
        )
        self.assertIn(
            '"$RECEIPT_ROOT/container-revocation-initial.json"', self.script
        )
        self.assertIn(
            '--arg producer_initial_snapshot '
            '"$stored_producer_initial_asset_snapshot_digest"',
            self.script,
        )
        self.assertIn(
            '--arg container_initial_snapshot '
            '"$stored_container_initial_asset_snapshot_digest"',
            self.script,
        )

    def test_typed_receipts_are_run_owned_and_persisted_as_sixth_asset(self):
        for required in (
            "write-receipt",
            '--workflow-sha "$GITHUB_SHA"',
            '--run-id "$GITHUB_RUN_ID"',
            '--run-attempt "$GITHUB_RUN_ATTEMPT"',
            '--receipts "$RECEIPT_ROOT"',
            "mlx90-verification-receipts.json",
            "final-revocation",
            "producer-central-ci",
            'actions/runs/${producer_ci_run_id}/attempts/${producer_ci_run_attempt}',
            'actions/runs/${producer_ci_run_id}/attempts/${producer_ci_run_attempt}/jobs?per_page=100',
            'if length != 1 then',
            'producer central validation job did not complete successfully',
            "final live revocation check found revocation evidence",
            "list_release_assets()",
            "gh api --paginate",
            'final_producer_assets="$(list_release_assets',
            'final_container_assets="$(list_release_assets',
            "durable acceptance receipt bundle digest mismatch",
            "durable acceptance receipt bundle size mismatch",
            'echo "verification_report_url=$durable_report_url"',
            'echo "verification_report_sha256=$durable_report_digest"',
            'echo "receipt_bundle_url=$durable_receipt_url"',
            'echo "receipt_bundle_sha256=$durable_receipt_digest"',
            '"$EVIDENCE_ROOT" "$release_dir"',
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.script)
        final_producer_fetch = self.script.index('final_producer_release="$(gh api')
        final_container_fetch = self.script.index('final_container_release="$(gh api')
        final_receipt = self.script.index("write_receipt final-revocation")
        report = self.script.index('python3 "$FINALIZER" write-report')
        finalize = self.script.index('python3 "$FINALIZER" finalize')
        self.assertLess(final_producer_fetch, final_receipt)
        self.assertLess(final_container_fetch, final_receipt)
        self.assertLess(final_receipt, report)
        self.assertLess(report, finalize)
        self.assertIn(
            "expected_files+=$'mlx90-verification-receipts.json\\n'",
            self.script,
        )
        checksum_block = self.script[
            self.script.index("    sha256sum \\") : self.script.index(
                "      >SHA256SUMS"
            )
        ]
        self.assertIn("mlx90-verification-receipts.json", checksum_block)

    def test_callback_dispatches_only_the_four_digest_bound_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture = root / "dispatch.json"
            arguments = root / "dispatch-args.txt"
            bash_env = root / "fake-gh.sh"
            bash_env.write_text(
                """#!/usr/bin/env bash
gh() {
  if [[ "$*" == *"installation/repositories?per_page=100"* ]]; then
    printf '%s\n' '{"repositories":[{"full_name":"lightning-it/container-ee-wunder-ansible-ubi9"}]}'
  elif [[ "$*" == *"security-release-promote-tags.yml/dispatches"* ]]; then
    printf '%s\n' "$*" >"${CALLBACK_ARGUMENTS:?}"
    cat >"${CALLBACK_CAPTURE:?}"
  else
    return 99
  fi
}
""",
                encoding="utf-8",
            )
            digest = "sha256:" + "a" * 64
            semver_at_limit = "1.2.3-" + "a" * 249
            semver_over_limit = "1.2.3-" + "a" * 250
            denial_of_service_payload = "1.2.3-" + "a." * 5_000
            self.assertEqual(255, len(semver_at_limit))
            self.assertEqual(256, len(semver_over_limit))
            env = {
                **os.environ,
                "APP_INSTALLATION_ID": "148019054",
                "APP_SLUG": "lightning-it-release-automation",
                "CALLBACK_ARGUMENTS": str(arguments),
                "CALLBACK_CAPTURE": str(capture),
                "CONSUMER_MERGE_SHA": "b" * 40,
                "CONTAINER_RELEASE_TAG": f"v{semver_at_limit}",
                "FINAL_ACCEPTANCE_SHA256": digest,
                "FINAL_ACCEPTANCE_URL": (
                    "https://github.com/lightning-it/modulix-validation/"
                    "releases/download/v0.0.0-mlx90.aaaaaaaaaaaaaaaa/"
                    "mlx90-final-acceptance.json"
                ),
                "GH_TOKEN": "synthetic-test-only",
                "GITHUB_ACTOR": "lightning-it-release-automation[bot]",
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_REPOSITORY": "lightning-it/modulix-validation",
                "BASH_ENV": str(bash_env),
                "RUNNER_TEMP": str(root),
            }
            completed = subprocess.run(
                [str(SCRIPT_PATH), "callback"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertNotIn("--slurp", self.script)
            self.assertEqual(
                {
                    "ref": "main",
                    "inputs": {
                        "final_acceptance_url": env["FINAL_ACCEPTANCE_URL"],
                        "final_acceptance_sha256": digest,
                        "consumer_merge_sha": "b" * 40,
                        "container_release_tag": f"v{semver_at_limit}",
                    },
                },
                json.loads(capture.read_text(encoding="utf-8")),
            )
            self.assertIn("--method POST", arguments.read_text(encoding="utf-8"))
            length_guard = self.script.index(
                '[ "${#value}" -le "$SEMVER_MAX_LENGTH" ]'
            )
            grammar = self.script.index(
                '[[ "$value" =~ ^[0-9A-Za-z.+-]+$ ]]'
            )
            self.assertLess(length_guard, grammar)

            capture.unlink()
            for invalid_tag in (
                "v01.2.3",
                "v1.2.3-01",
                "v1.2.3+build..1",
                "v1.2.3+_build",
                "v1.2.3-α",
                f"v{semver_over_limit}",
                f"v{denial_of_service_payload}",
            ):
                with self.subTest(invalid_tag=invalid_tag):
                    env["CONTAINER_RELEASE_TAG"] = invalid_tag
                    rejected = subprocess.run(
                        [str(SCRIPT_PATH), "callback"],
                        cwd=ROOT,
                        env=env,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertNotEqual(0, rejected.returncode)
                    self.assertIn(
                        "container release tag is invalid", rejected.stderr
                    )
                    self.assertFalse(capture.exists())

            env["CONTAINER_RELEASE_TAG"] = f"v{semver_at_limit}"
            env["APP_INSTALLATION_ID"] = "148019055"
            rejected = subprocess.run(
                [str(SCRIPT_PATH), "callback"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, rejected.returncode)
            self.assertIn("installation is invalid", rejected.stderr)
            self.assertFalse(capture.exists())

    def test_only_historical_fixture_profile_exists_and_cannot_release(self):
        profile_document = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(1, profile_document["schemaVersion"])
        self.assertEqual(
            {"lit.supplementary/mlx90-fixture"},
            set(profile_document["profiles"]),
        )
        fixture = profile_document["profiles"]["lit.supplementary/mlx90-fixture"]
        self.assertIs(fixture["releaseEligible"], False)
        self.assertEqual(["/bin/false"], fixture["containerCommand"])


if __name__ == "__main__":
    unittest.main()
