import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "mlx90_finalizer",
    ROOT / "scripts" / "finalize-mlx90-delivery.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def digest_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_json_line(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def reference(
    repository: str, tag: str, name: str, character: str
) -> dict[str, str]:
    return {
        "url": f"https://github.com/{repository}/releases/download/{tag}/{name}",
        "digest": f"sha256:{character * 64}",
    }


class FinalizerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.producer_path = self.root / "security-release-evidence.json"
        self.container_path = self.root / "mlx90-container-evidence.json"
        self.profiles_path = self.root / "profiles.json"
        self.profile = "lit.supplementary/security-fix-2026-001"
        self.producer = self.producer_fixture()
        write_json(self.producer_path, self.producer)
        producer_sha256 = digest_bytes(self.producer_path.read_bytes())
        self.identity = MODULE.DispatchIdentity(
            correlation_id="mlx90-LIT-SEC-2026-001",
            producer_evidence_url=(
                "https://github.com/lightning-it/"
                "ansible-collection-supplementary/releases/download/v3.2.0/"
                "security-release-evidence.json"
            ),
            producer_evidence_bundle_url=(
                "https://github.com/lightning-it/"
                "ansible-collection-supplementary/releases/download/v3.2.0/"
                "security-release-evidence.json.sigstore.json"
            ),
            producer_evidence_sha256=producer_sha256,
            consumer_pr=503,
            consumer_head_sha="2" * 40,
            consumer_merge_sha="3" * 40,
            container_release_id=987,
            container_release_tag="v1.25.0",
            container_release_run_id=123456,
            container_publish_run_attempt=1,
        )
        self.container = self.container_fixture()
        write_json(self.container_path, self.container)
        self.profiles = {
            "schemaVersion": 1,
            "profiles": {
                self.profile: {
                    "description": "Synthetic unit-test-only security profile.",
                    "releaseEligible": True,
                    "containerCommand": ["/usr/local/bin/security-fix-check"],
                }
            },
        }
        write_json(self.profiles_path, self.profiles)

    def tearDown(self):
        self.temporary.cleanup()

    def producer_fixture(self):
        producer_repository = MODULE.PRODUCER_REPOSITORY
        return {
            "apiVersion": "lit.security-release/v1",
            "kind": "SecurityReleaseEvidence",
            "metadata": {
                "id": "LIT-SEC-2026-001",
                "createdAt": "2026-08-02T10:00:00Z",
            },
            "security": {
                "identifiers": ["LIT-SEC-2026-001"],
                "affectedVersion": "3.1.2",
                "fixedVersion": "3.2.0",
            },
            "producer": {
                "repository": producer_repository,
                "sourceSha": "1" * 40,
                "workflowRepository": producer_repository,
                "workflowRef": "1" * 40,
            },
            "artifact": {
                "collection": "lit.supplementary",
                "version": "3.2.0",
                "digest": f"sha256:{'a' * 64}",
                "releaseUrl": (
                    f"https://github.com/{producer_repository}/"
                    "releases/tag/v3.2.0"
                ),
                "signature": reference(
                    producer_repository,
                    "v3.2.0",
                    "collection.sigstore.json",
                    "b",
                ),
                "sbom": reference(
                    producer_repository, "v3.2.0", "sbom.cdx.json", "c"
                ),
                "provenance": reference(
                    producer_repository, "v3.2.0", "provenance.json", "d"
                ),
            },
            "consumers": [MODULE.CONSUMER_REPOSITORY],
            "acceptance": {
                "profile": self.profile,
                "expectedCollection": "lit.supplementary",
                "expectedVersion": "3.2.0",
            },
            "validity": {
                "notBefore": "2026-08-02T09:00:00Z",
                "expiresAt": "2026-08-09T09:00:00Z",
                "revoked": False,
            },
            "status": "approved",
        }

    def container_fixture(self):
        container_repository = MODULE.CONSUMER_REPOSITORY
        producer_evidence = {
            "url": self.identity.producer_evidence_url,
            "digest": f"sha256:{self.identity.producer_evidence_sha256}",
        }
        variants = {}
        for index, name in enumerate(MODULE.VARIANTS, start=1):
            suffix = "" if name == "public" else f"-{name}"
            image = f"quay.io/lightning-it/ee-wunder{suffix}"
            variants[name] = {
                "image": image,
                "manifestDigest": f"sha256:{str(index) * 64}",
                "platformDigests": {
                    "linux/amd64": f"sha256:{'a' * 64}",
                    "linux/arm64": f"sha256:{'b' * 64}",
                },
                "signature": reference(
                    container_repository,
                    "v1.25.0",
                    f"signature-{name}.json",
                    "c",
                ),
                "sbom": reference(
                    container_repository,
                    "v1.25.0",
                    f"sbom-{name}.cdx.json",
                    "d",
                ),
                "provenance": reference(
                    container_repository,
                    "v1.25.0",
                    "release-provenance.intoto.jsonl",
                    "e",
                ),
            }
        return {
            "apiVersion": "lit.security-release.container/v1",
            "kind": "SecurityReleaseContainerEvidence",
            "securityEvidenceId": self.producer["metadata"]["id"],
            "producer": {
                "repository": MODULE.PRODUCER_REPOSITORY,
                "sourceSha": self.producer["producer"]["sourceSha"],
                "collection": self.producer["artifact"]["collection"],
                "version": self.producer["artifact"]["version"],
                "collectionDigest": self.producer["artifact"]["digest"],
                "evidence": producer_evidence,
            },
            "consumer": {
                "repository": container_repository,
                "pullRequest": self.identity.consumer_pr,
                "baseSha": "7" * 40,
                "headSha": self.identity.consumer_head_sha,
                "mergeSha": self.identity.consumer_merge_sha,
            },
            "release": {
                "repository": container_repository,
                "id": self.identity.container_release_id,
                "tag": self.identity.container_release_tag,
                "url": (
                    f"https://github.com/{container_repository}/releases/tag/"
                    f"{self.identity.container_release_tag}"
                ),
                "sourceSha": self.identity.consumer_merge_sha,
                "workflowRunId": self.identity.container_release_run_id,
                "workflowRunAttempt": 1,
            },
            "variants": variants,
            "revocation": {
                "status": "not_revoked",
                "checkedAt": "2026-08-02T11:00:00Z",
            },
        }

    def validated(self):
        self.identity.validate()
        profiles = MODULE.load_profiles(self.profiles_path)
        producer = MODULE.validate_producer_evidence(
            copy.deepcopy(self.producer), self.identity, profiles
        )
        container = MODULE.validate_container_evidence(
            copy.deepcopy(self.container), self.identity, producer
        )
        return producer, container

    def cli_arguments(self, command, *, receipt_id="producer-evidence"):
        identity = self.identity
        identity_arguments = [
            "--correlation-id",
            identity.correlation_id,
            "--producer-evidence-url",
            identity.producer_evidence_url,
            "--producer-evidence-bundle-url",
            identity.producer_evidence_bundle_url,
            "--producer-evidence-sha256",
            identity.producer_evidence_sha256,
            "--consumer-pr",
            str(identity.consumer_pr),
            "--consumer-head-sha",
            identity.consumer_head_sha,
            "--consumer-merge-sha",
            identity.consumer_merge_sha,
            "--container-release-id",
            str(identity.container_release_id),
            "--container-release-tag",
            identity.container_release_tag,
            "--container-release-run-id",
            str(identity.container_release_run_id),
            "--container-publish-run-attempt",
            str(identity.container_publish_run_attempt),
        ]
        evidence_arguments = [
            "--producer-evidence",
            str(self.producer_path),
            "--container-evidence",
            str(self.container_path),
            "--profiles",
            str(self.profiles_path),
        ]
        run_arguments = [
            "--workflow-sha",
            "6" * 40,
            "--run-id",
            "456789",
            "--run-attempt",
            "1",
        ]
        path = str(self.root / "placeholder.json")
        arguments = {
            "validate-inputs": identity_arguments,
            "preflight": identity_arguments + evidence_arguments,
            "profile-command": [
                "--profiles",
                str(self.profiles_path),
                "--profile",
                self.profile,
            ],
            "verify-producer-materials": [
                "--producer-evidence",
                str(self.producer_path),
                "--collection",
                path,
                "--sbom",
                path,
                "--provenance",
                path,
            ],
            "verify-index": [
                "--container-evidence",
                str(self.container_path),
                "--variant",
                "public",
                "--index",
                path,
            ],
            "verify-buildkit-attestations": [
                "--container-evidence",
                str(self.container_path),
                "--variant",
                "public",
                "--index",
                path,
                "--attestation-root",
                str(self.root),
            ],
            "verify-container-materials": [
                "--container-evidence",
                str(self.container_path),
                "--variant",
                "public",
                "--signature",
                path,
                "--live-signature",
                path,
                "--sbom",
                path,
                "--provenance",
                path,
            ],
            "verify-installed": [
                "--result",
                path,
                "--collection",
                "lit.supplementary",
                "--expect-absent",
                "--observation-output",
                str(self.root / "observation.json"),
            ],
            "write-receipt": identity_arguments
            + evidence_arguments
            + run_arguments
            + [
                "--receipt-id",
                receipt_id,
                "--observations",
                path,
                "--checked-at",
                "2026-08-02T12:00:00Z",
                "--output",
                str(self.root / f"{receipt_id}.json"),
            ],
            "write-report": identity_arguments
            + evidence_arguments
            + run_arguments
            + [
                "--receipts",
                str(self.root),
                "--receipt-bundle-output",
                str(self.root / "bundle.json"),
                "--output",
                str(self.root / "report.json"),
            ],
            "finalize": identity_arguments
            + evidence_arguments
            + run_arguments
            + [
                "--verification-report",
                path,
                "--receipt-bundle",
                path,
                "--delivered-output",
                str(self.root / "delivered.json"),
                "--acceptance-output",
                str(self.root / "acceptance.json"),
            ],
        }
        return ["finalizer", command, *arguments[command]]

    def receipt_observations(self, receipt_id, producer, container):
        artifact = producer["artifact"]
        release = container["release"]
        evidence_id = producer["metadata"]["id"]
        producer_release_id = 654321
        producer_identity = (
            f"https://github.com/{MODULE.PRODUCER_REPOSITORY}/"
            ".github/workflows/collection-publish.yml@refs/heads/main"
        )
        collection_identity = (
            f"https://github.com/{MODULE.PRODUCER_REPOSITORY}/"
            ".github/workflows/collection-ci.yml@refs/heads/main"
        )
        container_identity = (
            f"https://github.com/{MODULE.CONSUMER_REPOSITORY}/"
            ".github/workflows/container-build-publish.yml@"
            f"refs/tags/{self.identity.container_release_tag}"
        )
        producer_urls, container_urls = MODULE.consumed_release_asset_urls(
            self.identity, producer, container
        )

        def asset_snapshot(repository, release_id, urls, first_id):
            return {
                "repository": repository,
                "releaseId": release_id,
                "assets": [
                    {
                        "id": first_id + index,
                        "name": url.rsplit("/", 1)[-1],
                        "url": url,
                        "state": "uploaded",
                        "size": 1000 + index,
                    }
                    for index, url in enumerate(sorted(urls))
                ],
            }

        producer_asset_snapshot = asset_snapshot(
            MODULE.PRODUCER_REPOSITORY,
            producer_release_id,
            producer_urls,
            10000,
        )
        container_asset_snapshot = asset_snapshot(
            MODULE.CONSUMER_REPOSITORY,
            self.identity.container_release_id,
            container_urls,
            20000,
        )
        producer_asset_snapshot_digest = MODULE.canonical_value_digest(
            producer_asset_snapshot
        )
        container_asset_snapshot_digest = MODULE.canonical_value_digest(
            container_asset_snapshot
        )
        globals_by_id = {
            "producer-evidence": {
                "evidenceId": evidence_id,
                "evidenceUrl": self.identity.producer_evidence_url,
                "evidenceDigest": (
                    f"sha256:{self.identity.producer_evidence_sha256}"
                ),
                "sourceSha": producer["producer"]["sourceSha"],
            },
            "producer-identity": {
                "releaseId": producer_release_id,
                "releaseTag": f"v{artifact['version']}",
                "releaseUrl": artifact["releaseUrl"],
                "tagCommit": producer["producer"]["sourceSha"],
                "draft": False,
                "prerelease": False,
            },
            "producer-revocation-initial": {
                "releaseId": producer_release_id,
                "evidenceId": evidence_id,
                "revocationAssetCount": 0,
                "assetSnapshot": producer_asset_snapshot,
                "assetSnapshotDigest": producer_asset_snapshot_digest,
            },
            "producer-cosign": {
                "evidenceBundleDigest": f"sha256:{'8' * 64}",
                "collectionBundleDigest": f"sha256:{'9' * 64}",
                "evidenceIdentity": producer_identity,
                "collectionIdentity": collection_identity,
                "sourceSha": producer["producer"]["sourceSha"],
            },
            "producer-materials": {
                "collectionDigest": artifact["digest"],
                "sbomDigest": artifact["sbom"]["digest"],
                "provenanceDigest": artifact["provenance"]["digest"],
                "version": artifact["version"],
                "workflowRunId": 123456,
                "workflowRunAttempt": 1,
            },
            "producer-central-ci": {
                "provenanceDigest": artifact["provenance"]["digest"],
                "sourceSha": producer["producer"]["sourceSha"],
                "workflowRunId": 123456,
                "workflowRunAttempt": 1,
                "workflowRunUrl": (
                    "https://github.com/"
                    f"{MODULE.PRODUCER_REPOSITORY}/actions/runs/123456"
                ),
                "workflowName": MODULE.PRODUCER_WORKFLOW_NAME,
                "workflowPath": MODULE.PRODUCER_WORKFLOW,
                "runRepository": MODULE.PRODUCER_REPOSITORY,
                "headRepository": MODULE.PRODUCER_REPOSITORY,
                "event": "push",
                "headBranch": "main",
                "headSha": producer["producer"]["sourceSha"],
                "status": "completed",
                "conclusion": "success",
                "gateJobId": 987654,
                "gateJobName": MODULE.PRODUCER_VALIDATION_JOB,
                "gateJobStatus": "completed",
                "gateJobConclusion": "success",
            },
            "consumer-identity": {
                "pullRequest": self.identity.consumer_pr,
                "state": "closed",
                "mergedAt": "2026-08-02T10:30:00Z",
                "baseRef": "main",
                "baseSha": container["consumer"]["baseSha"],
                "headRepository": MODULE.CONSUMER_REPOSITORY,
                "headSha": self.identity.consumer_head_sha,
                "mergeSha": self.identity.consumer_merge_sha,
                "mergeParents": [
                    container["consumer"]["baseSha"],
                    self.identity.consumer_head_sha,
                ],
            },
            "container-release": {
                "releaseId": self.identity.container_release_id,
                "releaseTag": self.identity.container_release_tag,
                "releaseUrl": release["url"],
                "draft": False,
                "prerelease": False,
                "sourceSha": self.identity.consumer_merge_sha,
                "workflowRunId": self.identity.container_release_run_id,
                "workflowRunAttempt": release["workflowRunAttempt"],
                "publishRunAttempt": (
                    self.identity.container_publish_run_attempt
                ),
                "runRepository": MODULE.CONSUMER_REPOSITORY,
                "headRepository": MODULE.CONSUMER_REPOSITORY,
                "event": "workflow_dispatch",
                "workflowPath": MODULE.CONTAINER_WORKFLOW,
                "workflowBlobSha": "4" * 40,
                "publisherNeeds": ["build", "upload-trivy-sarif"],
                "headSha": self.identity.consumer_merge_sha,
                "headBranch": self.identity.container_release_tag,
                "actor": MODULE.CONTAINER_RELEASE_ACTOR,
                "evidenceTriggeringActor": MODULE.CONTAINER_RELEASE_ACTOR,
                "publishTriggeringActor": MODULE.CONTAINER_RELEASE_ACTOR,
                "immutable": True,
                "targetCommitish": self.identity.consumer_merge_sha,
                "author": MODULE.CONTAINER_RELEASE_ACTOR,
                "evidenceRunStatus": "completed",
                "evidenceRunConclusion": "success",
                "status": "completed",
                "conclusion": "success",
                "buildJobId": 456001,
                "buildJobName": "Build & push image to Quay.io",
                "buildJobStatus": "completed",
                "buildJobConclusion": "success",
                "publisherJobId": 456003,
                "publisherJobName": "Attach signed release evidence",
                "publisherJobStatus": "completed",
                "publisherJobConclusion": "success",
            },
            "container-revocation-initial": {
                "releaseId": self.identity.container_release_id,
                "evidenceId": evidence_id,
                "revocationAssetCount": 0,
                "assetSnapshot": container_asset_snapshot,
                "assetSnapshotDigest": container_asset_snapshot_digest,
            },
            "container-cosign": {
                "bundleDigest": f"sha256:{'7' * 64}",
                "identity": container_identity,
                "sourceSha": self.identity.consumer_merge_sha,
            },
            "final-revocation": {
                "producerReleaseId": producer_release_id,
                "producerReleaseTag": f"v{artifact['version']}",
                "containerReleaseId": self.identity.container_release_id,
                "containerReleaseTag": self.identity.container_release_tag,
                "producerTagCommit": producer["producer"]["sourceSha"],
                "containerTagCommit": self.identity.consumer_merge_sha,
                "evidenceId": evidence_id,
                "producerRevocationAssetCount": 0,
                "containerRevocationAssetCount": 0,
                "producerInitialAssetSnapshotDigest": (
                    producer_asset_snapshot_digest
                ),
                "producerFinalAssetSnapshotDigest": producer_asset_snapshot_digest,
                "containerInitialAssetSnapshotDigest": (
                    container_asset_snapshot_digest
                ),
                "containerFinalAssetSnapshotDigest": container_asset_snapshot_digest,
                "producerAssets": producer_asset_snapshot,
                "containerAssets": container_asset_snapshot,
            },
        }
        if receipt_id in globals_by_id:
            return globals_by_id[receipt_id]

        variant = next(
            name for name in MODULE.VARIANTS if receipt_id.startswith(f"{name}-")
        )
        suffix = receipt_id.removeprefix(f"{variant}-")
        source = container["variants"][variant]
        image_ref = f"{source['image']}@{source['manifestDigest']}"
        common = {
            "variant": variant,
            "image": source["image"],
            "manifestDigest": source["manifestDigest"],
        }
        live_signature_digest = f"sha256:{'6' * 64}"
        if suffix == "oci-index":
            return {
                **common,
                "indexDigest": source["manifestDigest"],
                "platformDigests": copy.deepcopy(source["platformDigests"]),
            }
        if suffix == "immutable-tags":
            return {
                **common,
                "tagDigests": {
                    self.identity.container_release_tag: source["manifestDigest"],
                    self.identity.container_release_tag.removeprefix("v"): source[
                        "manifestDigest"
                    ],
                    f"sha-{self.identity.consumer_merge_sha[:12]}": source[
                        "manifestDigest"
                    ],
                },
            }
        if suffix == "cosign":
            return {
                **common,
                "liveSignatureDigest": live_signature_digest,
                "identity": container_identity,
                "sourceSha": self.identity.consumer_merge_sha,
            }
        if suffix == "materials":
            return {
                **common,
                "signatureDigest": source["signature"]["digest"],
                "liveSignatureDigest": live_signature_digest,
                "sbomDigest": source["sbom"]["digest"],
                "provenanceDigest": source["provenance"]["digest"],
            }
        if suffix == "buildkit":
            platforms = {}
            for index, platform in enumerate(MODULE.PLATFORMS, start=1):
                platforms[platform] = {
                    "platformDigest": source["platformDigests"][platform],
                    "attestationManifestDigest": f"sha256:{str(index + 3) * 64}",
                    "spdxDigest": f"sha256:{str(index + 5) * 64}",
                    "slsaDigest": f"sha256:{str(index + 7) * 64}",
                }
            return {
                **common,
                "indexDigest": source["manifestDigest"],
                "platforms": platforms,
            }
        if suffix == "pull":
            return {**common, "pulledImage": image_ref, "repoDigests": [image_ref]}
        if suffix == "installed":
            return {
                "variant": variant,
                "imageRef": image_ref,
                "collection": artifact["collection"],
                "state": "absent" if variant == "bootstrap" else "present",
                "installedVersion": (
                    None if variant == "bootstrap" else artifact["version"]
                ),
                "profile": producer["acceptance"]["profile"],
            }
        if suffix == "profile":
            return {
                "variant": variant,
                "imageRef": image_ref,
                "profile": producer["acceptance"]["profile"],
                "command": self.profiles["profiles"][self.profile][
                    "containerCommand"
                ],
            }
        raise AssertionError(receipt_id)

    def write_receipt_set(self, producer, container):
        receipt_root = Path(tempfile.mkdtemp(prefix="receipts-", dir=self.root))
        profiles = MODULE.load_profiles(self.profiles_path)
        for receipt_id in MODULE.EXPECTED_RECEIPT_TYPES:
            checked_at = (
                "2026-08-02T12:00:01Z"
                if receipt_id == "final-revocation"
                else "2026-08-02T12:00:00Z"
            )
            receipt = MODULE.verification_receipt(
                self.identity,
                profiles,
                self.producer_path,
                self.container_path,
                producer,
                container,
                receipt_id=receipt_id,
                observations=self.receipt_observations(
                    receipt_id, producer, container
                ),
                checked_at=checked_at,
                workflow_sha="6" * 40,
                run_id=456789,
                run_attempt=1,
            )
            write_json(receipt_root / f"{receipt_id}.json", receipt)
        bundle_path = (
            receipt_root.parent / f"{receipt_root.name}-bundle.json"
        ).resolve()
        return receipt_root, bundle_path

    # Stage B1 keeps this core behavioral block together with the shared
    # fixtures above. Stage B2 extends this same module with the deeper
    # adversarial and BuildKit coverage below.
    def test_core_profiles_enforce_allowlist_and_release_eligibility(self):
        profiles = MODULE.load_profiles(self.profiles_path)
        eligible = MODULE.eligible_profile(profiles, self.profile)
        self.assertIs(eligible["releaseEligible"], True)
        self.assertEqual(
            ["/usr/local/bin/security-fix-check"],
            eligible["containerCommand"],
        )

        with self.assertRaisesRegex(ValueError, "fixed allowlist"):
            MODULE.eligible_profile(profiles, "lit.supplementary/not-listed")

        repository_profiles = MODULE.load_profiles(
            ROOT / "acceptance" / "mlx90" / "profiles.json"
        )
        forgejo_profile = MODULE.eligible_profile(
            repository_profiles,
            "lit.supplementary/forgejo-manifest-secret-permissions-v1",
        )
        self.assertEqual(
            [
                "/bin/bash",
                "-ceu",
                "script=/usr/share/ansible/collections/ansible_collections/lit/"
                "supplementary/scripts/verify-forgejo-manifest-security.py; "
                'test -f "$script"; test ! -L "$script"; '
                'test "$(sha256sum "$script" | cut -d\' \' -f1)" = '
                '"8095f617bb27f26043715d3b4466c75ea061f2277276e592809d256d8b456675"; '
                'exec python3 "$script"',
            ],
            forgejo_profile["containerCommand"],
        )
        with self.assertRaisesRegex(ValueError, "non-releaseable"):
            MODULE.eligible_profile(
                repository_profiles, "lit.supplementary/mlx90-fixture"
            )

    def test_core_semver_and_rfc3339_edges(self):
        for value in (
            "0.0.0",
            "1.2.3-alpha.1+001.sha-abc",
            "1.2.3-0A.0-",
        ):
            with self.subTest(valid_semver=value):
                self.assertTrue(MODULE.is_semver(value))
        for value in (
            "01.2.3",
            "1.2.3-01",
            "1.2.3-alpha..1",
            "1.2.3-α",
            "1.2.3-" + "a" * 250,
        ):
            with self.subTest(invalid_semver=value):
                self.assertFalse(MODULE.is_semver(value))

        for value in (
            "2026-08-02T12:00:00Z",
            "2026-08-02T12:00:00.1Z",
            "2028-02-29T23:59:59.123456+14:00",
        ):
            with self.subTest(valid_timestamp=value):
                MODULE.require_timestamp(value, "core timestamp")
        self.assertEqual(
            "2026-08-02T12:00:00.100000+00:00",
            MODULE.rfc3339_parser_value("2026-08-02T12:00:00.1Z"),
        )
        for value in (
            "2026-08-02 12:00:00Z",
            "2026-08-02T12:00Z",
            "2026-08-02T12:00:00",
            "2026-08-02T12:00:00.1234567Z",
            "2026-08-02T12:00:00z",
            "2026-02-29T12:00:00Z",
            "2026-08-02T12:00:60Z",
        ):
            with self.subTest(invalid_timestamp=value):
                with self.assertRaisesRegex(ValueError, "RFC3339 timestamp"):
                    MODULE.require_timestamp(value, "core timestamp")

    def test_core_producer_and_container_evidence_happy_path_and_tamper(self):
        producer, container = self.validated()
        self.assertEqual("LIT-SEC-2026-001", producer["metadata"]["id"])
        self.assertEqual(987, container["release"]["id"])
        self.assertEqual(set(MODULE.VARIANTS), set(container["variants"]))

        tampered = copy.deepcopy(self.container)
        tampered["consumer"]["mergeSha"] = "9" * 40
        with self.assertRaisesRegex(ValueError, "consumer identity"):
            MODULE.validate_container_evidence(
                tampered, self.identity, producer
            )

        mutable_image = copy.deepcopy(self.container)
        mutable_image["variants"]["public"]["image"] += ":latest"
        with self.assertRaisesRegex(ValueError, "untagged Quay"):
            MODULE.validate_container_evidence(
                mutable_image, self.identity, producer
            )

        retried_identity = replace(
            self.identity, container_publish_run_attempt=2
        )
        MODULE.validate_container_evidence(
            copy.deepcopy(self.container), retried_identity, producer
        )

        later_evidence = copy.deepcopy(self.container)
        later_evidence["release"]["workflowRunAttempt"] = 2
        with self.assertRaisesRegex(
            ValueError, "later than publisher attempt"
        ):
            MODULE.validate_container_evidence(
                later_evidence, self.identity, producer
            )

        with self.assertRaisesRegex(
            ValueError,
            "container_publish_run_attempt must be a positive integer",
        ):
            replace(
                self.identity, container_publish_run_attempt=0
            ).validate()

    def test_core_receipt_set_builds_both_final_documents(self):
        producer, container = self.validated()
        receipt_root, bundle_path = self.write_receipt_set(producer, container)
        profiles = MODULE.load_profiles(self.profiles_path)
        producer_digest = MODULE.file_digest(self.producer_path)
        container_digest = MODULE.file_digest(self.container_path)
        with mock.patch.object(
            MODULE,
            "file_digest_and_size",
            side_effect=AssertionError("receipt bundle must not be reopened"),
        ):
            report = MODULE.verification_report(
                self.identity,
                profiles,
                self.producer_path,
                self.container_path,
                producer,
                container,
                receipt_root,
                bundle_path,
                workflow_sha="6" * 40,
                run_id=456789,
                run_attempt=1,
                producer_digest=producer_digest,
                container_digest=container_digest,
            )
        report = MODULE.validate_verification_report(
            report,
            self.identity,
            profiles,
            self.producer_path,
            self.container_path,
            bundle_path,
            producer,
            container,
            workflow_sha="6" * 40,
            run_id=456789,
            run_attempt=1,
        )
        delivered, acceptance = MODULE.build_final_evidence(
            self.identity,
            producer,
            container,
            report,
            workflow_sha="6" * 40,
            run_id=456789,
            run_attempt=1,
        )
        self.assertEqual("delivered", delivered["status"])
        self.assertEqual("delivered", acceptance["status"])
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        self.assertEqual(
            sorted(MODULE.EXPECTED_RECEIPT_TYPES),
            [receipt["receiptId"] for receipt in bundle["receipts"]],
        )
        self.assertEqual(
            MODULE.file_digest(bundle_path),
            acceptance["receiptBundle"]["digest"],
        )

    def test_core_receipt_tamper_and_revocation_cross_binding_fail_closed(self):
        producer, container = self.validated()
        profiles = MODULE.load_profiles(self.profiles_path)

        def rejected(receipt_id, mutate, message):
            receipt_root, bundle_path = self.write_receipt_set(
                producer, container
            )
            path = receipt_root / f"{receipt_id}.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            mutate(payload)
            write_json(path, payload)
            with self.assertRaisesRegex(ValueError, message):
                MODULE.verification_report(
                    self.identity,
                    profiles,
                    self.producer_path,
                    self.container_path,
                    producer,
                    container,
                    receipt_root,
                    bundle_path,
                    workflow_sha="6" * 40,
                    run_id=456789,
                    run_attempt=1,
                )

        cases = (
            (
                "producer-evidence",
                lambda value: value.__setitem__(
                    "producerEvidenceDigest", f"sha256:{'0' * 64}"
                ),
                "producer evidence digest",
            ),
            (
                "container-release",
                lambda value: value["finalizer"].__setitem__(
                    "runId", 456788
                ),
                "foreign",
            ),
            (
                "container-release",
                lambda value: value["observations"].__setitem__(
                    "publishRunAttempt", 2
                ),
                "container release receipt mismatch",
            ),
            (
                "container-release",
                lambda value: value["observations"].__setitem__(
                    "evidenceTriggeringActor", "human-reviewer"
                ),
                "container release receipt mismatch",
            ),
            (
                "container-release",
                lambda value: value["observations"].__setitem__(
                    "publishTriggeringActor", "human-reviewer"
                ),
                "container release receipt mismatch",
            ),
            (
                "public-oci-index",
                lambda value: value["observations"].__setitem__(
                    "variant", "certified"
                ),
                "variant",
            ),
            (
                "producer-materials",
                lambda value: value.__setitem__(
                    "checkedAt", "2026-08-02T08:59:59Z"
                ),
                "stale",
            ),
            (
                "final-revocation",
                lambda value: value["observations"].__setitem__(
                    "containerTagCommit", "9" * 40
                ),
                "final live revocation receipt mismatch",
            ),
        )
        for receipt_id, mutate, message in cases:
            with self.subTest(receipt_tamper=receipt_id):
                rejected(receipt_id, mutate, message)

        for receipt_id in (
            "producer-revocation-initial",
            "container-revocation-initial",
        ):
            with self.subTest(snapshot_cross_binding=receipt_id):
                receipt_root, bundle_path = self.write_receipt_set(
                    producer, container
                )
                path = receipt_root / f"{receipt_id}.json"
                payload = json.loads(path.read_text(encoding="utf-8"))
                observations = payload["observations"]
                snapshot = observations["assetSnapshot"]
                snapshot["assets"][0]["size"] += 1
                observations["assetSnapshotDigest"] = (
                    MODULE.canonical_value_digest(snapshot)
                )
                write_json(path, payload)
                with self.assertRaisesRegex(
                    ValueError,
                    "final revocation receipt is not bound to initial asset snapshots",
                ):
                    MODULE.verification_report(
                        self.identity,
                        profiles,
                        self.producer_path,
                        self.container_path,
                        producer,
                        container,
                        receipt_root,
                        bundle_path,
                        workflow_sha="6" * 40,
                        run_id=456789,
                        run_attempt=1,
                    )

    def test_core_verify_index_binds_raw_bytes_before_semantics(self):
        container = copy.deepcopy(self.container)
        variant = container["variants"]["public"]
        manifests = []
        for position, (platform, digest) in enumerate(
            variant["platformDigests"].items(), start=3
        ):
            manifests.extend(
                (
                    {
                        "digest": digest,
                        "platform": {
                            "os": "linux",
                            "architecture": platform.split("/", 1)[1],
                        },
                    },
                    {
                        "mediaType": (
                            "application/vnd.oci.image.manifest.v1+json"
                        ),
                        "digest": f"sha256:{str(position) * 64}",
                        "annotations": {
                            "vnd.docker.reference.digest": digest,
                            "vnd.docker.reference.type": "attestation-manifest",
                        },
                        "platform": {
                            "os": "unknown",
                            "architecture": "unknown",
                        },
                    },
                )
            )
        index_path = self.root / "core-index.json"
        write_json(index_path, {"schemaVersion": 2, "manifests": manifests})
        variant["manifestDigest"] = MODULE.file_digest(index_path)
        write_json(self.container_path, container)
        arguments = [
            "finalizer",
            "verify-index",
            "--container-evidence",
            str(self.container_path),
            "--variant",
            "public",
            "--index",
            str(index_path),
        ]
        with mock.patch.object(sys, "argv", arguments):
            self.assertEqual(0, MODULE.main())

        with index_path.open("a", encoding="utf-8") as stream:
            stream.write(" ")

        def parser_error(message):
            raise ValueError(message)

        with mock.patch.object(sys, "argv", arguments), mock.patch.object(
            MODULE.argparse.ArgumentParser,
            "error",
            side_effect=parser_error,
        ):
            with self.assertRaisesRegex(ValueError, "raw OCI index digest"):
                MODULE.main()

    def test_core_paired_json_publication_is_atomic_and_inode_safe(self):
        root = self.root.resolve()
        first = root / "pair-first.json"
        second = root / "pair-second.json"
        MODULE.write_json_pair(first, {"first": 1}, second, {"second": 2})
        self.assertEqual({"first": 1}, json.loads(first.read_text()))
        self.assertEqual({"second": 2}, json.loads(second.read_text()))

        for occupied_position in ("first", "second"):
            with self.subTest(existing=occupied_position):
                first = root / f"existing-{occupied_position}-first.json"
                second = root / f"existing-{occupied_position}-second.json"
                occupied = first if occupied_position == "first" else second
                other = second if occupied_position == "first" else first
                occupied.write_text("EXISTING\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "output already exists"):
                    MODULE.write_json_pair(first, {}, second, {})
                self.assertEqual("EXISTING\n", occupied.read_text())
                self.assertFalse(other.exists())

        real_link = MODULE.os.link
        for raced_position in ("first", "second"):
            with self.subTest(raced=raced_position):
                first = root / f"raced-{raced_position}-first.json"
                second = root / f"raced-{raced_position}-second.json"
                raced = first if raced_position == "first" else second
                other = second if raced_position == "first" else first

                def race(source, destination):
                    if Path(destination) == raced:
                        raced.write_text("RACE-WINNER\n", encoding="utf-8")
                    return real_link(source, destination)

                with mock.patch.object(MODULE.os, "link", side_effect=race):
                    with self.assertRaisesRegex(
                        ValueError, "output already exists"
                    ):
                        MODULE.write_json_pair(first, {}, second, {})
                self.assertEqual("RACE-WINNER\n", raced.read_text())
                self.assertFalse(other.exists())

        first = root / "foreign-first.json"
        second = root / "foreign-second.json"

        def replace_first_before_second_race(source, destination):
            if Path(destination) == second:
                first.unlink()
                first.write_text("FOREIGN-FIRST\n", encoding="utf-8")
                second.write_text("FOREIGN-SECOND\n", encoding="utf-8")
            return real_link(source, destination)

        with mock.patch.object(
            MODULE.os,
            "link",
            side_effect=replace_first_before_second_race,
        ):
            with self.assertRaisesRegex(ValueError, "output already exists"):
                MODULE.write_json_pair(first, {}, second, {})
        self.assertEqual("FOREIGN-FIRST\n", first.read_text())
        self.assertEqual("FOREIGN-SECOND\n", second.read_text())

    def test_core_output_paths_and_os_errors_are_never_disclosed(self):
        marker = "github_pat_SECRET\nCONTROLLED"
        root = self.root.resolve()

        def assert_sanitized(action):
            with self.assertRaises(ValueError) as caught:
                action()
            message = str(caught.exception)
            self.assertNotIn(marker, message)
            self.assertNotIn(str(root), message)
            self.assertNotIn("\n", message)

        existing = root / f"{marker}-existing.json"
        existing.write_text("DO NOT REPLACE\n", encoding="utf-8")
        assert_sanitized(lambda: MODULE.write_json(existing, {}))

        output = root / f"{marker}-output.json"
        temporary = output.with_name(f".{output.name}.{MODULE.os.getpid()}.tmp")
        temporary.write_text("DO NOT REPLACE\n", encoding="utf-8")
        assert_sanitized(lambda: MODULE.write_json(output, {}))
        temporary.unlink()

        injected_error = OSError(f"denied: {output}")
        missing_parent_output = root / "missing-parent" / output.name
        with mock.patch.object(
            MODULE.Path, "mkdir", side_effect=injected_error
        ):
            assert_sanitized(
                lambda: MODULE.write_json(missing_parent_output, {})
            )
        with mock.patch.object(
            MODULE.Path, "open", side_effect=injected_error
        ):
            assert_sanitized(lambda: MODULE.write_json(output, {}))
        with mock.patch.object(MODULE.os, "link", side_effect=injected_error):
            assert_sanitized(lambda: MODULE.write_json(output, {}))
        with mock.patch.object(
            MODULE.Path, "unlink", side_effect=injected_error
        ):
            assert_sanitized(lambda: MODULE.write_json(output, {}))

        pair_first = root / f"{marker}-first.json"
        pair_second = root / f"{marker}-second.json"
        real_link = MODULE.os.link
        links = 0

        def fail_second_link(source, destination):
            nonlocal links
            links += 1
            if links == 2:
                raise injected_error
            return real_link(source, destination)

        with mock.patch.object(
            MODULE.os, "link", side_effect=fail_second_link
        ):
            assert_sanitized(
                lambda: MODULE.write_json_pair(
                    pair_first, {}, pair_second, {}
                )
            )

        result = root / "absent.json"
        write_json(result, {})
        cli_output = root / f"{marker}-cli.json"
        command = [
            sys.executable,
            str(ROOT / "scripts" / "finalize-mlx90-delivery.py"),
            "verify-installed",
            "--result",
            str(result),
            "--collection",
            "lit.supplementary",
            "--expect-absent",
            "--observation-output",
            str(cli_output),
        ]
        first = subprocess.run(
            command, capture_output=True, text=True, check=False
        )
        self.assertEqual(0, first.returncode, first.stderr)
        repeated = subprocess.run(
            command, capture_output=True, text=True, check=False
        )
        self.assertNotEqual(0, repeated.returncode)
        for completed in (first, repeated):
            output_text = completed.stdout + completed.stderr
            self.assertNotIn(marker, output_text)
            self.assertNotIn(str(root), output_text)

    def test_core_container_release_url_uses_consumer_repository_constant(self):
        alternate = "example/consumer"
        container = json.loads(
            json.dumps(self.container).replace(
                MODULE.CONSUMER_REPOSITORY, alternate
            )
        )
        with mock.patch.object(MODULE, "CONSUMER_REPOSITORY", alternate):
            self.assertIs(
                container,
                MODULE.validate_container_evidence(
                    container, self.identity, self.producer
                ),
            )

    def test_core_secure_snapshots_are_bounded_stable_and_same_byte(self):
        marker = "SECRET-SNAPSHOT-PATH\n"
        first = b'{"source":"first"}\n'
        second = b'{"source":"second"}\n'
        material = self.root / "material.json"
        material.write_bytes(first)
        snapshot = MODULE.secure_file_snapshot(
            material, 1024, capture_payload=True
        )
        replacement = self.root / "replacement.json"
        replacement.write_bytes(second)
        replacement.replace(material)
        self.assertEqual(
            {"source": "first"},
            MODULE.parse_json_snapshot(snapshot, "material"),
        )
        self.assertEqual(
            f"sha256:{digest_bytes(first)}", snapshot.digest
        )
        self.assertNotEqual(
            f"sha256:{digest_bytes(second)}", snapshot.digest
        )

        symlink = self.root / "material-link.json"
        symlink.symlink_to(material)
        fifo = self.root / "material.fifo"
        MODULE.os.mkfifo(fifo)
        directory = self.root / "material-directory"
        directory.mkdir()
        oversized = self.root / "oversized.json"
        oversized.write_bytes(b"12345")
        for candidate, limit in (
            (symlink, 1024),
            (fifo, 1024),
            (directory, 1024),
            (oversized, 4),
        ):
            with self.subTest(candidate=candidate.name):
                with self.assertRaises(ValueError) as caught:
                    MODULE.secure_file_snapshot(candidate, limit)
                self.assertEqual(
                    MODULE.MATERIAL_FILE_ERROR, str(caught.exception)
                )

        stable = material.stat()
        changed = mock.Mock(
            st_mode=stable.st_mode,
            st_dev=stable.st_dev,
            st_ino=stable.st_ino,
            st_size=stable.st_size,
            st_mtime_ns=stable.st_mtime_ns + 1,
            st_ctime_ns=stable.st_ctime_ns,
        )
        with mock.patch.object(
            MODULE.os, "fstat", side_effect=(stable, changed)
        ):
            with self.assertRaises(ValueError) as caught:
                MODULE.secure_file_snapshot(material, 1024)
        self.assertEqual(MODULE.MATERIAL_FILE_ERROR, str(caught.exception))

        injected = OSError(f"{marker}{self.root}")
        with mock.patch.object(MODULE.os, "open", side_effect=injected):
            with self.assertRaises(ValueError) as caught:
                MODULE.secure_file_snapshot(material, 1024)
        self.assertEqual(MODULE.MATERIAL_FILE_ERROR, str(caught.exception))
        self.assertNotIn(marker, str(caught.exception))
        self.assertNotIn(str(self.root), str(caught.exception))

    def test_core_every_cli_command_has_value_free_exception_boundaries(self):
        marker = f"SECRET-CLI-BOUNDARY\n{self.root}"
        commands = (
            ("validate-inputs", "identity_from_args"),
            ("preflight", "validated_inputs"),
            ("profile-command", "load_profiles"),
            ("verify-producer-materials", "load_json"),
            ("verify-index", "load_json"),
            ("verify-buildkit-attestations", "load_json"),
            ("verify-container-materials", "load_json"),
            ("verify-installed", "load_json"),
            ("write-receipt", "validated_inputs"),
            ("write-report", "validated_inputs"),
            ("finalize", "validated_inputs"),
        )

        class BoundaryError(Exception):
            pass

        def parser_error(message):
            raise BoundaryError(message)

        errors = (
            (KeyError, MODULE.CLI_CONTRACT_ERROR),
            (TypeError, MODULE.CLI_CONTRACT_ERROR),
            (IndexError, MODULE.CLI_CONTRACT_ERROR),
            (OSError, MODULE.CLI_IO_ERROR),
        )
        for command, target in commands:
            for error_type, expected in errors:
                with self.subTest(command=command, error=error_type.__name__):
                    with mock.patch.object(
                        sys, "argv", self.cli_arguments(command)
                    ), mock.patch.object(
                        MODULE, target, side_effect=error_type(marker)
                    ), mock.patch.object(
                        MODULE.argparse.ArgumentParser,
                        "error",
                        side_effect=parser_error,
                    ):
                        with self.assertRaises(BoundaryError) as caught:
                            MODULE.main()
                    self.assertEqual(expected, str(caught.exception))
                    self.assertNotIn(marker, str(caught.exception))
                    self.assertNotIn(str(self.root), str(caught.exception))

        script = str(ROOT / "scripts" / "finalize-mlx90-delivery.py")
        invalid_integer = self.cli_arguments("validate-inputs")[2:]
        consumer_pr = invalid_integer.index("--consumer-pr") + 1
        invalid_integer[consumer_pr] = marker
        for arguments in (
            ["unknown-" + marker],
            ["validate-inputs", *invalid_integer],
        ):
            completed = subprocess.run(
                [sys.executable, script, *arguments],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, completed.returncode)
            output = completed.stdout + completed.stderr
            self.assertIn(MODULE.CLI_ARGUMENT_ERROR, output)
            self.assertNotIn(marker, output)
            self.assertNotIn(str(self.root), output)
            self.assertNotIn("Traceback", output)

    def test_core_structural_inputs_fail_locally_without_value_echo(self):
        marker = f"SECRET-STRUCTURE\n{self.root}"
        profiles = MODULE.load_profiles(self.profiles_path)
        producer = copy.deepcopy(self.producer)
        producer["security"]["identifiers"] = [{marker: True}]
        with self.assertRaises(ValueError) as caught:
            MODULE.validate_producer_evidence(
                producer, self.identity, profiles
            )
        self.assertEqual(
            "security.identifiers must be a non-empty unique string list",
            str(caught.exception),
        )

        digest = f"sha256:{'a' * 64}"
        index = {
            "schemaVersion": 2,
            "manifests": [
                {
                    "mediaType": (
                        "application/vnd.oci.image.manifest.v1+json"
                    ),
                    "digest": f"sha256:{'b' * 64}",
                    "annotations": {
                        "vnd.docker.reference.digest": digest,
                        "vnd.docker.reference.type": "attestation-manifest",
                    },
                    "platform": {
                        "os": "unknown",
                        "architecture": "unknown",
                    },
                }
            ],
        }
        malformed_platforms = (
            [],
            {"linux/amd64": digest},
            {"linux/amd64": marker, "linux/arm64": digest},
        )
        for value in malformed_platforms:
            container = copy.deepcopy(self.container)
            container["variants"]["public"]["platformDigests"] = value
            with self.subTest(platform_digests=value):
                with self.assertRaises(ValueError) as caught:
                    MODULE.verify_index(container, "public", index)
                self.assertNotIn(marker, str(caught.exception))

        missing = self.root / "not-used"
        for action in (
            lambda: MODULE.verify_index({}, marker, {}),
            lambda: MODULE.verify_container_materials(
                {}, marker, missing, missing, missing, missing
            ),
            lambda: MODULE.verify_buildkit_attestations(
                {}, marker, missing, self.root
            ),
        ):
            with self.assertRaises(ValueError) as caught:
                action()
            self.assertNotIn(marker, str(caught.exception))

        validated = self.validated()
        with mock.patch.object(
            MODULE,
            "validated_inputs",
            return_value=(
                self.identity,
                profiles,
                *validated,
                None,
                None,
            ),
        ), mock.patch.object(MODULE, "load_json") as loader, mock.patch.object(
            sys,
            "argv",
            self.cli_arguments("write-receipt", receipt_id=marker),
        ), mock.patch.object(
            MODULE.argparse.ArgumentParser,
            "error",
            side_effect=ValueError,
        ):
            with self.assertRaises(ValueError) as caught:
                MODULE.main()
        loader.assert_not_called()
        self.assertNotIn(marker, str(caught.exception))

    def write_buildkit_fixture(
        self,
        container: dict,
        variant_name: str = "public",
        mutator=None,
    ) -> tuple[Path, Path]:
        variant = container["variants"][variant_name]
        release = container["release"]
        image = variant["image"]
        release_tag = release["tag"]
        source_sha = release["sourceSha"]
        version = release_tag.removeprefix("v")
        run_id = release["workflowRunId"]
        run_attempt = release["workflowRunAttempt"]
        title = MODULE.CONSUMER_REPOSITORY.split("/", 1)[1]
        if variant_name != "public":
            title = f"{title}-{variant_name}"
        args = {
            "build-arg:COLLECTION_PROFILE": variant_name,
            "cmdline": "docker/dockerfile:1.25",
            "label:org.opencontainers.image.created": (
                "2026-08-02T10:00:00Z"
            ),
            "label:org.opencontainers.image.revision": source_sha,
            "label:org.opencontainers.image.source": (
                f"https://github.com/{MODULE.CONSUMER_REPOSITORY}"
            ),
            "label:org.opencontainers.image.title": title,
            "label:org.opencontainers.image.version": version,
            "source": "docker/dockerfile:1.25",
        }
        root_args = {
            **{
                key: value
                for key, value in args.items()
                if key not in {"cmdline", "source"}
            },
            "vcs:localdir:context": ".",
            "vcs:localdir:dockerfile": ".",
            "vcs:revision": source_sha,
            "vcs:source": (
                f"https://github.com/{MODULE.CONSUMER_REPOSITORY}"
            ),
        }
        internal = {
            "builderPlatform": "",
            "github_actor": MODULE.CONTAINER_RELEASE_ACTOR,
            "github_event_name": "workflow_dispatch",
            "github_job": MODULE.CONTAINER_WORKFLOW_JOB,
            "github_ref": f"refs/tags/{release_tag}",
            "github_ref_name": release_tag,
            "github_ref_protected": "true",
            "github_ref_type": "tag",
            "github_repository": MODULE.CONSUMER_REPOSITORY,
            "github_run_attempt": str(run_attempt),
            "github_run_id": str(run_id),
            "github_workflow": MODULE.CONTAINER_WORKFLOW_NAME,
            "github_workflow_ref": (
                f"{MODULE.CONSUMER_REPOSITORY}/{MODULE.CONTAINER_WORKFLOW}@"
                f"refs/tags/{release_tag}"
            ),
            "github_workflow_sha": source_sha,
        }
        attestation_root = self.root / f"{variant_name}-buildkit"
        attestation_root.mkdir(exist_ok=True)
        manifests = []
        for platform in MODULE.PLATFORMS:
            platform_digest = variant["platformDigests"][platform]
            encoded_platform = platform.replace("/", "%2F")
            subjects = [
                {
                    "name": (
                        f"pkg:docker/{image}@mlx90-candidate-{source_sha}"
                        f"?platform={encoded_platform}"
                    ),
                    "digest": {
                        "sha256": platform_digest.removeprefix("sha256:")
                    },
                }
            ]
            spdx = {
                "SPDXID": "SPDXRef-DOCUMENT",
                "creationInfo": {
                    "created": "2026-08-02T10:01:00Z",
                    "creators": [
                        "Organization: Anchore, Inc",
                        "Tool: syft-1.42.3",
                        "Tool: buildkit-0.31.2",
                    ],
                },
                "dataLicense": "CC0-1.0",
                "documentNamespace": (
                    "https://anchore.com/syft/dir/synthetic-sbom"
                ),
                "files": [{"SPDXID": "SPDXRef-File-synthetic"}],
                "hasExtractedLicensingInfos": [],
                "name": "sbom",
                "packages": [
                    {"SPDXID": "SPDXRef-Package-synthetic", "name": "base"}
                ],
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-DOCUMENT",
                        "relatedSpdxElement": "SPDXRef-Package-synthetic",
                        "relationshipType": "DESCRIBES",
                    }
                ],
                "spdxVersion": "SPDX-2.3",
            }
            slsa_internal = copy.deepcopy(internal)
            slsa_internal["builderPlatform"] = "linux/amd64"
            slsa = {
                "buildDefinition": {
                    "buildType": MODULE.BUILDKIT_BUILD_TYPE,
                    "externalParameters": {
                        "configSource": {"path": "Dockerfile"},
                        "request": {
                            "args": copy.deepcopy(args),
                            "compatibilityVersion": 30,
                            "frontend": "gateway.v0",
                            "locals": [
                                {"name": "context"},
                                {"name": "dockerfile"},
                            ],
                            "root": {
                                "configSource": {"path": "Dockerfile"},
                                "request": {
                                    "args": copy.deepcopy(root_args)
                                },
                            },
                            "secrets": [],
                        },
                    },
                    "internalParameters": slsa_internal,
                    "resolvedDependencies": [
                        {
                            "uri": (
                                "git+https://github.com/"
                                f"{MODULE.CONSUMER_REPOSITORY}@{source_sha}"
                            ),
                            "digest": {"gitCommit": source_sha},
                        }
                    ],
                },
                "runDetails": {
                    "builder": {
                        "id": (
                            "https://github.com/"
                            f"{MODULE.CONSUMER_REPOSITORY}/actions/runs/"
                            f"{run_id}/attempts/{run_attempt}"
                        )
                    },
                    "metadata": {
                        "buildkit_completeness": {
                            "request": True,
                            "resolvedDependencies": False,
                        },
                        "buildkit_metadata": {"vcs:revision": source_sha},
                        "finishedOn": "2026-08-02T10:04:00Z",
                        "invocationId": f"synthetic-{platform}",
                        "startedOn": "2026-08-02T10:02:00Z",
                    },
                },
            }
            statements = {
                MODULE.SPDX_PREDICATE: {
                    "_type": MODULE.IN_TOTO_STATEMENT,
                    "subject": copy.deepcopy(subjects),
                    "predicateType": MODULE.SPDX_PREDICATE,
                    "predicate": spdx,
                },
                MODULE.SLSA_PREDICATE: {
                    "_type": MODULE.IN_TOTO_STATEMENT,
                    "subject": copy.deepcopy(subjects),
                    "predicateType": MODULE.SLSA_PREDICATE,
                    "predicate": slsa,
                },
            }
            if mutator is not None:
                mutator(platform, statements)
            basename = platform.replace("/", "-")
            layers = []
            for predicate_type, filename in (
                (MODULE.SPDX_PREDICATE, "spdx"),
                (MODULE.SLSA_PREDICATE, "slsa"),
            ):
                statement_path = (
                    attestation_root / f"{basename}-{filename}.json"
                )
                write_json(statement_path, statements[predicate_type])
                layers.append(
                    {
                        "mediaType": "application/vnd.in-toto+json",
                        "digest": MODULE.file_digest(statement_path),
                        "size": statement_path.stat().st_size,
                        "annotations": {
                            "in-toto.io/predicate-type": predicate_type
                        },
                    }
                )
            manifest = {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": f"sha256:{'c' * 64}",
                    "size": 241,
                },
                "layers": layers,
            }
            manifest_path = attestation_root / f"{basename}-manifest.json"
            write_json(manifest_path, manifest)
            manifests.extend(
                [
                    {
                        "mediaType": (
                            "application/vnd.oci.image.manifest.v1+json"
                        ),
                        "digest": platform_digest,
                        "platform": {
                            "os": "linux",
                            "architecture": platform.split("/", 1)[1],
                        },
                    },
                    {
                        "mediaType": (
                            "application/vnd.oci.image.manifest.v1+json"
                        ),
                        "digest": MODULE.file_digest(manifest_path),
                        "annotations": {
                            "vnd.docker.reference.digest": platform_digest,
                            "vnd.docker.reference.type": (
                                "attestation-manifest"
                            ),
                        },
                        "platform": {
                            "os": "unknown",
                            "architecture": "unknown",
                        },
                    },
                ]
            )
        index_path = self.root / f"{variant_name}-index.json"
        write_json(index_path, {"schemaVersion": 2, "manifests": manifests})
        variant["manifestDigest"] = MODULE.file_digest(index_path)
        return index_path, attestation_root

    def test_dispatch_and_both_signed_evidence_documents_bind_exactly(self):
        producer, container = self.validated()
        self.assertEqual("LIT-SEC-2026-001", producer["metadata"]["id"])
        self.assertEqual(987, container["release"]["id"])

        tampered = copy.deepcopy(self.container)
        tampered["consumer"]["mergeSha"] = "9" * 40
        with self.assertRaisesRegex(ValueError, "consumer identity"):
            MODULE.validate_container_evidence(
                tampered, self.identity, producer
            )

        mutable_image = copy.deepcopy(self.container)
        mutable_image["variants"]["public"]["image"] += ":latest"
        with self.assertRaisesRegex(ValueError, "untagged Quay"):
            MODULE.validate_container_evidence(
                mutable_image, self.identity, producer
            )

    def test_timestamp_parser_uses_strict_rfc3339_profile(self):
        valid = (
            "0001-01-01T00:00:00-23:59",
            "2026-08-02T12:00:00Z",
            "2026-08-02T12:00:00.1Z",
            "2028-02-29T23:59:59.123456+14:00",
        )
        for value in valid:
            with self.subTest(valid=value):
                MODULE.require_timestamp(value, "test timestamp")

        normalized = {
            "2026-08-02T12:00:00Z": "2026-08-02T12:00:00+00:00",
            "2026-08-02T12:00:00.1Z": (
                "2026-08-02T12:00:00.100000+00:00"
            ),
            "2026-08-02T12:00:00.12+05:30": (
                "2026-08-02T12:00:00.120000+05:30"
            ),
            "2026-08-02T12:00:00.123456-23:59": (
                "2026-08-02T12:00:00.123456-23:59"
            ),
        }
        for value, expected in normalized.items():
            with self.subTest(normalized=value):
                self.assertEqual(expected, MODULE.rfc3339_parser_value(value))

        for zone, offset_seconds in (("Z", 0), ("+05:30", 19_800)):
            for digits in ("1", "12", "123", "1234", "12345", "123456"):
                with self.subTest(fraction=digits, zone=zone):
                    parsed = MODULE.require_timestamp(
                        f"2026-08-02T12:00:00.{digits}{zone}",
                        "test timestamp",
                    )
                    self.assertEqual(
                        int(digits.ljust(6, "0")), parsed.microsecond
                    )
                    self.assertEqual(
                        offset_seconds, parsed.utcoffset().total_seconds()
                    )

        invalid = (
            "2026-08-02X12:00:00+00:00",
            "2026-08-02 12:00:00+00:00",
            "2026-08-02T12:00Z",
            "2026-08-02T12:00:00",
            "2026-08-02T12:00:00.1234567Z",
            "2026-08-02T12:00:00.Z",
            "2026-08-02T12:00:00,1Z",
            "2026-08-02t12:00:00Z",
            "2026-08-02T12:00:00z",
            "2026-02-29T12:00:00Z",
            "2026-08-02T12:00:60Z",
            "2026-08-02T12:00:00+24:00",
            "2026-08-02T12:00:00+0000",
        )
        for value in invalid:
            with self.subTest(invalid=value):
                with self.assertRaisesRegex(ValueError, "RFC3339 timestamp"):
                    MODULE.require_timestamp(value, "test timestamp")

        with mock.patch.object(MODULE, "rfc3339_parser_value") as normalizer:
            with self.assertRaisesRegex(ValueError, "RFC3339 timestamp"):
                MODULE.require_timestamp(
                    "2026-08-02T12:00:00z", "test timestamp"
                )
            normalizer.assert_not_called()

    def test_ascii_controls_fail_before_trusted_url_parsing(self):
        controls = tuple(chr(value) for value in range(0x20)) + ("\x7f",)
        for control in controls:
            with self.subTest(control=ord(control)):
                with self.assertRaisesRegex(ValueError, "ASCII control"):
                    MODULE.require_string(
                        f"security{control}identifier", "security string"
                    )

        release_url = self.identity.producer_evidence_url.replace(
            "/releases/", "/\treleases/"
        )
        release_identity = replace(
            self.identity,
            producer_evidence_url=release_url,
            producer_evidence_bundle_url=f"{release_url}.sigstore.json",
        )
        with self.assertRaisesRegex(ValueError, "ASCII control"):
            release_identity.validate()

        with mock.patch.object(MODULE, "urlsplit") as parser:
            with self.assertRaisesRegex(ValueError, "ASCII control"):
                MODULE.producer_release_tag(release_identity)
            parser.assert_not_called()

        producer = copy.deepcopy(self.producer)
        signature = producer["artifact"]["signature"]
        signature["url"] = signature["url"].replace(
            "collection.sigstore", "collection\x1fsigstore"
        )
        profiles = MODULE.load_profiles(self.profiles_path)
        with self.assertRaisesRegex(ValueError, "ASCII control"):
            MODULE.validate_producer_evidence(
                producer, self.identity, profiles
            )

        marker = "SENSITIVE-CONTROL-VALUE"
        with self.assertRaisesRegex(ValueError, "ASCII control") as caught:
            MODULE.require_string(f"{marker}\tvalue", "security string")
        self.assertNotIn(marker, str(caught.exception))

        container = copy.deepcopy(self.container)
        container["variants"]["public"]["signature"]["url"] = container[
            "variants"
        ]["public"]["signature"]["url"].replace("signature", "sig\tnature")
        missing = self.root / "not-reached"
        with mock.patch.object(MODULE, "urlsplit") as parser:
            with self.assertRaisesRegex(ValueError, "ASCII control"):
                MODULE.verify_container_materials(
                    container,
                    "public",
                    missing,
                    missing,
                    missing,
                    missing,
                )
            parser.assert_not_called()

        producer = copy.deepcopy(self.producer)
        producer["consumers"].append("SENSITIVE\tCONSUMER")
        profiles = MODULE.load_profiles(self.profiles_path)
        with self.assertRaisesRegex(ValueError, "ASCII control") as caught:
            MODULE.validate_producer_evidence(
                producer,
                self.identity,
                profiles,
            )
        self.assertNotIn("SENSITIVE", str(caught.exception))

    def test_malformed_urls_fail_without_parser_value_leakage(self):
        parser_marker = "SENSITIVE-PARSER-ERROR-MARKER"
        with mock.patch.object(
            MODULE,
            "urlsplit",
            side_effect=ValueError(parser_marker),
        ) as parser:
            with self.assertRaisesRegex(
                ValueError, "test URL must be an HTTPS URL"
            ) as caught:
                MODULE.require_https("https://example.com/release", "test URL")
        parser.assert_called_once_with("https://example.com/release")
        self.assertNotIn(parser_marker, str(caught.exception))

        cli_marker = "SENSITIVE-CLI-URL-MARKER"
        malformed = f"https://[{cli_marker}/release"
        command = [
            sys.executable,
            str(ROOT / "scripts" / "finalize-mlx90-delivery.py"),
            "validate-inputs",
            "--correlation-id",
            self.identity.correlation_id,
            "--producer-evidence-url",
            malformed,
            "--producer-evidence-bundle-url",
            self.identity.producer_evidence_bundle_url,
            "--producer-evidence-sha256",
            self.identity.producer_evidence_sha256,
            "--consumer-pr",
            str(self.identity.consumer_pr),
            "--consumer-head-sha",
            self.identity.consumer_head_sha,
            "--consumer-merge-sha",
            self.identity.consumer_merge_sha,
            "--container-release-id",
            str(self.identity.container_release_id),
            "--container-release-tag",
            self.identity.container_release_tag,
            "--container-release-run-id",
            str(self.identity.container_release_run_id),
            "--container-publish-run-attempt",
            str(self.identity.container_publish_run_attempt),
        ]
        completed = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(0, completed.returncode)
        self.assertIn(
            "producer_evidence_url must be an HTTPS URL",
            completed.stderr,
        )
        self.assertNotIn(cli_marker, completed.stderr)
        self.assertNotIn(malformed, completed.stderr)

    def test_untrusted_json_and_jsonl_reject_duplicates_without_values(self):
        cases = {
            "status": (
                '{"status":"SENSITIVE-STATUS-A",'
                '"status":"SENSITIVE-STATUS-B"}'
            ),
            "identity": (
                '{"identity":{"sourceSha":"SENSITIVE-IDENTITY-A",'
                '"sourceSha":"SENSITIVE-IDENTITY-B"}}'
            ),
            "digest": (
                '{"outer":{"evidence":{"digest":"SENSITIVE-DIGEST-A",'
                '"digest":"SENSITIVE-DIGEST-B"}}}'
            ),
            "nested": '{"outer":{"inner":{"key":1,"key":2}}}',
        }
        for name, raw in cases.items():
            with self.subTest(duplicate=name):
                path = self.root / f"duplicate-{name}.json"
                path.write_text(raw, encoding="utf-8")
                with self.assertRaisesRegex(
                    ValueError, "duplicate JSON object keys"
                ) as caught:
                    MODULE.load_json(path, "untrusted document")
                message = str(caught.exception)
                self.assertNotIn("SENSITIVE-", message)
                self.assertNotIn('"key"', message)

        with self.assertRaisesRegex(ValueError, "unknown fields") as caught:
            MODULE.require_exact(
                {"status": "ok", "SENSITIVE-UNKNOWN-KEY": "value"},
                {"status"},
                "untrusted document",
            )
        self.assertNotIn("SENSITIVE-", str(caught.exception))

        jsonl_path = self.root / "duplicate.jsonl"
        jsonl_path.write_text(
            '{"status":"ok"}\n'
            '{"identity":{"digest":"SENSITIVE-JSONL-A",'
            '"digest":"SENSITIVE-JSONL-B"}}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            ValueError, "duplicate JSON object keys"
        ) as caught:
            MODULE.load_json_or_json_lines(jsonl_path, "untrusted JSONL")
        self.assertNotIn("SENSITIVE-JSONL-A", str(caught.exception))
        self.assertNotIn("SENSITIVE-JSONL-B", str(caught.exception))

        constant_path = self.root / "non-standard.json"
        constant_path.write_text('{"digest":NaN}', encoding="utf-8")
        with self.assertRaisesRegex(
            ValueError, "non-standard JSON numeric constant"
        ) as caught:
            MODULE.load_json(constant_path, "untrusted document")
        self.assertNotIn("NaN", str(caught.exception))

        unsafe_json = {
            "control-key": (
                '{"SENSITIVE-KEY\\u007fVALUE":"SENSITIVE-CONTENT"}',
                "ASCII control characters in JSON object keys",
            ),
            "overflow": ('{"number":1e400}', "non-finite JSON number"),
            "oversized-integer": (
                '{"number":' + "9" * (MODULE.JSON_NUMBER_MAX_LENGTH + 1) + "}",
                "oversized JSON number",
            ),
            "nesting": (
                "[" * 2000 + "]" * 2000,
                "JSON nesting depth",
            ),
        }
        for name, (raw, pattern) in unsafe_json.items():
            with self.subTest(unsafe=name):
                path = self.root / f"unsafe-{name}.json"
                path.write_text(raw, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, pattern) as caught:
                    MODULE.load_json(path, "untrusted document")
                message = str(caught.exception)
                self.assertNotIn("SENSITIVE-", message)
                self.assertNotIn("1e400", message)

        non_lf_jsonl = self.root / "non-lf.jsonl"
        non_lf_jsonl.write_text(
            '{"status":"first"}\v{"status":"second"}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "not valid JSON or JSONL"):
            MODULE.load_json_or_json_lines(non_lf_jsonl, "untrusted JSONL")

        bounded_path = self.root / "bounded.json"
        bounded_path.write_text('{"value":"SENSITIVE"}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "input limit") as caught:
            MODULE.read_bounded_utf8(bounded_path, "document", 8)
        self.assertNotIn("SENSITIVE", str(caught.exception))

        invalid_utf8 = self.root / "invalid-utf8.json"
        invalid_utf8.write_bytes(b'\xffSENSITIVE')
        with self.assertRaisesRegex(ValueError, "valid UTF-8") as caught:
            MODULE.load_json(invalid_utf8, "untrusted document")
        self.assertNotIn("SENSITIVE", str(caught.exception))

        symlink = self.root / "symlink.json"
        symlink.symlink_to(constant_path)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            MODULE.load_json(symlink, "untrusted document")

    def test_all_version_paths_use_strict_semver(self):
        valid = (
            "0.0.0",
            "1.2.3-0",
            "1.2.3-alpha",
            "1.2.3-alpha.1",
            "1.2.3-0A.0-",
            "1.2.3+001",
            "1.2.3-alpha.1+001.sha-abc",
            f"{'9' * 80}.0.1",
        )
        for value in valid:
            with self.subTest(valid=value):
                self.assertTrue(MODULE.is_semver(value))

        invalid = (
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.2",
            "1.2.3.4",
            "1.2.3-",
            "1.2.3+",
            "1.2.3-01",
            "1.2.3-alpha.01",
            "1.2.3-alpha..1",
            "1.2.3+build..1",
            "1.2.3+_build",
            "1.2.3-α",
        )
        for value in invalid:
            with self.subTest(invalid=value):
                self.assertFalse(MODULE.is_semver(value))

        at_limit = "1.2.3-" + "a" * 249
        over_limit = "1.2.3-" + "a" * 250
        self.assertEqual(MODULE.SEMVER_MAX_LENGTH, len(at_limit))
        self.assertEqual(MODULE.SEMVER_MAX_LENGTH + 1, len(over_limit))
        self.assertTrue(MODULE.is_semver(at_limit))
        self.assertFalse(MODULE.is_semver(over_limit))
        self.assertIsNone(MODULE.SEMVER.fullmatch(over_limit))

        denial_of_service_payload = "1.2.3-" + "a." * 50_000
        self.assertIsNone(MODULE.SEMVER.fullmatch(denial_of_service_payload))
        with mock.patch.object(MODULE, "SEMVER") as grammar:
            self.assertFalse(MODULE.is_semver(denial_of_service_payload))
            grammar.fullmatch.assert_not_called()

        container_identity = replace(
            self.identity,
            container_release_tag="v1.25.0-rc.1+001",
        )
        container_identity.validate()

        producer_version = "3.2.0-rc.1+001"
        producer_tag = f"v{producer_version}"
        producer_identity = replace(
            self.identity,
            producer_evidence_url=(
                f"https://github.com/{MODULE.PRODUCER_REPOSITORY}/"
                f"releases/download/{producer_tag}/"
                "security-release-evidence.json"
            ),
            producer_evidence_bundle_url=(
                f"https://github.com/{MODULE.PRODUCER_REPOSITORY}/"
                f"releases/download/{producer_tag}/"
                "security-release-evidence.json.sigstore.json"
            ),
        )
        producer = copy.deepcopy(self.producer)
        producer["security"]["fixedVersion"] = producer_version
        producer["artifact"]["version"] = producer_version
        producer["artifact"]["releaseUrl"] = (
            f"https://github.com/{MODULE.PRODUCER_REPOSITORY}/"
            f"releases/tag/{producer_tag}"
        )
        producer["acceptance"]["expectedVersion"] = producer_version
        for field in ("signature", "sbom", "provenance"):
            asset = producer["artifact"][field]["url"].rsplit("/", 1)[-1]
            producer["artifact"][field]["url"] = (
                f"https://github.com/{MODULE.PRODUCER_REPOSITORY}/"
                f"releases/download/{producer_tag}/{asset}"
            )
        profiles = MODULE.load_profiles(self.profiles_path)
        MODULE.validate_producer_evidence(
            producer, producer_identity, profiles
        )

        invalid_producer = copy.deepcopy(self.producer)
        invalid_producer["artifact"]["version"] = "3.2.0-01"
        with self.assertRaisesRegex(
            ValueError, "producer evidence version is invalid"
        ):
            MODULE.validate_producer_evidence(
                invalid_producer, self.identity, profiles
            )

        invalid_affected = copy.deepcopy(self.producer)
        invalid_affected["security"]["affectedVersion"] = "3.1.2-01"
        with self.assertRaisesRegex(
            ValueError, "security affected version is invalid"
        ):
            MODULE.validate_producer_evidence(
                invalid_affected, self.identity, profiles
            )

        invalid_container = replace(
            self.identity,
            container_release_tag="v1.0.0-01",
        )
        with self.assertRaisesRegex(
            ValueError, "container_release_tag must be v-prefixed semantic version"
        ):
            invalid_container.validate()

        overlong_container = replace(
            self.identity,
            container_release_tag=f"v{over_limit}",
        )
        with self.assertRaisesRegex(
            ValueError, "container_release_tag must be v-prefixed semantic version"
        ):
            overlong_container.validate()

        overlong_producer = copy.deepcopy(self.producer)
        overlong_producer["artifact"]["version"] = over_limit
        with self.assertRaisesRegex(
            ValueError, "producer evidence version is invalid"
        ):
            MODULE.validate_producer_evidence(
                overlong_producer, self.identity, profiles
            )

        with self.assertRaisesRegex(
            ValueError, "expected installed collection version is invalid"
        ):
            MODULE.verify_installed_collection(
                {}, "lit.supplementary", "3.2.0-01"
            )

    def test_profile_id_is_bounded_and_has_exactly_two_segments(self):
        existing = (
            self.profile,
            "lit.supplementary/mlx90-fixture",
        )
        for value in existing:
            with self.subTest(valid=value):
                self.assertTrue(MODULE.is_profile_id(value))

        at_limit = "a/" + "b" * (MODULE.PROFILE_ID_MAX_LENGTH - 2)
        over_limit = f"{at_limit}b"
        self.assertEqual(MODULE.PROFILE_ID_MAX_LENGTH, len(at_limit))
        self.assertEqual(MODULE.PROFILE_ID_MAX_LENGTH + 1, len(over_limit))
        self.assertTrue(MODULE.is_profile_id(at_limit))
        self.assertFalse(MODULE.is_profile_id(over_limit))
        self.assertIsNone(MODULE.PROFILE_ID.fullmatch(over_limit))
        with mock.patch.object(MODULE, "PROFILE_ID") as grammar:
            self.assertFalse(MODULE.is_profile_id(over_limit))
            grammar.fullmatch.assert_not_called()

        invalid = (
            "a/b/c",
            "a//b",
            "a/../b",
            "a/b/",
            "a/b",
            "a/..",
            "../bb",
            "a/bb/.",
            "a/bé",
            over_limit,
        )
        profile = copy.deepcopy(self.profiles["profiles"][self.profile])
        for index, value in enumerate(invalid):
            with self.subTest(invalid=value):
                self.assertFalse(MODULE.is_profile_id(value))
                path = self.root / f"invalid-profile-{index}.json"
                write_json(
                    path,
                    {
                        "schemaVersion": 1,
                        "profiles": {value: profile},
                    },
                )
                with self.assertRaisesRegex(ValueError, "profile ID is invalid"):
                    MODULE.load_profiles(path)

        with self.assertRaisesRegex(ValueError, "fixed allowlist"):
            MODULE.eligible_profile({}, "a/b/c")

    def test_producer_workflow_ref_must_equal_source_sha(self):
        producer = copy.deepcopy(self.producer)
        producer["producer"]["workflowRef"] = "9" * 40
        profiles = MODULE.load_profiles(self.profiles_path)
        with self.assertRaisesRegex(ValueError, "workflowRef must equal"):
            MODULE.validate_producer_evidence(producer, self.identity, profiles)

    def test_repository_profile_is_explicitly_non_releaseable(self):
        repository_profiles = MODULE.load_profiles(
            ROOT / "acceptance" / "mlx90" / "profiles.json"
        )
        with self.assertRaisesRegex(ValueError, "non-releaseable"):
            MODULE.eligible_profile(
                repository_profiles, "lit.supplementary/mlx90-fixture"
            )

    def test_verified_observations_build_both_final_documents(self):
        producer, container = self.validated()
        receipt_root, bundle_path = self.write_receipt_set(producer, container)
        profiles = MODULE.load_profiles(self.profiles_path)
        report = MODULE.verification_report(
            self.identity,
            profiles,
            self.producer_path,
            self.container_path,
            producer,
            container,
            receipt_root,
            bundle_path,
            workflow_sha="6" * 40,
            run_id=456789,
            run_attempt=1,
        )
        report = MODULE.validate_verification_report(
            report,
            self.identity,
            profiles,
            self.producer_path,
            self.container_path,
            bundle_path,
            producer,
            container,
            workflow_sha="6" * 40,
            run_id=456789,
            run_attempt=1,
        )
        delivered, acceptance = MODULE.build_final_evidence(
            self.identity,
            producer,
            container,
            report,
            workflow_sha="6" * 40,
            run_id=456789,
            run_attempt=1,
        )
        self.assertEqual("delivered", delivered["status"])
        self.assertEqual(
            self.identity.consumer_merge_sha,
            delivered["delivery"]["consumerMergeSha"],
        )
        self.assertEqual("delivered", acceptance["status"])
        self.assertEqual(
            "quay.io/lightning-it/ee-wunder@" + f"sha256:{'1' * 64}",
            acceptance["container"]["variants"]["public"]["pulledImage"],
        )
        bootstrap = acceptance["container"]["variants"]["bootstrap"]
        self.assertIs(bootstrap["collectionPresent"], False)
        self.assertIsNone(bootstrap["installedCollectionVersion"])
        self.assertIs(bootstrap["profileExecuted"], False)
        self.assertEqual(
            MODULE.file_digest(bundle_path),
            acceptance["receiptBundle"]["digest"],
        )
        self.assertEqual(
            bundle_path.stat().st_size,
            acceptance["receiptBundle"]["size"],
        )

    def test_verification_report_rejects_tampered_input_digest(self):
        producer, container = self.validated()
        receipt_root, bundle_path = self.write_receipt_set(producer, container)
        profiles = MODULE.load_profiles(self.profiles_path)
        report = MODULE.verification_report(
            self.identity,
            profiles,
            self.producer_path,
            self.container_path,
            producer,
            container,
            receipt_root,
            bundle_path,
            workflow_sha="6" * 40,
            run_id=456789,
            run_attempt=1,
        )
        self.container_path.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "container evidence digest"):
            MODULE.validate_verification_report(
                report,
                self.identity,
                profiles,
                self.producer_path,
                self.container_path,
                bundle_path,
                producer,
                container,
                workflow_sha="6" * 40,
                run_id=456789,
                run_attempt=1,
            )

    def test_every_typed_receipt_is_mandatory(self):
        producer, container = self.validated()
        profiles = MODULE.load_profiles(self.profiles_path)
        for missing in MODULE.EXPECTED_RECEIPT_TYPES:
            with self.subTest(missing=missing):
                receipt_root, bundle_path = self.write_receipt_set(
                    producer, container
                )
                (receipt_root / f"{missing}.json").unlink()
                with self.assertRaisesRegex(ValueError, "missing"):
                    MODULE.verification_report(
                        self.identity,
                        profiles,
                        self.producer_path,
                        self.container_path,
                        producer,
                        container,
                        receipt_root,
                        bundle_path,
                        workflow_sha="6" * 40,
                        run_id=456789,
                        run_attempt=1,
                    )

    def test_receipts_reject_digest_run_variant_and_staleness_tampering(self):
        producer, container = self.validated()
        profiles = MODULE.load_profiles(self.profiles_path)
        cases = (
            (
                "producer-evidence",
                lambda value: value.__setitem__(
                    "producerEvidenceDigest", f"sha256:{'0' * 64}"
                ),
                "producer evidence digest",
            ),
            (
                "container-release",
                lambda value: value["finalizer"].__setitem__("runId", 456788),
                "foreign",
            ),
            (
                "public-oci-index",
                lambda value: value["observations"].__setitem__(
                    "variant", "certified"
                ),
                "variant",
            ),
            (
                "producer-materials",
                lambda value: value.__setitem__(
                    "checkedAt", "2026-08-02T08:59:59Z"
                ),
                "stale",
            ),
            (
                "final-revocation",
                lambda value: value["observations"].__setitem__(
                    "containerTagCommit", "9" * 40
                ),
                "final live revocation receipt mismatch",
            ),
        )
        for receipt_id, mutate, message in cases:
            with self.subTest(receipt_id=receipt_id):
                receipt_root, bundle_path = self.write_receipt_set(
                    producer, container
                )
                path = receipt_root / f"{receipt_id}.json"
                payload = json.loads(path.read_text(encoding="utf-8"))
                mutate(payload)
                write_json(path, payload)
                with self.assertRaisesRegex(ValueError, message):
                    MODULE.verification_report(
                        self.identity,
                        profiles,
                        self.producer_path,
                        self.container_path,
                        producer,
                        container,
                        receipt_root,
                        bundle_path,
                        workflow_sha="6" * 40,
                        run_id=456789,
                        run_attempt=1,
                    )

    def test_final_asset_snapshot_rejects_reordering_and_metadata_tampering(self):
        producer, container = self.validated()
        profiles = MODULE.load_profiles(self.profiles_path)
        for mutate, message in (
            (
                lambda value: value["observations"]["producerAssets"][
                    "assets"
                ].reverse(),
                "canonical URL order",
            ),
            (
                lambda value: value["observations"]["containerAssets"]["assets"][
                    0
                ].__setitem__("size", 2001),
                "final live revocation receipt mismatch",
            ),
            (
                lambda value: value["observations"]["producerAssets"]["assets"][
                    1
                ].__setitem__(
                    "id",
                    value["observations"]["producerAssets"]["assets"][0]["id"],
                ),
                "duplicate asset metadata",
            ),
        ):
            with self.subTest(message=message):
                receipt_root, bundle_path = self.write_receipt_set(
                    producer, container
                )
                path = receipt_root / "final-revocation.json"
                payload = json.loads(path.read_text(encoding="utf-8"))
                mutate(payload)
                write_json(path, payload)
                with self.assertRaisesRegex(ValueError, message):
                    MODULE.verification_report(
                        self.identity,
                        profiles,
                        self.producer_path,
                        self.container_path,
                        producer,
                        container,
                        receipt_root,
                        bundle_path,
                        workflow_sha="6" * 40,
                        run_id=456789,
                        run_attempt=1,
                    )

    def test_initial_asset_snapshots_reject_metadata_and_digest_tampering(self):
        producer, container = self.validated()
        profiles = MODULE.load_profiles(self.profiles_path)
        for receipt_id in (
            "producer-revocation-initial",
            "container-revocation-initial",
        ):
            cases = (
                (
                    "id",
                    lambda observations: observations["assetSnapshot"][
                        "assets"
                    ][0].__setitem__("id", 0),
                    "must be a positive integer",
                ),
                (
                    "size",
                    lambda observations: observations["assetSnapshot"][
                        "assets"
                    ][0].__setitem__("size", 0),
                    "must be a positive integer",
                ),
                (
                    "url",
                    lambda observations: observations["assetSnapshot"][
                        "assets"
                    ][0].__setitem__(
                        "url", "https://github.com/lightning-it/other/asset"
                    ),
                    "not an exact consumed release asset",
                ),
                (
                    "metadata",
                    lambda observations: observations["assetSnapshot"][
                        "assets"
                    ][0].__setitem__("unexpected", True),
                    "unknown fields",
                ),
                (
                    "digest",
                    lambda observations: observations.__setitem__(
                        "assetSnapshotDigest", f"sha256:{'0' * 64}"
                    ),
                    "asset snapshot digest mismatch",
                ),
            )
            for name, mutate, message in cases:
                with self.subTest(receipt_id=receipt_id, tamper=name):
                    receipt_root, bundle_path = self.write_receipt_set(
                        producer, container
                    )
                    path = receipt_root / f"{receipt_id}.json"
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    mutate(payload["observations"])
                    write_json(path, payload)
                    with self.assertRaisesRegex(ValueError, message):
                        MODULE.verification_report(
                            self.identity,
                            profiles,
                            self.producer_path,
                            self.container_path,
                            producer,
                            container,
                            receipt_root,
                            bundle_path,
                            workflow_sha="6" * 40,
                            run_id=456789,
                            run_attempt=1,
                        )

    def test_initial_and_final_asset_snapshot_receipts_are_cross_bound(self):
        producer, container = self.validated()
        profiles = MODULE.load_profiles(self.profiles_path)
        for receipt_id in (
            "producer-revocation-initial",
            "container-revocation-initial",
        ):
            with self.subTest(receipt_id=receipt_id):
                receipt_root, bundle_path = self.write_receipt_set(
                    producer, container
                )
                path = receipt_root / f"{receipt_id}.json"
                payload = json.loads(path.read_text(encoding="utf-8"))
                snapshot = payload["observations"]["assetSnapshot"]
                snapshot["assets"][0]["size"] += 1
                payload["observations"]["assetSnapshotDigest"] = (
                    MODULE.canonical_value_digest(snapshot)
                )
                write_json(path, payload)
                with self.assertRaisesRegex(
                    ValueError,
                    "final revocation receipt is not bound to initial asset snapshots",
                ):
                    MODULE.verification_report(
                        self.identity,
                        profiles,
                        self.producer_path,
                        self.container_path,
                        producer,
                        container,
                        receipt_root,
                        bundle_path,
                        workflow_sha="6" * 40,
                        run_id=456789,
                        run_attempt=1,
                    )

        receipt_root, bundle_path = self.write_receipt_set(producer, container)
        final_path = receipt_root / "final-revocation.json"
        final_payload = json.loads(final_path.read_text(encoding="utf-8"))
        final_payload["observations"]["producerInitialAssetSnapshotDigest"] = (
            f"sha256:{'0' * 64}"
        )
        write_json(final_path, final_payload)
        with self.assertRaisesRegex(
            ValueError, "final live revocation receipt mismatch"
        ):
            MODULE.verification_report(
                self.identity,
                profiles,
                self.producer_path,
                self.container_path,
                producer,
                container,
                receipt_root,
                bundle_path,
                workflow_sha="6" * 40,
                run_id=456789,
                run_attempt=1,
            )

        receipt_root, bundle_path = self.write_receipt_set(producer, container)
        producer_path = receipt_root / "producer-revocation-initial.json"
        container_path = receipt_root / "container-revocation-initial.json"
        producer_payload = json.loads(producer_path.read_text(encoding="utf-8"))
        container_payload = json.loads(
            container_path.read_text(encoding="utf-8")
        )
        producer_observations = producer_payload["observations"]
        container_observations = container_payload["observations"]
        producer_snapshot = producer_observations["assetSnapshot"]
        producer_digest = producer_observations["assetSnapshotDigest"]
        producer_observations["assetSnapshot"] = container_observations[
            "assetSnapshot"
        ]
        producer_observations["assetSnapshotDigest"] = container_observations[
            "assetSnapshotDigest"
        ]
        container_observations["assetSnapshot"] = producer_snapshot
        container_observations["assetSnapshotDigest"] = producer_digest
        write_json(producer_path, producer_payload)
        write_json(container_path, container_payload)
        with self.assertRaisesRegex(ValueError, "asset snapshot release identity"):
            MODULE.verification_report(
                self.identity,
                profiles,
                self.producer_path,
                self.container_path,
                producer,
                container,
                receipt_root,
                bundle_path,
                workflow_sha="6" * 40,
                run_id=456789,
                run_attempt=1,
            )

    def test_producer_central_ci_receipt_is_bound_to_provenance_run(self):
        producer, container = self.validated()
        profiles = MODULE.load_profiles(self.profiles_path)
        receipt_root, bundle_path = self.write_receipt_set(producer, container)
        path = receipt_root / "producer-central-ci.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["observations"]["workflowRunId"] = 123457
        payload["observations"]["workflowRunUrl"] = (
            "https://github.com/"
            f"{MODULE.PRODUCER_REPOSITORY}/actions/runs/123457"
        )
        write_json(path, payload)
        with self.assertRaisesRegex(ValueError, "not bound to producer provenance"):
            MODULE.verification_report(
                self.identity,
                profiles,
                self.producer_path,
                self.container_path,
                producer,
                container,
                receipt_root,
                bundle_path,
                workflow_sha="6" * 40,
                run_id=456789,
                run_attempt=1,
            )

    def test_receipt_file_set_rejects_duplicates_and_unknown_files(self):
        producer, container = self.validated()
        profiles = MODULE.load_profiles(self.profiles_path)
        receipt_root, bundle_path = self.write_receipt_set(producer, container)
        duplicate = json.loads(
            (receipt_root / "producer-evidence.json").read_text(encoding="utf-8")
        )
        write_json(receipt_root / "duplicate.json", duplicate)
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            MODULE.verification_report(
                self.identity,
                profiles,
                self.producer_path,
                self.container_path,
                producer,
                container,
                receipt_root,
                bundle_path,
                workflow_sha="6" * 40,
                run_id=456789,
                run_attempt=1,
            )

    def test_write_report_cannot_run_from_evidence_documents_only(self):
        command = [
            sys.executable,
            str(ROOT / "scripts" / "finalize-mlx90-delivery.py"),
            "write-report",
            "--correlation-id",
            self.identity.correlation_id,
            "--producer-evidence-url",
            self.identity.producer_evidence_url,
            "--producer-evidence-bundle-url",
            self.identity.producer_evidence_bundle_url,
            "--producer-evidence-sha256",
            self.identity.producer_evidence_sha256,
            "--consumer-pr",
            str(self.identity.consumer_pr),
            "--consumer-head-sha",
            self.identity.consumer_head_sha,
            "--consumer-merge-sha",
            self.identity.consumer_merge_sha,
            "--container-release-id",
            str(self.identity.container_release_id),
            "--container-release-tag",
            self.identity.container_release_tag,
            "--container-release-run-id",
            str(self.identity.container_release_run_id),
            "--container-publish-run-attempt",
            str(self.identity.container_publish_run_attempt),
            "--producer-evidence",
            str(self.producer_path),
            "--container-evidence",
            str(self.container_path),
            "--profiles",
            str(self.profiles_path),
            "--workflow-sha",
            "6" * 40,
            "--run-id",
            "456789",
            "--run-attempt",
            "1",
            "--receipt-bundle-output",
            str(self.root / "bundle.json"),
            "--output",
            str(self.root / "report.json"),
        ]
        completed = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("--receipts", completed.stderr)
        self.assertFalse((self.root / "report.json").exists())

    def test_write_report_and_finalize_cli_never_overwrite_outputs(self):
        producer, container = self.validated()
        receipt_root, bundle_path = self.write_receipt_set(producer, container)
        common = [
            "--correlation-id",
            self.identity.correlation_id,
            "--producer-evidence-url",
            self.identity.producer_evidence_url,
            "--producer-evidence-bundle-url",
            self.identity.producer_evidence_bundle_url,
            "--producer-evidence-sha256",
            self.identity.producer_evidence_sha256,
            "--consumer-pr",
            str(self.identity.consumer_pr),
            "--consumer-head-sha",
            self.identity.consumer_head_sha,
            "--consumer-merge-sha",
            self.identity.consumer_merge_sha,
            "--container-release-id",
            str(self.identity.container_release_id),
            "--container-release-tag",
            self.identity.container_release_tag,
            "--container-release-run-id",
            str(self.identity.container_release_run_id),
            "--container-publish-run-attempt",
            str(self.identity.container_publish_run_attempt),
            "--producer-evidence",
            str(self.producer_path),
            "--container-evidence",
            str(self.container_path),
            "--profiles",
            str(self.profiles_path),
        ]
        run = [
            "--workflow-sha",
            "6" * 40,
            "--run-id",
            "456789",
            "--run-attempt",
            "1",
        ]
        executable = [
            sys.executable,
            str(ROOT / "scripts" / "finalize-mlx90-delivery.py"),
        ]
        output_root = self.root.resolve()
        report_path = output_root / "report.json"
        report_command = [
            *executable,
            "write-report",
            *common,
            *run,
            "--receipts",
            str(receipt_root),
            "--receipt-bundle-output",
            str(bundle_path),
            "--output",
            str(report_path),
        ]
        first_report = subprocess.run(
            report_command, capture_output=True, text=True, check=False
        )
        self.assertEqual(0, first_report.returncode, first_report.stderr)
        report_bytes = report_path.read_bytes()
        bundle_bytes = bundle_path.read_bytes()

        repeated_bundle = output_root / "repeated-bundle.json"
        repeated_report_command = [
            *report_command[:-4],
            "--receipt-bundle-output",
            str(repeated_bundle),
            "--output",
            str(report_path),
        ]
        repeated_report = subprocess.run(
            repeated_report_command,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(0, repeated_report.returncode)
        self.assertIn("output already exists", repeated_report.stderr)
        self.assertEqual(report_bytes, report_path.read_bytes())
        self.assertEqual(bundle_bytes, bundle_path.read_bytes())

        delivered_path = output_root / "delivered.json"
        acceptance_path = output_root / "acceptance.json"
        finalize_command = [
            *executable,
            "finalize",
            *common,
            *run,
            "--verification-report",
            str(report_path),
            "--receipt-bundle",
            str(bundle_path),
            "--delivered-output",
            str(delivered_path),
            "--acceptance-output",
            str(acceptance_path),
        ]
        first_finalize = subprocess.run(
            finalize_command, capture_output=True, text=True, check=False
        )
        self.assertEqual(0, first_finalize.returncode, first_finalize.stderr)
        delivered_bytes = delivered_path.read_bytes()
        acceptance_bytes = acceptance_path.read_bytes()
        repeated_finalize = subprocess.run(
            finalize_command, capture_output=True, text=True, check=False
        )
        self.assertNotEqual(0, repeated_finalize.returncode)
        self.assertIn("output already exists", repeated_finalize.stderr)
        self.assertEqual(delivered_bytes, delivered_path.read_bytes())
        self.assertEqual(acceptance_bytes, acceptance_path.read_bytes())

        for occupied_position in ("delivered", "acceptance"):
            with self.subTest(existing_terminal_output=occupied_position):
                delivered = output_root / f"existing-{occupied_position}-delivered.json"
                acceptance = output_root / f"existing-{occupied_position}-acceptance.json"
                occupied = (
                    delivered
                    if occupied_position == "delivered"
                    else acceptance
                )
                other = acceptance if occupied is delivered else delivered
                occupied.write_bytes(b"EXISTING-TERMINAL\n")
                command = [
                    *finalize_command[:-4],
                    "--delivered-output",
                    str(delivered),
                    "--acceptance-output",
                    str(acceptance),
                ]
                completed = subprocess.run(
                    command, capture_output=True, text=True, check=False
                )
                self.assertNotEqual(0, completed.returncode)
                self.assertIn("output already exists", completed.stderr)
                self.assertEqual(b"EXISTING-TERMINAL\n", occupied.read_bytes())
                self.assertFalse(other.exists())

        real_link = MODULE.os.link
        for raced_position in ("delivered", "acceptance"):
            with self.subTest(racing_terminal_output=raced_position):
                delivered = output_root / f"raced-{raced_position}-delivered.json"
                acceptance = output_root / f"raced-{raced_position}-acceptance.json"
                raced = delivered if raced_position == "delivered" else acceptance
                other = acceptance if raced is delivered else delivered
                command = [
                    *finalize_command[:-4],
                    "--delivered-output",
                    str(delivered),
                    "--acceptance-output",
                    str(acceptance),
                ]

                def race(source, destination):
                    if Path(destination) == raced:
                        raced.write_bytes(b"RACE-TERMINAL\n")
                    return real_link(source, destination)

                with mock.patch.object(sys, "argv", command[1:]), mock.patch.object(
                    MODULE.os, "link", side_effect=race
                ), mock.patch.object(
                    MODULE.argparse.ArgumentParser,
                    "error",
                    side_effect=ValueError,
                ):
                    with self.assertRaises(ValueError):
                        MODULE.main()
                self.assertEqual(b"RACE-TERMINAL\n", raced.read_bytes())
                self.assertFalse(other.exists())
                self.assertFalse(
                    list(output_root.glob(f".{delivered.name}.*.tmp"))
                )
                self.assertFalse(
                    list(output_root.glob(f".{acceptance.name}.*.tmp"))
                )

    def test_report_does_not_statically_synthesize_success(self):
        source = (ROOT / "scripts" / "finalize-mlx90-delivery.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("{name: True for name", source)

    def test_receipt_bundle_reference_and_order_are_not_advisory(self):
        producer, container = self.validated()
        profiles = MODULE.load_profiles(self.profiles_path)
        receipt_root, bundle_path = self.write_receipt_set(producer, container)
        report = MODULE.verification_report(
            self.identity,
            profiles,
            self.producer_path,
            self.container_path,
            producer,
            container,
            receipt_root,
            bundle_path,
            workflow_sha="6" * 40,
            run_id=456789,
            run_attempt=1,
        )
        wrong_size = copy.deepcopy(report)
        wrong_size["receiptBundle"]["size"] += 1
        with self.assertRaisesRegex(ValueError, "bundle reference"):
            MODULE.validate_verification_report(
                wrong_size,
                self.identity,
                profiles,
                self.producer_path,
                self.container_path,
                bundle_path,
                producer,
                container,
                workflow_sha="6" * 40,
                run_id=456789,
                run_attempt=1,
            )

        reordered_path = (self.root / "reordered-receipts.json").resolve()
        reordered = json.loads(bundle_path.read_text(encoding="utf-8"))
        reordered["receipts"].reverse()
        write_json(reordered_path, reordered)
        reordered_report = copy.deepcopy(report)
        reordered_report["receiptBundle"] = {
            "assetName": "mlx90-verification-receipts.json",
            "digest": MODULE.file_digest(reordered_path),
            "size": reordered_path.stat().st_size,
        }
        with self.assertRaisesRegex(ValueError, "order is not canonical"):
            MODULE.validate_verification_report(
                reordered_report,
                self.identity,
                profiles,
                self.producer_path,
                self.container_path,
                reordered_path,
                producer,
                container,
                workflow_sha="6" * 40,
                run_id=456789,
                run_attempt=1,
            )

    def test_producer_materials_bind_candidate_sbom_and_provenance(self):
        producer = copy.deepcopy(self.producer)
        collection = self.root / "lit-supplementary-3.2.0.tar.gz"
        sbom = self.root / "sbom.cdx.json"
        provenance = self.root / "provenance.json"
        collection.write_bytes(b"synthetic collection archive")
        collection_digest = digest_bytes(collection.read_bytes())
        producer["artifact"]["digest"] = f"sha256:{collection_digest}"
        write_json(
            sbom,
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "metadata": {
                    "component": {
                        "type": "application",
                        "group": "lit",
                        "name": "supplementary",
                        "version": "3.2.0",
                        "hashes": [
                            {"alg": "SHA-256", "content": collection_digest}
                        ],
                    }
                },
            },
        )
        write_json(
            provenance,
            {
                "schema_version": 1,
                "repository": MODULE.PRODUCER_REPOSITORY,
                "commit_sha": producer["producer"]["sourceSha"],
                "candidate": "lit-supplementary-3.2.0.tar.gz",
                "candidate_sha256": collection_digest,
                "workflow_run_id": "123456",
                "workflow_attempt": "1",
                "generated_at": "2026-08-02T10:00:00Z",
            },
        )
        producer["artifact"]["sbom"]["digest"] = MODULE.file_digest(sbom)
        producer["artifact"]["provenance"]["digest"] = MODULE.file_digest(
            provenance
        )
        MODULE.verify_producer_materials(
            producer, collection, sbom, provenance
        )

        tampered = json.loads(sbom.read_text(encoding="utf-8"))
        tampered["metadata"]["component"]["version"] = "3.1.2"
        write_json(sbom, tampered)
        producer["artifact"]["sbom"]["digest"] = MODULE.file_digest(sbom)
        with self.assertRaisesRegex(ValueError, "does not match"):
            MODULE.verify_producer_materials(
                producer, collection, sbom, provenance
            )

        tampered["metadata"]["component"]["version"] = "3.2.0"
        write_json(sbom, tampered)
        producer["artifact"]["sbom"]["digest"] = MODULE.file_digest(sbom)
        valid_provenance = json.loads(provenance.read_text(encoding="utf-8"))
        for field, value in (
            ("workflow_run_id", "0123456"),
            ("workflow_attempt", "0"),
            ("workflow_attempt", "not-a-number"),
        ):
            with self.subTest(field=field, value=value):
                invalid = copy.deepcopy(valid_provenance)
                invalid[field] = value
                write_json(provenance, invalid)
                producer["artifact"]["provenance"]["digest"] = MODULE.file_digest(
                    provenance
                )
                with self.assertRaisesRegex(ValueError, "canonical positive"):
                    MODULE.verify_producer_materials(
                        producer, collection, sbom, provenance
                    )

    def test_container_materials_bind_references_to_live_verification(self):
        _, container = self.validated()
        variant = container["variants"]["public"]
        manifest = variant["manifestDigest"]
        image = variant["image"]
        image_ref = f"{image}@{manifest}"
        workflow_identity = (
            f"https://github.com/{MODULE.CONSUMER_REPOSITORY}/"
            ".github/workflows/container-build-publish.yml@"
            f"refs/tags/{self.identity.container_release_tag}"
        )
        signature_value = [
            {
                "critical": {
                    "identity": {"docker-reference": image},
                    "image": {"docker-manifest-digest": manifest},
                    "type": "cosign container image signature",
                },
                "optional": {
                    "Issuer": "https://token.actions.githubusercontent.com",
                    "Subject": workflow_identity,
                },
            }
        ]
        sbom_value = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "group": "aquasecurity",
                            "name": "trivy",
                            "version": "0.70.0",
                        }
                    ]
                },
                "component": {
                    "type": "container",
                    "name": image_ref,
                },
            },
            "components": [{"type": "library", "name": "synthetic"}],
        }

        signature = self.root / "signature-public.json"
        live_signature = self.root / "signature-public-live.json"
        sbom = self.root / "sbom-public.cdx.json"
        provenance = self.root / "release-provenance.intoto.jsonl"
        write_json(signature, signature_value)
        write_json(live_signature, signature_value)
        write_json(sbom, sbom_value)
        signature_digest = MODULE.file_digest(signature)
        sbom_digest = MODULE.file_digest(sbom)
        provenance_value = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": signature.name,
                    "digest": {
                        "sha256": signature_digest.removeprefix("sha256:")
                    },
                },
                {
                    "name": sbom.name,
                    "digest": {"sha256": sbom_digest.removeprefix("sha256:")},
                },
                {"name": image_ref},
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://lightning-it.io/provenance/workflow-release",
                    "externalParameters": {
                        "repository": MODULE.CONSUMER_REPOSITORY,
                        "release": self.identity.container_release_tag,
                        "commit": self.identity.consumer_merge_sha,
                    },
                    "internalParameters": {},
                    "resolvedDependencies": [
                        {
                            "uri": (
                                "git+https://github.com/"
                                f"{MODULE.CONSUMER_REPOSITORY}@"
                                f"{self.identity.consumer_merge_sha}"
                            ),
                            "digest": {
                                "gitCommit": self.identity.consumer_merge_sha
                            },
                        }
                    ],
                },
                "runDetails": {
                    "builder": {
                        "id": (
                            f"https://github.com/{MODULE.CONSUMER_REPOSITORY}/"
                            "actions"
                        )
                    },
                    "metadata": {
                        "invocationId": str(
                            self.identity.container_release_run_id
                        ),
                        "startedOn": "2026-08-02T11:00:00Z",
                        "finishedOn": "2026-08-02T11:00:00Z",
                    },
                    "byproducts": [
                        {
                            "name": "workflow_run",
                            "uri": (
                                f"https://github.com/{MODULE.CONSUMER_REPOSITORY}/"
                                "actions/runs/"
                                f"{self.identity.container_release_run_id}"
                            ),
                        }
                    ],
                },
            },
        }
        write_json_line(provenance, provenance_value)
        variant["signature"]["digest"] = signature_digest
        variant["sbom"]["digest"] = sbom_digest
        variant["provenance"]["digest"] = MODULE.file_digest(provenance)

        def verify() -> None:
            MODULE.verify_container_materials(
                container,
                "public",
                signature,
                live_signature,
                sbom,
                provenance,
            )

        verify()

        unrelated_signature = copy.deepcopy(signature_value)
        unrelated_signature[0]["optional"]["unrelated"] = True
        write_json(signature, unrelated_signature)
        variant["signature"]["digest"] = MODULE.file_digest(signature)
        with self.assertRaisesRegex(ValueError, "absent from the live"):
            verify()

        write_json(signature, signature_value)
        variant["signature"]["digest"] = MODULE.file_digest(signature)
        unrelated_sbom = copy.deepcopy(sbom_value)
        unrelated_sbom["metadata"]["component"]["name"] = (
            "quay.io/lightning-it/unrelated@" + manifest
        )
        write_json(sbom, unrelated_sbom)
        variant["sbom"]["digest"] = MODULE.file_digest(sbom)
        with self.assertRaisesRegex(ValueError, "exact immutable image"):
            verify()

        write_json(sbom, sbom_value)
        variant["sbom"]["digest"] = MODULE.file_digest(sbom)
        unrelated_provenance = copy.deepcopy(provenance_value)
        unrelated_provenance["subject"][-1] = {
            "name": "quay.io/lightning-it/unrelated@" + manifest
        }
        write_json_line(provenance, unrelated_provenance)
        variant["provenance"]["digest"] = MODULE.file_digest(provenance)
        with self.assertRaisesRegex(ValueError, "does not bind"):
            verify()

    def test_oci_index_requires_both_exact_platform_digests(self):
        _, container = self.validated()
        index = {
            "schemaVersion": 2,
            "manifests": [
                {
                    "digest": f"sha256:{'a' * 64}",
                    "platform": {"os": "linux", "architecture": "amd64"},
                },
                {
                    "digest": f"sha256:{'b' * 64}",
                    "platform": {"os": "linux", "architecture": "arm64"},
                },
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": f"sha256:{'c' * 64}",
                    "annotations": {
                        "vnd.docker.reference.digest": f"sha256:{'a' * 64}",
                        "vnd.docker.reference.type": "attestation-manifest",
                    },
                    "platform": {"os": "unknown", "architecture": "unknown"},
                },
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": f"sha256:{'d' * 64}",
                    "annotations": {
                        "vnd.docker.reference.digest": f"sha256:{'b' * 64}",
                        "vnd.docker.reference.type": "attestation-manifest",
                    },
                    "platform": {"os": "unknown", "architecture": "unknown"},
                },
            ],
        }
        MODULE.verify_index(container, "public", index)
        unexpected_platform = copy.deepcopy(index)
        platform_marker = "SENSITIVE-PLATFORM-MARKER"
        unexpected_platform["manifests"].append(
            {
                "digest": f"sha256:{'c' * 64}",
                "platform": {
                    "os": "linux",
                    "architecture": platform_marker,
                },
            }
        )
        with self.assertRaisesRegex(
            ValueError, "unexpected platform"
        ) as caught:
            MODULE.verify_index(container, "public", unexpected_platform)
        self.assertNotIn(platform_marker, str(caught.exception))

        malformed_platforms = (
            (
                "control",
                {"os": "linux", "architecture": "SENSITIVE-CONTROL\tVALUE"},
                "must be a non-empty single-line string",
            ),
            (
                "object",
                {
                    "os": {"SENSITIVE-OBJECT": "VALUE"},
                    "architecture": "amd64",
                },
                "must be a non-empty single-line string",
            ),
            (
                "unknown-key",
                {
                    "os": "linux",
                    "architecture": "amd64",
                    "SENSITIVE-UNKNOWN-KEY": "VALUE",
                },
                "unknown fields",
            ),
        )
        for name, platform, message in malformed_platforms:
            with self.subTest(platform=name):
                malformed = copy.deepcopy(index)
                malformed["manifests"][0]["platform"] = platform
                with self.assertRaisesRegex(ValueError, message) as caught:
                    MODULE.verify_index(container, "public", malformed)
                self.assertNotIn("SENSITIVE", str(caught.exception))
        missing_platform = copy.deepcopy(index)
        missing_platform["manifests"] = [
            descriptor
            for descriptor in missing_platform["manifests"]
            if descriptor["platform"].get("architecture") != "arm64"
        ]
        with self.assertRaisesRegex(ValueError, "do not match"):
            MODULE.verify_index(container, "public", missing_platform)
        duplicate_attestation = copy.deepcopy(index)
        duplicate_attestation["manifests"][-1]["annotations"][
            "vnd.docker.reference.digest"
        ] = f"sha256:{'a' * 64}"
        with self.assertRaisesRegex(ValueError, "duplicate attestation target"):
            MODULE.verify_index(container, "public", duplicate_attestation)
        duplicate_platform = copy.deepcopy(index)
        duplicate_platform["manifests"].append(
            copy.deepcopy(duplicate_platform["manifests"][0])
        )
        with self.assertRaisesRegex(ValueError, "duplicate platform") as caught:
            MODULE.verify_index(container, "public", duplicate_platform)
        self.assertNotIn("linux/amd64", str(caught.exception))

    def test_buildkit_spdx_and_slsa_are_transitively_bound_and_semantic(self):
        _, container = self.validated()
        index_path, attestation_root = self.write_buildkit_fixture(container)
        MODULE.verify_buildkit_attestations(
            container,
            "public",
            index_path,
            attestation_root,
        )

    def test_buildkit_subject_is_the_exact_sha_bound_candidate(self):
        _, container = self.validated()
        variant = container["variants"]["public"]
        source_sha = container["release"]["sourceSha"]
        self.assertEqual(
            {
                f"pkg:docker/{variant['image']}@mlx90-candidate-{source_sha}"
                "?platform=linux%2Farm64"
            },
            MODULE.buildkit_subject_names(
                variant["image"], source_sha, "linux/arm64"
            ),
        )

    def test_buildkit_subject_rejects_post_build_release_aliases(self):
        _, container = self.validated()

        def add_release_alias(platform, statements):
            if platform != "linux/amd64":
                return
            platform_digest = container["variants"]["public"][
                "platformDigests"
            ][platform]
            alias = {
                "name": (
                    "pkg:docker/"
                    f"{container['variants']['public']['image']}@"
                    f"{container['release']['tag']}?platform=linux%2Famd64"
                ),
                "digest": {
                    "sha256": platform_digest.removeprefix("sha256:")
                },
            }
            for statement in statements.values():
                statement["subject"].append(copy.deepcopy(alias))

        index_path, attestation_root = self.write_buildkit_fixture(
            container, mutator=add_release_alias
        )
        with self.assertRaisesRegex(ValueError, "SHA-bound candidate"):
            MODULE.verify_buildkit_attestations(
                container,
                "public",
                index_path,
                attestation_root,
            )

    def test_buildkit_subject_rejects_latest_before_delivery(self):
        _, container = self.validated()

        def replace_candidate_with_latest(platform, statements):
            if platform != "linux/arm64":
                return
            for statement in statements.values():
                statement["subject"][0]["name"] = statement["subject"][0][
                    "name"
                ].replace(
                    "@mlx90-candidate-" + container["release"]["sourceSha"],
                    "@latest",
                )

        index_path, attestation_root = self.write_buildkit_fixture(
            container, mutator=replace_candidate_with_latest
        )
        with self.assertRaisesRegex(ValueError, "SHA-bound candidate"):
            MODULE.verify_buildkit_attestations(
                container,
                "public",
                index_path,
                attestation_root,
            )

    def test_buildkit_payload_bytes_must_match_the_attestation_layer(self):
        _, container = self.validated()
        index_path, attestation_root = self.write_buildkit_fixture(container)
        statement_path = attestation_root / "linux-amd64-spdx.json"
        statement = json.loads(statement_path.read_text(encoding="utf-8"))
        statement["predicate"]["name"] = "unrelated"
        write_json(statement_path, statement)
        with self.assertRaisesRegex(ValueError, "payload is not bound"):
            MODULE.verify_buildkit_attestations(
                container,
                "public",
                index_path,
                attestation_root,
            )

    def test_buildkit_subject_must_bind_the_exact_platform_digest(self):
        _, container = self.validated()

        def mutate(platform, statements):
            if platform == "linux/amd64":
                statements[MODULE.SLSA_PREDICATE]["subject"][0]["digest"][
                    "sha256"
                ] = "f" * 64

        index_path, attestation_root = self.write_buildkit_fixture(
            container, mutator=mutate
        )
        with self.assertRaisesRegex(ValueError, "exact platform digest"):
            MODULE.verify_buildkit_attestations(
                container,
                "public",
                index_path,
                attestation_root,
            )

    def test_buildkit_spdx_rejects_wrong_standard_and_generators(self):
        _, container = self.validated()

        def wrong_standard(platform, statements):
            if platform == "linux/amd64":
                statements[MODULE.SPDX_PREDICATE]["predicate"][
                    "spdxVersion"
                ] = "SPDX-2.2"

        index_path, attestation_root = self.write_buildkit_fixture(
            container, mutator=wrong_standard
        )
        with self.assertRaisesRegex(ValueError, "document identity"):
            MODULE.verify_buildkit_attestations(
                container,
                "public",
                index_path,
                attestation_root,
            )

        def wrong_generator(platform, statements):
            if platform == "linux/amd64":
                statements[MODULE.SPDX_PREDICATE]["predicate"][
                    "creationInfo"
                ]["creators"] = ["Tool: unrelated-1.0"]

        index_path, attestation_root = self.write_buildkit_fixture(
            container, mutator=wrong_generator
        )
        with self.assertRaisesRegex(ValueError, "Syft"):
            MODULE.verify_buildkit_attestations(
                container,
                "public",
                index_path,
                attestation_root,
            )

        def control_generator(platform, statements):
            if platform == "linux/amd64":
                statements[MODULE.SPDX_PREDICATE]["predicate"][
                    "creationInfo"
                ]["creators"].append("SENSITIVE\tGENERATOR")

        index_path, attestation_root = self.write_buildkit_fixture(
            container, mutator=control_generator
        )
        with self.assertRaisesRegex(ValueError, "ASCII control") as caught:
            MODULE.verify_buildkit_attestations(
                container,
                "public",
                index_path,
                attestation_root,
            )
        self.assertNotIn("SENSITIVE", str(caught.exception))

    def test_buildkit_slsa_rejects_unrelated_profile_and_workflow(self):
        _, container = self.validated()

        def wrong_profile(platform, statements):
            if platform == "linux/amd64":
                request = statements[MODULE.SLSA_PREDICATE]["predicate"][
                    "buildDefinition"
                ]["externalParameters"]["request"]
                request["args"]["build-arg:COLLECTION_PROFILE"] = "certified"
                request["root"]["request"]["args"][
                    "build-arg:COLLECTION_PROFILE"
                ] = "certified"

        index_path, attestation_root = self.write_buildkit_fixture(
            container, mutator=wrong_profile
        )
        with self.assertRaisesRegex(ValueError, "release identity"):
            MODULE.verify_buildkit_attestations(
                container,
                "public",
                index_path,
                attestation_root,
            )

        def wrong_workflow(platform, statements):
            if platform == "linux/amd64":
                statements[MODULE.SLSA_PREDICATE]["predicate"][
                    "buildDefinition"
                ]["internalParameters"]["github_workflow_sha"] = "f" * 40

        index_path, attestation_root = self.write_buildkit_fixture(
            container, mutator=wrong_workflow
        )
        with self.assertRaisesRegex(ValueError, "github_workflow_sha"):
            MODULE.verify_buildkit_attestations(
                container,
                "public",
                index_path,
                attestation_root,
            )

        def legacy_release_event(platform, statements):
            if platform == "linux/amd64":
                statements[MODULE.SLSA_PREDICATE]["predicate"][
                    "buildDefinition"
                ]["internalParameters"]["github_event_name"] = "release"

        index_path, attestation_root = self.write_buildkit_fixture(
            container, mutator=legacy_release_event
        )
        with self.assertRaisesRegex(ValueError, "github_event_name"):
            MODULE.verify_buildkit_attestations(
                container,
                "public",
                index_path,
                attestation_root,
            )

    def test_buildkit_manifest_must_be_covered_by_the_signed_index(self):
        _, container = self.validated()
        index_path, attestation_root = self.write_buildkit_fixture(container)
        index = json.loads(index_path.read_text(encoding="utf-8"))
        index["manifests"][1]["digest"] = f"sha256:{'f' * 64}"
        write_json(index_path, index)
        container["variants"]["public"]["manifestDigest"] = MODULE.file_digest(
            index_path
        )
        with self.assertRaisesRegex(ValueError, "signed OCI index"):
            MODULE.verify_buildkit_attestations(
                container,
                "public",
                index_path,
                attestation_root,
            )

    def test_installed_collection_must_exist_exactly_once(self):
        result = {
            "/usr/share/ansible/collections": {
                "lit.supplementary": {"version": "3.2.0"}
            }
        }
        MODULE.verify_installed_collection(
            result, "lit.supplementary", "3.2.0"
        )
        result["/other/path"] = {
            "lit.supplementary": {"version": "3.2.0"}
        }
        with self.assertRaisesRegex(ValueError, "does not match"):
            MODULE.verify_installed_collection(
                result, "lit.supplementary", "3.2.0"
            )
        MODULE.verify_installed_collection({}, "lit.supplementary", None)
        with self.assertRaisesRegex(ValueError, "does not match"):
            MODULE.verify_installed_collection(
                result, "lit.supplementary", None
            )

        observed_marker = "SENSITIVE-OBSERVED-VERSION"
        expected_marker = "3.2.0-SENSITIVE-EXPECTED-VERSION"
        secret_shaped = {
            "/sensitive/path": {
                "lit.supplementary": {"version": observed_marker}
            }
        }
        with self.assertRaisesRegex(ValueError, "does not match") as caught:
            MODULE.verify_installed_collection(
                secret_shaped,
                "lit.supplementary",
                expected_marker,
            )
        message = str(caught.exception)
        self.assertNotIn(observed_marker, message)
        self.assertNotIn(expected_marker, message)

    def test_bundle_url_and_digest_are_not_advisory(self):
        invalid = replace(
            self.identity,
            producer_evidence_bundle_url=(
                self.identity.producer_evidence_bundle_url.replace(
                    "/v3.2.0/", "/v3.2.1/"
                )
            ),
        )
        with self.assertRaisesRegex(ValueError, "must be derived"):
            invalid.validate()


if __name__ == "__main__":
    unittest.main()
