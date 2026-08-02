import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
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
                "runRepository": MODULE.CONSUMER_REPOSITORY,
                "event": "release",
                "workflowPath": MODULE.CONTAINER_WORKFLOW,
                "headSha": self.identity.consumer_merge_sha,
                "headBranch": self.identity.container_release_tag,
                "status": "completed",
                "conclusion": "success",
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

    def test_core_receipt_set_builds_both_final_documents(self):
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

        receipt_root, bundle_path = self.write_receipt_set(producer, container)
        path = receipt_root / "producer-revocation-initial.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        observations = payload["observations"]
        observations["assetSnapshot"]["assets"][0]["size"] += 1
        observations["assetSnapshotDigest"] = MODULE.canonical_value_digest(
            observations["assetSnapshot"]
        )
        write_json(path, payload)
        with self.assertRaisesRegex(ValueError, "initial asset snapshots"):
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
        for owner, operation, target in (
            (MODULE.Path, "mkdir", missing_parent_output),
            (MODULE.Path, "open", output),
            (MODULE.os, "link", output),
            (MODULE.Path, "unlink", output),
        ):
            with self.subTest(operation=operation), mock.patch.object(
                owner, operation, side_effect=injected_error
            ):
                assert_sanitized(lambda: MODULE.write_json(target, {}))

        pair_first = root / f"{marker}-first.json"
        pair_second = root / f"{marker}-second.json"
        with mock.patch.object(
            MODULE.os, "link", side_effect=[None, injected_error]
        ):
            assert_sanitized(
                lambda: MODULE.write_json_pair(pair_first, {}, pair_second, {})
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


if __name__ == "__main__":
    unittest.main()
