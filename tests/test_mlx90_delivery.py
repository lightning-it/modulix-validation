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
    "mlx90_delivery_validator",
    ROOT / "scripts" / "validate-mlx90-delivery.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def reference(
    repository: str, tag: str, name: str, character: str
) -> dict[str, str]:
    return {
        "url": f"https://github.com/{repository}/releases/download/{tag}/{name}",
        "digest": f"sha256:{character * 64}",
    }


def variant(name: str, character: str) -> dict[str, object]:
    suffix = "" if name == "public" else f"-{name}"
    image = f"quay.io/lightning-it/ee-wunder{suffix}"
    manifest = f"sha256:{character * 64}"
    return {
        "image": image,
        "manifestDigest": manifest,
        "platformDigests": {
            "linux/amd64": f"sha256:{'a' * 64}",
            "linux/arm64": f"sha256:{'b' * 64}",
        },
        "signature": reference(
            MODULE.CONSUMER_REPOSITORY,
            "v1.25.0",
            f"{name}-signature.json",
            "c",
        ),
        "sbom": reference(
            MODULE.CONSUMER_REPOSITORY,
            "v1.25.0",
            f"{name}-sbom.json",
            "d",
        ),
        "provenance": reference(
            MODULE.CONSUMER_REPOSITORY,
            "v1.25.0",
            f"{name}-provenance.json",
            "e",
        ),
        "pulledImage": f"{image}@{manifest}",
        "collectionPresent": name != "bootstrap",
        "installedCollectionVersion": (
            None if name == "bootstrap" else "3.2.0"
        ),
        "profileExecuted": name != "bootstrap",
    }


def delivered_fixture() -> dict[str, object]:
    return {
        "apiVersion": "lit.security-release.acceptance/v1",
        "kind": "SecurityReleaseAcceptance",
        "status": "delivered",
        "securityEvidenceId": "LIT-SEC-MLX90-2026-001",
        "producer": {
            "repository": MODULE.PRODUCER_REPOSITORY,
            "sourceSha": "1" * 40,
            "collection": "lit.supplementary",
            "version": "3.2.0",
            "collectionDigest": f"sha256:{'f' * 64}",
            "releaseUrl": (
                "https://github.com/lightning-it/"
                "ansible-collection-supplementary/releases/tag/v3.2.0"
            ),
            "evidence": reference(
                MODULE.PRODUCER_REPOSITORY,
                "v3.2.0",
                "security-release-evidence.json",
                "1",
            ),
            "workflowRunId": 111111,
        },
        "consumer": {
            "repository": MODULE.CONSUMER_REPOSITORY,
            "pullRequest": 503,
            "baseSha": "7" * 40,
            "headSha": "2" * 40,
            "changeMergeSha": "8" * 40,
            "promotionPullRequest": 504,
            "mergeSha": "3" * 40,
        },
        "container": {
            "repository": MODULE.CONSUMER_REPOSITORY,
            "releaseId": 987,
            "releaseTag": "v1.25.0",
            "releaseUrl": (
                "https://github.com/lightning-it/"
                "container-ee-wunder-ansible-ubi9/releases/tag/v1.25.0"
            ),
            "sourceSha": "3" * 40,
            "evidence": reference(
                MODULE.CONSUMER_REPOSITORY,
                "v1.25.0",
                "mlx90-container-evidence.json",
                "2",
            ),
            "variants": {
                "public": variant("public", "3"),
                "certified": variant("certified", "4"),
                "bootstrap": variant("bootstrap", "5"),
            },
            "workflowRunId": 222222,
        },
        "acceptance": {
            "profile": "lit.supplementary/security-fix-2026-001",
            "expectedCollection": "lit.supplementary",
            "expectedVersion": "3.2.0",
            "acceptedAt": "2026-08-02T12:00:00Z",
        },
        "receiptBundle": {
            "assetName": "mlx90-verification-receipts.json",
            "digest": f"sha256:{'9' * 64}",
            "size": 12345,
        },
        "checks": {name: True for name in MODULE.REQUIRED_CHECKS},
        "zeroTouch": {
            "humanActions": {
                "scope": MODULE.HUMAN_ACTION_SCOPE,
                "count": 0,
            },
            "app": {
                "slug": MODULE.RELEASE_AUTOMATION_APP_SLUG,
                "installationId": MODULE.RELEASE_AUTOMATION_INSTALLATION_ID,
            },
            "finalizer": {
                "repository": MODULE.FINALIZER_REPOSITORY,
                "runId": 123456,
                "actor": MODULE.RELEASE_AUTOMATION_ACTOR,
                "triggeringActor": MODULE.RELEASE_AUTOMATION_ACTOR,
            },
            "mergeEvents": [
                {
                    "purpose": "consumer-change",
                    "repository": MODULE.CONSUMER_REPOSITORY,
                    "pullRequest": 503,
                    "actor": MODULE.RELEASE_AUTOMATION_ACTOR,
                    "commitSha": "8" * 40,
                },
                {
                    "purpose": "main-promotion",
                    "repository": MODULE.CONSUMER_REPOSITORY,
                    "pullRequest": 504,
                    "actor": MODULE.RELEASE_AUTOMATION_ACTOR,
                    "commitSha": "3" * 40,
                },
            ],
            "currentHeadReviewGate": {
                "id": 765432,
                "name": "Successful Copilot review",
                "headSha": "2" * 40,
                "status": "completed",
                "conclusion": "success",
                "appId": MODULE.GITHUB_ACTIONS_APP_ID,
                "workflowRunId": 765431,
                "workflowRunAttempt": 1,
                "workflowName": MODULE.COPILOT_REVIEW_WORKFLOW_NAME,
                "workflowPath": MODULE.COPILOT_REVIEW_WORKFLOW,
                "workflowContentDigest": f"sha256:{'6' * 64}",
                "workflowEvent": "pull_request",
                "workflowActor": MODULE.RELEASE_AUTOMATION_ACTOR,
                "workflowTriggeringActor": MODULE.RELEASE_AUTOMATION_ACTOR,
                "pullRequest": 503,
                "baseRef": "main",
                "baseSha": "7" * 40,
                "headRef": "security-release/LIT-SEC-MLX90-2026-001",
                "headRepository": MODULE.CONSUMER_REPOSITORY,
            },
            "workflowApprovalHistory": [
                {
                    "repository": MODULE.PRODUCER_REPOSITORY,
                    "runId": 111111,
                    "reviews": [],
                },
                {
                    "repository": MODULE.CONSUMER_REPOSITORY,
                    "runId": 765431,
                    "reviews": [],
                },
                {
                    "repository": MODULE.CONSUMER_REPOSITORY,
                    "runId": 222222,
                    "reviews": [],
                },
                {
                    "repository": MODULE.FINALIZER_REPOSITORY,
                    "runId": 123456,
                    "reviews": [],
                },
            ],
        },
        "finalizer": {
            "repository": MODULE.FINALIZER_REPOSITORY,
            "workflow": MODULE.FINALIZER_WORKFLOW,
            "workflowSha": "6" * 40,
            "runId": 123456,
            "runAttempt": 1,
            "runUrl": (
                "https://github.com/lightning-it/"
                "modulix-validation/actions/runs/123456"
            ),
        },
    }


class DeliveryTests(unittest.TestCase):
    def test_complete_immutable_chain_is_delivered(self):
        MODULE.validate(delivered_fixture())

    def test_acceptance_timestamp_uses_strict_rfc3339_profile(self):
        valid = (
            "0001-01-01T00:00:00-23:59",
            "2026-08-02T12:00:00Z",
            "2026-08-02T12:00:00.1Z",
            "2028-02-29T23:59:59.123456+14:00",
        )
        for value in valid:
            with self.subTest(valid=value):
                document = delivered_fixture()
                document["acceptance"]["acceptedAt"] = value
                MODULE.validate(document)

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
                    parsed = MODULE.timestamp(
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
                document = delivered_fixture()
                document["acceptance"]["acceptedAt"] = value
                with self.assertRaisesRegex(ValueError, "RFC3339 timestamp"):
                    MODULE.validate(document)

        with mock.patch.object(MODULE, "rfc3339_parser_value") as normalizer:
            with self.assertRaisesRegex(ValueError, "RFC3339 timestamp"):
                MODULE.timestamp(
                    "2026-08-02T12:00:00z", "test timestamp"
                )
            normalizer.assert_not_called()

    def test_producer_and_container_versions_use_strict_semver(self):
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

        document = delivered_fixture()
        producer_version = "3.2.0-rc.1+001"
        producer_tag = f"v{producer_version}"
        document["producer"]["version"] = producer_version
        document["producer"]["releaseUrl"] = (
            f"https://github.com/{MODULE.PRODUCER_REPOSITORY}/"
            f"releases/tag/{producer_tag}"
        )
        document["producer"]["evidence"]["url"] = (
            f"https://github.com/{MODULE.PRODUCER_REPOSITORY}/"
            f"releases/download/{producer_tag}/security-release-evidence.json"
        )
        document["acceptance"]["expectedVersion"] = producer_version
        for name in ("public", "certified"):
            document["container"]["variants"][name][
                "installedCollectionVersion"
            ] = producer_version

        container_tag = "v1.25.0-rc.1+001"
        document["container"]["releaseTag"] = container_tag
        document["container"]["releaseUrl"] = (
            f"https://github.com/{MODULE.CONSUMER_REPOSITORY}/"
            f"releases/tag/{container_tag}"
        )
        document["container"]["evidence"]["url"] = (
            f"https://github.com/{MODULE.CONSUMER_REPOSITORY}/"
            f"releases/download/{container_tag}/mlx90-container-evidence.json"
        )
        for value in document["container"]["variants"].values():
            for field in ("signature", "sbom", "provenance"):
                asset = value[field]["url"].rsplit("/", 1)[-1]
                value[field]["url"] = (
                    f"https://github.com/{MODULE.CONSUMER_REPOSITORY}/"
                    f"releases/download/{container_tag}/{asset}"
                )
        MODULE.validate(document)

        invalid_producer = delivered_fixture()
        invalid_producer["producer"]["version"] = "3.2.0-01"
        with self.assertRaisesRegex(ValueError, "producer.version is invalid"):
            MODULE.validate(invalid_producer)

        invalid_container = delivered_fixture()
        invalid_container["container"]["releaseTag"] = "v1.0.0-01"
        with self.assertRaisesRegex(
            ValueError, "container.releaseTag must be v-prefixed semantic version"
        ):
            MODULE.validate(invalid_container)

        overlong_producer = delivered_fixture()
        overlong_producer["producer"]["version"] = over_limit
        with self.assertRaisesRegex(ValueError, "producer.version is invalid"):
            MODULE.validate(overlong_producer)

        overlong_container = delivered_fixture()
        overlong_container["container"]["releaseTag"] = f"v{over_limit}"
        with self.assertRaisesRegex(
            ValueError, "container.releaseTag must be v-prefixed semantic version"
        ):
            MODULE.validate(overlong_container)

    def test_profile_id_is_bounded_and_has_exactly_two_segments(self):
        existing = (
            "lit.supplementary/security-fix-2026-001",
            "lit.supplementary/mlx90-fixture",
        )
        for value in existing:
            with self.subTest(valid=value):
                self.assertTrue(MODULE.is_profile_id(value))
                document = delivered_fixture()
                document["acceptance"]["profile"] = value
                MODULE.validate(document)

        at_limit = "a/" + "b" * (MODULE.PROFILE_ID_MAX_LENGTH - 2)
        over_limit = f"{at_limit}b"
        self.assertEqual(MODULE.PROFILE_ID_MAX_LENGTH, len(at_limit))
        self.assertEqual(MODULE.PROFILE_ID_MAX_LENGTH + 1, len(over_limit))
        self.assertTrue(MODULE.is_profile_id(at_limit))
        self.assertFalse(MODULE.is_profile_id(over_limit))
        self.assertIsNone(MODULE.PROFILE.fullmatch(over_limit))
        with mock.patch.object(MODULE, "PROFILE") as grammar:
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
        for value in invalid:
            with self.subTest(invalid=value):
                self.assertFalse(MODULE.is_profile_id(value))
                document = delivered_fixture()
                document["acceptance"]["profile"] = value
                with self.assertRaisesRegex(
                    ValueError, "acceptance.profile is invalid"
                ):
                    MODULE.validate(document)

    def test_every_variant_and_platform_is_required(self):
        missing_variant = delivered_fixture()
        del missing_variant["container"]["variants"]["bootstrap"]
        with self.assertRaisesRegex(ValueError, "missing: bootstrap"):
            MODULE.validate(missing_variant)

        missing_platform = delivered_fixture()
        del missing_platform["container"]["variants"]["public"][
            "platformDigests"
        ]["linux/arm64"]
        with self.assertRaisesRegex(ValueError, "missing: linux/arm64"):
            MODULE.validate(missing_platform)

    def test_mutable_pull_or_failed_check_cannot_deliver(self):
        mutable_pull = delivered_fixture()
        mutable_pull["container"]["variants"]["public"][
            "pulledImage"
        ] = "quay.io/lightning-it/ee-wunder:latest"
        with self.assertRaisesRegex(ValueError, "not bound"):
            MODULE.validate(mutable_pull)

        failed_check = delivered_fixture()
        failed_check["checks"]["provenance"] = False
        with self.assertRaisesRegex(ValueError, "must be true"):
            MODULE.validate(failed_check)

        bootstrap_with_collection = delivered_fixture()
        bootstrap = bootstrap_with_collection["container"]["variants"][
            "bootstrap"
        ]
        bootstrap["collectionPresent"] = True
        bootstrap["installedCollectionVersion"] = "3.2.0"
        with self.assertRaisesRegex(ValueError, "bootstrap must prove"):
            MODULE.validate(bootstrap_with_collection)

    def test_identity_and_release_links_are_exactly_bound(self):
        wrong_repository = delivered_fixture()
        wrong_repository["producer"]["repository"] = "attacker/repository"
        with self.assertRaisesRegex(ValueError, "trusted MLX-90 producer"):
            MODULE.validate(wrong_repository)

        wrong_release = delivered_fixture()
        wrong_release["container"]["releaseUrl"] = (
            "https://github.com/lightning-it/"
            "container-ee-wunder-ansible-ubi9/releases/tag/v1.24.0"
        )
        with self.assertRaisesRegex(ValueError, "not bound to the release tag"):
            MODULE.validate(wrong_release)

        wrong_run = delivered_fixture()
        wrong_run["finalizer"]["runUrl"] = (
            "https://github.com/lightning-it/"
            "modulix-validation/actions/runs/654321"
        )
        with self.assertRaisesRegex(ValueError, "does not match"):
            MODULE.validate(wrong_run)

    def test_zero_touch_events_are_bound_to_the_accepted_chain(self):
        mutations = (
            ("consumer PR", 0, "pullRequest", 999, "consumer identity"),
            (
                "consumer merge",
                0,
                "commitSha",
                "4" * 40,
                "consumer identity",
            ),
            (
                "consumer purpose",
                0,
                "purpose",
                "main-promotion",
                "consumer identity",
            ),
            (
                "promotion source",
                1,
                "commitSha",
                "5" * 40,
                "consumer identity",
            ),
            (
                "promotion PR",
                1,
                "pullRequest",
                999,
                "consumer identity",
            ),
            (
                "promotion purpose",
                1,
                "purpose",
                "consumer-change",
                "consumer identity",
            ),
        )
        for label, position, field, value, message in mutations:
            with self.subTest(label=label):
                document = delivered_fixture()
                document["zeroTouch"]["mergeEvents"][position][field] = value
                with self.assertRaisesRegex(ValueError, message):
                    MODULE.validate(document)

        wrong_review_head = delivered_fixture()
        wrong_review_head["zeroTouch"]["currentHeadReviewGate"]["headSha"] = (
            "6" * 40
        )
        with self.assertRaisesRegex(ValueError, "bound to consumer head"):
            MODULE.validate(wrong_review_head)

        for field, value in (
            ("workflowName", "Spoofed review gate"),
            ("workflowPath", ".github/workflows/spoof.yml"),
            ("workflowEvent", "workflow_dispatch"),
            ("workflowActor", "attacker[bot]"),
            ("workflowTriggeringActor", "attacker[bot]"),
            ("pullRequest", 999),
            ("baseRef", "develop"),
            ("baseSha", "6" * 40),
            ("headRepository", "attacker/repository"),
        ):
            with self.subTest(review_field=field):
                spoofed_review = delivered_fixture()
                spoofed_review["zeroTouch"]["currentHeadReviewGate"][field] = (
                    value
                )
                with self.assertRaisesRegex(ValueError, "review gate is invalid"):
                    MODULE.validate(spoofed_review)

        malformed_workflow_digest = delivered_fixture()
        malformed_workflow_digest["zeroTouch"]["currentHeadReviewGate"][
            "workflowContentDigest"
        ] = "sha256:spoofed"
        with self.assertRaisesRegex(ValueError, "immutable sha256 digest"):
            MODULE.validate(malformed_workflow_digest)

        human_review_gate = delivered_fixture()
        human_review_gate["zeroTouch"]["workflowApprovalHistory"][1][
            "reviews"
        ].append({"reviewer": "human"})
        with self.assertRaisesRegex(ValueError, "human approval"):
            MODULE.validate(human_review_gate)

        foreign_review_run = delivered_fixture()
        foreign_review_run["zeroTouch"]["workflowApprovalHistory"][1][
            "runId"
        ] = 765499
        with self.assertRaisesRegex(ValueError, "not evidence-bound"):
            MODULE.validate(foreign_review_run)

        float_zero = delivered_fixture()
        float_zero["zeroTouch"]["humanActions"]["count"] = 0.0
        with self.assertRaisesRegex(ValueError, "zero scoped approvals"):
            MODULE.validate(float_zero)

        for position, label, foreign_id in (
            (0, "producer", 111112),
            (2, "container", 222223),
        ):
            foreign_run = delivered_fixture()
            foreign_run["zeroTouch"]["workflowApprovalHistory"][position][
                "runId"
            ] = foreign_id
            with self.assertRaisesRegex(
                ValueError, f"{label}.*not evidence-bound"
            ):
                MODULE.validate(foreign_run)

    def test_ascii_controls_fail_before_trusted_url_parsing(self):
        controls = tuple(chr(value) for value in range(0x20)) + ("\x7f",)
        for control in controls:
            with self.subTest(control=ord(control)):
                with self.assertRaisesRegex(ValueError, "ASCII control"):
                    MODULE.string(
                        f"security{control}identifier", "security string"
                    )

                release = delivered_fixture()
                release["producer"]["releaseUrl"] = release["producer"][
                    "releaseUrl"
                ].replace("/releases/", f"/{control}releases/")
                with self.assertRaisesRegex(ValueError, "ASCII control"):
                    MODULE.validate(release)

                asset = delivered_fixture()
                signature = asset["container"]["variants"]["public"][
                    "signature"
                ]
                signature["url"] = signature["url"].replace(
                    "public-signature", f"public{control}-signature"
                )
                with self.assertRaisesRegex(ValueError, "ASCII control"):
                    MODULE.validate(asset)

        marker = "SENSITIVE-CONTROL-VALUE"
        with self.assertRaisesRegex(ValueError, "ASCII control") as caught:
            MODULE.string(f"{marker}\tvalue", "security string")
        self.assertNotIn(marker, str(caught.exception))

    def test_malformed_urls_fail_without_parser_value_leakage(self):
        parser_marker = "SENSITIVE-PARSER-ERROR-MARKER"
        with mock.patch.object(
            MODULE,
            "urlsplit",
            side_effect=ValueError(parser_marker),
        ) as parser:
            with self.assertRaisesRegex(
                ValueError, "producer.releaseUrl must use HTTPS"
            ) as caught:
                MODULE.https_url(
                    "https://example.com/release", "producer.releaseUrl"
                )
        parser.assert_called_once_with("https://example.com/release")
        self.assertNotIn(parser_marker, str(caught.exception))

        cli_marker = "SENSITIVE-CLI-URL-MARKER"
        malformed = f"https://[{cli_marker}/release"
        document = delivered_fixture()
        document["producer"]["releaseUrl"] = malformed
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "malformed-url.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/validate-mlx90-delivery.py"),
                    str(path),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("producer.releaseUrl must use HTTPS", completed.stderr)
        self.assertNotIn(cli_marker, completed.stderr)
        self.assertNotIn(malformed, completed.stderr)

    def test_cli_and_nested_json_reject_duplicate_keys_without_values(self):
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
                with self.assertRaisesRegex(
                    MODULE.DuplicateJsonKeyError,
                    "duplicate JSON object keys",
                ) as caught:
                    MODULE.strict_json_loads(raw)
                message = str(caught.exception)
                self.assertNotIn("SENSITIVE-", message)
                self.assertNotIn('"key"', message)

        with self.assertRaisesRegex(
            MODULE.NonStandardJsonConstantError,
            "non-standard JSON numeric constant",
        ) as caught:
            MODULE.strict_json_loads('{"digest":NaN}')
        self.assertNotIn("NaN", str(caught.exception))

        unsafe_json = {
            "control key": (
                '{"SENSITIVE-KEY\\u0009VALUE":"SENSITIVE-CONTENT"}',
                MODULE.JsonKeyControlError,
                "ASCII control characters in JSON object keys",
            ),
            "overflow": (
                '{"number":1e400}',
                MODULE.JsonNumberRangeError,
                "non-finite JSON number",
            ),
            "oversized integer": (
                '{"number":' + "9" * (MODULE.JSON_NUMBER_MAX_LENGTH + 1) + "}",
                MODULE.JsonNumberRangeError,
                "oversized JSON number",
            ),
            "nesting": (
                "[" * 2000 + "]" * 2000,
                MODULE.JsonNestingError,
                "JSON nesting depth",
            ),
        }
        for name, (raw, error, pattern) in unsafe_json.items():
            with self.subTest(unsafe=name):
                with self.assertRaisesRegex(error, pattern) as caught:
                    MODULE.strict_json_loads(raw)
                message = str(caught.exception)
                self.assertNotIn("SENSITIVE-", message)
                self.assertNotIn("1e400", message)

        unknown = delivered_fixture()
        unknown["SENSITIVE-UNKNOWN-KEY"] = "SENSITIVE-UNKNOWN-VALUE"
        with self.assertRaisesRegex(ValueError, "unknown fields") as caught:
            MODULE.validate(unknown)
        self.assertNotIn("SENSITIVE-", str(caught.exception))

        with tempfile.TemporaryDirectory() as temporary:
            result_path = Path(temporary) / "result.json"
            result_path.write_text(cases["status"], encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/validate-mlx90-delivery.py"),
                    str(result_path),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertIn(
                "contains duplicate JSON object keys", completed.stderr
            )
            self.assertNotIn("SENSITIVE-STATUS-A", completed.stderr)
            self.assertNotIn("SENSITIVE-STATUS-B", completed.stderr)

            bounded_path = Path(temporary) / "bounded.json"
            bounded_path.write_text('{"value":"SENSITIVE"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "input limit") as caught:
                MODULE.read_bounded_utf8(bounded_path, "document", 8)
            self.assertNotIn("SENSITIVE", str(caught.exception))

            invalid_utf8 = Path(temporary) / "invalid-utf8.json"
            invalid_utf8.write_bytes(b'\xffSENSITIVE')
            with self.assertRaisesRegex(ValueError, "valid UTF-8") as caught:
                MODULE.read_bounded_utf8(invalid_utf8, "document")
            self.assertNotIn("SENSITIVE", str(caught.exception))

            symlink = Path(temporary) / "symlink.json"
            symlink.symlink_to(result_path)
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                MODULE.read_bounded_utf8(symlink, "document")

    def test_unknown_fields_fail_closed(self):
        value = delivered_fixture()
        value["administratorOverride"] = True
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            MODULE.validate(value)

    def test_blocked_and_revoked_require_an_explicit_reason(self):
        for state in ("blocked", "revoked"):
            with self.subTest(state=state):
                MODULE.validate(
                    {
                        "apiVersion": "lit.security-release.acceptance/v1",
                        "kind": "SecurityReleaseAcceptance",
                        "status": state,
                        "reason": "authoritative security profile unavailable",
                    }
                )
                missing_reason = {
                    "apiVersion": "lit.security-release.acceptance/v1",
                    "kind": "SecurityReleaseAcceptance",
                    "status": state,
                }
                with self.assertRaisesRegex(ValueError, "missing: reason"):
                    MODULE.validate(missing_reason)

        for status in (["SENSITIVE-ARRAY"], {"SENSITIVE-OBJECT": "VALUE"}):
            with self.subTest(unhashable=type(status).__name__):
                document = {
                    "apiVersion": "lit.security-release.acceptance/v1",
                    "kind": "SecurityReleaseAcceptance",
                    "status": status,
                    "reason": "authoritative security profile unavailable",
                }
                with self.assertRaisesRegex(
                    ValueError, "status must be a non-empty"
                ) as caught:
                    MODULE.validate(document)
                self.assertNotIsInstance(caught.exception, TypeError)
                self.assertNotIn("SENSITIVE", str(caught.exception))

    def test_fixture_helpers_do_not_share_mutable_state(self):
        first = delivered_fixture()
        second = delivered_fixture()
        self.assertIsNot(first["checks"], second["checks"])
        second["checks"]["signature"] = False
        self.assertIs(first["checks"]["signature"], True)


if __name__ == "__main__":
    unittest.main()
