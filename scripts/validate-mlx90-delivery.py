#!/usr/bin/env python3
"""Validate the immutable MLX-90 final-acceptance result.

The canonical producer and delivery evidence contract remains owned by
``lightning-it/shared-assets-lit``.  This repository-specific guard requires
the additional public/certified/bootstrap verification matrix before a result
may claim ``delivered``.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit


SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ASCII_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
DELIVERY_JSON_MAX_BYTES = 10 * 1024 * 1024
JSON_MAX_NESTING = 128
JSON_NUMBER_MAX_LENGTH = 4300
SEMVER_MAX_LENGTH = 255
# SemVer 2.0.0: numeric core and prerelease identifiers are canonical, while
# build identifiers may be numeric with leading zeroes.  The explicit ASCII
# ranges deliberately reject Unicode digits and letters.  The lookahead also
# bounds direct pattern use before the potentially backtracking grammar.
SEMVER = re.compile(
    rf"\A(?=[\x00-\x7f]{{1,{SEMVER_MAX_LENGTH}}}\Z)"
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
SECURITY_ID = re.compile(r"^[A-Z0-9][A-Z0-9._-]{2,127}$")
PROFILE_ID_MIN_LENGTH = 4
PROFILE_ID_MAX_LENGTH = 255
PROFILE = re.compile(
    rf"\A(?=[\x00-\x7f]{{{PROFILE_ID_MIN_LENGTH},{PROFILE_ID_MAX_LENGTH}}}\Z)"
    r"[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]+\Z"
)
IMAGE = re.compile(
    r"^quay\.io/[a-z0-9]+(?:[._-][a-z0-9]+)*/"
    r"[a-z0-9]+(?:[._/-][a-z0-9]+)*$"
)
SAFE_ASSET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
# RFC3339 profile for evidence: uppercase T/Z, mandatory seconds and timezone,
# optional fractional seconds limited to Python's exact microsecond precision.
# Leap seconds are rejected rather than normalized or truncated.
RFC3339_TIMESTAMP = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$"
)

PRODUCER_REPOSITORY = "lightning-it/ansible-collection-supplementary"
CONSUMER_REPOSITORY = "lightning-it/container-ee-wunder-ansible-ubi9"
FINALIZER_REPOSITORY = "lightning-it/modulix-validation"
FINALIZER_WORKFLOW = ".github/workflows/mlx90-final-acceptance.yml"

VARIANTS = ("public", "certified", "bootstrap")
PLATFORMS = ("linux/amd64", "linux/arm64")
REQUIRED_CHECKS = {
    "producerEvidence",
    "producerSignature",
    "consumerIdentity",
    "containerRelease",
    "manifestDigests",
    "platformDigests",
    "pulledByDigest",
    "collectionVersion",
    "bootstrapCollectionAbsent",
    "securityAcceptance",
    "signature",
    "sbom",
    "provenance",
    "buildkitAttestations",
    "notRevoked",
}


def fail(message: str) -> None:
    raise ValueError(message)


class StrictJsonError(ValueError):
    """Base class for safe errors from the strict JSON decoder."""


class DuplicateJsonKeyError(StrictJsonError):
    """Raised without echoing a duplicate key or either untrusted value."""


class JsonKeyControlError(StrictJsonError):
    """Raised without echoing an untrusted JSON object key."""


class NonStandardJsonConstantError(StrictJsonError):
    """Raised without echoing an untrusted non-RFC JSON token."""


class JsonNumberRangeError(StrictJsonError):
    """Raised without echoing an oversized or non-finite JSON number."""


class JsonNestingError(StrictJsonError):
    """Raised without echoing an excessively nested JSON value."""


def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if ASCII_CONTROL.search(key) is not None:
            raise JsonKeyControlError(
                "contains ASCII control characters in JSON object keys"
            )
        if key in value:
            raise DuplicateJsonKeyError("contains duplicate JSON object keys")
        value[key] = item
    return value


def reject_nonstandard_json_constant(_: str) -> Any:
    raise NonStandardJsonConstantError(
        "contains a non-standard JSON numeric constant"
    )


def bounded_json_integer(value: str) -> int:
    if len(value.removeprefix("-")) > JSON_NUMBER_MAX_LENGTH:
        raise JsonNumberRangeError("contains an oversized JSON number")
    return int(value)


def finite_json_float(value: str) -> float:
    if len(value) > JSON_NUMBER_MAX_LENGTH:
        raise JsonNumberRangeError("contains an oversized JSON number")
    parsed = float(value)
    if not math.isfinite(parsed):
        raise JsonNumberRangeError("contains a non-finite JSON number")
    return parsed


def require_bounded_json_nesting(value: Any) -> Any:
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > JSON_MAX_NESTING:
            raise JsonNestingError("exceeds the supported JSON nesting depth")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


def strict_json_loads(value: str) -> Any:
    try:
        return require_bounded_json_nesting(
            json.loads(
                value,
                object_pairs_hook=reject_duplicate_json_keys,
                parse_constant=reject_nonstandard_json_constant,
                parse_float=finite_json_float,
                parse_int=bounded_json_integer,
            )
        )
    except RecursionError as exc:
        raise JsonNestingError("exceeds the supported JSON nesting depth") from exc


def read_bounded_utf8(
    path: Path,
    field: str,
    maximum_bytes: int = DELIVERY_JSON_MAX_BYTES,
) -> str:
    if path.is_symlink():
        fail(f"{field} must be a regular non-symlink file")
    descriptor: int | None = None
    try:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(path, flags)
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            fail(f"{field} must be a regular non-symlink file")
        if status.st_size > maximum_bytes:
            fail(f"{field} exceeds the {maximum_bytes}-byte input limit")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            payload = stream.read(maximum_bytes + 1)
    except OSError as exc:
        raise ValueError(f"{field} is not a readable regular file") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(payload) > maximum_bytes:
        fail(f"{field} exceeds the {maximum_bytes}-byte input limit")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{field} is not valid UTF-8") from exc


def is_semver(value: Any) -> bool:
    """Return whether value is bounded ASCII SemVer 2.0.0."""
    if not isinstance(value, str) or not 1 <= len(value) <= SEMVER_MAX_LENGTH:
        return False
    if not value.isascii():
        return False
    return SEMVER.fullmatch(value) is not None


def is_profile_id(value: Any) -> bool:
    """Return whether value is a bounded two-segment ASCII profile ID."""
    if (
        not isinstance(value, str)
        or not PROFILE_ID_MIN_LENGTH <= len(value) <= PROFILE_ID_MAX_LENGTH
    ):
        return False
    if not value.isascii():
        return False
    return PROFILE.fullmatch(value) is not None


def mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{field} must be an object")
    return value


def exact_fields(
    value: dict[str, Any], required: set[str], field: str
) -> None:
    missing = required - value.keys()
    unknown = value.keys() - required
    if missing:
        fail(f"{field} missing: {', '.join(sorted(missing))}")
    if unknown:
        fail(f"{field} has unknown fields")


def string(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or ASCII_CONTROL.search(value) is not None
    ):
        fail(
            f"{field} must be a non-empty single-line string without "
            "ASCII control characters"
        )
    return value


def full_sha(value: Any, field: str) -> str:
    value = string(value, field)
    if SHA.fullmatch(value) is None:
        fail(f"{field} must be a full lowercase commit SHA")
    return value


def digest(value: Any, field: str) -> str:
    value = string(value, field)
    if DIGEST.fullmatch(value) is None:
        fail(f"{field} must be an immutable sha256 digest")
    return value


def positive_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        fail(f"{field} must be a positive integer")
    return value


def https_url(value: Any, field: str) -> str:
    value = string(value, field)
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        fail(f"{field} must use HTTPS without user information")
    return value


def rfc3339_parser_value(value: str) -> str:
    """Normalize a grammar-validated RFC3339 value for Python 3.9."""
    parser_value = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    local_time, timezone = parser_value[:-6], parser_value[-6:]
    if "." not in local_time:
        return parser_value
    seconds, fraction = local_time.rsplit(".", 1)
    return f"{seconds}.{fraction.ljust(6, '0')}{timezone}"


def timestamp(value: Any, field: str) -> datetime:
    value = string(value, field)
    requirement = (
        f"{field} must be an RFC3339 timestamp with T, seconds, timezone, "
        "and 1-6 fractional digits when a fraction is present"
    )
    if RFC3339_TIMESTAMP.fullmatch(value) is None:
        fail(requirement)
    try:
        parsed = datetime.fromisoformat(rfc3339_parser_value(value))
    except ValueError as exc:
        raise ValueError(requirement) from exc
    if parsed.tzinfo is None:
        fail(requirement)
    return parsed


def immutable_reference(value: Any, field: str) -> dict[str, Any]:
    value = mapping(value, field)
    exact_fields(value, {"url", "digest"}, field)
    https_url(value["url"], f"{field}.url")
    digest(value["digest"], f"{field}.digest")
    return value


def release_asset_reference(
    value: dict[str, Any],
    repository: str,
    tag: str,
    field: str,
    *,
    expected_name: str | None = None,
) -> None:
    url = immutable_reference(value, field)["url"]
    parsed = urlsplit(url)
    parts = unquote(parsed.path).split("/")
    if (
        parsed.netloc != "github.com"
        or parsed.query
        or parsed.fragment
        or len(parts) != 7
        or parts[1:5] != [*repository.split("/"), "releases", "download"]
        or parts[5] != tag
        or SAFE_ASSET.fullmatch(parts[6]) is None
        or (expected_name is not None and parts[6] != expected_name)
    ):
        fail(f"{field}.url is not an immutable {repository} {tag} asset")


def trusted_release_url(
    value: Any, repository: str, tag: str, field: str
) -> None:
    url = https_url(value, field)
    parsed = urlsplit(url)
    parts = unquote(parsed.path).split("/")
    prefix = [*repository.split("/"), "releases"]
    tag_page = len(parts) == 6 and parts[1:4] == prefix and parts[4:] == ["tag", tag]
    download = (
        len(parts) == 7
        and parts[1:4] == prefix
        and parts[4] == "download"
        and parts[5] == tag
        and SAFE_ASSET.fullmatch(parts[6]) is not None
    )
    if (
        parsed.netloc != "github.com"
        or parsed.query
        or parsed.fragment
        or not (tag_page or download)
    ):
        fail(f"{field} is not bound to {repository} {tag}")


def validate_terminal(result: dict[str, Any]) -> None:
    exact_fields(result, {"apiVersion", "kind", "status", "reason"}, "result")
    status = string(result["status"], "status")
    if status not in {"blocked", "revoked"}:
        fail("terminal non-delivery status must be blocked or revoked")
    string(result["reason"], "reason")


def validate_delivered(result: dict[str, Any]) -> None:
    exact_fields(
        result,
        {
            "apiVersion",
            "kind",
            "status",
            "securityEvidenceId",
            "producer",
            "consumer",
            "container",
            "acceptance",
            "receiptBundle",
            "checks",
            "finalizer",
        },
        "result",
    )
    evidence_id = string(result["securityEvidenceId"], "securityEvidenceId")
    if SECURITY_ID.fullmatch(evidence_id) is None:
        fail("securityEvidenceId is invalid")

    producer = mapping(result["producer"], "producer")
    exact_fields(
        producer,
        {
            "repository",
            "sourceSha",
            "collection",
            "version",
            "collectionDigest",
            "releaseUrl",
            "evidence",
        },
        "producer",
    )
    repository = string(producer["repository"], "producer.repository")
    if repository != PRODUCER_REPOSITORY:
        fail("producer.repository is not the trusted MLX-90 producer")
    full_sha(producer["sourceSha"], "producer.sourceSha")
    collection = string(producer["collection"], "producer.collection")
    if re.fullmatch(r"[a-z0-9_]+\.[a-z0-9_]+", collection) is None:
        fail("producer.collection is invalid")
    version = string(producer["version"], "producer.version")
    if not is_semver(version):
        fail("producer.version is invalid")
    digest(producer["collectionDigest"], "producer.collectionDigest")
    producer_tag = f"v{version}"
    trusted_release_url(
        producer["releaseUrl"],
        PRODUCER_REPOSITORY,
        producer_tag,
        "producer.releaseUrl",
    )
    release_asset_reference(
        producer["evidence"],
        PRODUCER_REPOSITORY,
        producer_tag,
        "producer.evidence",
        expected_name="security-release-evidence.json",
    )

    consumer = mapping(result["consumer"], "consumer")
    exact_fields(
        consumer,
        {"repository", "pullRequest", "baseSha", "headSha", "mergeSha"},
        "consumer",
    )
    consumer_repository = string(
        consumer["repository"], "consumer.repository"
    )
    if consumer_repository != CONSUMER_REPOSITORY:
        fail("consumer.repository is not the trusted MLX-90 consumer")
    positive_integer(consumer["pullRequest"], "consumer.pullRequest")
    full_sha(consumer["baseSha"], "consumer.baseSha")
    full_sha(consumer["headSha"], "consumer.headSha")
    consumer_merge_sha = full_sha(consumer["mergeSha"], "consumer.mergeSha")

    container = mapping(result["container"], "container")
    exact_fields(
        container,
        {
            "repository",
            "releaseId",
            "releaseTag",
            "releaseUrl",
            "sourceSha",
            "evidence",
            "variants",
        },
        "container",
    )
    container_repository = string(
        container["repository"], "container.repository"
    )
    if container_repository != CONSUMER_REPOSITORY:
        fail("container.repository is not the trusted MLX-90 container")
    if container_repository != consumer_repository:
        fail("container repository must equal the consumer repository")
    positive_integer(container["releaseId"], "container.releaseId")
    release_tag = string(container["releaseTag"], "container.releaseTag")
    if not release_tag.startswith("v") or not is_semver(release_tag[1:]):
        fail("container.releaseTag must be v-prefixed semantic version")
    container_release_url = https_url(
        container["releaseUrl"], "container.releaseUrl"
    )
    expected_container_release_url = (
        f"https://github.com/{CONSUMER_REPOSITORY}/releases/tag/{release_tag}"
    )
    if container_release_url != expected_container_release_url:
        fail("container.releaseUrl is not bound to the release tag")
    if full_sha(container["sourceSha"], "container.sourceSha") != consumer_merge_sha:
        fail("container source SHA must equal the consumer merge SHA")
    release_asset_reference(
        container["evidence"],
        CONSUMER_REPOSITORY,
        release_tag,
        "container.evidence",
        expected_name="mlx90-container-evidence.json",
    )

    variants = mapping(container["variants"], "container.variants")
    exact_fields(variants, set(VARIANTS), "container.variants")
    images: set[str] = set()
    for name in VARIANTS:
        field = f"container.variants.{name}"
        variant = mapping(variants[name], field)
        exact_fields(
            variant,
            {
                "image",
                "manifestDigest",
                "platformDigests",
                "signature",
                "sbom",
                "provenance",
                "pulledImage",
                "collectionPresent",
                "installedCollectionVersion",
                "profileExecuted",
            },
            field,
        )
        image = string(variant["image"], f"{field}.image")
        if IMAGE.fullmatch(image) is None:
            fail(f"{field}.image must be an untagged Quay image name")
        if image in images:
            fail("container variant image names must be unique")
        images.add(image)
        manifest_digest = digest(
            variant["manifestDigest"], f"{field}.manifestDigest"
        )
        platforms = mapping(variant["platformDigests"], f"{field}.platformDigests")
        exact_fields(platforms, set(PLATFORMS), f"{field}.platformDigests")
        for platform in PLATFORMS:
            digest(platforms[platform], f"{field}.platformDigests.{platform}")
        for reference in ("signature", "sbom", "provenance"):
            release_asset_reference(
                variant[reference],
                CONSUMER_REPOSITORY,
                release_tag,
                f"{field}.{reference}",
            )
        pulled_image = string(variant["pulledImage"], f"{field}.pulledImage")
        if pulled_image != f"{image}@{manifest_digest}":
            fail(f"{field}.pulledImage is not bound to the manifest digest")
        if not isinstance(variant["collectionPresent"], bool):
            fail(f"{field}.collectionPresent must be boolean")
        if not isinstance(variant["profileExecuted"], bool):
            fail(f"{field}.profileExecuted must be boolean")
        if name == "bootstrap":
            if (
                variant["collectionPresent"] is not False
                or variant["installedCollectionVersion"] is not None
                or variant["profileExecuted"] is not False
            ):
                fail(
                    "bootstrap must prove collection absence and must not run "
                    "the collection acceptance profile"
                )
        elif (
            variant["collectionPresent"] is not True
            or variant["installedCollectionVersion"] != version
            or variant["profileExecuted"] is not True
        ):
            fail(f"{field} does not prove the required collection acceptance")
    public_image = variants["public"]["image"]
    if variants["certified"]["image"] != f"{public_image}-certified":
        fail("certified image name must derive from the public image")
    if variants["bootstrap"]["image"] != f"{public_image}-bootstrap":
        fail("bootstrap image name must derive from the public image")

    acceptance = mapping(result["acceptance"], "acceptance")
    exact_fields(
        acceptance,
        {"profile", "expectedCollection", "expectedVersion", "acceptedAt"},
        "acceptance",
    )
    profile = string(acceptance["profile"], "acceptance.profile")
    if not is_profile_id(profile):
        fail("acceptance.profile is invalid")
    if acceptance["expectedCollection"] != collection:
        fail("acceptance expected collection does not match producer")
    if acceptance["expectedVersion"] != version:
        fail("acceptance expected version does not match producer")
    timestamp(acceptance["acceptedAt"], "acceptance.acceptedAt")

    receipt_bundle = mapping(result["receiptBundle"], "receiptBundle")
    exact_fields(
        receipt_bundle,
        {"assetName", "digest", "size"},
        "receiptBundle",
    )
    if receipt_bundle["assetName"] != "mlx90-verification-receipts.json":
        fail("receiptBundle.assetName is invalid")
    digest(receipt_bundle["digest"], "receiptBundle.digest")
    positive_integer(receipt_bundle["size"], "receiptBundle.size")

    checks = mapping(result["checks"], "checks")
    exact_fields(checks, REQUIRED_CHECKS, "checks")
    if any(value is not True for value in checks.values()):
        fail("all final acceptance checks must be true")

    finalizer = mapping(result["finalizer"], "finalizer")
    exact_fields(
        finalizer,
        {
            "repository",
            "workflow",
            "workflowSha",
            "runId",
            "runAttempt",
            "runUrl",
        },
        "finalizer",
    )
    if finalizer["repository"] != FINALIZER_REPOSITORY:
        fail("finalizer repository is invalid")
    if finalizer["workflow"] != FINALIZER_WORKFLOW:
        fail("finalizer workflow is invalid")
    full_sha(finalizer["workflowSha"], "finalizer.workflowSha")
    run_id = positive_integer(finalizer["runId"], "finalizer.runId")
    positive_integer(finalizer["runAttempt"], "finalizer.runAttempt")
    run_url = https_url(finalizer["runUrl"], "finalizer.runUrl")
    expected_url = (
        f"https://github.com/{FINALIZER_REPOSITORY}/actions/runs/{run_id}"
    )
    if run_url != expected_url:
        fail("finalizer.runUrl does not match finalizer.runId")


def validate(result: Any) -> None:
    result = mapping(result, "result")
    if result.get("apiVersion") != "lit.security-release.acceptance/v1":
        fail("unsupported acceptance version")
    if result.get("kind") != "SecurityReleaseAcceptance":
        fail("unsupported acceptance kind")
    status = result.get("status")
    if status == "delivered":
        validate_delivered(result)
        return
    validate_terminal(result)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("result", type=Path)
    args = parser.parse_args()
    try:
        payload = strict_json_loads(read_bounded_utf8(args.result, "result"))
        validate(payload)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))
    print(payload["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
