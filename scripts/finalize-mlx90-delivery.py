#!/usr/bin/env python3
"""Build MLX-90 final evidence only from independently verified observations.

This program performs no network access and executes no acceptance command.  A
protected workflow must first verify signatures, live GitHub identities, OCI
indices, immutable pulls, installed collection versions, attestations and the
fixed acceptance profile.  The resulting local verification report is then
bound to the signed producer and container evidence here.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import math
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
DELIVERY_VALIDATOR = ROOT / "scripts" / "validate-mlx90-delivery.py"
PRODUCER_REPOSITORY = "lightning-it/ansible-collection-supplementary"
PRODUCER_WORKFLOW = ".github/workflows/collection-ci.yml"
PRODUCER_WORKFLOW_NAME = "Collection CI"
PRODUCER_VALIDATION_JOB = "Collection / Release Validation"
CONSUMER_REPOSITORY = "lightning-it/container-ee-wunder-ansible-ubi9"
COPILOT_REVIEW_WORKFLOW = ".github/workflows/copilot-review.yml"
COPILOT_REVIEW_WORKFLOW_NAME = "Copilot review gate"
COPILOT_REVIEW_JOB_NAME = "Successful Copilot review"
HUMAN_ACTION_SCOPE = "environment-approval-reviews-on-evidence-bound-runs"
FINALIZER_REPOSITORY = "lightning-it/modulix-validation"
FINALIZER_WORKFLOW = ".github/workflows/mlx90-final-acceptance.yml"
CONTAINER_WORKFLOW = ".github/workflows/container-build-publish.yml"
CONTAINER_WORKFLOW_NAME = "Container Build & Publish"
CONTAINER_WORKFLOW_JOB = "build"
CONTAINER_RELEASE_ACTOR = "lightning-it-release-automation[bot]"
RELEASE_AUTOMATION_APP_SLUG = "lightning-it-release-automation"
RELEASE_AUTOMATION_INSTALLATION_ID = 148019054
GITHUB_ACTIONS_APP_ID = 15368
BUILDKIT_BUILD_TYPE = (
    "https://github.com/moby/buildkit/blob/master/"
    "docs/attestations/slsa-definitions.md"
)
IN_TOTO_STATEMENT = "https://in-toto.io/Statement/v1"
SPDX_PREDICATE = "https://spdx.dev/Document"
SLSA_PREDICATE = "https://slsa.dev/provenance/v1"

SHA = re.compile(r"^[0-9a-f]{40}$")
RAW_DIGEST = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ASCII_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
FINALIZER_INPUT_MAX_BYTES = 64 * 1024 * 1024
RELEASE_ASSET_MAX_BYTES = 10 * 1024 * 1024
CONTAINER_SBOM_ASSET_MAX_BYTES = 64 * 1024 * 1024
COLLECTION_ARCHIVE_MAX_BYTES = RELEASE_ASSET_MAX_BYTES
CONTAINER_SBOM_ASSET_NAMES = frozenset(
    {
        "sbom.cdx.json",
        "sbom-bootstrap.cdx.json",
        "sbom-certified.cdx.json",
        "sbom-public.cdx.json",
    }
)
MATERIAL_FILE_ERROR = "material is not a bounded regular file"
CLI_CONTRACT_ERROR = "input does not satisfy the required contract"
CLI_IO_ERROR = "file operation failed"
CLI_ARGUMENT_ERROR = "command arguments do not satisfy the required contract"
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
SECURITY_IDENTIFIER = re.compile(
    r"^(?:CVE-[0-9]{4}-[0-9]{4,}"
    r"|GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2}"
    r"|LIT-SEC-[A-Z0-9._-]+)$"
)
PROFILE_ID_MIN_LENGTH = 4
PROFILE_ID_MAX_LENGTH = 255
PROFILE_ID = re.compile(
    rf"\A(?=[\x00-\x7f]{{{PROFILE_ID_MIN_LENGTH},{PROFILE_ID_MAX_LENGTH}}}\Z)"
    r"[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]+\Z"
)
CORRELATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
SAFE_ASSET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
IMAGE = re.compile(
    r"^quay\.io/[a-z0-9]+(?:[._-][a-z0-9]+)*/"
    r"[a-z0-9]+(?:[._/-][a-z0-9]+)*$"
)
# RFC3339 profile for evidence: uppercase T/Z, mandatory seconds and timezone,
# optional fractional seconds limited to Python's exact microsecond precision.
# Leap seconds are rejected rather than normalized or truncated.
RFC3339_TIMESTAMP = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$"
)
# BuildKit serializes its SLSA timestamps with Go's nanosecond precision.
# Keep that third-party contract separate from the microsecond-only profile for
# MLX-90-authored evidence so accepting BuildKit bytes cannot weaken it.
RFC3339_BUILDKIT_TIMESTAMP = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$"
)

VARIANTS = ("public", "certified", "bootstrap")
PLATFORMS = ("linux/amd64", "linux/arm64")
FINAL_CHECKS = {
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
    "zeroTouch",
}
RECEIPT_API_VERSION = "lit.security-release.verification-receipt/v1"
RECEIPT_BUNDLE_API_VERSION = (
    "lit.security-release.verification-receipt-bundle/v1"
)
GLOBAL_RECEIPT_TYPES = {
    "producer-evidence": "ProducerEvidence",
    "producer-identity": "ProducerIdentity",
    "producer-revocation-initial": "ProducerRevocation",
    "producer-cosign": "ProducerCosign",
    "producer-materials": "ProducerMaterials",
    "producer-central-ci": "ProducerCentralCI",
    "consumer-identity": "ConsumerIdentity",
    "container-release": "ContainerRelease",
    "container-revocation-initial": "ContainerRevocation",
    "container-cosign": "ContainerCosign",
    "zero-touch": "ZeroTouch",
    "final-revocation": "FinalRevocation",
}
VARIANT_RECEIPT_TYPES = {
    "oci-index": "OciIndex",
    "immutable-tags": "ImmutableTags",
    "cosign": "ImageCosign",
    "materials": "ContainerMaterials",
    "buildkit": "BuildKitAttestations",
    "pull": "PullByDigest",
    "installed": "InstalledCollection",
    "profile": "AcceptanceProfile",
}


def expected_receipt_types() -> dict[str, str]:
    expected = dict(GLOBAL_RECEIPT_TYPES)
    for variant in VARIANTS:
        for suffix, receipt_type in VARIANT_RECEIPT_TYPES.items():
            if suffix == "profile" and variant == "bootstrap":
                continue
            expected[f"{variant}-{suffix}"] = receipt_type
    return expected


EXPECTED_RECEIPT_TYPES = expected_receipt_types()
CHECK_RECEIPTS = {
    "producerEvidence": {
        "producer-evidence",
        "producer-identity",
        "producer-central-ci",
    },
    "producerSignature": {"producer-cosign", "producer-materials"},
    "consumerIdentity": {"consumer-identity"},
    "containerRelease": {"container-release", "container-cosign"},
    "manifestDigests": {f"{variant}-oci-index" for variant in VARIANTS},
    "platformDigests": {f"{variant}-oci-index" for variant in VARIANTS},
    "pulledByDigest": {f"{variant}-pull" for variant in VARIANTS},
    "collectionVersion": {
        "public-installed",
        "certified-installed",
    },
    "bootstrapCollectionAbsent": {"bootstrap-installed"},
    "securityAcceptance": {"public-profile", "certified-profile"},
    "signature": {
        "container-cosign",
        *(f"{variant}-cosign" for variant in VARIANTS),
        *(f"{variant}-materials" for variant in VARIANTS),
    },
    "sbom": {
        "producer-materials",
        *(f"{variant}-materials" for variant in VARIANTS),
    },
    "provenance": {
        "producer-materials",
        *(f"{variant}-materials" for variant in VARIANTS),
    },
    "buildkitAttestations": {
        *(f"{variant}-buildkit" for variant in VARIANTS),
    },
    "notRevoked": {"final-revocation"},
    "zeroTouch": {"zero-touch"},
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


class ValueFreeArgumentParser(argparse.ArgumentParser):
    sanitize_errors = True

    def error(self, message: str) -> None:
        if self.sanitize_errors:
            message = CLI_ARGUMENT_ERROR
        super().error(message)


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


def read_bounded_bytes(
    path: Path,
    field: str,
    maximum_bytes: int = FINALIZER_INPUT_MAX_BYTES,
) -> bytes:
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
    return payload


def decode_utf8(payload: bytes, field: str) -> str:
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{field} is not valid UTF-8") from exc


def read_bounded_utf8(
    path: Path,
    field: str,
    maximum_bytes: int = FINALIZER_INPUT_MAX_BYTES,
) -> str:
    return decode_utf8(read_bounded_bytes(path, field, maximum_bytes), field)


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
    return PROFILE_ID.fullmatch(value) is not None


def require_mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{field} must be an object")
    return value


def require_exact(
    value: dict[str, Any], required: set[str], field: str
) -> None:
    missing = required - value.keys()
    unknown = value.keys() - required
    if missing:
        fail(f"{field} missing: {', '.join(sorted(missing))}")
    if unknown:
        fail(f"{field} has unknown fields")


def require_string(value: Any, field: str) -> str:
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


def require_sha(value: Any, field: str) -> str:
    value = require_string(value, field)
    if SHA.fullmatch(value) is None:
        fail(f"{field} must be a full lowercase commit SHA")
    return value


def require_digest(value: Any, field: str) -> str:
    value = require_string(value, field)
    if DIGEST.fullmatch(value) is None:
        fail(f"{field} must be an immutable sha256 digest")
    return value


def require_positive(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        fail(f"{field} must be a positive integer")
    return value


def require_canonical_positive_string(value: Any, field: str) -> int:
    value = require_string(value, field)
    if re.fullmatch(r"[1-9][0-9]*", value) is None:
        fail(f"{field} must be a canonical positive integer string")
    return int(value)


def require_nonnegative(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        fail(f"{field} must be a non-negative integer")
    return value


def rfc3339_parser_value(value: str) -> str:
    """Normalize a grammar-validated RFC3339 value for Python 3.9."""
    parser_value = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    local_time, timezone = parser_value[:-6], parser_value[-6:]
    if "." not in local_time:
        return parser_value
    seconds, fraction = local_time.rsplit(".", 1)
    return f"{seconds}.{fraction.ljust(6, '0')}{timezone}"


def require_timestamp(value: Any, field: str) -> datetime:
    value = require_string(value, field)
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


def require_buildkit_timestamp(value: Any, field: str) -> tuple[datetime, int]:
    """Parse a BuildKit RFC3339 timestamp without losing nanosecond ordering."""
    value = require_string(value, field)
    requirement = (
        f"{field} must be an RFC3339 timestamp with T, seconds, timezone, "
        "and 1-9 fractional digits when a fraction is present"
    )
    if RFC3339_BUILDKIT_TIMESTAMP.fullmatch(value) is None:
        fail(requirement)
    parser_value = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    local_time, timezone = parser_value[:-6], parser_value[-6:]
    submicroseconds = 0
    if "." in local_time:
        seconds, fraction = local_time.rsplit(".", 1)
        parser_fraction = fraction[:6].ljust(6, "0")
        parser_value = f"{seconds}.{parser_fraction}{timezone}"
        if len(fraction) > 6:
            submicroseconds = int(fraction[6:].ljust(3, "0"))
    try:
        parsed = datetime.fromisoformat(parser_value)
    except ValueError as exc:
        raise ValueError(requirement) from exc
    if parsed.tzinfo is None:
        fail(requirement)
    return parsed, submicroseconds


def require_https(value: Any, field: str) -> str:
    value = require_string(value, field)
    requirement = f"{field} must be an HTTPS URL without user information"
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise ValueError(requirement) from None
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        fail(requirement)
    return value


def require_reference(value: Any, field: str) -> dict[str, Any]:
    value = require_mapping(value, field)
    require_exact(value, {"url", "digest"}, field)
    require_https(value["url"], f"{field}.url")
    require_digest(value["digest"], f"{field}.digest")
    return value


def parse_json(text: str, field: str) -> Any:
    try:
        return strict_json_loads(text)
    except StrictJsonError as exc:
        raise ValueError(f"{field} {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{field} is not valid JSON") from exc


def load_json(path: Path, field: str) -> Any:
    return parse_json(read_bounded_utf8(path, field), field)


@dataclass(frozen=True)
class SecureFileSnapshot:
    payload: bytes | None
    digest: str
    size: int


def secure_file_snapshot(
    path: Path,
    maximum_bytes: int = FINALIZER_INPUT_MAX_BYTES,
    *,
    capture_payload: bool = False,
) -> SecureFileSnapshot:
    digest = hashlib.sha256()
    payload = bytearray() if capture_payload else None
    descriptor: int | None = None
    try:
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        if not no_follow and stat.S_ISLNK(os.lstat(path).st_mode):
            fail(MATERIAL_FILE_ERROR)
        flags = (
            os.O_RDONLY
            | no_follow
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size > maximum_bytes
        ):
            fail(MATERIAL_FILE_ERROR)
        size = 0
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                size += len(chunk)
                if size > maximum_bytes:
                    fail(MATERIAL_FILE_ERROR)
                digest.update(chunk)
                if payload is not None:
                    payload.extend(chunk)
            after = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(after.st_mode)
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            or size != before.st_size
        ):
            fail(MATERIAL_FILE_ERROR)
    except OSError as exc:
        raise ValueError(MATERIAL_FILE_ERROR) from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as exc:
                raise ValueError(MATERIAL_FILE_ERROR) from exc
    return SecureFileSnapshot(
        None if payload is None else bytes(payload),
        "sha256:" + digest.hexdigest(),
        size,
    )


def file_digest_and_size(
    path: Path,
    maximum_bytes: int = FINALIZER_INPUT_MAX_BYTES,
) -> tuple[str, int]:
    snapshot = secure_file_snapshot(path, maximum_bytes)
    return snapshot.digest, snapshot.size


def file_digest(
    path: Path,
    maximum_bytes: int = FINALIZER_INPUT_MAX_BYTES,
) -> str:
    return file_digest_and_size(path, maximum_bytes)[0]


def parse_json_snapshot(snapshot: SecureFileSnapshot, field: str) -> Any:
    if snapshot.payload is None:  # pragma: no cover - internal contract.
        fail(MATERIAL_FILE_ERROR)
    return parse_json(decode_utf8(snapshot.payload, field), field)


def resolved_evidence_digest(path: Path, supplied: str | None) -> str:
    if supplied is None:
        return file_digest(path, RELEASE_ASSET_MAX_BYTES)
    return require_digest(supplied, "validated evidence digest")


def safe_output(path: Path) -> None:
    try:
        if path.exists() or path.is_symlink():
            fail("output already exists")
        current = path.parent
        while current != current.parent:
            if current.is_symlink():
                fail("output path contains a symlink")
            current = current.parent
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ValueError("output path cannot be prepared") from exc


def serialize_json(value: Any) -> str:
    return json.dumps(
        value, allow_nan=False, indent=2, sort_keys=True
    ) + "\n"


def prepare_json_output(
    path: Path, serialized: bytes
) -> tuple[Path, os.stat_result]:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        if temporary.exists() or temporary.is_symlink():
            fail("temporary output already exists")
        with temporary.open("xb") as stream:
            stream.write(serialized)
        return temporary, os.lstat(temporary)
    except FileExistsError:
        fail("temporary output already exists")
    except OSError as exc:
        raise ValueError("temporary output cannot be prepared") from exc


def unlink_owned(path: Path, owner: os.stat_result) -> None:
    try:
        observed = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ValueError("owned output cleanup failed") from exc
    try:
        if (observed.st_dev, observed.st_ino) == (owner.st_dev, owner.st_ino):
            path.unlink()
    except OSError as exc:
        raise ValueError("owned output cleanup failed") from exc


def write_json(path: Path, value: Any) -> tuple[str, int]:
    safe_output(path)
    serialized = serialize_json(value).encode("utf-8")
    temporary, owner = prepare_json_output(path, serialized)
    try:
        try:
            os.link(temporary, path)
        except FileExistsError:
            fail("output already exists")
        except OSError as exc:
            raise ValueError("output cannot be published") from exc
    finally:
        unlink_owned(temporary, owner)
    return "sha256:" + hashlib.sha256(serialized).hexdigest(), len(serialized)


def write_json_pair(
    first_path: Path,
    first_value: Any,
    second_path: Path,
    second_value: Any,
) -> None:
    try:
        same_output = first_path.resolve() == second_path.resolve()
    except OSError as exc:
        raise ValueError("output paths cannot be resolved") from exc
    if same_output:
        fail("delivered and acceptance outputs must be different files")
    safe_output(first_path)
    safe_output(second_path)
    first_serialized = serialize_json(first_value).encode("utf-8")
    second_serialized = serialize_json(second_value).encode("utf-8")
    first_temporary = second_temporary = None
    first_owner = second_owner = None
    try:
        first_temporary, first_owner = prepare_json_output(
            first_path, first_serialized
        )
        second_temporary, second_owner = prepare_json_output(
            second_path, second_serialized
        )
        try:
            os.link(first_temporary, first_path)
        except FileExistsError:
            fail("output already exists")
        except OSError as exc:
            raise ValueError("output cannot be published") from exc
        try:
            os.link(second_temporary, second_path)
        except FileExistsError:
            unlink_owned(first_path, first_owner)
            fail("output already exists")
        except OSError as exc:
            unlink_owned(first_path, first_owner)
            raise ValueError("output cannot be published") from exc
    finally:
        if first_temporary is not None and first_owner is not None:
            unlink_owned(first_temporary, first_owner)
        if second_temporary is not None and second_owner is not None:
            unlink_owned(second_temporary, second_owner)


@dataclass(frozen=True)
class DispatchIdentity:
    correlation_id: str
    producer_evidence_url: str
    producer_evidence_bundle_url: str
    producer_evidence_sha256: str
    consumer_pr: int
    consumer_head_sha: str
    consumer_merge_sha: str
    container_release_id: int
    container_release_tag: str
    container_release_run_id: int
    container_publish_run_attempt: int

    def validate(self) -> None:
        if CORRELATION_ID.fullmatch(self.correlation_id) is None:
            fail("correlation_id is invalid")
        validate_producer_asset_url(
            self.producer_evidence_url, "producer_evidence_url"
        )
        validate_producer_asset_url(
            self.producer_evidence_bundle_url,
            "producer_evidence_bundle_url",
            bundle=True,
        )
        if (
            self.producer_evidence_bundle_url
            != f"{self.producer_evidence_url}.sigstore.json"
        ):
            fail("producer evidence bundle URL must be derived from evidence URL")
        if RAW_DIGEST.fullmatch(self.producer_evidence_sha256) is None:
            fail("producer_evidence_sha256 must be 64 lowercase hex characters")
        require_positive(self.consumer_pr, "consumer_pr")
        require_sha(self.consumer_head_sha, "consumer_head_sha")
        require_sha(self.consumer_merge_sha, "consumer_merge_sha")
        require_positive(self.container_release_id, "container_release_id")
        if (
            not self.container_release_tag.startswith("v")
            or not is_semver(self.container_release_tag[1:])
        ):
            fail("container_release_tag must be v-prefixed semantic version")
        require_positive(self.container_release_run_id, "container_release_run_id")
        require_positive(
            self.container_publish_run_attempt,
            "container_publish_run_attempt",
        )


def validate_producer_asset_url(
    value: str, field: str, *, bundle: bool = False
) -> None:
    value = require_https(value, field)
    parsed = urlsplit(value)
    if parsed.netloc != "github.com" or parsed.query or parsed.fragment:
        fail(f"{field} must be a stable GitHub release URL")
    parts = unquote(parsed.path).split("/")
    if len(parts) != 7 or parts[1:5] != [
        "lightning-it",
        "ansible-collection-supplementary",
        "releases",
        "download",
    ]:
        fail(f"{field} must reference the trusted producer release")
    tag, asset = parts[5], parts[6]
    if not tag.startswith("v") or not is_semver(tag[1:]):
        fail(f"{field} release tag is invalid")
    expected_asset = (
        "security-release-evidence.json.sigstore.json"
        if bundle
        else "security-release-evidence.json"
    )
    if asset != expected_asset:
        fail(f"{field} must name {expected_asset}")


def producer_release_tag(identity: DispatchIdentity) -> str:
    value = identity.producer_evidence_url
    validate_producer_asset_url(
        value,
        "producer_evidence_url",
    )
    return unquote(urlsplit(value).path).split("/")[5]


def validate_release_asset_url(
    value: Any, repository: str, tag: str, field: str
) -> str:
    value = require_https(value, field)
    parsed = urlsplit(value)
    parts = unquote(parsed.path).split("/")
    if (
        parsed.netloc != "github.com"
        or parsed.query
        or parsed.fragment
        or len(parts) != 7
        or parts[1:5] != [*repository.split("/"), "releases", "download"]
        or parts[5] != tag
        or SAFE_ASSET.fullmatch(parts[6]) is None
    ):
        fail(f"{field} must be an immutable asset of {repository} {tag}")
    return value


def validate_release_url(
    value: Any, repository: str, tag: str, field: str
) -> str:
    value = require_https(value, field)
    parsed = urlsplit(value)
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
        fail(f"{field} must be bound to {repository} {tag}")
    return value


def load_profiles(path: Path) -> dict[str, dict[str, Any]]:
    root = require_mapping(load_json(path, "profiles"), "profiles")
    require_exact(root, {"schemaVersion", "profiles"}, "profiles")
    if root["schemaVersion"] != 1:
        fail("unsupported profile schema")
    profiles = require_mapping(root["profiles"], "profiles.profiles")
    for profile_id, profile in profiles.items():
        if not is_profile_id(profile_id):
            fail("profile ID is invalid")
        profile = require_mapping(profile, f"profiles.{profile_id}")
        require_exact(
            profile,
            {"description", "releaseEligible", "containerCommand"},
            f"profiles.{profile_id}",
        )
        require_string(profile["description"], f"profiles.{profile_id}.description")
        if not isinstance(profile["releaseEligible"], bool):
            fail(f"profiles.{profile_id}.releaseEligible must be boolean")
        command = profile["containerCommand"]
        if not isinstance(command, list) or not command:
            fail(f"profiles.{profile_id}.containerCommand must be non-empty")
        for index, argument in enumerate(command):
            argument = require_string(
                argument, f"profiles.{profile_id}.containerCommand[{index}]"
            )
            if len(argument) > 512:
                fail(f"profiles.{profile_id}.containerCommand argument is too long")
        if not command[0].startswith("/"):
            fail(f"profiles.{profile_id}.containerCommand must be absolute")
    return profiles


def eligible_profile(
    profiles: dict[str, dict[str, Any]], profile_id: str
) -> dict[str, Any]:
    if not is_profile_id(profile_id) or profile_id not in profiles:
        fail("acceptance profile is not in the fixed allowlist")
    profile = profiles[profile_id]
    if profile["releaseEligible"] is not True:
        fail("acceptance profile is explicitly non-releaseable")
    return profile


def require_security_identifiers(value: Any) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(
            not isinstance(item, str)
            or SECURITY_IDENTIFIER.fullmatch(item) is None
            for item in value
        )
        or len(value) != len(set(value))
    ):
        fail("security.identifiers must be a non-empty unique string list")
    return value


def validate_producer_evidence(
    payload: Any,
    identity: DispatchIdentity,
    profiles: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    payload = require_mapping(payload, "producer evidence")
    require_exact(
        payload,
        {
            "apiVersion",
            "kind",
            "metadata",
            "security",
            "producer",
            "artifact",
            "consumers",
            "acceptance",
            "validity",
            "status",
        },
        "producer evidence",
    )
    if (
        payload["apiVersion"] != "lit.security-release/v1"
        or payload["kind"] != "SecurityReleaseEvidence"
        or payload["status"] != "approved"
    ):
        fail("producer evidence must be approved canonical v1 evidence")
    metadata = require_mapping(payload["metadata"], "producer metadata")
    require_exact(metadata, {"id", "createdAt"}, "producer metadata")
    evidence_id = require_string(metadata["id"], "producer metadata.id")
    if SECURITY_ID.fullmatch(evidence_id) is None:
        fail("producer evidence ID is invalid")
    created_at = require_timestamp(
        metadata["createdAt"], "producer metadata.createdAt"
    )
    security = require_mapping(payload["security"], "security")
    require_exact(
        security,
        {"identifiers", "affectedVersion", "fixedVersion"},
        "security",
    )
    require_security_identifiers(security["identifiers"])
    affected_version = require_string(
        security["affectedVersion"], "security.affectedVersion"
    )
    fixed_version = require_string(
        security["fixedVersion"], "security.fixedVersion"
    )
    if not is_semver(affected_version):
        fail("security affected version is invalid")
    if not is_semver(fixed_version):
        fail("security fixed version is invalid")
    producer = require_mapping(payload["producer"], "producer")
    require_exact(
        producer,
        {"repository", "sourceSha", "workflowRepository", "workflowRef"},
        "producer",
    )
    if producer["repository"] != PRODUCER_REPOSITORY:
        fail("producer evidence repository is not trusted")
    if producer["workflowRepository"] != PRODUCER_REPOSITORY:
        fail("producer evidence workflow repository is not trusted")
    source_sha = require_sha(producer["sourceSha"], "producer.sourceSha")
    workflow_ref = require_sha(producer["workflowRef"], "producer.workflowRef")
    if workflow_ref != source_sha:
        fail("producer workflowRef must equal producer sourceSha")
    artifact = require_mapping(payload["artifact"], "artifact")
    require_exact(
        artifact,
        {
            "collection",
            "version",
            "digest",
            "releaseUrl",
            "signature",
            "sbom",
            "provenance",
        },
        "artifact",
    )
    collection = require_string(artifact["collection"], "artifact.collection")
    if collection != "lit.supplementary":
        fail("producer evidence collection is not trusted")
    version = require_string(artifact["version"], "artifact.version")
    if not is_semver(version):
        fail("producer evidence version is invalid")
    if fixed_version != version:
        fail("security fixed version does not match the collection version")
    tag = producer_release_tag(identity)
    if tag != f"v{version}":
        fail("producer release tag does not match the collection version")
    require_digest(artifact["digest"], "artifact.digest")
    validate_release_url(
        artifact["releaseUrl"], PRODUCER_REPOSITORY, tag, "artifact.releaseUrl"
    )
    for field in ("signature", "sbom", "provenance"):
        reference = require_reference(artifact[field], f"artifact.{field}")
        validate_release_asset_url(
            reference["url"],
            PRODUCER_REPOSITORY,
            tag,
            f"artifact.{field}.url",
        )
    consumers = payload["consumers"]
    if not isinstance(consumers, list):
        fail("producer evidence does not allowlist the consumer")
    for index, item in enumerate(consumers):
        require_string(item, f"consumers[{index}]")
    if CONSUMER_REPOSITORY not in consumers:
        fail("producer evidence does not allowlist the consumer")
    acceptance = require_mapping(payload["acceptance"], "acceptance")
    require_exact(
        acceptance,
        {"profile", "expectedCollection", "expectedVersion"},
        "acceptance",
    )
    profile_id = require_string(acceptance["profile"], "acceptance.profile")
    eligible_profile(profiles, profile_id)
    if (
        acceptance["expectedCollection"] != collection
        or acceptance["expectedVersion"] != version
    ):
        fail("producer acceptance does not bind the collection artifact")
    validity = require_mapping(payload["validity"], "validity")
    require_exact(
        validity,
        {"notBefore", "expiresAt", "revoked"},
        "validity",
    )
    not_before = require_timestamp(validity["notBefore"], "validity.notBefore")
    expires_at = require_timestamp(validity["expiresAt"], "validity.expiresAt")
    if expires_at <= not_before:
        fail("producer evidence validity interval is empty")
    if created_at < not_before or created_at >= expires_at:
        fail("producer evidence creation is outside its validity interval")
    if validity["revoked"] is not False:
        fail("producer evidence is revoked")
    return payload


def validate_container_variant(
    value: Any, field: str, release_tag: str, variant: str
) -> dict[str, Any]:
    value = require_mapping(value, field)
    require_exact(
        value,
        {
            "image",
            "manifestDigest",
            "platformDigests",
            "signature",
            "sbom",
            "provenance",
        },
        field,
    )
    image = require_string(value["image"], f"{field}.image")
    if IMAGE.fullmatch(image) is None:
        fail(f"{field}.image must be an untagged Quay image name")
    require_digest(value["manifestDigest"], f"{field}.manifestDigest")
    platforms = require_mapping(value["platformDigests"], f"{field}.platformDigests")
    require_exact(platforms, set(PLATFORMS), f"{field}.platformDigests")
    for platform in PLATFORMS:
        require_digest(platforms[platform], f"{field}.platformDigests.{platform}")
    expected_assets = {
        "signature": f"signature-{variant}.json",
        "sbom": f"sbom-{variant}.cdx.json",
        "provenance": "release-provenance.intoto.jsonl",
    }
    for reference, expected_asset in expected_assets.items():
        immutable = require_reference(value[reference], f"{field}.{reference}")
        validate_release_asset_url(
            immutable["url"],
            CONSUMER_REPOSITORY,
            release_tag,
            f"{field}.{reference}.url",
        )
        if unquote(urlsplit(immutable["url"]).path).split("/")[-1] != expected_asset:
            fail(f"{field}.{reference}.url must name {expected_asset}")
    return value


def validate_container_evidence(
    payload: Any,
    identity: DispatchIdentity,
    producer_evidence: dict[str, Any],
) -> dict[str, Any]:
    payload = require_mapping(payload, "container evidence")
    require_exact(
        payload,
        {
            "apiVersion",
            "kind",
            "securityEvidenceId",
            "producer",
            "consumer",
            "release",
            "variants",
            "revocation",
        },
        "container evidence",
    )
    if (
        payload["apiVersion"] != "lit.security-release.container/v1"
        or payload["kind"] != "SecurityReleaseContainerEvidence"
    ):
        fail("unsupported container evidence kind or version")
    if payload["securityEvidenceId"] != producer_evidence["metadata"]["id"]:
        fail("container evidence ID does not match producer evidence")

    producer = require_mapping(payload["producer"], "container producer")
    require_exact(
        producer,
        {
            "repository",
            "sourceSha",
            "collection",
            "version",
            "collectionDigest",
            "evidence",
        },
        "container producer",
    )
    artifact = producer_evidence["artifact"]
    expected_producer = {
        "repository": PRODUCER_REPOSITORY,
        "sourceSha": producer_evidence["producer"]["sourceSha"],
        "collection": artifact["collection"],
        "version": artifact["version"],
        "collectionDigest": artifact["digest"],
        "evidence": {
            "url": identity.producer_evidence_url,
            "digest": f"sha256:{identity.producer_evidence_sha256}",
        },
    }
    if producer != expected_producer:
        fail("container evidence does not exactly bind producer evidence")

    consumer = require_mapping(payload["consumer"], "container consumer")
    require_exact(
        consumer,
        {"repository", "pullRequest", "baseSha", "headSha", "mergeSha"},
        "container consumer",
    )
    require_sha(consumer["baseSha"], "container consumer.baseSha")
    expected_consumer = {
        "repository": CONSUMER_REPOSITORY,
        "pullRequest": identity.consumer_pr,
        "headSha": identity.consumer_head_sha,
        "mergeSha": identity.consumer_merge_sha,
    }
    if any(consumer.get(key) != value for key, value in expected_consumer.items()):
        fail("container evidence does not exactly bind the consumer identity")

    release = require_mapping(payload["release"], "container release")
    require_exact(
        release,
        {
            "repository",
            "id",
            "tag",
            "url",
            "sourceSha",
            "workflowRunId",
            "workflowRunAttempt",
        },
        "container release",
    )
    if release.get("repository") != CONSUMER_REPOSITORY:
        fail("container release repository is invalid")
    if release.get("id") != identity.container_release_id:
        fail("container release ID mismatch")
    if release.get("tag") != identity.container_release_tag:
        fail("container release tag mismatch")
    if release.get("sourceSha") != identity.consumer_merge_sha:
        fail("container release source SHA mismatch")
    if release.get("workflowRunId") != identity.container_release_run_id:
        fail("container release workflow run mismatch")
    evidence_run_attempt = require_positive(
        release.get("workflowRunAttempt"), "release.workflowRunAttempt"
    )
    if evidence_run_attempt > identity.container_publish_run_attempt:
        fail("container evidence run attempt is later than publisher attempt")
    expected_release_url = (
        f"https://github.com/{CONSUMER_REPOSITORY}/releases/tag/"
        f"{identity.container_release_tag}"
    )
    if release.get("url") != expected_release_url:
        fail("container release URL mismatch")

    variants = require_mapping(payload["variants"], "container variants")
    require_exact(variants, set(VARIANTS), "container variants")
    images: set[str] = set()
    for name in VARIANTS:
        variant = validate_container_variant(
            variants[name],
            f"container variants.{name}",
            identity.container_release_tag,
            name,
        )
        if variant["image"] in images:
            fail("container variant image names must be unique")
        images.add(variant["image"])
    public_image = variants["public"]["image"]
    if variants["certified"]["image"] != f"{public_image}-certified":
        fail("certified image name must derive from the public image")
    if variants["bootstrap"]["image"] != f"{public_image}-bootstrap":
        fail("bootstrap image name must derive from the public image")

    revocation = require_mapping(payload["revocation"], "container revocation")
    require_exact(revocation, {"status", "checkedAt"}, "container revocation")
    if revocation["status"] != "not_revoked":
        fail("container evidence is revoked")
    require_timestamp(revocation["checkedAt"], "container revocation.checkedAt")
    return payload


def verify_producer_materials(
    producer_evidence: dict[str, Any],
    collection_path: Path,
    sbom_path: Path,
    provenance_path: Path,
) -> None:
    artifact = require_mapping(producer_evidence.get("artifact"), "artifact")
    require_exact(
        artifact,
        {
            "collection",
            "version",
            "digest",
            "releaseUrl",
            "signature",
            "sbom",
            "provenance",
        },
        "artifact",
    )
    expected_digest = require_digest(artifact["digest"], "artifact.digest")
    sbom_reference = require_reference(artifact["sbom"], "artifact.sbom")
    provenance_reference = require_reference(
        artifact["provenance"], "artifact.provenance"
    )
    if (
        file_digest(collection_path, COLLECTION_ARCHIVE_MAX_BYTES)
        != expected_digest
    ):
        fail("collection archive digest does not match producer evidence")
    sbom_snapshot = secure_file_snapshot(
        sbom_path, RELEASE_ASSET_MAX_BYTES, capture_payload=True
    )
    provenance_snapshot = secure_file_snapshot(
        provenance_path, RELEASE_ASSET_MAX_BYTES, capture_payload=True
    )
    if sbom_snapshot.digest != sbom_reference["digest"]:
        fail("SBOM digest does not match producer evidence")
    if provenance_snapshot.digest != provenance_reference["digest"]:
        fail("provenance digest does not match producer evidence")

    sbom = require_mapping(
        parse_json_snapshot(sbom_snapshot, "producer SBOM"),
        "producer SBOM",
    )
    if sbom.get("bomFormat") != "CycloneDX":
        fail("producer SBOM must be CycloneDX")
    require_string(sbom.get("specVersion"), "producer SBOM specVersion")
    if (
        isinstance(sbom.get("version"), bool)
        or not isinstance(sbom.get("version"), int)
        or sbom["version"] < 1
    ):
        fail("producer SBOM version must be a positive integer")
    metadata = require_mapping(sbom.get("metadata"), "producer SBOM metadata")
    component = require_mapping(
        metadata.get("component"), "producer SBOM metadata.component"
    )
    expected_component = {
        "group": "lit",
        "name": "supplementary",
        "version": artifact["version"],
    }
    if any(component.get(key) != value for key, value in expected_component.items()):
        fail("producer SBOM component does not match the collection")
    hashes = component.get("hashes")
    raw_digest = expected_digest.removeprefix("sha256:")
    if not isinstance(hashes, list) or not any(
        isinstance(item, dict)
        and item.get("alg") == "SHA-256"
        and item.get("content") == raw_digest
        for item in hashes
    ):
        fail("producer SBOM is not bound to the collection digest")

    provenance = require_mapping(
        parse_json_snapshot(provenance_snapshot, "producer provenance"),
        "producer provenance",
    )
    expected_candidate = f"lit-supplementary-{artifact['version']}.tar.gz"
    expected_provenance = {
        "schema_version": 1,
        "repository": PRODUCER_REPOSITORY,
        "commit_sha": producer_evidence["producer"]["sourceSha"],
        "candidate": expected_candidate,
        "candidate_sha256": raw_digest,
    }
    if any(
        provenance.get(key) != value
        for key, value in expected_provenance.items()
    ):
        fail("producer provenance does not bind the exact collection candidate")
    require_canonical_positive_string(
        provenance.get("workflow_run_id"),
        "producer provenance.workflow_run_id",
    )
    require_canonical_positive_string(
        provenance.get("workflow_attempt"),
        "producer provenance.workflow_attempt",
    )
    require_timestamp(
        provenance.get("generated_at"), "producer provenance.generated_at"
    )


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def canonical_value_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def release_asset_max_bytes(repository: str, asset_name: str) -> int:
    if (
        repository == CONSUMER_REPOSITORY
        and asset_name in CONTAINER_SBOM_ASSET_NAMES
    ):
        return CONTAINER_SBOM_ASSET_MAX_BYTES
    return RELEASE_ASSET_MAX_BYTES


def consumed_release_asset_urls(
    identity: DispatchIdentity,
    producer: dict[str, Any],
    container: dict[str, Any],
) -> tuple[set[str], set[str]]:
    artifact = producer["artifact"]
    producer_tag = producer_release_tag(identity)
    producer_urls = {
        identity.producer_evidence_url,
        identity.producer_evidence_bundle_url,
        (
            f"https://github.com/{PRODUCER_REPOSITORY}/releases/download/"
            f"{producer_tag}/lit-supplementary-{artifact['version']}.tar.gz"
        ),
        *(artifact[name]["url"] for name in ("signature", "sbom", "provenance")),
    }
    release_tag = identity.container_release_tag
    container_urls = {
        (
            f"https://github.com/{CONSUMER_REPOSITORY}/releases/download/"
            f"{release_tag}/mlx90-container-evidence.json"
        ),
        (
            f"https://github.com/{CONSUMER_REPOSITORY}/releases/download/"
            f"{release_tag}/mlx90-container-evidence.json.sigstore.json"
        ),
    }
    for variant in VARIANTS:
        source = container["variants"][variant]
        container_urls.update(
            source[name]["url"] for name in ("signature", "sbom", "provenance")
        )
    if len(producer_urls) != 6 or len(container_urls) != 9:
        fail("consumed source release asset URL set is not exact")
    return producer_urls, container_urls


def validate_consumed_asset_snapshot(
    value: Any,
    repository: str,
    release_id: int,
    expected_urls: set[str],
    field: str,
) -> dict[str, Any]:
    value = require_mapping(value, field)
    require_exact(value, {"repository", "releaseId", "assets"}, field)
    snapshot_repository = require_string(
        value["repository"], f"{field}.repository"
    )
    snapshot_release_id = require_positive(
        value["releaseId"], f"{field}.releaseId"
    )
    if snapshot_repository != repository or snapshot_release_id != release_id:
        fail(f"{field} release identity mismatch")
    assets = value["assets"]
    if not isinstance(assets, list) or len(assets) != len(expected_urls):
        fail(f"{field} asset count is not exact")
    observed_ids: set[int] = set()
    observed_names: set[str] = set()
    observed_urls: set[str] = set()
    previous_url = ""
    for position, item in enumerate(assets):
        item_field = f"{field}.assets[{position}]"
        item = require_mapping(item, item_field)
        require_exact(item, {"id", "name", "url", "state", "size"}, item_field)
        asset_id = require_positive(item["id"], f"{item_field}.id")
        size = require_positive(item["size"], f"{item_field}.size")
        name = require_string(item["name"], f"{item_field}.name")
        url = require_https(item["url"], f"{item_field}.url")
        if (
            size > release_asset_max_bytes(repository, name)
            or item["state"] != "uploaded"
        ):
            fail(f"{item_field} is not a bounded uploaded asset")
        if url not in expected_urls or unquote(urlsplit(url).path).split("/")[-1] != name:
            fail(f"{item_field} is not an exact consumed release asset")
        if url <= previous_url:
            fail(f"{field} assets are not in canonical URL order")
        if (
            asset_id in observed_ids
            or name in observed_names
            or url in observed_urls
        ):
            fail(f"{field} contains duplicate asset metadata")
        observed_ids.add(asset_id)
        observed_names.add(name)
        observed_urls.add(url)
        previous_url = url
    if observed_urls != expected_urls:
        fail(f"{field} does not bind every consumed release asset")
    return value


def parse_json_or_json_lines(text: str, field: str) -> list[Any]:
    try:
        value = strict_json_loads(text)
    except StrictJsonError as exc:
        raise ValueError(f"{field} {exc}") from exc
    except json.JSONDecodeError:
        values: list[Any] = []
        try:
            for line in text.split("\n"):
                if line.strip():
                    values.append(strict_json_loads(line))
        except StrictJsonError as exc:
            raise ValueError(f"{field} {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ValueError(f"{field} is not valid JSON or JSONL") from exc
        if not values:
            fail(f"{field} must not be empty")
        return values
    if isinstance(value, list):
        if not value:
            fail(f"{field} must not be empty")
        return value
    return [value]


def load_json_or_json_lines(path: Path, field: str) -> list[Any]:
    return parse_json_or_json_lines(read_bounded_utf8(path, field), field)


def verify_container_materials(
    container_evidence: dict[str, Any],
    variant_name: str,
    signature_path: Path,
    live_signature_path: Path,
    sbom_path: Path,
    provenance_path: Path,
) -> None:
    if variant_name not in VARIANTS:
        fail("container material variant is unsupported")
    variants = require_mapping(
        container_evidence.get("variants"), "container variants"
    )
    variant = require_mapping(
        variants.get(variant_name), f"container variants.{variant_name}"
    )
    image = require_string(variant.get("image"), f"{variant_name}.image")
    manifest_digest = require_digest(
        variant.get("manifestDigest"), f"{variant_name}.manifestDigest"
    )
    image_ref = f"{image}@{manifest_digest}"
    release = require_mapping(container_evidence.get("release"), "container release")
    release_tag = require_string(release.get("tag"), "container release.tag")
    source_sha = require_sha(release.get("sourceSha"), "container release.sourceSha")
    run_id = require_positive(
        release.get("workflowRunId"), "container release.workflowRunId"
    )

    reference_urls: dict[str, str] = {}
    material_snapshots: dict[str, SecureFileSnapshot] = {}
    for reference, path in (
        ("signature", signature_path),
        ("sbom", sbom_path),
        ("provenance", provenance_path),
    ):
        expected = require_mapping(
            variant.get(reference), f"{variant_name}.{reference}"
        )
        reference_urls[reference] = require_https(
            expected.get("url"), f"{variant_name}.{reference}.url"
        )
        maximum_bytes = (
            CONTAINER_SBOM_ASSET_MAX_BYTES
            if reference == "sbom"
            else RELEASE_ASSET_MAX_BYTES
        )
        material_snapshots[reference] = secure_file_snapshot(
            path, maximum_bytes, capture_payload=True
        )
        if material_snapshots[reference].digest != expected.get("digest"):
            fail(f"{variant_name} {reference} file digest mismatch")

    signature = parse_json_snapshot(
        material_snapshots["signature"],
        f"{variant_name} signature receipt",
    )
    live_signature = load_json(
        live_signature_path, f"{variant_name} live signature receipt"
    )
    if not isinstance(signature, list) or not signature:
        fail(f"{variant_name} signature receipt must be a non-empty array")
    if not isinstance(live_signature, list) or not live_signature:
        fail(f"{variant_name} live signature receipt must be a non-empty array")
    live_entries = {canonical_json(item) for item in live_signature}
    for index, item in enumerate(signature):
        entry = require_mapping(item, f"{variant_name} signature[{index}]")
        critical = require_mapping(
            entry.get("critical"), f"{variant_name} signature[{index}].critical"
        )
        signed_image = require_mapping(
            critical.get("image"),
            f"{variant_name} signature[{index}].critical.image",
        )
        identity = require_mapping(
            critical.get("identity"),
            f"{variant_name} signature[{index}].critical.identity",
        )
        optional = entry.get("optional")
        if optional is not None and not isinstance(optional, dict):
            fail(f"{variant_name} signature[{index}].optional is malformed")
        signature_type = critical.get("type")
        docker_reference = identity.get("docker-reference")
        legacy_signature = (
            signature_type == "cosign container image signature"
            and docker_reference == image
        )
        sigstore_v1_signature = (
            signature_type == "https://sigstore.dev/cosign/sign/v1"
            and docker_reference == image_ref
        )
        if (
            signed_image.get("docker-manifest-digest") != manifest_digest
            or not (legacy_signature or sigstore_v1_signature)
        ):
            fail(f"{variant_name} signature receipt identity or digest mismatch")
        if canonical_json(entry) not in live_entries:
            fail(
                f"{variant_name} signature receipt is absent from the live "
                "cryptographic verification"
            )

    sbom = require_mapping(
        parse_json_snapshot(
            material_snapshots["sbom"], f"{variant_name} SBOM"
        ),
        "SBOM",
    )
    if sbom.get("bomFormat") != "CycloneDX":
        fail(f"{variant_name} SBOM must be CycloneDX")
    require_string(sbom.get("specVersion"), f"{variant_name} SBOM specVersion")
    require_positive(sbom.get("version"), f"{variant_name} SBOM version")
    components = sbom.get("components")
    if not isinstance(components, list) or not components:
        fail(f"{variant_name} SBOM components must be non-empty")
    metadata = require_mapping(sbom.get("metadata"), f"{variant_name} SBOM metadata")
    component = require_mapping(
        metadata.get("component"), f"{variant_name} SBOM metadata.component"
    )
    if component.get("type") != "container" or component.get("name") != image_ref:
        fail(f"{variant_name} SBOM does not identify the exact immutable image")
    tools = metadata.get("tools")
    if isinstance(tools, dict):
        tool_entries = tools.get("components")
    else:
        tool_entries = tools
    if not isinstance(tool_entries, list) or not any(
        isinstance(tool, dict)
        and tool.get("name") == "trivy"
        and (tool.get("group") == "aquasecurity" or tool.get("vendor") == "aquasecurity")
        for tool in tool_entries
    ):
        fail(f"{variant_name} SBOM does not identify Trivy as its generator")

    provenance_payload = material_snapshots["provenance"].payload
    if provenance_payload is None:  # pragma: no cover - internal contract.
        fail(MATERIAL_FILE_ERROR)
    statements = parse_json_or_json_lines(
        decode_utf8(
            provenance_payload, f"{variant_name} release provenance"
        ),
        f"{variant_name} release provenance",
    )
    if len(statements) != 1:
        fail("release provenance must contain exactly one statement")
    statement = require_mapping(statements[0], "release provenance statement")
    require_exact(
        statement,
        {"_type", "subject", "predicateType", "predicate"},
        "release provenance statement",
    )
    if (
        statement["_type"] != "https://in-toto.io/Statement/v1"
        or statement["predicateType"] != "https://slsa.dev/provenance/v1"
    ):
        fail("release provenance type is invalid")
    predicate = require_mapping(statement["predicate"], "release provenance predicate")
    require_exact(
        predicate,
        {"buildDefinition", "runDetails"},
        "release provenance predicate",
    )
    build = require_mapping(
        predicate["buildDefinition"], "release provenance buildDefinition"
    )
    expected_build = {
        "buildType": "https://lightning-it.io/provenance/workflow-release",
        "externalParameters": {
            "repository": CONSUMER_REPOSITORY,
            "release": release_tag,
            "commit": source_sha,
        },
        "internalParameters": {},
        "resolvedDependencies": [
            {
                "uri": f"git+https://github.com/{CONSUMER_REPOSITORY}@{source_sha}",
                "digest": {"gitCommit": source_sha},
            }
        ],
    }
    if build != expected_build:
        fail("release provenance build identity does not match")
    run_details = require_mapping(
        predicate["runDetails"], "release provenance runDetails"
    )
    require_exact(
        run_details,
        {"builder", "metadata", "byproducts"},
        "release provenance runDetails",
    )
    if run_details["builder"] != {
        "id": f"https://github.com/{CONSUMER_REPOSITORY}/actions"
    }:
        fail("release provenance builder is invalid")
    run_metadata = require_mapping(
        run_details["metadata"], "release provenance runDetails.metadata"
    )
    require_exact(
        run_metadata,
        {"invocationId", "startedOn", "finishedOn"},
        "release provenance runDetails.metadata",
    )
    if run_metadata["invocationId"] != str(run_id):
        fail("release provenance workflow run ID mismatch")
    started = require_timestamp(run_metadata["startedOn"], "provenance startedOn")
    finished = require_timestamp(run_metadata["finishedOn"], "provenance finishedOn")
    if started != finished:
        fail("release provenance generation timestamps differ")
    expected_byproducts = [
        {
            "name": "workflow_run",
            "uri": f"https://github.com/{CONSUMER_REPOSITORY}/actions/runs/{run_id}",
        }
    ]
    if run_details["byproducts"] != expected_byproducts:
        fail("release provenance workflow run URL mismatch")

    subjects = statement["subject"]
    if not isinstance(subjects, list) or not subjects:
        fail("release provenance subjects must be non-empty")
    subjects_by_name: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(subjects):
        subject = require_mapping(item, f"release provenance subject[{index}]")
        name = require_string(
            subject.get("name"), f"release provenance subject[{index}].name"
        )
        if name in subjects_by_name:
            fail("release provenance contains duplicate subject names")
        subjects_by_name[name] = subject
    signature_name = unquote(
        urlsplit(reference_urls["signature"]).path
    ).split("/")[-1]
    sbom_name = unquote(urlsplit(reference_urls["sbom"]).path).split("/")[-1]
    expected_subjects = {
        signature_name: {
            "name": signature_name,
            "digest": {
                "sha256": material_snapshots["signature"].digest.removeprefix(
                    "sha256:"
                )
            },
        },
        sbom_name: {
            "name": sbom_name,
            "digest": {
                "sha256": material_snapshots["sbom"].digest.removeprefix(
                    "sha256:"
                )
            },
        },
        image_ref: {"name": image_ref},
    }
    for name, expected in expected_subjects.items():
        if subjects_by_name.get(name) != expected:
            fail(f"release provenance does not bind {name}")



def validate_verification_report(
    payload: Any,
    identity: DispatchIdentity,
    profiles: dict[str, dict[str, Any]],
    producer_path: Path,
    container_path: Path,
    receipt_bundle_path: Path,
    producer_evidence: dict[str, Any],
    container_evidence: dict[str, Any],
    *,
    workflow_sha: str,
    run_id: int,
    run_attempt: int,
    producer_digest: str | None = None,
    container_digest: str | None = None,
) -> dict[str, Any]:
    producer_digest = resolved_evidence_digest(
        producer_path, producer_digest
    )
    container_digest = resolved_evidence_digest(
        container_path, container_digest
    )
    payload = require_mapping(payload, "verification report")
    require_exact(
        payload,
        {
            "apiVersion",
            "correlationId",
            "checkedAt",
            "producerEvidenceDigest",
            "containerEvidenceDigest",
            "receiptBundle",
            "checks",
            "zeroTouch",
            "variants",
        },
        "verification report",
    )
    if payload["apiVersion"] != "lit.security-release.verification/v1":
        fail("unsupported verification report version")
    if payload["correlationId"] != identity.correlation_id:
        fail("verification correlation ID mismatch")
    checked_at = require_timestamp(
        payload["checkedAt"], "verification checkedAt"
    )
    not_before = require_timestamp(
        producer_evidence["validity"]["notBefore"],
        "producer validity.notBefore",
    )
    expires_at = require_timestamp(
        producer_evidence["validity"]["expiresAt"],
        "producer validity.expiresAt",
    )
    if checked_at < not_before or checked_at >= expires_at:
        fail("verification occurred outside producer evidence validity")
    revocation_checked_at = require_timestamp(
        container_evidence["revocation"]["checkedAt"],
        "container revocation.checkedAt",
    )
    if revocation_checked_at > checked_at:
        fail("container revocation check is later than final verification")
    if payload["producerEvidenceDigest"] != producer_digest:
        fail("verification producer evidence digest mismatch")
    if payload["containerEvidenceDigest"] != container_digest:
        fail("verification container evidence digest mismatch")
    receipt_bundle_snapshot = secure_file_snapshot(
        receipt_bundle_path,
        RELEASE_ASSET_MAX_BYTES,
        capture_payload=True,
    )
    receipt_reference = require_mapping(
        payload["receiptBundle"], "verification receiptBundle"
    )
    require_exact(
        receipt_reference,
        {"assetName", "digest", "size"},
        "verification receiptBundle",
    )
    expected_receipt_reference = {
        "assetName": "mlx90-verification-receipts.json",
        "digest": receipt_bundle_snapshot.digest,
        "size": receipt_bundle_snapshot.size,
    }
    if receipt_reference != expected_receipt_reference:
        fail("verification receipt bundle reference mismatch")
    receipt_bundle_payload = parse_json_snapshot(
        receipt_bundle_snapshot, "verification receipt bundle"
    )
    receipts = validate_receipt_bundle(
        receipt_bundle_payload,
        identity,
        profiles,
        producer_path,
        container_path,
        producer_evidence,
        container_evidence,
        workflow_sha=workflow_sha,
        run_id=run_id,
        run_attempt=run_attempt,
        producer_digest=producer_digest,
        container_digest=container_digest,
    )
    if checked_at != require_timestamp(
        receipts["final-revocation"]["checkedAt"],
        "final revocation receipt checkedAt",
    ):
        fail("verification checkedAt is not derived from final revocation receipt")
    if payload["zeroTouch"] != receipts["zero-touch"]["observations"]:
        fail("verification zeroTouch evidence is not receipt-derived")
    checks = require_mapping(payload["checks"], "verification checks")
    require_exact(checks, FINAL_CHECKS, "verification checks")
    if any(value is not True for value in checks.values()):
        fail("every final verification check must be true")
    variants = require_mapping(payload["variants"], "verification variants")
    require_exact(variants, set(VARIANTS), "verification variants")
    expected_version = producer_evidence["artifact"]["version"]
    expected_profile = producer_evidence["acceptance"]["profile"]
    for name in VARIANTS:
        field = f"verification variants.{name}"
        observed = require_mapping(variants[name], field)
        require_exact(
            observed,
            {
                "image",
                "manifestDigest",
                "platformDigests",
                "pulledImage",
                "collectionPresent",
                "installedCollectionVersion",
                "profile",
                "profileExecuted",
            },
            field,
        )
        expected = container_evidence["variants"][name]
        if observed["image"] != expected["image"]:
            fail(f"{field}.image mismatch")
        if observed["manifestDigest"] != expected["manifestDigest"]:
            fail(f"{field}.manifestDigest mismatch")
        if observed["platformDigests"] != expected["platformDigests"]:
            fail(f"{field}.platformDigests mismatch")
        expected_pulled = f"{expected['image']}@{expected['manifestDigest']}"
        if observed["pulledImage"] != expected_pulled:
            fail(f"{field}.pulledImage mismatch")
        if observed["profile"] != expected_profile:
            fail(f"{field}.profile mismatch")
        if name == "bootstrap":
            if (
                observed["collectionPresent"] is not False
                or observed["installedCollectionVersion"] is not None
                or observed["profileExecuted"] is not False
            ):
                fail(f"{field} does not prove bootstrap collection absence")
        elif (
            observed["collectionPresent"] is not True
            or observed["installedCollectionVersion"] != expected_version
            or observed["profileExecuted"] is not True
        ):
            fail(f"{field} does not prove collection acceptance")
    return payload


def load_delivery_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "mlx90_delivery_validator", DELIVERY_VALIDATOR
    )
    if spec is None or spec.loader is None:
        fail("unable to load MLX-90 delivery validator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def build_final_evidence(
    identity: DispatchIdentity,
    producer_evidence: dict[str, Any],
    container_evidence: dict[str, Any],
    verification: dict[str, Any],
    *,
    workflow_sha: str,
    run_id: int,
    run_attempt: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    require_sha(workflow_sha, "workflow_sha")
    require_positive(run_id, "run_id")
    require_positive(run_attempt, "run_attempt")
    run_url = f"https://github.com/{FINALIZER_REPOSITORY}/actions/runs/{run_id}"
    producer_artifact = producer_evidence["artifact"]
    release = container_evidence["release"]
    variants: dict[str, Any] = {}
    all_digests: set[str] = set()
    for name in VARIANTS:
        source = container_evidence["variants"][name]
        observed = verification["variants"][name]
        variants[name] = {
            **copy.deepcopy(source),
            "pulledImage": observed["pulledImage"],
            "collectionPresent": observed["collectionPresent"],
            "installedCollectionVersion": observed[
                "installedCollectionVersion"
            ],
            "profileExecuted": observed["profileExecuted"],
        }
        all_digests.add(source["manifestDigest"])
        all_digests.update(source["platformDigests"].values())

    container_evidence_reference = {
        "url": (
            "https://github.com/lightning-it/"
            "container-ee-wunder-ansible-ubi9/releases/download/"
            f"{release['tag']}/mlx90-container-evidence.json"
        ),
        "digest": verification["containerEvidenceDigest"],
    }
    consumer = copy.deepcopy(container_evidence["consumer"])
    consumer["changeMergeSha"] = verification["zeroTouch"]["mergeEvents"][0][
        "commitSha"
    ]
    consumer["promotionPullRequest"] = verification["zeroTouch"][
        "mergeEvents"
    ][1]["pullRequest"]
    acceptance = {
        "apiVersion": "lit.security-release.acceptance/v1",
        "kind": "SecurityReleaseAcceptance",
        "status": "delivered",
        "securityEvidenceId": producer_evidence["metadata"]["id"],
        "producer": {
            "repository": PRODUCER_REPOSITORY,
            "sourceSha": producer_evidence["producer"]["sourceSha"],
            "collection": producer_artifact["collection"],
            "version": producer_artifact["version"],
            "collectionDigest": producer_artifact["digest"],
            "releaseUrl": producer_artifact["releaseUrl"],
            "evidence": {
                "url": identity.producer_evidence_url,
                "digest": f"sha256:{identity.producer_evidence_sha256}",
            },
            "workflowRunId": verification["zeroTouch"][
                "workflowApprovalHistory"
            ][0]["runId"],
        },
        "consumer": consumer,
        "container": {
            "repository": CONSUMER_REPOSITORY,
            "releaseId": release["id"],
            "releaseTag": release["tag"],
            "releaseUrl": release["url"],
            "sourceSha": release["sourceSha"],
            "evidence": container_evidence_reference,
            "variants": variants,
            "workflowRunId": release["workflowRunId"],
        },
        "acceptance": {
            "profile": producer_evidence["acceptance"]["profile"],
            "expectedCollection": producer_artifact["collection"],
            "expectedVersion": producer_artifact["version"],
            "acceptedAt": verification["checkedAt"],
        },
        "receiptBundle": copy.deepcopy(verification["receiptBundle"]),
        "checks": copy.deepcopy(verification["checks"]),
        "zeroTouch": copy.deepcopy(verification["zeroTouch"]),
        "finalizer": {
            "repository": FINALIZER_REPOSITORY,
            "workflow": FINALIZER_WORKFLOW,
            "workflowSha": workflow_sha,
            "runId": run_id,
            "runAttempt": run_attempt,
            "runUrl": run_url,
        },
    }
    load_delivery_validator().validate(acceptance)

    delivered = copy.deepcopy(producer_evidence)
    delivered["status"] = "delivered"
    public = container_evidence["variants"]["public"]
    delivered["delivery"] = {
        "consumerRepository": CONSUMER_REPOSITORY,
        "consumerHeadSha": identity.consumer_head_sha,
        "consumerMergeSha": identity.consumer_merge_sha,
        "container": {
            "tag": identity.container_release_tag,
            "manifestDigest": public["manifestDigest"],
            "imageDigests": sorted(all_digests),
            "signature": copy.deepcopy(public["signature"]),
            "sbom": copy.deepcopy(public["sbom"]),
            "provenance": copy.deepcopy(public["provenance"]),
        },
        "acceptedAt": verification["checkedAt"],
        "acceptanceRunUrl": run_url,
    }
    return delivered, acceptance


def receipt_run(
    workflow_sha: str, run_id: int, run_attempt: int
) -> dict[str, Any]:
    require_sha(workflow_sha, "workflow_sha")
    require_positive(run_id, "run_id")
    require_positive(run_attempt, "run_attempt")
    return {
        "repository": FINALIZER_REPOSITORY,
        "workflow": FINALIZER_WORKFLOW,
        "workflowSha": workflow_sha,
        "runId": run_id,
        "runAttempt": run_attempt,
    }


def require_variant_observation(
    observations: dict[str, Any], receipt_id: str
) -> tuple[str, str]:
    variant = require_string(observations.get("variant"), "receipt variant")
    if variant not in VARIANTS or not receipt_id.startswith(f"{variant}-"):
        fail("receipt variant does not match its typed receipt ID")
    return variant, receipt_id.removeprefix(f"{variant}-")


def mlx90_candidate_tag(
    source_sha: str, workflow_run_id: int, workflow_run_attempt: int
) -> str:
    source_sha = require_sha(source_sha, "candidate source SHA")
    workflow_run_id = require_positive(
        workflow_run_id, "candidate workflow run ID"
    )
    workflow_run_attempt = require_positive(
        workflow_run_attempt, "candidate workflow run attempt"
    )
    return (
        f"mlx90-candidate-{source_sha}-{workflow_run_id}-{workflow_run_attempt}"
    )


def validate_receipt_observations(
    receipt_id: str,
    observations: Any,
    identity: DispatchIdentity,
    profiles: dict[str, dict[str, Any]],
    producer: dict[str, Any],
    container: dict[str, Any],
) -> dict[str, Any]:
    observations = require_mapping(observations, f"{receipt_id} observations")
    artifact = producer["artifact"]
    release = container["release"]
    source_sha = producer["producer"]["sourceSha"]
    evidence_id = producer["metadata"]["id"]
    profile = producer["acceptance"]["profile"]

    if receipt_id == "producer-evidence":
        require_exact(
            observations,
            {"evidenceId", "evidenceUrl", "evidenceDigest", "sourceSha"},
            "producer-evidence observations",
        )
        expected = {
            "evidenceId": evidence_id,
            "evidenceUrl": identity.producer_evidence_url,
            "evidenceDigest": f"sha256:{identity.producer_evidence_sha256}",
            "sourceSha": source_sha,
        }
        if observations != expected:
            fail("producer evidence receipt is not bound to the live artifact")
        return observations

    if receipt_id == "producer-identity":
        require_exact(
            observations,
            {
                "releaseId",
                "releaseTag",
                "releaseUrl",
                "tagCommit",
                "draft",
                "prerelease",
            },
            "producer-identity observations",
        )
        require_positive(observations["releaseId"], "producer release ID")
        expected = {
            "releaseTag": f"v{artifact['version']}",
            "releaseUrl": artifact["releaseUrl"],
            "tagCommit": source_sha,
            "draft": False,
            "prerelease": False,
        }
        if any(observations.get(key) != value for key, value in expected.items()):
            fail("producer identity receipt does not match producer evidence")
        return observations

    if receipt_id in {
        "producer-revocation-initial",
        "container-revocation-initial",
    }:
        require_exact(
            observations,
            {
                "releaseId",
                "evidenceId",
                "revocationAssetCount",
                "assetSnapshot",
                "assetSnapshotDigest",
            },
            f"{receipt_id} observations",
        )
        release_id = require_positive(
            observations["releaseId"], f"{receipt_id} releaseId"
        )
        producer_urls, container_urls = consumed_release_asset_urls(
            identity, producer, container
        )
        if receipt_id == "producer-revocation-initial":
            repository = PRODUCER_REPOSITORY
            expected_urls = producer_urls
        else:
            repository = CONSUMER_REPOSITORY
            expected_urls = container_urls
        snapshot = validate_consumed_asset_snapshot(
            observations["assetSnapshot"],
            repository,
            release_id,
            expected_urls,
            f"{receipt_id} asset snapshot",
        )
        snapshot_digest = require_digest(
            observations["assetSnapshotDigest"],
            f"{receipt_id} asset snapshot digest",
        )
        if snapshot_digest != canonical_value_digest(snapshot):
            fail(f"{receipt_id} asset snapshot digest mismatch")
        if (
            observations["evidenceId"] != evidence_id
            or require_nonnegative(
                observations["revocationAssetCount"],
                f"{receipt_id} revocationAssetCount",
            )
            != 0
        ):
            fail(f"{receipt_id} does not prove an unrevoked live release")
        if (
            receipt_id == "container-revocation-initial"
            and observations["releaseId"] != identity.container_release_id
        ):
            fail("container revocation receipt release ID mismatch")
        return observations

    if receipt_id == "producer-cosign":
        require_exact(
            observations,
            {
                "evidenceBundleDigest",
                "collectionBundleDigest",
                "evidenceIdentity",
                "collectionIdentity",
                "sourceSha",
            },
            "producer-cosign observations",
        )
        require_digest(
            observations["evidenceBundleDigest"], "producer evidence bundle digest"
        )
        require_digest(
            observations["collectionBundleDigest"],
            "producer collection bundle digest",
        )
        expected = {
            "evidenceIdentity": (
                f"https://github.com/{PRODUCER_REPOSITORY}/"
                ".github/workflows/collection-publish.yml@refs/heads/main"
            ),
            "collectionIdentity": (
                f"https://github.com/{PRODUCER_REPOSITORY}/"
                ".github/workflows/collection-ci.yml@refs/heads/main"
            ),
            "sourceSha": source_sha,
        }
        if any(observations.get(key) != value for key, value in expected.items()):
            fail("producer Cosign receipt identity mismatch")
        return observations

    if receipt_id == "producer-materials":
        require_exact(
            observations,
            {
                "collectionDigest",
                "sbomDigest",
                "provenanceDigest",
                "version",
                "workflowRunId",
                "workflowRunAttempt",
            },
            "producer-materials observations",
        )
        workflow_run_id = require_positive(
            observations["workflowRunId"], "producer materials workflowRunId"
        )
        workflow_run_attempt = require_positive(
            observations["workflowRunAttempt"],
            "producer materials workflowRunAttempt",
        )
        expected = {
            "collectionDigest": artifact["digest"],
            "sbomDigest": artifact["sbom"]["digest"],
            "provenanceDigest": artifact["provenance"]["digest"],
            "version": artifact["version"],
            "workflowRunId": workflow_run_id,
            "workflowRunAttempt": workflow_run_attempt,
        }
        if observations != expected:
            fail("producer materials receipt digest or version mismatch")
        return observations

    if receipt_id == "producer-central-ci":
        require_exact(
            observations,
            {
                "provenanceDigest",
                "sourceSha",
                "workflowRunId",
                "workflowRunAttempt",
                "workflowRunUrl",
                "workflowName",
                "workflowPath",
                "runRepository",
                "headRepository",
                "event",
                "headBranch",
                "headSha",
                "status",
                "conclusion",
                "gateJobId",
                "gateJobName",
                "gateJobStatus",
                "gateJobConclusion",
            },
            "producer-central-ci observations",
        )
        run_id = require_positive(
            observations["workflowRunId"], "producer central CI workflowRunId"
        )
        run_attempt = require_positive(
            observations["workflowRunAttempt"],
            "producer central CI workflowRunAttempt",
        )
        require_positive(observations["gateJobId"], "producer central CI gateJobId")
        expected = {
            "provenanceDigest": artifact["provenance"]["digest"],
            "sourceSha": source_sha,
            "workflowRunId": run_id,
            "workflowRunAttempt": run_attempt,
            "workflowRunUrl": (
                f"https://github.com/{PRODUCER_REPOSITORY}/actions/runs/{run_id}"
            ),
            "workflowName": PRODUCER_WORKFLOW_NAME,
            "workflowPath": PRODUCER_WORKFLOW,
            "runRepository": PRODUCER_REPOSITORY,
            "headRepository": PRODUCER_REPOSITORY,
            "event": "push",
            "headBranch": "main",
            "headSha": source_sha,
            "status": "completed",
            "conclusion": "success",
            "gateJobId": observations["gateJobId"],
            "gateJobName": PRODUCER_VALIDATION_JOB,
            "gateJobStatus": "completed",
            "gateJobConclusion": "success",
        }
        if observations != expected:
            fail("producer central CI receipt does not bind the exact source gate")
        return observations

    if receipt_id == "consumer-identity":
        require_exact(
            observations,
            {
                "pullRequest",
                "state",
                "mergedAt",
                "baseRef",
                "baseSha",
                "headRepository",
                "headSha",
                "pullRequestMergeSha",
                "pullRequestMergeParents",
                "mergeSha",
                "mergeParents",
                "ancestryStatus",
                "ancestryAheadBy",
                "ancestryBehindBy",
                "ancestryMergeBaseSha",
                "protectedMainSha",
                "protectedMainProtected",
                "protectedMainAncestryStatus",
                "protectedMainAheadBy",
                "protectedMainBehindBy",
                "protectedMainMergeBaseSha",
                "protectedMainRules",
                "protectedMainRulesDigest",
                "releasePromotionPullRequest",
                "releasePromotionMergedAt",
                "releasePromotionBaseSha",
                "releasePromotionHeadRepository",
                "releasePromotionHeadSha",
                "releasePromotionAuthor",
                "releasePromotionMergeSha",
                "releasePromotionMergeParents",
            },
            "consumer-identity observations",
        )
        require_timestamp(observations["mergedAt"], "consumer mergedAt")
        pull_request_merge_sha = require_sha(
            observations["pullRequestMergeSha"],
            "consumer pullRequestMergeSha",
        )
        ancestry_merge_base_sha = require_sha(
            observations["ancestryMergeBaseSha"],
            "consumer ancestryMergeBaseSha",
        )
        pull_request_merge_parents = observations["pullRequestMergeParents"]
        if not isinstance(pull_request_merge_parents, list) or len(
            pull_request_merge_parents
        ) != 2:
            fail("consumer pull-request merge parents are invalid")
        for position, parent in enumerate(pull_request_merge_parents):
            require_sha(parent, f"consumer pullRequestMergeParents[{position}]")
        merge_parents = observations["mergeParents"]
        if not isinstance(merge_parents, list) or len(merge_parents) != 2:
            fail("consumer release source merge parents are invalid")
        for position, parent in enumerate(merge_parents):
            require_sha(parent, f"consumer mergeParents[{position}]")
        ancestry_status = observations["ancestryStatus"]
        ancestry_ahead_by = require_nonnegative(
            observations["ancestryAheadBy"],
            "consumer ancestryAheadBy",
        )
        ancestry_behind_by = require_nonnegative(
            observations["ancestryBehindBy"],
            "consumer ancestryBehindBy",
        )
        if ancestry_status not in {"ahead", "identical"}:
            fail("consumer pull-request ancestry status is invalid")
        if ancestry_behind_by != 0:
            fail("consumer pull-request ancestry behind count is invalid")
        if ancestry_merge_base_sha != pull_request_merge_sha:
            fail("consumer pull-request ancestry merge base is invalid")
        release_source_sha = identity.consumer_merge_sha
        if pull_request_merge_sha == release_source_sha:
            if ancestry_status != "identical" or ancestry_ahead_by != 0:
                fail("consumer pull-request identical ancestry is invalid")
        elif ancestry_status != "ahead" or ancestry_ahead_by <= 0:
            fail("consumer pull-request ancestor relation is invalid")
        protected_main_sha = require_sha(
            observations["protectedMainSha"],
            "consumer protectedMainSha",
        )
        protected_main_merge_base_sha = require_sha(
            observations["protectedMainMergeBaseSha"],
            "consumer protectedMainMergeBaseSha",
        )
        protected_main_status = observations["protectedMainAncestryStatus"]
        protected_main_ahead_by = require_nonnegative(
            observations["protectedMainAheadBy"],
            "consumer protectedMainAheadBy",
        )
        protected_main_behind_by = require_nonnegative(
            observations["protectedMainBehindBy"],
            "consumer protectedMainBehindBy",
        )
        if observations["protectedMainProtected"] is not True:
            fail("consumer main branch is not protected")
        if protected_main_status not in {"ahead", "identical"}:
            fail("consumer protected main ancestry status is invalid")
        if protected_main_behind_by != 0:
            fail("consumer protected main ancestry behind count is invalid")
        if protected_main_merge_base_sha != release_source_sha:
            fail("consumer protected main ancestry merge base is invalid")
        if protected_main_sha == release_source_sha:
            if protected_main_status != "identical" or protected_main_ahead_by != 0:
                fail("consumer protected main identical ancestry is invalid")
        elif protected_main_status != "ahead" or protected_main_ahead_by <= 0:
            fail("consumer release source is not on protected main")
        protected_main_rules = observations["protectedMainRules"]
        if not isinstance(protected_main_rules, list) or not protected_main_rules:
            fail("consumer protected main rules are invalid")
        for position, rule in enumerate(protected_main_rules):
            field = f"consumer protectedMainRules[{position}]"
            rule = require_mapping(rule, field)
            require_exact(
                rule,
                {
                    "type",
                    "parameters",
                    "rulesetSourceType",
                    "rulesetSource",
                    "rulesetId",
                },
                field,
            )
            require_string(rule["type"], f"{field}.type")
            require_string(rule["rulesetSourceType"], f"{field}.rulesetSourceType")
            require_string(rule["rulesetSource"], f"{field}.rulesetSource")
            require_positive(rule["rulesetId"], f"{field}.rulesetId")
            if rule["parameters"] is not None:
                require_mapping(rule["parameters"], f"{field}.parameters")

        def protected_rules(rule_type: str) -> list[dict[str, Any]]:
            return [
                rule
                for rule in protected_main_rules
                if rule["type"] == rule_type
            ]

        if not protected_rules("non_fast_forward"):
            fail("consumer protected main permits non-fast-forward updates")
        if not protected_rules("deletion"):
            fail("consumer protected main permits deletion")
        pull_request_rules = protected_rules("pull_request")
        if not any(
            rule["parameters"] is not None
            and rule["parameters"].get("dismiss_stale_reviews_on_push") is True
            and rule["parameters"].get("required_review_thread_resolution") is True
            for rule in pull_request_rules
        ):
            fail("consumer protected main pull-request rule is invalid")
        status_check_rules = protected_rules("required_status_checks")
        if not any(
            rule["parameters"] is not None
            and rule["parameters"].get(
                "strict_required_status_checks_policy"
            )
            is True
            and any(
                isinstance(check, dict)
                and check.get("context") == "Successful Copilot review"
                for check in rule["parameters"].get(
                    "required_status_checks", []
                )
            )
            for rule in status_check_rules
        ):
            fail("consumer protected main status-check rule is invalid")
        protected_main_rules_digest = require_digest(
            observations["protectedMainRulesDigest"],
            "consumer protectedMainRulesDigest",
        )
        if canonical_value_digest(protected_main_rules) != protected_main_rules_digest:
            fail("consumer protected main rules digest is invalid")
        release_promotion_pull_request = require_positive(
            observations["releasePromotionPullRequest"],
            "consumer releasePromotionPullRequest",
        )
        require_timestamp(
            observations["releasePromotionMergedAt"],
            "consumer releasePromotionMergedAt",
        )
        release_promotion_base_sha = require_sha(
            observations["releasePromotionBaseSha"],
            "consumer releasePromotionBaseSha",
        )
        release_promotion_head_sha = require_sha(
            observations["releasePromotionHeadSha"],
            "consumer releasePromotionHeadSha",
        )
        release_promotion_merge_sha = require_sha(
            observations["releasePromotionMergeSha"],
            "consumer releasePromotionMergeSha",
        )
        release_promotion_merge_parents = observations[
            "releasePromotionMergeParents"
        ]
        if not isinstance(release_promotion_merge_parents, list) or len(
            release_promotion_merge_parents
        ) != 2:
            fail("consumer release promotion merge parents are invalid")
        for position, parent in enumerate(release_promotion_merge_parents):
            require_sha(parent, f"consumer releasePromotionMergeParents[{position}]")
        if release_promotion_merge_parents != [
            release_promotion_base_sha,
            release_promotion_head_sha,
        ]:
            fail("consumer release promotion merge topology is invalid")
        if merge_parents != release_promotion_merge_parents:
            fail("consumer release source merge parents do not match promotion")
        if release_promotion_merge_sha != release_source_sha:
            fail("consumer release promotion merge SHA is invalid")
        expected = {
            "pullRequest": identity.consumer_pr,
            "state": "closed",
            "baseRef": "main",
            "baseSha": container["consumer"]["baseSha"],
            "headRepository": CONSUMER_REPOSITORY,
            "headSha": identity.consumer_head_sha,
            "pullRequestMergeSha": pull_request_merge_sha,
            "pullRequestMergeParents": [
                container["consumer"]["baseSha"],
                identity.consumer_head_sha,
            ],
            "mergeSha": release_source_sha,
            "mergeParents": merge_parents,
            "ancestryStatus": ancestry_status,
            "ancestryAheadBy": ancestry_ahead_by,
            "ancestryBehindBy": 0,
            "ancestryMergeBaseSha": pull_request_merge_sha,
            "protectedMainSha": protected_main_sha,
            "protectedMainProtected": True,
            "protectedMainAncestryStatus": protected_main_status,
            "protectedMainAheadBy": protected_main_ahead_by,
            "protectedMainBehindBy": 0,
            "protectedMainMergeBaseSha": release_source_sha,
            "protectedMainRules": protected_main_rules,
            "protectedMainRulesDigest": protected_main_rules_digest,
            "releasePromotionPullRequest": release_promotion_pull_request,
            "releasePromotionMergedAt": observations["releasePromotionMergedAt"],
            "releasePromotionBaseSha": release_promotion_base_sha,
            "releasePromotionHeadRepository": CONSUMER_REPOSITORY,
            "releasePromotionHeadSha": release_promotion_head_sha,
            "releasePromotionAuthor": "lightning-it-release-automation[bot]",
            "releasePromotionMergeSha": release_source_sha,
            "releasePromotionMergeParents": release_promotion_merge_parents,
        }
        if any(observations.get(key) != value for key, value in expected.items()):
            fail("consumer identity receipt mismatch")
        return observations

    if receipt_id == "container-release":
        require_exact(
            observations,
            {
                "releaseId",
                "releaseTag",
                "releaseUrl",
                "draft",
                "prerelease",
                "sourceSha",
                "workflowRunId",
                "workflowRunAttempt",
                "publishRunAttempt",
                "runRepository",
                "headRepository",
                "event",
                "workflowPath",
                "workflowBlobSha",
                "publisherNeeds",
                "headSha",
                "headBranch",
                "actor",
                "evidenceTriggeringActor",
                "publishTriggeringActor",
                "immutable",
                "targetCommitish",
                "author",
                "evidenceRunStatus",
                "evidenceRunConclusion",
                "status",
                "conclusion",
                "buildJobId",
                "buildJobName",
                "buildJobStatus",
                "buildJobConclusion",
                "publisherJobId",
                "publisherJobName",
                "publisherJobStatus",
                "publisherJobConclusion",
            },
            "container-release observations",
        )
        require_positive(observations["buildJobId"], "container build job ID")
        require_positive(
            observations["publisherJobId"], "container publisher job ID"
        )
        require_sha(
            observations["workflowBlobSha"], "container workflow blob SHA"
        )
        expected = {
            "releaseId": identity.container_release_id,
            "releaseTag": identity.container_release_tag,
            "releaseUrl": release["url"],
            "draft": False,
            "prerelease": False,
            "sourceSha": identity.consumer_merge_sha,
            "workflowRunId": identity.container_release_run_id,
            "workflowRunAttempt": release["workflowRunAttempt"],
            "publishRunAttempt": identity.container_publish_run_attempt,
            "runRepository": CONSUMER_REPOSITORY,
            "headRepository": CONSUMER_REPOSITORY,
            "event": "workflow_dispatch",
            "workflowPath": CONTAINER_WORKFLOW,
            "workflowBlobSha": observations["workflowBlobSha"],
            "publisherNeeds": ["build", "upload-trivy-sarif"],
            "headSha": identity.consumer_merge_sha,
            "headBranch": identity.container_release_tag,
            "actor": CONTAINER_RELEASE_ACTOR,
            "evidenceTriggeringActor": CONTAINER_RELEASE_ACTOR,
            "publishTriggeringActor": CONTAINER_RELEASE_ACTOR,
            "immutable": True,
            "targetCommitish": identity.consumer_merge_sha,
            "author": CONTAINER_RELEASE_ACTOR,
            "evidenceRunStatus": "completed",
            "evidenceRunConclusion": observations["evidenceRunConclusion"],
            "status": "completed",
            "conclusion": "success",
            "buildJobId": observations["buildJobId"],
            "buildJobName": "Build & push image to Quay.io",
            "buildJobStatus": "completed",
            "buildJobConclusion": "success",
            "publisherJobId": observations["publisherJobId"],
            "publisherJobName": "Attach signed release evidence",
            "publisherJobStatus": "completed",
            "publisherJobConclusion": "success",
        }
        if observations["evidenceRunConclusion"] not in {
            "success",
            "failure",
            "neutral",
            "cancelled",
            "skipped",
            "timed_out",
            "action_required",
            "stale",
            "startup_failure",
        }:
            fail("container evidence run conclusion is invalid")
        if observations != expected:
            fail("container release receipt mismatch")
        return observations

    if receipt_id == "container-cosign":
        require_exact(
            observations,
            {"bundleDigest", "identity", "sourceSha"},
            "container-cosign observations",
        )
        require_digest(observations["bundleDigest"], "container bundle digest")
        expected_identity = (
            f"https://github.com/{CONSUMER_REPOSITORY}/"
            ".github/workflows/container-build-publish.yml@"
            f"refs/tags/{identity.container_release_tag}"
        )
        if (
            observations["identity"] != expected_identity
            or observations["sourceSha"] != identity.consumer_merge_sha
        ):
            fail("container Cosign receipt identity mismatch")
        return observations

    if receipt_id == "zero-touch":
        require_exact(
            observations,
            {
                "humanActions",
                "app",
                "finalizer",
                "mergeEvents",
                "currentHeadReviewGate",
                "workflowApprovalHistory",
            },
            "zero-touch observations",
        )
        human_actions = require_mapping(
            observations["humanActions"], "zero-touch humanActions"
        )
        require_exact(
            human_actions, {"scope", "count"}, "zero-touch humanActions"
        )
        if (
            human_actions["scope"] != HUMAN_ACTION_SCOPE
            or isinstance(human_actions["count"], bool)
            or not isinstance(human_actions["count"], int)
            or human_actions["count"] != 0
        ):
            fail("zero-touch humanActions must record zero scoped approvals")
        app = require_mapping(observations["app"], "zero-touch app")
        require_exact(app, {"slug", "installationId"}, "zero-touch app")
        if app != {
            "slug": RELEASE_AUTOMATION_APP_SLUG,
            "installationId": RELEASE_AUTOMATION_INSTALLATION_ID,
        }:
            fail("zero-touch App identity is invalid")
        finalizer = require_mapping(
            observations["finalizer"], "zero-touch finalizer"
        )
        require_exact(
            finalizer,
            {"repository", "runId", "actor", "triggeringActor"},
            "zero-touch finalizer",
        )
        require_positive(finalizer["runId"], "zero-touch finalizer runId")
        if (
            finalizer["repository"] != FINALIZER_REPOSITORY
            or finalizer["actor"] != CONTAINER_RELEASE_ACTOR
            or finalizer["triggeringActor"] != CONTAINER_RELEASE_ACTOR
        ):
            fail("zero-touch finalizer identity is invalid")
        merge_events = observations["mergeEvents"]
        if not isinstance(merge_events, list) or len(merge_events) != 2:
            fail("zero-touch mergeEvents must contain exactly two events")
        for position, event_value in enumerate(merge_events):
            event = require_mapping(
                event_value, f"zero-touch mergeEvents[{position}]"
            )
            require_exact(
                event,
                {"purpose", "repository", "pullRequest", "actor", "commitSha"},
                f"zero-touch mergeEvents[{position}]",
            )
            if event["purpose"] not in {"consumer-change", "main-promotion"}:
                fail("zero-touch merge event purpose is invalid")
            if (
                event["repository"] != CONSUMER_REPOSITORY
                or event["actor"] != CONTAINER_RELEASE_ACTOR
            ):
                fail("zero-touch merge event identity is invalid")
            require_positive(
                event["pullRequest"],
                f"zero-touch mergeEvents[{position}].pullRequest",
            )
            require_sha(
                event["commitSha"],
                f"zero-touch mergeEvents[{position}].commitSha",
            )
        review_gate = require_mapping(
            observations["currentHeadReviewGate"],
            "zero-touch currentHeadReviewGate",
        )
        require_exact(
            review_gate,
            {
                "id",
                "name",
                "headSha",
                "status",
                "conclusion",
                "appId",
                "workflowRunId",
                "workflowRunAttempt",
                "workflowName",
                "workflowPath",
                "workflowContentDigest",
                "workflowEvent",
                "workflowActor",
                "workflowTriggeringActor",
                "pullRequest",
                "baseRef",
                "baseSha",
                "headRef",
                "headRepository",
            },
            "zero-touch currentHeadReviewGate",
        )
        require_positive(review_gate["id"], "zero-touch review gate ID")
        require_positive(
            review_gate["workflowRunId"],
            "zero-touch review workflow run ID",
        )
        require_positive(
            review_gate["workflowRunAttempt"],
            "zero-touch review workflow run attempt",
        )
        require_positive(
            review_gate["pullRequest"],
            "zero-touch review pull request",
        )
        require_sha(review_gate["baseSha"], "zero-touch review base SHA")
        require_digest(
            review_gate["workflowContentDigest"],
            "zero-touch review workflow content digest",
        )
        require_string(review_gate["headRef"], "zero-touch review head ref")
        if review_gate != {
            "id": review_gate["id"],
            "name": COPILOT_REVIEW_JOB_NAME,
            "headSha": identity.consumer_head_sha,
            "status": "completed",
            "conclusion": "success",
            "appId": GITHUB_ACTIONS_APP_ID,
            "workflowRunId": review_gate["workflowRunId"],
            "workflowRunAttempt": review_gate["workflowRunAttempt"],
            "workflowName": COPILOT_REVIEW_WORKFLOW_NAME,
            "workflowPath": COPILOT_REVIEW_WORKFLOW,
            "workflowContentDigest": review_gate["workflowContentDigest"],
            "workflowEvent": "pull_request",
            "workflowActor": CONTAINER_RELEASE_ACTOR,
            "workflowTriggeringActor": CONTAINER_RELEASE_ACTOR,
            "pullRequest": identity.consumer_pr,
            "baseRef": "main",
            "baseSha": container["consumer"]["baseSha"],
            "headRef": review_gate["headRef"],
            "headRepository": CONSUMER_REPOSITORY,
        }:
            fail("zero-touch current-head review gate is invalid")
        approval_history = observations["workflowApprovalHistory"]
        if not isinstance(approval_history, list) or len(approval_history) != 4:
            fail("zero-touch workflowApprovalHistory must contain four runs")
        observed_runs: set[tuple[str, int]] = set()
        for position, history_value in enumerate(approval_history):
            history = require_mapping(
                history_value,
                f"zero-touch workflowApprovalHistory[{position}]",
            )
            require_exact(
                history,
                {"repository", "runId", "reviews"},
                f"zero-touch workflowApprovalHistory[{position}]",
            )
            repository = require_string(
                history["repository"],
                f"zero-touch workflowApprovalHistory[{position}].repository",
            )
            run_id = require_positive(
                history["runId"],
                f"zero-touch workflowApprovalHistory[{position}].runId",
            )
            if history["reviews"] != []:
                fail("zero-touch workflow run contains a human approval")
            key = (repository, run_id)
            if key in observed_runs:
                fail("zero-touch workflow approval histories must be unique")
            observed_runs.add(key)
        return observations

    if receipt_id == "final-revocation":
        require_exact(
            observations,
            {
                "producerReleaseId",
                "producerReleaseTag",
                "containerReleaseId",
                "containerReleaseTag",
                "producerTagCommit",
                "containerTagCommit",
                "evidenceId",
                "producerRevocationAssetCount",
                "containerRevocationAssetCount",
                "producerInitialAssetSnapshotDigest",
                "producerFinalAssetSnapshotDigest",
                "containerInitialAssetSnapshotDigest",
                "containerFinalAssetSnapshotDigest",
                "producerAssets",
                "containerAssets",
            },
            "final-revocation observations",
        )
        producer_release_id = require_positive(
            observations["producerReleaseId"], "final producer release ID"
        )
        producer_urls, container_urls = consumed_release_asset_urls(
            identity, producer, container
        )
        producer_assets = validate_consumed_asset_snapshot(
            observations["producerAssets"],
            PRODUCER_REPOSITORY,
            producer_release_id,
            producer_urls,
            "final producer asset snapshot",
        )
        container_assets = validate_consumed_asset_snapshot(
            observations["containerAssets"],
            CONSUMER_REPOSITORY,
            identity.container_release_id,
            container_urls,
            "final container asset snapshot",
        )
        producer_snapshot_digest = canonical_value_digest(producer_assets)
        container_snapshot_digest = canonical_value_digest(container_assets)
        require_digest(
            observations["producerInitialAssetSnapshotDigest"],
            "final producer initial asset snapshot digest",
        )
        require_digest(
            observations["producerFinalAssetSnapshotDigest"],
            "final producer asset snapshot digest",
        )
        require_digest(
            observations["containerInitialAssetSnapshotDigest"],
            "final container initial asset snapshot digest",
        )
        require_digest(
            observations["containerFinalAssetSnapshotDigest"],
            "final container asset snapshot digest",
        )
        expected = {
            "producerReleaseTag": f"v{artifact['version']}",
            "containerReleaseId": identity.container_release_id,
            "containerReleaseTag": identity.container_release_tag,
            "producerTagCommit": source_sha,
            "containerTagCommit": identity.consumer_merge_sha,
            "evidenceId": evidence_id,
            "producerRevocationAssetCount": 0,
            "containerRevocationAssetCount": 0,
            "producerInitialAssetSnapshotDigest": producer_snapshot_digest,
            "producerFinalAssetSnapshotDigest": producer_snapshot_digest,
            "containerInitialAssetSnapshotDigest": container_snapshot_digest,
            "containerFinalAssetSnapshotDigest": container_snapshot_digest,
            "producerAssets": producer_assets,
            "containerAssets": container_assets,
        }
        if any(observations.get(key) != value for key, value in expected.items()):
            fail("final live revocation receipt mismatch")
        return observations

    variant, suffix = require_variant_observation(observations, receipt_id)
    source = container["variants"][variant]
    image_ref = f"{source['image']}@{source['manifestDigest']}"
    common = {
        "variant": variant,
        "image": source["image"],
        "manifestDigest": source["manifestDigest"],
    }

    if suffix == "oci-index":
        require_exact(
            observations,
            {*common, "indexDigest", "platformDigests"},
            f"{receipt_id} observations",
        )
        expected = {
            **common,
            "indexDigest": source["manifestDigest"],
            "platformDigests": source["platformDigests"],
        }
        if observations != expected:
            fail(f"{receipt_id} OCI index observations mismatch")
        return observations

    if suffix == "immutable-tags":
        require_exact(
            observations,
            {*common, "tagDigests"},
            f"{receipt_id} observations",
        )
        tag_digests = require_mapping(
            observations["tagDigests"], f"{receipt_id} tagDigests"
        )
        expected_tags = {
            mlx90_candidate_tag(
                identity.consumer_merge_sha,
                release["workflowRunId"],
                release["workflowRunAttempt"],
            )
        }
        require_exact(tag_digests, expected_tags, f"{receipt_id} tagDigests")
        if (
            any(observations.get(key) != value for key, value in common.items())
            or any(value != source["manifestDigest"] for value in tag_digests.values())
        ):
            fail(f"{receipt_id} immutable tag digest mismatch")
        return observations

    if suffix == "cosign":
        require_exact(
            observations,
            {*common, "liveSignatureDigest", "identity", "sourceSha"},
            f"{receipt_id} observations",
        )
        require_digest(
            observations["liveSignatureDigest"],
            f"{receipt_id} liveSignatureDigest",
        )
        expected_identity = (
            f"https://github.com/{CONSUMER_REPOSITORY}/"
            ".github/workflows/container-build-publish.yml@"
            f"refs/tags/{identity.container_release_tag}"
        )
        expected = {
            **common,
            "identity": expected_identity,
            "sourceSha": identity.consumer_merge_sha,
        }
        if any(observations.get(key) != value for key, value in expected.items()):
            fail(f"{receipt_id} live Cosign identity mismatch")
        return observations

    if suffix == "materials":
        require_exact(
            observations,
            {
                *common,
                "signatureDigest",
                "liveSignatureDigest",
                "sbomDigest",
                "provenanceDigest",
            },
            f"{receipt_id} observations",
        )
        expected = {
            **common,
            "signatureDigest": source["signature"]["digest"],
            "sbomDigest": source["sbom"]["digest"],
            "provenanceDigest": source["provenance"]["digest"],
        }
        require_digest(
            observations["liveSignatureDigest"],
            f"{receipt_id} liveSignatureDigest",
        )
        if any(observations.get(key) != value for key, value in expected.items()):
            fail(f"{receipt_id} materials digest mismatch")
        return observations

    if suffix == "buildkit":
        require_exact(
            observations,
            {*common, "indexDigest", "platforms"},
            f"{receipt_id} observations",
        )
        if (
            any(observations.get(key) != value for key, value in common.items())
            or observations["indexDigest"] != source["manifestDigest"]
        ):
            fail(f"{receipt_id} BuildKit index binding mismatch")
        platforms = require_mapping(
            observations["platforms"], f"{receipt_id} platforms"
        )
        require_exact(platforms, set(PLATFORMS), f"{receipt_id} platforms")
        for platform in PLATFORMS:
            values = require_mapping(
                platforms[platform], f"{receipt_id} platforms.{platform}"
            )
            require_exact(
                values,
                {
                    "platformDigest",
                    "attestationManifestDigest",
                    "spdxDigest",
                    "slsaDigest",
                },
                f"{receipt_id} platforms.{platform}",
            )
            if values["platformDigest"] != source["platformDigests"][platform]:
                fail(f"{receipt_id} {platform} platform digest mismatch")
            for name in (
                "attestationManifestDigest",
                "spdxDigest",
                "slsaDigest",
            ):
                require_digest(values[name], f"{receipt_id} {platform} {name}")
        return observations

    if suffix == "pull":
        require_exact(
            observations,
            {*common, "pulledImage", "repoDigests"},
            f"{receipt_id} observations",
        )
        repo_digests = observations["repoDigests"]
        if not isinstance(repo_digests, list) or not repo_digests:
            fail(f"{receipt_id} repoDigests must be a non-empty array")
        for position, value in enumerate(repo_digests):
            require_string(value, f"{receipt_id} repoDigests[{position}]")
        expected = {**common, "pulledImage": image_ref}
        if (
            any(observations.get(key) != value for key, value in expected.items())
            or image_ref not in repo_digests
        ):
            fail(f"{receipt_id} does not prove an immutable digest pull")
        return observations

    if suffix == "installed":
        require_exact(
            observations,
            {
                "variant",
                "imageRef",
                "collection",
                "state",
                "installedVersion",
                "profile",
            },
            f"{receipt_id} observations",
        )
        expected_state = "absent" if variant == "bootstrap" else "present"
        expected_version = None if variant == "bootstrap" else artifact["version"]
        expected = {
            "variant": variant,
            "imageRef": image_ref,
            "collection": artifact["collection"],
            "state": expected_state,
            "installedVersion": expected_version,
            "profile": profile,
        }
        if observations != expected:
            fail(f"{receipt_id} installed collection observation mismatch")
        return observations

    if suffix == "profile":
        require_exact(
            observations,
            {"variant", "imageRef", "profile", "command"},
            f"{receipt_id} observations",
        )
        if variant == "bootstrap":
            fail("bootstrap must not have an acceptance profile receipt")
        expected = {
            "variant": variant,
            "imageRef": image_ref,
            "profile": profile,
            "command": eligible_profile(profiles, profile)["containerCommand"],
        }
        if observations != expected:
            fail(f"{receipt_id} profile command observation mismatch")
        return observations

    fail(f"unsupported typed receipt: {receipt_id}")


def verification_receipt(
    identity: DispatchIdentity,
    profiles: dict[str, dict[str, Any]],
    producer_path: Path,
    container_path: Path,
    producer: dict[str, Any],
    container: dict[str, Any],
    *,
    receipt_id: str,
    observations: Any,
    checked_at: str,
    workflow_sha: str,
    run_id: int,
    run_attempt: int,
    producer_digest: str | None = None,
    container_digest: str | None = None,
) -> dict[str, Any]:
    producer_digest = resolved_evidence_digest(
        producer_path, producer_digest
    )
    container_digest = resolved_evidence_digest(
        container_path, container_digest
    )
    receipt_type = EXPECTED_RECEIPT_TYPES.get(receipt_id)
    if receipt_type is None:
        fail("receipt ID is not part of the exact MLX-90 receipt set")
    checked = require_timestamp(checked_at, f"{receipt_id} checkedAt")
    not_before = require_timestamp(
        producer["validity"]["notBefore"], "producer validity.notBefore"
    )
    expires_at = require_timestamp(
        producer["validity"]["expiresAt"], "producer validity.expiresAt"
    )
    if checked < not_before or checked >= expires_at:
        fail(f"{receipt_id} is stale or outside producer evidence validity")
    observations = validate_receipt_observations(
        receipt_id, observations, identity, profiles, producer, container
    )
    return {
        "apiVersion": RECEIPT_API_VERSION,
        "kind": "SecurityReleaseVerificationReceipt",
        "receiptId": receipt_id,
        "receiptType": receipt_type,
        "correlationId": identity.correlation_id,
        "producerEvidenceDigest": producer_digest,
        "containerEvidenceDigest": container_digest,
        "finalizer": receipt_run(workflow_sha, run_id, run_attempt),
        "checkedAt": checked_at,
        "observations": copy.deepcopy(observations),
    }


def validate_receipt(
    payload: Any,
    identity: DispatchIdentity,
    profiles: dict[str, dict[str, Any]],
    producer_path: Path,
    container_path: Path,
    producer: dict[str, Any],
    container: dict[str, Any],
    *,
    workflow_sha: str,
    run_id: int,
    run_attempt: int,
    producer_digest: str | None = None,
    container_digest: str | None = None,
) -> dict[str, Any]:
    producer_digest = resolved_evidence_digest(
        producer_path, producer_digest
    )
    container_digest = resolved_evidence_digest(
        container_path, container_digest
    )
    payload = require_mapping(payload, "verification receipt")
    require_exact(
        payload,
        {
            "apiVersion",
            "kind",
            "receiptId",
            "receiptType",
            "correlationId",
            "producerEvidenceDigest",
            "containerEvidenceDigest",
            "finalizer",
            "checkedAt",
            "observations",
        },
        "verification receipt",
    )
    if (
        payload["apiVersion"] != RECEIPT_API_VERSION
        or payload["kind"] != "SecurityReleaseVerificationReceipt"
    ):
        fail("unsupported verification receipt schema")
    receipt_id = require_string(payload["receiptId"], "receiptId")
    expected_type = EXPECTED_RECEIPT_TYPES.get(receipt_id)
    if expected_type is None or payload["receiptType"] != expected_type:
        fail("receipt type does not match its exact receipt ID")
    if payload["correlationId"] != identity.correlation_id:
        fail("receipt correlation ID mismatch")
    if payload["producerEvidenceDigest"] != producer_digest:
        fail("receipt producer evidence digest mismatch")
    if payload["containerEvidenceDigest"] != container_digest:
        fail("receipt container evidence digest mismatch")
    if payload["finalizer"] != receipt_run(workflow_sha, run_id, run_attempt):
        fail("receipt is foreign to this workflow run or attempt")
    checked = require_timestamp(payload["checkedAt"], f"{receipt_id} checkedAt")
    not_before = require_timestamp(
        producer["validity"]["notBefore"], "producer validity.notBefore"
    )
    expires_at = require_timestamp(
        producer["validity"]["expiresAt"], "producer validity.expiresAt"
    )
    if checked < not_before or checked >= expires_at:
        fail(f"{receipt_id} is stale or outside producer evidence validity")
    validate_receipt_observations(
        receipt_id,
        payload["observations"],
        identity,
        profiles,
        producer,
        container,
    )
    return payload


def validate_receipt_set(
    receipts: list[Any],
    identity: DispatchIdentity,
    profiles: dict[str, dict[str, Any]],
    producer_path: Path,
    container_path: Path,
    producer: dict[str, Any],
    container: dict[str, Any],
    *,
    workflow_sha: str,
    run_id: int,
    run_attempt: int,
    producer_digest: str | None = None,
    container_digest: str | None = None,
) -> dict[str, dict[str, Any]]:
    producer_digest = resolved_evidence_digest(
        producer_path, producer_digest
    )
    container_digest = resolved_evidence_digest(
        container_path, container_digest
    )
    by_id: dict[str, dict[str, Any]] = {}
    for item in receipts:
        receipt = validate_receipt(
            item,
            identity,
            profiles,
            producer_path,
            container_path,
            producer,
            container,
            workflow_sha=workflow_sha,
            run_id=run_id,
            run_attempt=run_attempt,
            producer_digest=producer_digest,
            container_digest=container_digest,
        )
        receipt_id = receipt["receiptId"]
        if receipt_id in by_id:
            fail(f"duplicate verification receipt: {receipt_id}")
        by_id[receipt_id] = receipt
    require_exact(by_id, set(EXPECTED_RECEIPT_TYPES), "verification receipt set")

    producer_release_id = by_id["producer-identity"]["observations"]["releaseId"]
    if (
        by_id["producer-revocation-initial"]["observations"]["releaseId"]
        != producer_release_id
        or by_id["final-revocation"]["observations"]["producerReleaseId"]
        != producer_release_id
    ):
        fail("producer revocation receipts refer to a different release")
    producer_initial = by_id["producer-revocation-initial"]["observations"][
        "assetSnapshotDigest"
    ]
    container_initial = by_id["container-revocation-initial"]["observations"][
        "assetSnapshotDigest"
    ]
    final_revocation = by_id["final-revocation"]["observations"]
    if (
        final_revocation["producerInitialAssetSnapshotDigest"]
        != producer_initial
        or final_revocation["containerInitialAssetSnapshotDigest"]
        != container_initial
        or final_revocation["producerAssets"]
        != by_id["producer-revocation-initial"]["observations"][
            "assetSnapshot"
        ]
        or final_revocation["containerAssets"]
        != by_id["container-revocation-initial"]["observations"][
            "assetSnapshot"
        ]
    ):
        fail("final revocation receipt is not bound to initial asset snapshots")
    if (
        final_revocation["producerInitialAssetSnapshotDigest"]
        != final_revocation["producerFinalAssetSnapshotDigest"]
        or final_revocation["containerInitialAssetSnapshotDigest"]
        != final_revocation["containerFinalAssetSnapshotDigest"]
    ):
        fail("initial and final asset snapshots do not match")
    producer_materials = by_id["producer-materials"]["observations"]
    producer_central_ci = by_id["producer-central-ci"]["observations"]
    if (
        producer_central_ci["workflowRunId"]
        != producer_materials["workflowRunId"]
        or producer_central_ci["workflowRunAttempt"]
        != producer_materials["workflowRunAttempt"]
        or producer_central_ci["provenanceDigest"]
        != producer_materials["provenanceDigest"]
    ):
        fail("producer central CI receipt is not bound to producer provenance")
    zero_touch = by_id["zero-touch"]["observations"]
    consumer_identity = by_id["consumer-identity"]["observations"]
    container_release = by_id["container-release"]["observations"]
    expected_merge_events = [
        {
            "purpose": "consumer-change",
            "repository": CONSUMER_REPOSITORY,
            "pullRequest": consumer_identity["pullRequest"],
            "actor": CONTAINER_RELEASE_ACTOR,
            "commitSha": consumer_identity["pullRequestMergeSha"],
        },
        {
            "purpose": "main-promotion",
            "repository": CONSUMER_REPOSITORY,
            "pullRequest": consumer_identity["releasePromotionPullRequest"],
            "actor": CONTAINER_RELEASE_ACTOR,
            "commitSha": consumer_identity["releasePromotionMergeSha"],
        },
    ]
    if zero_touch["mergeEvents"] != expected_merge_events:
        fail("zero-touch merge events are not bound to consumer identity")
    if zero_touch["finalizer"]["runId"] != run_id:
        fail("zero-touch finalizer run ID is foreign to this receipt bundle")
    expected_approval_history = [
        {
            "repository": PRODUCER_REPOSITORY,
            "runId": producer_central_ci["workflowRunId"],
            "reviews": [],
        },
        {
            "repository": CONSUMER_REPOSITORY,
            "runId": zero_touch["currentHeadReviewGate"]["workflowRunId"],
            "reviews": [],
        },
        {
            "repository": CONSUMER_REPOSITORY,
            "runId": container_release["workflowRunId"],
            "reviews": [],
        },
        {
            "repository": FINALIZER_REPOSITORY,
            "runId": run_id,
            "reviews": [],
        },
    ]
    if zero_touch["workflowApprovalHistory"] != expected_approval_history:
        fail("zero-touch workflow approval history is not evidence-bound")
    final_checked = require_timestamp(
        by_id["final-revocation"]["checkedAt"], "final revocation checkedAt"
    )
    for receipt_id, receipt in by_id.items():
        if require_timestamp(receipt["checkedAt"], f"{receipt_id} checkedAt") > final_checked:
            fail("final live revocation receipt is not the last observation")
    container_revocation_checked = require_timestamp(
        container["revocation"]["checkedAt"], "container revocation.checkedAt"
    )
    if final_checked < container_revocation_checked:
        fail("final live revocation receipt predates signed container evidence")

    for variant in VARIANTS:
        live_digest = by_id[f"{variant}-cosign"]["observations"][
            "liveSignatureDigest"
        ]
        if (
            by_id[f"{variant}-materials"]["observations"][
                "liveSignatureDigest"
            ]
            != live_digest
        ):
            fail(f"{variant} material receipt is not bound to live Cosign output")
    return by_id


def load_receipt_directory(
    receipt_root: Path,
    identity: DispatchIdentity,
    profiles: dict[str, dict[str, Any]],
    producer_path: Path,
    container_path: Path,
    producer: dict[str, Any],
    container: dict[str, Any],
    *,
    workflow_sha: str,
    run_id: int,
    run_attempt: int,
    producer_digest: str | None = None,
    container_digest: str | None = None,
) -> dict[str, dict[str, Any]]:
    try:
        if receipt_root.is_symlink() or not receipt_root.is_dir():
            fail("verification receipt root must be a regular directory")
        paths = sorted(receipt_root.iterdir())
    except OSError as exc:
        raise ValueError("verification receipt root is not readable") from exc
    expected_names = {f"{receipt_id}.json" for receipt_id in EXPECTED_RECEIPT_TYPES}
    actual_names = {path.name for path in paths}
    require_exact(
        {name: None for name in actual_names},
        expected_names,
        "verification receipt files",
    )
    receipts = []
    for path in paths:
        try:
            if path.is_symlink() or not path.is_file():
                fail("verification receipt must be a regular file")
        except OSError as exc:
            raise ValueError("verification receipt cannot be inspected") from exc
        receipt = load_json(path, "verification receipt")
        if not isinstance(receipt, dict) or path.name != f"{receipt.get('receiptId')}.json":
            fail("verification receipt filename does not match receiptId")
        receipts.append(receipt)
    return validate_receipt_set(
        receipts,
        identity,
        profiles,
        producer_path,
        container_path,
        producer,
        container,
        workflow_sha=workflow_sha,
        run_id=run_id,
        run_attempt=run_attempt,
        producer_digest=producer_digest,
        container_digest=container_digest,
    )


def receipt_bundle(
    receipts: dict[str, dict[str, Any]],
    identity: DispatchIdentity,
    producer_path: Path,
    container_path: Path,
    *,
    workflow_sha: str,
    run_id: int,
    run_attempt: int,
    producer_digest: str | None = None,
    container_digest: str | None = None,
) -> dict[str, Any]:
    producer_digest = resolved_evidence_digest(
        producer_path, producer_digest
    )
    container_digest = resolved_evidence_digest(
        container_path, container_digest
    )
    return {
        "apiVersion": RECEIPT_BUNDLE_API_VERSION,
        "kind": "SecurityReleaseVerificationReceiptBundle",
        "correlationId": identity.correlation_id,
        "producerEvidenceDigest": producer_digest,
        "containerEvidenceDigest": container_digest,
        "finalizer": receipt_run(workflow_sha, run_id, run_attempt),
        "receipts": [copy.deepcopy(receipts[name]) for name in sorted(receipts)],
    }


def validate_receipt_bundle(
    payload: Any,
    identity: DispatchIdentity,
    profiles: dict[str, dict[str, Any]],
    producer_path: Path,
    container_path: Path,
    producer: dict[str, Any],
    container: dict[str, Any],
    *,
    workflow_sha: str,
    run_id: int,
    run_attempt: int,
    producer_digest: str | None = None,
    container_digest: str | None = None,
) -> dict[str, dict[str, Any]]:
    producer_digest = resolved_evidence_digest(
        producer_path, producer_digest
    )
    container_digest = resolved_evidence_digest(
        container_path, container_digest
    )
    payload = require_mapping(payload, "verification receipt bundle")
    require_exact(
        payload,
        {
            "apiVersion",
            "kind",
            "correlationId",
            "producerEvidenceDigest",
            "containerEvidenceDigest",
            "finalizer",
            "receipts",
        },
        "verification receipt bundle",
    )
    if (
        payload["apiVersion"] != RECEIPT_BUNDLE_API_VERSION
        or payload["kind"] != "SecurityReleaseVerificationReceiptBundle"
    ):
        fail("unsupported verification receipt bundle schema")
    if payload["correlationId"] != identity.correlation_id:
        fail("receipt bundle correlation ID mismatch")
    if payload["producerEvidenceDigest"] != producer_digest:
        fail("receipt bundle producer evidence digest mismatch")
    if payload["containerEvidenceDigest"] != container_digest:
        fail("receipt bundle container evidence digest mismatch")
    if payload["finalizer"] != receipt_run(workflow_sha, run_id, run_attempt):
        fail("receipt bundle is foreign to this workflow run or attempt")
    receipts = payload["receipts"]
    if not isinstance(receipts, list):
        fail("verification receipt bundle receipts must be an array")
    observed_order = [
        require_string(
            require_mapping(item, f"receipt bundle receipts[{index}]").get(
                "receiptId"
            ),
            f"receipt bundle receipts[{index}].receiptId",
        )
        for index, item in enumerate(receipts)
    ]
    if observed_order != sorted(EXPECTED_RECEIPT_TYPES):
        fail("verification receipt bundle order is not canonical")
    return validate_receipt_set(
        receipts,
        identity,
        profiles,
        producer_path,
        container_path,
        producer,
        container,
        workflow_sha=workflow_sha,
        run_id=run_id,
        run_attempt=run_attempt,
        producer_digest=producer_digest,
        container_digest=container_digest,
    )


def verification_report(
    identity: DispatchIdentity,
    profiles: dict[str, dict[str, Any]],
    producer_path: Path,
    container_path: Path,
    producer_evidence: dict[str, Any],
    container_evidence: dict[str, Any],
    receipt_root: Path,
    receipt_bundle_output: Path,
    *,
    workflow_sha: str,
    run_id: int,
    run_attempt: int,
    producer_digest: str | None = None,
    container_digest: str | None = None,
) -> dict[str, Any]:
    producer_digest = resolved_evidence_digest(
        producer_path, producer_digest
    )
    container_digest = resolved_evidence_digest(
        container_path, container_digest
    )
    receipts = load_receipt_directory(
        receipt_root,
        identity,
        profiles,
        producer_path,
        container_path,
        producer_evidence,
        container_evidence,
        workflow_sha=workflow_sha,
        run_id=run_id,
        run_attempt=run_attempt,
        producer_digest=producer_digest,
        container_digest=container_digest,
    )
    bundle = receipt_bundle(
        receipts,
        identity,
        producer_path,
        container_path,
        workflow_sha=workflow_sha,
        run_id=run_id,
        run_attempt=run_attempt,
        producer_digest=producer_digest,
        container_digest=container_digest,
    )
    receipt_bundle_digest, receipt_bundle_size = write_json(
        receipt_bundle_output, bundle
    )

    observed_variants: dict[str, Any] = {}
    for name in VARIANTS:
        index = receipts[f"{name}-oci-index"]["observations"]
        pull = receipts[f"{name}-pull"]["observations"]
        installed = receipts[f"{name}-installed"]["observations"]
        profile_receipt = receipts.get(f"{name}-profile")
        observed_variants[name] = {
            "image": index["image"],
            "manifestDigest": index["manifestDigest"],
            "platformDigests": copy.deepcopy(index["platformDigests"]),
            "pulledImage": pull["pulledImage"],
            "collectionPresent": installed["state"] == "present",
            "installedCollectionVersion": installed["installedVersion"],
            "profile": installed["profile"],
            "profileExecuted": profile_receipt is not None,
        }
    checks = {
        name: required.issubset(receipts)
        for name, required in CHECK_RECEIPTS.items()
    }
    require_exact(checks, FINAL_CHECKS, "receipt-derived verification checks")
    if any(value is not True for value in checks.values()):
        fail("receipt set cannot derive every required verification check")
    return {
        "apiVersion": "lit.security-release.verification/v1",
        "correlationId": identity.correlation_id,
        "checkedAt": receipts["final-revocation"]["checkedAt"],
        "producerEvidenceDigest": producer_digest,
        "containerEvidenceDigest": container_digest,
        "receiptBundle": {
            "assetName": "mlx90-verification-receipts.json",
            "digest": receipt_bundle_digest,
            "size": receipt_bundle_size,
        },
        "checks": checks,
        "zeroTouch": copy.deepcopy(receipts["zero-touch"]["observations"]),
        "variants": observed_variants,
    }


def load_verified_index(
    container_evidence: dict[str, Any], variant_name: str, index_path: Path
) -> Any:
    if variant_name not in VARIANTS:
        fail("variant is not allowlisted")
    variants = require_mapping(
        container_evidence.get("variants"), "container variants"
    )
    variant = require_mapping(
        variants.get(variant_name), f"container variants.{variant_name}"
    )
    expected = require_digest(
        variant.get("manifestDigest"), f"{variant_name}.manifestDigest"
    )
    field = f"{variant_name} OCI index"
    snapshot = secure_file_snapshot(
        index_path, FINALIZER_INPUT_MAX_BYTES, capture_payload=True
    )
    if snapshot.digest != expected:
        fail(
            f"{variant_name} raw OCI index digest does not match "
            "container evidence"
        )
    return parse_json_snapshot(snapshot, field)


def verify_index(
    container_evidence: dict[str, Any], variant_name: str, index: Any
) -> dict[str, dict[str, str]]:
    if variant_name not in VARIANTS:
        fail("variant is not allowlisted")
    index = require_mapping(index, "OCI index")
    if index.get("schemaVersion") != 2:
        fail("OCI index schemaVersion must be 2")
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or not manifests:
        fail("OCI index manifests must be non-empty")
    observed: dict[str, str] = {}
    attestation_targets: dict[str, str] = {}
    for descriptor in manifests:
        descriptor = require_mapping(descriptor, "OCI descriptor")
        platform = require_mapping(
            descriptor.get("platform"), "OCI descriptor platform"
        )
        require_exact(
            platform,
            {"os", "architecture"},
            "OCI descriptor platform",
        )
        platform_os = require_string(
            platform["os"], "OCI descriptor platform os"
        )
        platform_architecture = require_string(
            platform["architecture"],
            "OCI descriptor platform architecture",
        )
        key = f"{platform_os}/{platform_architecture}"
        if key not in PLATFORMS:
            if key != "unknown/unknown":
                fail("OCI index contains an unexpected platform")
            digest = require_digest(
                descriptor.get("digest"), "OCI attestation descriptor digest"
            )
            annotations = require_mapping(
                descriptor.get("annotations"), "OCI attestation annotations"
            )
            target = require_digest(
                annotations.get("vnd.docker.reference.digest"),
                "OCI attestation target digest",
            )
            if (
                descriptor.get("mediaType")
                != "application/vnd.oci.image.manifest.v1+json"
                or annotations.get("vnd.docker.reference.type")
                != "attestation-manifest"
            ):
                fail("OCI attestation descriptor type is invalid")
            if target in attestation_targets:
                fail("OCI index contains duplicate attestation target")
            attestation_targets[target] = digest
            continue
        if key in observed:
            fail("OCI index contains a duplicate platform")
        observed[key] = require_digest(
            descriptor.get("digest"), "OCI index platform digest"
        )
    variants = require_mapping(
        container_evidence.get("variants"), "container variants"
    )
    variant = require_mapping(
        variants.get(variant_name), f"container variants.{variant_name}"
    )
    expected = require_mapping(
        variant.get("platformDigests"),
        f"container variants.{variant_name}.platformDigests",
    )
    require_exact(
        expected,
        set(PLATFORMS),
        f"container variants.{variant_name}.platformDigests",
    )
    for platform in PLATFORMS:
        require_digest(
            expected[platform],
            f"container variants.{variant_name}.platformDigests.{platform}",
        )
    if observed != expected:
        fail("OCI index platform digests do not match container evidence")
    if set(attestation_targets) != set(expected.values()):
        fail("OCI index does not attest each exact platform manifest")
    if len(set(attestation_targets.values())) != len(PLATFORMS):
        fail("OCI index attestation manifest digests must be distinct")
    if len(manifests) != len(PLATFORMS) * 2:
        fail("OCI index must contain only platforms and their attestations")
    return {
        platform: {
            "platformDigest": digest,
            "attestationDigest": attestation_targets[digest],
        }
        for platform, digest in observed.items()
    }


def buildkit_subject_names(
    image: str,
    source_sha: str,
    workflow_run_id: int,
    workflow_run_attempt: int,
    platform: str,
) -> set[str]:
    suffix = f"?platform={quote(platform, safe='')}"
    candidate_tag = mlx90_candidate_tag(
        source_sha, workflow_run_id, workflow_run_attempt
    )
    return {f"pkg:docker/{image}@{candidate_tag}{suffix}"}


def verify_buildkit_statement(
    statement: Any,
    predicate_type: str,
    image: str,
    source_sha: str,
    workflow_run_id: int,
    workflow_run_attempt: int,
    platform: str,
    platform_digest: str,
) -> dict[str, Any]:
    statement = require_mapping(statement, f"{platform} in-toto statement")
    require_exact(
        statement,
        {"_type", "subject", "predicateType", "predicate"},
        f"{platform} in-toto statement",
    )
    if statement["_type"] != IN_TOTO_STATEMENT:
        fail(f"{platform} BuildKit statement type is invalid")
    if statement["predicateType"] != predicate_type:
        fail(f"{platform} BuildKit predicate type is invalid")
    subjects = statement["subject"]
    if not isinstance(subjects, list) or not subjects:
        fail(f"{platform} BuildKit subjects must be non-empty")
    expected_names = buildkit_subject_names(
        image,
        source_sha,
        workflow_run_id,
        workflow_run_attempt,
        platform,
    )
    observed_names: set[str] = set()
    expected_digest = platform_digest.removeprefix("sha256:")
    for position, item in enumerate(subjects):
        field = f"{platform} BuildKit subject[{position}]"
        subject = require_mapping(item, field)
        require_exact(subject, {"name", "digest"}, field)
        name = require_string(subject["name"], f"{field}.name")
        if name in observed_names:
            fail(f"{platform} BuildKit statement has duplicate subjects")
        observed_names.add(name)
        digest = require_mapping(subject["digest"], f"{field}.digest")
        require_exact(digest, {"sha256"}, f"{field}.digest")
        if digest["sha256"] != expected_digest:
            fail(
                f"{platform} BuildKit subject is not bound to the exact "
                "platform digest"
            )
    if observed_names != expected_names:
        fail(
            f"{platform} BuildKit subjects do not match the attempt-bound "
            "candidate reference"
        )
    return require_mapping(
        statement["predicate"], f"{platform} BuildKit predicate"
    )


def verify_buildkit_spdx(predicate: dict[str, Any], platform: str) -> None:
    field = f"{platform} BuildKit SPDX"
    require_exact(
        predicate,
        {
            "SPDXID",
            "creationInfo",
            "dataLicense",
            "documentNamespace",
            "files",
            "hasExtractedLicensingInfos",
            "name",
            "packages",
            "relationships",
            "spdxVersion",
        },
        field,
    )
    if (
        predicate["spdxVersion"] != "SPDX-2.3"
        or predicate["SPDXID"] != "SPDXRef-DOCUMENT"
        or predicate["dataLicense"] != "CC0-1.0"
        or predicate["name"] != "sbom"
    ):
        fail(f"{field} document identity is invalid")
    require_https(predicate["documentNamespace"], f"{field}.documentNamespace")
    creation = require_mapping(predicate["creationInfo"], f"{field}.creationInfo")
    require_timestamp(creation.get("created"), f"{field}.creationInfo.created")
    creators = creation.get("creators")
    if not isinstance(creators, list) or not creators:
        fail(f"{field} creators must be non-empty strings")
    for index, item in enumerate(creators):
        require_string(item, f"{field}.creationInfo.creators[{index}]")
    if not any(item.startswith("Tool: syft-") for item in creators):
        fail(f"{field} does not identify Syft as its generator")
    if not any(item.startswith("Tool: buildkit-") for item in creators):
        fail(f"{field} does not identify BuildKit as its generator")
    packages = predicate["packages"]
    if not isinstance(packages, list) or not packages:
        fail(f"{field} packages must be non-empty")
    for position, item in enumerate(packages):
        package = require_mapping(item, f"{field}.packages[{position}]")
        require_string(
            package.get("SPDXID"), f"{field}.packages[{position}].SPDXID"
        )
        require_string(package.get("name"), f"{field}.packages[{position}].name")
    relationships = predicate["relationships"]
    if not isinstance(relationships, list) or not relationships:
        fail(f"{field} relationships must be non-empty")
    for position, item in enumerate(relationships):
        relationship = require_mapping(
            item, f"{field}.relationships[{position}]"
        )
        for key in ("spdxElementId", "relatedSpdxElement", "relationshipType"):
            require_string(
                relationship.get(key),
                f"{field}.relationships[{position}].{key}",
            )
    files = predicate["files"]
    licenses = predicate["hasExtractedLicensingInfos"]
    if not isinstance(files, list) or not files:
        fail(f"{field} files must be non-empty")
    if not isinstance(licenses, list):
        fail(f"{field} extracted licensing information must be an array")


def require_buildkit_args(
    args: Any,
    expected: dict[str, str],
    field: str,
    require_frontend: bool = True,
) -> dict[str, Any]:
    args = require_mapping(args, field)
    for key, value in expected.items():
        if args.get(key) != value:
            fail(f"{field}.{key} does not match the release identity")
    if require_frontend:
        frontend = require_string(args.get("cmdline"), f"{field}.cmdline")
        if args.get("source") != frontend:
            fail(f"{field}.source does not match its pinned Dockerfile frontend")
    return args


def verify_buildkit_slsa(
    predicate: dict[str, Any],
    container_evidence: dict[str, Any],
    variant_name: str,
    platform: str,
) -> None:
    field = f"{platform} BuildKit SLSA"
    require_exact(predicate, {"buildDefinition", "runDetails"}, field)
    build = require_mapping(
        predicate["buildDefinition"], f"{field}.buildDefinition"
    )
    require_exact(
        build,
        {
            "buildType",
            "externalParameters",
            "internalParameters",
            "resolvedDependencies",
        },
        f"{field}.buildDefinition",
    )
    if build["buildType"] != BUILDKIT_BUILD_TYPE:
        fail(f"{field} build type is invalid")
    release = require_mapping(container_evidence.get("release"), "container release")
    release_tag = require_string(release.get("tag"), "container release.tag")
    source_sha = require_sha(release.get("sourceSha"), "container release.sourceSha")
    run_id = require_positive(
        release.get("workflowRunId"), "container release.workflowRunId"
    )
    run_attempt = require_positive(
        release.get("workflowRunAttempt"),
        "container release.workflowRunAttempt",
    )
    source_url = f"https://github.com/{CONSUMER_REPOSITORY}"
    title = CONSUMER_REPOSITORY.split("/", 1)[1]
    if variant_name != "public":
        title = f"{title}-{variant_name}"
    expected_args = {
        "build-arg:COLLECTION_PROFILE": variant_name,
        "label:org.opencontainers.image.revision": source_sha,
        "label:org.opencontainers.image.source": source_url,
        "label:org.opencontainers.image.title": title,
        "label:org.opencontainers.image.version": release_tag.removeprefix("v"),
    }
    external = require_mapping(
        build["externalParameters"], f"{field}.externalParameters"
    )
    require_exact(
        external,
        {"configSource", "request"},
        f"{field}.externalParameters",
    )
    if external["configSource"] != {"path": "Dockerfile"}:
        fail(f"{field} config source is not the release Dockerfile")
    request = require_mapping(
        external["request"], f"{field}.externalParameters.request"
    )
    require_exact(
        request,
        {
            "args",
            "compatibilityVersion",
            "frontend",
            "locals",
            "root",
            "secrets",
        },
        f"{field}.externalParameters.request",
    )
    if request["compatibilityVersion"] != 30 or request["frontend"] != "gateway.v0":
        fail(f"{field} BuildKit request frontend is invalid")
    if request["locals"] != [{"name": "context"}, {"name": "dockerfile"}]:
        fail(f"{field} BuildKit request locals are invalid")
    if not isinstance(request["secrets"], list):
        fail(f"{field} BuildKit secret identifiers must be an array")
    request_args = require_buildkit_args(
        request["args"], expected_args, f"{field}.externalParameters.request.args"
    )
    created_key = "label:org.opencontainers.image.created"
    require_timestamp(
        request_args.get(created_key),
        f"{field}.externalParameters.request.args.{created_key}",
    )
    root = require_mapping(
        request["root"], f"{field}.externalParameters.request.root"
    )
    if root.get("configSource") != {"path": "Dockerfile"}:
        fail(f"{field} root config source is not the release Dockerfile")
    root_request = require_mapping(
        root.get("request"), f"{field}.externalParameters.request.root.request"
    )
    root_args = require_buildkit_args(
        root_request.get("args"),
        expected_args,
        f"{field}.externalParameters.request.root.request.args",
        require_frontend=False,
    )
    expected_vcs = {
        "vcs:localdir:context": ".",
        "vcs:localdir:dockerfile": ".",
        "vcs:revision": source_sha,
        "vcs:source": source_url,
    }
    for key, value in expected_vcs.items():
        if root_args.get(key) != value:
            fail(f"{field} root request {key} does not match the release source")
    if root_args.get(created_key) != request_args[created_key]:
        fail(f"{field} root request creation label does not match")

    internal = require_mapping(
        build["internalParameters"], f"{field}.internalParameters"
    )
    expected_internal = {
        "builderPlatform": "linux/amd64",
        "github_actor": CONTAINER_RELEASE_ACTOR,
        "github_event_name": "workflow_dispatch",
        "github_job": CONTAINER_WORKFLOW_JOB,
        "github_ref": f"refs/tags/{release_tag}",
        "github_ref_name": release_tag,
        "github_ref_protected": "true",
        "github_ref_type": "tag",
        "github_repository": CONSUMER_REPOSITORY,
        "github_run_attempt": str(run_attempt),
        "github_run_id": str(run_id),
        "github_workflow": CONTAINER_WORKFLOW_NAME,
        "github_workflow_ref": (
            f"{CONSUMER_REPOSITORY}/{CONTAINER_WORKFLOW}@"
            f"refs/tags/{release_tag}"
        ),
        "github_workflow_sha": source_sha,
    }
    for key, value in expected_internal.items():
        if internal.get(key) != value:
            fail(f"{field} internal parameter {key} does not match")
    dependencies = build["resolvedDependencies"]
    if not isinstance(dependencies, list) or not dependencies:
        fail(f"{field} resolved dependencies must be non-empty")
    for position, item in enumerate(dependencies):
        require_mapping(item, f"{field}.resolvedDependencies[{position}]")

    run_details = require_mapping(predicate["runDetails"], f"{field}.runDetails")
    require_exact(run_details, {"builder", "metadata"}, f"{field}.runDetails")
    expected_builder = {
        "id": (
            f"https://github.com/{CONSUMER_REPOSITORY}/actions/runs/"
            f"{run_id}/attempts/{run_attempt}"
        )
    }
    if run_details["builder"] != expected_builder:
        fail(f"{field} builder identity is invalid")
    metadata = require_mapping(
        run_details["metadata"], f"{field}.runDetails.metadata"
    )
    require_exact(
        metadata,
        {
            "buildkit_completeness",
            "buildkit_metadata",
            "finishedOn",
            "invocationId",
            "startedOn",
        },
        f"{field}.runDetails.metadata",
    )
    completeness = require_mapping(
        metadata["buildkit_completeness"],
        f"{field}.runDetails.metadata.buildkit_completeness",
    )
    require_exact(
        completeness,
        {"request", "resolvedDependencies"},
        f"{field}.runDetails.metadata.buildkit_completeness",
    )
    if completeness["request"] is not True or not isinstance(
        completeness["resolvedDependencies"], bool
    ):
        fail(f"{field} BuildKit completeness is invalid")
    buildkit_metadata = require_mapping(
        metadata["buildkit_metadata"],
        f"{field}.runDetails.metadata.buildkit_metadata",
    )
    if not buildkit_metadata:
        fail(f"{field} BuildKit metadata must be non-empty")
    require_string(
        metadata["invocationId"], f"{field}.runDetails.metadata.invocationId"
    )
    started = require_buildkit_timestamp(
        metadata["startedOn"], f"{field}.runDetails.metadata.startedOn"
    )
    finished = require_buildkit_timestamp(
        metadata["finishedOn"], f"{field}.runDetails.metadata.finishedOn"
    )
    if started >= finished:
        fail(f"{field} build timestamps are not increasing")


def verify_buildkit_attestations(
    container_evidence: dict[str, Any],
    variant_name: str,
    index_path: Path,
    attestation_root: Path,
) -> None:
    if variant_name not in VARIANTS:
        fail("variant is not allowlisted")
    if attestation_root.is_symlink() or not attestation_root.is_dir():
        fail("BuildKit attestation root must be a regular directory")
    variants = require_mapping(
        container_evidence.get("variants"), "container variants"
    )
    variant = require_mapping(
        variants.get(variant_name), f"container variants.{variant_name}"
    )
    index = load_verified_index(
        container_evidence, variant_name, index_path
    )
    bindings = verify_index(container_evidence, variant_name, index)
    image = require_string(variant.get("image"), f"{variant_name}.image")
    release = require_mapping(container_evidence.get("release"), "container release")
    source_sha = require_sha(release.get("sourceSha"), "container release.sourceSha")
    workflow_run_id = require_positive(
        release.get("workflowRunId"), "container release.workflowRunId"
    )
    workflow_run_attempt = require_positive(
        release.get("workflowRunAttempt"), "container release.workflowRunAttempt"
    )
    predicate_paths = {
        SPDX_PREDICATE: "spdx",
        SLSA_PREDICATE: "slsa",
    }
    for platform in PLATFORMS:
        basename = platform.replace("/", "-")
        manifest_path = attestation_root / f"{basename}-manifest.json"
        manifest_snapshot = secure_file_snapshot(
            manifest_path,
            FINALIZER_INPUT_MAX_BYTES,
            capture_payload=True,
        )
        binding = bindings[platform]
        if manifest_snapshot.digest != binding["attestationDigest"]:
            fail(
                f"{platform} attestation manifest is not bound to the "
                "signed OCI index"
            )
        manifest = require_mapping(
            parse_json_snapshot(
                manifest_snapshot, f"{platform} attestation manifest"
            ),
            f"{platform} attestation manifest",
        )
        require_exact(
            manifest,
            {"schemaVersion", "mediaType", "config", "layers"},
            f"{platform} attestation manifest",
        )
        if (
            manifest["schemaVersion"] != 2
            or manifest["mediaType"]
            != "application/vnd.oci.image.manifest.v1+json"
        ):
            fail(f"{platform} attestation manifest type is invalid")
        config = require_mapping(
            manifest["config"], f"{platform} attestation manifest config"
        )
        require_exact(
            config,
            {"mediaType", "digest", "size"},
            f"{platform} attestation manifest config",
        )
        if config["mediaType"] != "application/vnd.oci.image.config.v1+json":
            fail(f"{platform} attestation config type is invalid")
        require_digest(config["digest"], f"{platform} attestation config digest")
        require_positive(config["size"], f"{platform} attestation config size")
        layers = manifest["layers"]
        if not isinstance(layers, list) or len(layers) != len(predicate_paths):
            fail(f"{platform} attestation manifest must have exactly two layers")
        layer_by_predicate: dict[str, dict[str, Any]] = {}
        for position, item in enumerate(layers):
            layer = require_mapping(
                item, f"{platform} attestation layer[{position}]"
            )
            require_exact(
                layer,
                {"mediaType", "digest", "size", "annotations"},
                f"{platform} attestation layer[{position}]",
            )
            if layer["mediaType"] != "application/vnd.in-toto+json":
                fail(f"{platform} attestation layer media type is invalid")
            require_digest(
                layer["digest"], f"{platform} attestation layer digest"
            )
            require_positive(
                layer["size"], f"{platform} attestation layer size"
            )
            annotations = require_mapping(
                layer["annotations"],
                f"{platform} attestation layer annotations",
            )
            require_exact(
                annotations,
                {"in-toto.io/predicate-type"},
                f"{platform} attestation layer annotations",
            )
            predicate_type = annotations["in-toto.io/predicate-type"]
            if predicate_type not in predicate_paths:
                fail(f"{platform} attestation predicate type is unsupported")
            if predicate_type in layer_by_predicate:
                fail(f"{platform} attestation predicate type is duplicated")
            layer_by_predicate[predicate_type] = layer
        if set(layer_by_predicate) != set(predicate_paths):
            fail(f"{platform} attestation manifest is missing SPDX or SLSA")
        for predicate_type, filename in predicate_paths.items():
            statement_path = attestation_root / f"{basename}-{filename}.json"
            statement_snapshot = secure_file_snapshot(
                statement_path,
                FINALIZER_INPUT_MAX_BYTES,
                capture_payload=True,
            )
            layer = layer_by_predicate[predicate_type]
            if (
                statement_snapshot.digest != layer["digest"]
                or statement_snapshot.size != layer["size"]
            ):
                fail(
                    f"{platform} {filename} payload is not bound to its "
                    "attestation manifest"
                )
            statement = parse_json_snapshot(
                statement_snapshot, f"{platform} {filename} statement"
            )
            predicate = verify_buildkit_statement(
                statement,
                predicate_type,
                image,
                source_sha,
                workflow_run_id,
                workflow_run_attempt,
                platform,
                binding["platformDigest"],
            )
            if predicate_type == SPDX_PREDICATE:
                verify_buildkit_spdx(predicate, platform)
            else:
                verify_buildkit_slsa(
                    predicate, container_evidence, variant_name, platform
                )


def verify_installed_collection(
    payload: Any, collection: str, version: str | None
) -> dict[str, Any]:
    if version is not None and not is_semver(version):
        fail("expected installed collection version is invalid")
    payload = require_mapping(payload, "ansible-galaxy output")
    versions: list[str] = []
    for root in payload.values():
        if not isinstance(root, dict) or collection not in root:
            continue
        entry = root[collection]
        if not isinstance(entry, dict) or not isinstance(entry.get("version"), str):
            fail("ansible-galaxy collection entry is invalid")
        versions.append(
            require_string(entry["version"], "ansible-galaxy collection version")
        )
    expected = [] if version is None else [version]
    if versions != expected:
        fail("installed collection state does not match the expected contract")
    return {
        "collection": collection,
        "state": "absent" if version is None else "present",
        "installedVersion": None if version is None else versions[0],
    }


def identity_from_args(args: argparse.Namespace) -> DispatchIdentity:
    identity = DispatchIdentity(
        correlation_id=args.correlation_id,
        producer_evidence_url=args.producer_evidence_url,
        producer_evidence_bundle_url=args.producer_evidence_bundle_url,
        producer_evidence_sha256=args.producer_evidence_sha256,
        consumer_pr=args.consumer_pr,
        consumer_head_sha=args.consumer_head_sha,
        consumer_merge_sha=args.consumer_merge_sha,
        container_release_id=args.container_release_id,
        container_release_tag=args.container_release_tag,
        container_release_run_id=args.container_release_run_id,
        container_publish_run_attempt=args.container_publish_run_attempt,
    )
    identity.validate()
    return identity


def add_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--producer-evidence-url", required=True)
    parser.add_argument("--producer-evidence-bundle-url", required=True)
    parser.add_argument("--producer-evidence-sha256", required=True)
    parser.add_argument("--consumer-pr", type=int, required=True)
    parser.add_argument("--consumer-head-sha", required=True)
    parser.add_argument("--consumer-merge-sha", required=True)
    parser.add_argument("--container-release-id", type=int, required=True)
    parser.add_argument("--container-release-tag", required=True)
    parser.add_argument("--container-release-run-id", type=int, required=True)
    parser.add_argument(
        "--container-publish-run-attempt", type=int, required=True
    )


def add_evidence_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--producer-evidence", type=Path, required=True)
    parser.add_argument("--container-evidence", type=Path, required=True)
    parser.add_argument("--profiles", type=Path, required=True)


def add_run_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)


def validated_inputs(
    args: argparse.Namespace,
) -> tuple[
    DispatchIdentity,
    dict[str, dict[str, Any]],
    dict[str, Any],
    dict[str, Any],
    SecureFileSnapshot,
    SecureFileSnapshot,
]:
    identity = identity_from_args(args)
    profiles = load_profiles(args.profiles)
    producer_snapshot = secure_file_snapshot(
        args.producer_evidence,
        RELEASE_ASSET_MAX_BYTES,
        capture_payload=True,
    )
    if producer_snapshot.digest != (
        f"sha256:{identity.producer_evidence_sha256}"
    ):
        fail("producer evidence file digest does not match dispatch identity")
    producer_payload = parse_json_snapshot(
        producer_snapshot, "producer evidence"
    )
    producer = validate_producer_evidence(producer_payload, identity, profiles)
    container_snapshot = secure_file_snapshot(
        args.container_evidence,
        RELEASE_ASSET_MAX_BYTES,
        capture_payload=True,
    )
    container_payload = parse_json_snapshot(
        container_snapshot, "container evidence"
    )
    container = validate_container_evidence(container_payload, identity, producer)
    return (
        identity,
        profiles,
        producer,
        container,
        producer_snapshot,
        container_snapshot,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = ValueFreeArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    validate_inputs = commands.add_parser("validate-inputs")
    add_identity_arguments(validate_inputs)

    preflight = commands.add_parser("preflight")
    add_identity_arguments(preflight)
    add_evidence_arguments(preflight)

    profile = commands.add_parser("profile-command")
    profile.add_argument("--profiles", type=Path, required=True)
    profile.add_argument("--profile", required=True)

    producer_materials = commands.add_parser("verify-producer-materials")
    producer_materials.add_argument(
        "--producer-evidence", type=Path, required=True
    )
    producer_materials.add_argument("--collection", type=Path, required=True)
    producer_materials.add_argument("--sbom", type=Path, required=True)
    producer_materials.add_argument("--provenance", type=Path, required=True)

    index = commands.add_parser("verify-index")
    index.add_argument("--container-evidence", type=Path, required=True)
    index.add_argument("--variant", required=True)
    index.add_argument("--index", type=Path, required=True)

    buildkit = commands.add_parser("verify-buildkit-attestations")
    buildkit.add_argument("--container-evidence", type=Path, required=True)
    buildkit.add_argument("--variant", required=True)
    buildkit.add_argument("--index", type=Path, required=True)
    buildkit.add_argument("--attestation-root", type=Path, required=True)

    container_materials = commands.add_parser("verify-container-materials")
    container_materials.add_argument(
        "--container-evidence", type=Path, required=True
    )
    container_materials.add_argument("--variant", required=True)
    container_materials.add_argument("--signature", type=Path, required=True)
    container_materials.add_argument(
        "--live-signature", type=Path, required=True
    )
    container_materials.add_argument("--sbom", type=Path, required=True)
    container_materials.add_argument("--provenance", type=Path, required=True)

    installed = commands.add_parser("verify-installed")
    installed.add_argument("--result", type=Path, required=True)
    installed.add_argument("--collection", required=True)
    installed.add_argument("--observation-output", type=Path, required=True)
    installed_expectation = installed.add_mutually_exclusive_group(
        required=True
    )
    installed_expectation.add_argument("--version")
    installed_expectation.add_argument("--expect-absent", action="store_true")

    receipt = commands.add_parser("write-receipt")
    add_identity_arguments(receipt)
    add_evidence_arguments(receipt)
    add_run_arguments(receipt)
    receipt.add_argument("--receipt-id", required=True)
    receipt.add_argument("--observations", type=Path, required=True)
    receipt.add_argument("--checked-at", required=True)
    receipt.add_argument("--output", type=Path, required=True)

    report = commands.add_parser("write-report")
    add_identity_arguments(report)
    add_evidence_arguments(report)
    add_run_arguments(report)
    report.add_argument("--receipts", type=Path, required=True)
    report.add_argument("--receipt-bundle-output", type=Path, required=True)
    report.add_argument("--output", type=Path, required=True)

    finalize = commands.add_parser("finalize")
    add_identity_arguments(finalize)
    add_evidence_arguments(finalize)
    finalize.add_argument("--verification-report", type=Path, required=True)
    finalize.add_argument("--receipt-bundle", type=Path, required=True)
    add_run_arguments(finalize)
    finalize.add_argument("--delivered-output", type=Path, required=True)
    finalize.add_argument("--acceptance-output", type=Path, required=True)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    parser.sanitize_errors = False
    try:
        if args.command == "validate-inputs":
            identity_from_args(args)
            print("immutable dispatch inputs accepted")
        elif args.command == "preflight":
            _, _, producer, _, _, _ = validated_inputs(args)
            print(
                f"preflight accepted {producer['metadata']['id']} with "
                f"profile {producer['acceptance']['profile']}"
            )
        elif args.command == "profile-command":
            profile = eligible_profile(load_profiles(args.profiles), args.profile)
            print(json.dumps(profile["containerCommand"], separators=(",", ":")))
        elif args.command == "verify-producer-materials":
            producer = require_mapping(
                load_json(args.producer_evidence, "producer evidence"),
                "producer evidence",
            )
            verify_producer_materials(
                producer,
                args.collection,
                args.sbom,
                args.provenance,
            )
            print("producer collection, SBOM and provenance accepted")
        elif args.command == "verify-index":
            container = require_mapping(
                load_json(args.container_evidence, "container evidence"),
                "container evidence",
            )
            verify_index(
                container,
                args.variant,
                load_verified_index(container, args.variant, args.index),
            )
            print(f"OCI index accepted for {args.variant}")
        elif args.command == "verify-buildkit-attestations":
            verify_buildkit_attestations(
                require_mapping(
                    load_json(args.container_evidence, "container evidence"),
                    "container evidence",
                ),
                args.variant,
                args.index,
                args.attestation_root,
            )
            print(
                f"cryptographically bound BuildKit SPDX and SLSA accepted "
                f"for {args.variant}"
            )
        elif args.command == "verify-container-materials":
            verify_container_materials(
                require_mapping(
                    load_json(args.container_evidence, "container evidence"),
                    "container evidence",
                ),
                args.variant,
                args.signature,
                args.live_signature,
                args.sbom,
                args.provenance,
            )
            print(f"signed container materials accepted for {args.variant}")
        elif args.command == "verify-installed":
            observation = verify_installed_collection(
                load_json(args.result, "ansible-galaxy result"),
                args.collection,
                None if args.expect_absent else args.version,
            )
            write_json(args.observation_output, observation)
            expected = "absent" if args.expect_absent else args.version
            print(f"installed collection state accepted: {args.collection} {expected}")
        elif args.command == "write-receipt":
            (
                identity,
                profiles,
                producer,
                container,
                producer_snapshot,
                container_snapshot,
            ) = validated_inputs(args)
            if args.receipt_id not in EXPECTED_RECEIPT_TYPES:
                fail("receipt ID is not part of the exact MLX-90 receipt set")
            if args.output.name != f"{args.receipt_id}.json":
                fail("verification receipt output filename must equal receiptId.json")
            write_json(
                args.output,
                verification_receipt(
                    identity,
                    profiles,
                    args.producer_evidence,
                    args.container_evidence,
                    producer,
                    container,
                    receipt_id=args.receipt_id,
                    observations=load_json(
                        args.observations,
                        f"{args.receipt_id} observations",
                    ),
                    checked_at=args.checked_at,
                    workflow_sha=args.workflow_sha,
                    run_id=args.run_id,
                    run_attempt=args.run_attempt,
                    producer_digest=producer_snapshot.digest,
                    container_digest=container_snapshot.digest,
                ),
            )
            print("wrote verification receipt")
        elif args.command == "write-report":
            (
                identity,
                profiles,
                producer,
                container,
                producer_snapshot,
                container_snapshot,
            ) = validated_inputs(args)
            write_json(
                args.output,
                verification_report(
                    identity,
                    profiles,
                    args.producer_evidence,
                    args.container_evidence,
                    producer,
                    container,
                    args.receipts,
                    args.receipt_bundle_output,
                    workflow_sha=args.workflow_sha,
                    run_id=args.run_id,
                    run_attempt=args.run_attempt,
                    producer_digest=producer_snapshot.digest,
                    container_digest=container_snapshot.digest,
                ),
            )
            print("wrote verification report")
        elif args.command == "finalize":
            (
                identity,
                profiles,
                producer,
                container,
                producer_snapshot,
                container_snapshot,
            ) = validated_inputs(args)
            verification = validate_verification_report(
                load_json(args.verification_report, "verification report"),
                identity,
                profiles,
                args.producer_evidence,
                args.container_evidence,
                args.receipt_bundle,
                producer,
                container,
                workflow_sha=args.workflow_sha,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                producer_digest=producer_snapshot.digest,
                container_digest=container_snapshot.digest,
            )
            delivered, acceptance = build_final_evidence(
                identity,
                producer,
                container,
                verification,
                workflow_sha=args.workflow_sha,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
            )
            write_json_pair(
                args.delivered_output,
                delivered,
                args.acceptance_output,
                acceptance,
            )
            print("wrote delivered evidence")
            print("wrote final acceptance")
        else:  # pragma: no cover - argparse enforces subcommands.
            fail("unsupported command")
    except (KeyError, TypeError, IndexError):
        parser.error(CLI_CONTRACT_ERROR)
    except OSError:
        parser.error(CLI_IO_ERROR)
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
