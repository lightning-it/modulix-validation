#!/usr/bin/env python3
"""Validate one immutable MLX-90 collection candidate and emit its receipt.

The command deliberately separates the public dispatch contract, the private
Nexus readback, and the final receipt.  No credential is accepted through a
command-line argument or written to evidence.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any


SOURCE_REPOSITORY = "lightning-it/ansible-collection-supplementary"
SOURCE_WORKFLOW = ".github/workflows/collection-publish.yml"
CONTROLLER_REPOSITORY = "lightning-it/modulix-validation"
CONTROLLER_REF = "refs/heads/main"
CONTROLLER_WORKFLOW = ".github/workflows/mlx90-collection-candidate-validation.yml"
APP_SLUG = "lightning-it-release-automation"
APP_INSTALLATION_ID = 148019054
APP_ACTOR = f"{APP_SLUG}[bot]"
APP_ACTOR_ID = 307565056
APP_PERMISSIONS = {
    "actions": "write",
    "checks": "read",
    "contents": "write",
    "metadata": "read",
    "pull_requests": "write",
}
REQUEST_API_VERSION = "lit.mlx90.collection-validation-request/v2"
REQUEST_KIND = "CollectionValidationRequest"
RECEIPT_API_VERSION = "lit.mlx90.collection-validation-receipt/v2"
RECEIPT_KIND = "CollectionValidationReceipt"
RECEIPT_NAME = "mlx90-collection-validation-receipt.json"
ARTIFACT_PREFIX = "mlx90-collection-validation-"
MAX_REQUEST_BYTES = 32 * 1024
MAX_CANDIDATE_BYTES = 512 * 1024 * 1024
MAX_MEMBER_COUNT = 20_000
MAX_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REQUEST_ID = re.compile(r"[0-9a-f]{64}\Z")
VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\Z"
)
EVIDENCE_ID = re.compile(r"MLX90-[A-Z0-9][A-Z0-9._-]{2,121}\Z")
REPOSITORY_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,126}\Z")
ARTIFACT_NAME = re.compile(
    r"lit-supplementary-(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.tar\.gz\Z"
)


class ContractError(ValueError):
    """The immutable validation contract was not satisfied."""


def fail(message: str) -> None:
    raise ContractError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("JSON contains a duplicate object key")
        result[key] = value
    return result


def strict_loads(payload: str, label: str) -> Any:
    try:
        return json.loads(
            payload,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda _value: fail(
                f"{label} contains a non-standard JSON constant"
            ),
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ContractError(f"{label} is not valid JSON") from error


def read_json(path: Path, label: str, *, maximum: int = MAX_REQUEST_BYTES) -> Any:
    if path.is_symlink() or not path.is_file():
        fail(f"{label} must be a regular non-symlink file")
    status = path.stat()
    if not stat.S_ISREG(status.st_mode) or status.st_size > maximum:
        fail(f"{label} exceeds its bounded regular-file contract")
    try:
        payload = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ContractError(f"{label} is not readable UTF-8") from error
    return strict_loads(payload, label)


def canonical_compact(value: Mapping[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def canonical_pretty(value: Mapping[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"


def exact_keys(value: object, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} fields differ from the v2 contract")
    return value


def positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        fail(f"{label} must be a positive integer")
    return value


def exact_actor(value: object, label: str) -> None:
    actor = exact_keys(value, set(value) if isinstance(value, dict) else set(), label)
    if (
        actor.get("login") != APP_ACTOR
        or actor.get("id") != APP_ACTOR_ID
        or actor.get("type") != "Bot"
    ):
        fail(f"{label} is not the approved release-automation App actor")


def _validate_url_contract(candidate: Mapping[str, Any]) -> None:
    nexus = exact_keys(
        candidate.get("nexus"),
        {"repository", "repositoryUrl", "url"},
        "request.candidate.nexus",
    )
    repository = nexus.get("repository")
    repository_url = nexus.get("repositoryUrl")
    artifact_url = nexus.get("url")
    if not isinstance(repository, str) or REPOSITORY_NAME.fullmatch(repository) is None:
        fail("request Nexus repository name is invalid")
    if not isinstance(repository_url, str) or not isinstance(artifact_url, str):
        fail("request Nexus URLs must be strings")
    base = urllib.parse.urlsplit(repository_url)
    artifact = urllib.parse.urlsplit(artifact_url)
    if (
        base.scheme != "https"
        or not base.hostname
        or base.username is not None
        or base.password is not None
        or base.query
        or base.fragment
        or base.path != f"/repository/{repository}"
    ):
        fail("request Nexus repository URL is not a credential-free native endpoint")
    expected_artifact_url = (
        f"{repository_url}/api/v3/plugin/ansible/content/published/"
        f"collections/artifacts/{candidate['name']}"
    )
    if (
        artifact_url != expected_artifact_url
        or artifact.scheme != base.scheme
        or artifact.netloc != base.netloc
        or artifact.query
        or artifact.fragment
    ):
        fail("request Nexus artifact URL differs from its native Galaxy v3 binding")


def validate_request(
    request_json: str,
    request_id: str,
    *,
    controller_sha: str,
    repository: str,
    ref: str,
    actor: str,
    actor_id: int,
    triggering_actor: str,
) -> dict[str, Any]:
    if len(request_json.encode("utf-8")) > MAX_REQUEST_BYTES:
        fail("request JSON exceeds the bounded input contract")
    if REQUEST_ID.fullmatch(request_id) is None:
        fail("request ID is not a lowercase SHA-256")
    value = strict_loads(request_json, "request JSON")
    request = exact_keys(
        value,
        {"apiVersion", "kind", "source", "security", "candidate", "controller"},
        "request",
    )
    if canonical_compact(request) != request_json:
        fail("request JSON is not canonical compact sorted JSON")
    actual_id = hashlib.sha256(request_json.encode("utf-8")).hexdigest()
    if actual_id != request_id:
        fail("request ID does not match the exact request bytes")
    if request.get("apiVersion") != REQUEST_API_VERSION or request.get("kind") != REQUEST_KIND:
        fail("request schema is unsupported")
    if (
        repository != CONTROLLER_REPOSITORY
        or ref != CONTROLLER_REF
        or SHA.fullmatch(controller_sha) is None
        or actor != APP_ACTOR
        or actor_id != APP_ACTOR_ID
        or triggering_actor != APP_ACTOR
    ):
        fail("workflow dispatch context is not the approved App/main controller")

    source = exact_keys(
        request.get("source"),
        {"repository", "workflow", "sha", "runId", "runAttempt"},
        "request.source",
    )
    if (
        source.get("repository") != SOURCE_REPOSITORY
        or source.get("workflow") != SOURCE_WORKFLOW
        or not isinstance(source.get("sha"), str)
        or SHA.fullmatch(source["sha"]) is None
    ):
        fail("request source identity differs from the Golden Path producer")
    positive_integer(source.get("runId"), "request source run ID")
    positive_integer(source.get("runAttempt"), "request source run attempt")

    security = exact_keys(
        request.get("security"), {"evidenceId", "humanActions"}, "request.security"
    )
    if (
        not isinstance(security.get("evidenceId"), str)
        or EVIDENCE_ID.fullmatch(security["evidenceId"]) is None
        or security.get("humanActions") != 0
    ):
        fail("request Security evidence binding is invalid")

    candidate = exact_keys(
        request.get("candidate"),
        {"name", "sha256", "size", "version", "nexus"},
        "request.candidate",
    )
    if (
        not isinstance(candidate.get("version"), str)
        or VERSION.fullmatch(candidate["version"]) is None
        or candidate.get("name") != f"lit-supplementary-{candidate['version']}.tar.gz"
        or ARTIFACT_NAME.fullmatch(str(candidate.get("name"))) is None
        or not isinstance(candidate.get("sha256"), str)
        or DIGEST.fullmatch(candidate["sha256"]) is None
        or not 0 < positive_integer(candidate.get("size"), "candidate size") <= MAX_CANDIDATE_BYTES
    ):
        fail("request candidate identity is invalid")
    _validate_url_contract(candidate)

    controller = exact_keys(
        request.get("controller"),
        {"repository", "ref", "sha", "workflow"},
        "request.controller",
    )
    if controller != {
        "repository": CONTROLLER_REPOSITORY,
        "ref": CONTROLLER_REF,
        "sha": controller_sha,
        "workflow": CONTROLLER_WORKFLOW,
    }:
        fail("request controller binding differs from the executing protected main SHA")
    return dict(request)


def validate_controller_run(
    run: object,
    request: Mapping[str, Any],
    *,
    run_id: int,
    run_attempt: int,
) -> None:
    payload = exact_keys(
        run, set(run) if isinstance(run, dict) else set(), "controller run"
    )
    repository = payload.get("repository")
    head_repository = payload.get("head_repository")
    if not isinstance(repository, dict) or not isinstance(head_repository, dict):
        fail("controller run repository identity is incomplete")
    exact_actor(payload.get("actor"), "controller run actor")
    exact_actor(payload.get("triggering_actor"), "controller run triggering actor")
    if (
        payload.get("id") != run_id
        or payload.get("run_attempt") != run_attempt
        or payload.get("event") != "workflow_dispatch"
        or payload.get("path") != CONTROLLER_WORKFLOW
        or payload.get("head_sha") != request["controller"]["sha"]
        or payload.get("head_branch") != "main"
        or payload.get("status") != "in_progress"
        or payload.get("conclusion") is not None
        or repository.get("full_name") != CONTROLLER_REPOSITORY
        or head_repository.get("full_name") != CONTROLLER_REPOSITORY
    ):
        fail("controller run does not match the active App dispatch")


def validate_source_run(run: object, request: Mapping[str, Any]) -> None:
    payload = exact_keys(run, set(run) if isinstance(run, dict) else set(), "source run")
    source = request["source"]
    repository = payload.get("repository")
    head_repository = payload.get("head_repository")
    if not isinstance(repository, dict) or not isinstance(head_repository, dict):
        fail("source run repository identity is incomplete")
    exact_actor(payload.get("actor"), "source run actor")
    exact_actor(payload.get("triggering_actor"), "source run triggering actor")
    if (
        payload.get("id") != source["runId"]
        or payload.get("run_attempt") != source["runAttempt"]
        or payload.get("event") != "workflow_dispatch"
        or payload.get("path") != SOURCE_WORKFLOW
        or payload.get("head_sha") != source["sha"]
        or payload.get("head_branch") != "main"
        or payload.get("status") != "in_progress"
        or payload.get("conclusion") is not None
        or repository.get("full_name") != SOURCE_REPOSITORY
        or head_repository.get("full_name") != SOURCE_REPOSITORY
    ):
        fail("source run does not match the active App-dispatched producer run")


def validate_installation(
    installation: object,
    repositories: object,
    *,
    app_slug: str,
    installation_id: int,
) -> None:
    payload = exact_keys(
        installation,
        set(installation) if isinstance(installation, dict) else set(),
        "App installation",
    )
    account = payload.get("account")
    permissions = payload.get("permissions")
    if not isinstance(account, dict) or not isinstance(permissions, dict):
        fail("App installation response is incomplete")
    if (
        app_slug != APP_SLUG
        or installation_id != APP_INSTALLATION_ID
        or payload.get("id") != APP_INSTALLATION_ID
        or payload.get("app_slug") != APP_SLUG
        or payload.get("repository_selection") != "selected"
        or payload.get("target_type") != "Organization"
        or account.get("login") != "lightning-it"
        or permissions != APP_PERMISSIONS
    ):
        fail("App installation identity, selection, or permission matrix differs")
    if repositories != [SOURCE_REPOSITORY]:
        fail("read token repository scope is not exactly the Golden Path producer")


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def validate_candidate_archive(path: Path, request: Mapping[str, Any]) -> None:
    candidate = request["candidate"]
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > MAX_MEMBER_COUNT:
                fail("candidate archive member count is outside the bounded contract")
            seen: set[str] = set()
            expanded = 0
            manifest_member: tarfile.TarInfo | None = None
            for member in members:
                member_path = PurePosixPath(member.name)
                normalized = member_path.as_posix()
                if (
                    member_path.is_absolute()
                    or ".." in member_path.parts
                    or normalized in {"", "."}
                    or normalized in seen
                    or not (member.isfile() or member.isdir())
                    or member.size > MAX_CANDIDATE_BYTES
                ):
                    fail("candidate archive contains an unsafe member")
                seen.add(normalized)
                expanded += member.size
                if expanded > MAX_EXPANDED_BYTES:
                    fail("candidate archive expands beyond the bounded contract")
                if normalized == "MANIFEST.json":
                    manifest_member = member
            if expanded > path.stat().st_size * 1_000:
                fail("candidate archive compression ratio is unsafe")
            if manifest_member is None or not manifest_member.isfile():
                fail("candidate archive lacks a regular MANIFEST.json")
            stream = archive.extractfile(manifest_member)
            if stream is None:
                fail("candidate MANIFEST.json cannot be read")
            manifest = strict_loads(stream.read().decode("utf-8"), "candidate MANIFEST")
    except (OSError, tarfile.TarError, UnicodeDecodeError) as error:
        raise ContractError("candidate archive is not a valid bounded collection") from error
    info = manifest.get("collection_info") if isinstance(manifest, dict) else None
    if not isinstance(info, dict) or (
        info.get("namespace") != "lit"
        or info.get("name") != "supplementary"
        or str(info.get("version")) != candidate["version"]
    ):
        fail("candidate MANIFEST identity differs from the request")


def download_candidate(request: Mapping[str, Any], output_directory: Path) -> Path:
    username = os.environ.get("NEXUS_GALAXY_USERNAME", "")
    password = os.environ.get("NEXUS_GALAXY_PASSWORD", "")
    repository = os.environ.get("NEXUS_GALAXY_REPOSITORY", "")
    repository_url = os.environ.get("NEXUS_GALAXY_REPOSITORY_URL", "")
    candidate = request["candidate"]
    nexus = candidate["nexus"]
    if (
        not username
        or not password
        or repository != nexus["repository"]
        or repository_url != nexus["repositoryUrl"]
    ):
        fail("protected Nexus configuration differs from the immutable request")
    if output_directory.exists() or output_directory.is_symlink():
        fail("candidate output directory must start absent")
    output_directory.mkdir(parents=True, mode=0o700)
    destination = output_directory / candidate["name"]
    temporary = output_directory / f".{candidate['name']}.partial"
    credentials = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    request_object = urllib.request.Request(
        nexus["url"],
        headers={"Authorization": f"Basic {credentials}", "Accept": "application/octet-stream"},
        method="GET",
    )
    opener = urllib.request.build_opener(NoRedirects())
    try:
        with opener.open(request_object, timeout=120) as response, temporary.open("xb") as stream:
            if response.status != 200 or response.geturl() != nexus["url"]:
                fail("Nexus did not return the exact immutable artifact endpoint")
            written = 0
            while True:
                chunk = response.read(min(1024 * 1024, candidate["size"] + 1 - written))
                if not chunk:
                    break
                stream.write(chunk)
                written += len(chunk)
                if written > candidate["size"] or written > MAX_CANDIDATE_BYTES:
                    fail("Nexus readback exceeds the exact candidate size")
        if temporary.stat().st_size != candidate["size"]:
            fail("Nexus readback size differs from the immutable request")
        if file_sha256(temporary) != candidate["sha256"]:
            fail("Nexus readback digest differs from the immutable request")
        temporary.replace(destination)
        validate_candidate_archive(destination, request)
    except ContractError:
        if output_directory.exists() and not output_directory.is_symlink():
            shutil.rmtree(output_directory)
        raise
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as error:
        if output_directory.exists() and not output_directory.is_symlink():
            shutil.rmtree(output_directory)
        raise ContractError("Nexus exact-byte readback failed") from error
    return destination


def build_receipt(
    request: Mapping[str, Any],
    request_id: str,
    *,
    run_id: int,
    run_attempt: int,
    controller_sha: str,
    actor: str,
    actor_id: int,
) -> dict[str, Any]:
    if (
        REQUEST_ID.fullmatch(request_id) is None
        or hashlib.sha256(canonical_compact(request).encode()).hexdigest() != request_id
        or actor != APP_ACTOR
        or actor_id != APP_ACTOR_ID
        or request["controller"]["sha"] != controller_sha
    ):
        fail("receipt execution identity differs from the validated request")
    positive_integer(run_id, "validation run ID")
    positive_integer(run_attempt, "validation run attempt")
    digest = request["candidate"]["sha256"]
    return {
        "apiVersion": RECEIPT_API_VERSION,
        "kind": RECEIPT_KIND,
        "request": request,
        "requestId": f"sha256:{request_id}",
        "validation": {
            "actor": APP_ACTOR,
            "actorId": APP_ACTOR_ID,
            "actorType": "Bot",
            "conclusion": "success",
            "event": "workflow_dispatch",
            "humanActions": 0,
            "observations": {
                "applicationAcceptance": "passed",
                "candidateDigest": digest,
                "heavy": "passed",
                "nexusReadback": digest,
                "sourceRun": {
                    "repository": request["source"]["repository"],
                    "runAttempt": request["source"]["runAttempt"],
                    "runId": request["source"]["runId"],
                    "sha": request["source"]["sha"],
                    "workflow": request["source"]["workflow"],
                },
            },
            "receiptArtifact": f"{ARTIFACT_PREFIX}{request_id}",
            "ref": CONTROLLER_REF,
            "repository": CONTROLLER_REPOSITORY,
            "runAttempt": run_attempt,
            "runId": run_id,
            "sha": controller_sha,
            "workflow": CONTROLLER_WORKFLOW,
        },
        "decision": {
            "candidateUnchanged": True,
            "galaxyPublicationAuthorized": True,
            "releaseEligible": True,
        },
    }


def validated_request_from_file(path: Path, request_id: str) -> dict[str, Any]:
    value = read_json(path, "validated request")
    request = exact_keys(
        value,
        {"apiVersion", "kind", "source", "security", "candidate", "controller"},
        "validated request",
    )
    if (
        canonical_pretty(request) != path.read_text(encoding="utf-8")
        or REQUEST_ID.fullmatch(request_id) is None
        or hashlib.sha256(canonical_compact(request).encode()).hexdigest() != request_id
    ):
        fail("validated request file is not canonical or request-ID bound")
    return dict(request)


def command_validate(args: argparse.Namespace) -> None:
    request = validate_request(
        args.request_json,
        args.request_id,
        controller_sha=args.controller_sha,
        repository=args.repository,
        ref=args.ref,
        actor=args.actor,
        actor_id=args.actor_id,
        triggering_actor=args.triggering_actor,
    )
    validate_controller_run(
        read_json(args.controller_run, "controller run", maximum=512 * 1024),
        request,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
    )
    validate_source_run(read_json(args.source_run, "source run", maximum=512 * 1024), request)
    validate_installation(
        read_json(args.installation, "App installation", maximum=512 * 1024),
        read_json(args.installation_repositories, "App token repositories"),
        app_slug=args.app_slug,
        installation_id=args.installation_id,
    )
    if args.output.exists() or args.output.is_symlink():
        fail("validated request output must start absent")
    args.output.write_text(canonical_pretty(request), encoding="utf-8")


def command_readback(args: argparse.Namespace) -> None:
    request = validated_request_from_file(args.request, args.request_id)
    destination = download_candidate(request, args.output_directory)
    print(destination)


def command_receipt(args: argparse.Namespace) -> None:
    for label, result in (
        ("validate", args.validate_result),
        ("Nexus", args.nexus_result),
        ("Heavy", args.heavy_result),
        ("Application Acceptance", args.acceptance_result),
    ):
        if result != "success":
            fail(f"{label} prerequisite did not succeed")
    request = validated_request_from_file(args.request, args.request_id)
    receipt = build_receipt(
        request,
        args.request_id,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
        controller_sha=args.controller_sha,
        actor=args.actor,
        actor_id=args.actor_id,
    )
    if args.output_directory.exists() or args.output_directory.is_symlink():
        fail("receipt output directory must start absent")
    args.output_directory.mkdir(parents=True, mode=0o700)
    (args.output_directory / RECEIPT_NAME).write_text(
        canonical_pretty(receipt), encoding="utf-8"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-request")
    validate.add_argument("--request-id", required=True)
    validate.add_argument("--request-json", required=True)
    validate.add_argument("--controller-sha", required=True)
    validate.add_argument("--repository", required=True)
    validate.add_argument("--ref", required=True)
    validate.add_argument("--actor", required=True)
    validate.add_argument("--actor-id", type=int, required=True)
    validate.add_argument("--triggering-actor", required=True)
    validate.add_argument("--run-id", type=int, required=True)
    validate.add_argument("--run-attempt", type=int, required=True)
    validate.add_argument("--controller-run", type=Path, required=True)
    validate.add_argument("--source-run", type=Path, required=True)
    validate.add_argument("--installation", type=Path, required=True)
    validate.add_argument("--installation-repositories", type=Path, required=True)
    validate.add_argument("--app-slug", required=True)
    validate.add_argument("--installation-id", type=int, required=True)
    validate.add_argument("--output", type=Path, required=True)
    validate.set_defaults(handler=command_validate)

    readback = commands.add_parser("nexus-readback")
    readback.add_argument("--request", type=Path, required=True)
    readback.add_argument("--request-id", required=True)
    readback.add_argument("--output-directory", type=Path, required=True)
    readback.set_defaults(handler=command_readback)

    receipt = commands.add_parser("create-receipt")
    receipt.add_argument("--request", type=Path, required=True)
    receipt.add_argument("--request-id", required=True)
    receipt.add_argument("--run-id", type=int, required=True)
    receipt.add_argument("--run-attempt", type=int, required=True)
    receipt.add_argument("--controller-sha", required=True)
    receipt.add_argument("--actor", required=True)
    receipt.add_argument("--actor-id", type=int, required=True)
    receipt.add_argument("--validate-result", required=True)
    receipt.add_argument("--nexus-result", required=True)
    receipt.add_argument("--heavy-result", required=True)
    receipt.add_argument("--acceptance-result", required=True)
    receipt.add_argument("--output-directory", type=Path, required=True)
    receipt.set_defaults(handler=command_receipt)
    return parser


def main() -> int:
    try:
        args = build_parser().parse_args()
        args.handler(args)
    except (ContractError, OSError) as error:
        print(f"MLX-90 candidate validation failed: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
