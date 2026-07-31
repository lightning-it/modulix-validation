#!/usr/bin/env python3
"""Validate the v1 prevalidated-candidate evidence contract.

The verifier is intentionally independent of the infrastructure runners.  It
only accepts evidence that proves a successful, cleaned-up validation for the
exact candidate identity.  A shadow manifest is useful to prove wiring, but
can never be accepted as release evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = 1
DEFAULT_MAX_AGE_HOURS = 36
SHA_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class EvidenceError(ValueError):
    """Raised for an evidence contract violation with a stable error code."""


def fail(code: str) -> None:
    raise EvidenceError(code)


def require_mapping(value: Any, code: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        fail(code)
    return value


def require_list(value: Any, code: str) -> list[Any]:
    if not isinstance(value, list) or not value:
        fail(code)
    return value


def require_string(value: Any, code: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(code)
    return value


def require_sha(value: Any, code: str) -> str:
    value = require_string(value, code)
    if SHA_RE.fullmatch(value) is None:
        fail(code)
    return value


def require_digest(value: Any, code: str) -> str:
    value = require_string(value, code)
    if DIGEST_RE.fullmatch(value) is None:
        fail(code)
    return value


def require_reference(value: Any, code: str) -> str:
    value = require_string(value, code)
    if value.startswith(("https://", "artifact://", "github://")):
        return value
    fail(code)


def parse_timestamp(value: Any, code: str) -> datetime:
    value = require_string(value, code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(code)
    if parsed.tzinfo is None:
        fail(code)
    return parsed.astimezone(UTC)


def effective_max_age_hours(policy: Mapping[str, Any], requested: int) -> int:
    if not isinstance(requested, int) or not 1 <= requested <= DEFAULT_MAX_AGE_HOURS:
        fail("max_age_hours_invalid")
    declared = policy.get("max_age_hours", DEFAULT_MAX_AGE_HOURS)
    if not isinstance(declared, int) or not 1 <= declared <= DEFAULT_MAX_AGE_HOURS:
        fail("policy_max_age_invalid")
    return min(declared, requested)


@dataclass(frozen=True)
class ExpectedIdentity:
    repository: str
    source_sha: str
    git_tree: str | None = None
    artifact_digest: str | None = None

    def __post_init__(self) -> None:
        if REPOSITORY_RE.fullmatch(self.repository) is None:
            fail("expected_repository_invalid")
        require_sha(self.source_sha, "expected_source_sha_invalid")
        if self.git_tree is not None:
            require_sha(self.git_tree, "expected_git_tree_invalid")
        if self.artifact_digest is not None:
            require_digest(self.artifact_digest, "expected_artifact_digest_invalid")
        if self.git_tree is None and self.artifact_digest is None:
            fail("expected_candidate_identity_missing")


@dataclass(frozen=True)
class ExpectedControls:
    """Trusted expected control identities supplied outside the evidence document."""

    policy_sha: str
    matrix_sha: str
    validation_workflow_sha: str
    bom_digest: str

    def __post_init__(self) -> None:
        require_sha(self.policy_sha, "expected_policy_sha_invalid")
        require_sha(self.matrix_sha, "expected_matrix_sha_invalid")
        require_sha(
            self.validation_workflow_sha, "expected_validation_workflow_sha_invalid"
        )
        require_digest(self.bom_digest, "expected_bom_digest_invalid")


def canonical_bom_digest(bom: list[Any]) -> str:
    """Hash the BOM's deterministic canonical JSON representation.

    The BOM list must be sorted by repository, source SHA and artifact digest;
    object keys are sorted, non-ASCII is escaped and no insignificant whitespace
    is emitted.  This is intentionally independent of source formatting.
    """

    encoded = json.dumps(
        bom, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def validate_evidence(
    payload: Any,
    expected: ExpectedIdentity,
    controls: ExpectedControls,
    *,
    now: datetime | None = None,
    max_age_hours: int = DEFAULT_MAX_AGE_HOURS,
) -> None:
    """Fail closed unless *payload* proves the exact successfully cleaned-up candidate."""

    root = require_mapping(payload, "evidence_root_invalid")
    if root.get("schema_version") != SCHEMA_VERSION:
        fail("schema_version_unsupported")
    if root.get("kind") != "modulix-validation-evidence":
        fail("evidence_kind_invalid")
    if root.get("mode") != "executed" or root.get("release_eligible") is not True:
        fail("shadow_or_non_release_evidence")
    if root.get("outcome") != "success":
        fail("outcome_not_success")

    candidate = require_mapping(root.get("candidate"), "candidate_invalid")
    repository = require_string(candidate.get("repository"), "candidate_repository_invalid")
    source_sha = require_sha(candidate.get("source_sha"), "candidate_source_sha_invalid")
    if repository != expected.repository or source_sha != expected.source_sha:
        fail("candidate_identity_mismatch")
    git_tree = candidate.get("git_tree")
    artifact_digest = candidate.get("artifact_digest")
    if git_tree is not None:
        require_sha(git_tree, "candidate_git_tree_invalid")
    if artifact_digest is not None:
        require_digest(artifact_digest, "candidate_artifact_digest_invalid")
    if git_tree is None and artifact_digest is None:
        fail("candidate_immutable_identity_missing")
    if expected.git_tree is not None and git_tree != expected.git_tree:
        fail("candidate_immutable_identity_mismatch")
    if (
        expected.artifact_digest is not None
        and artifact_digest != expected.artifact_digest
    ):
        fail("candidate_immutable_identity_mismatch")

    policy = require_mapping(root.get("policy"), "policy_invalid")
    if require_sha(policy.get("policy_sha"), "policy_sha_invalid") != controls.policy_sha:
        fail("policy_identity_mismatch")
    if require_sha(policy.get("matrix_sha"), "matrix_sha_invalid") != controls.matrix_sha:
        fail("matrix_identity_mismatch")
    validation_workflow_sha = require_sha(
        policy.get("validation_workflow_sha"), "validation_workflow_sha_invalid"
    )
    if validation_workflow_sha != controls.validation_workflow_sha:
        fail("validation_workflow_identity_mismatch")
    allowed_age = effective_max_age_hours(policy, max_age_hours)

    components = require_mapping(root.get("components"), "components_invalid")
    bom = require_list(components.get("bom"), "component_bom_missing")
    bom_identities: set[tuple[str, str | None, str | None]] = set()
    bom_order: list[tuple[str, str | None, str | None]] = []
    candidate_bom_entry: Mapping[str, Any] | None = None
    for item in bom:
        component = require_mapping(item, "component_bom_item_invalid")
        component_repository = require_string(
            component.get("repository"), "component_repository_invalid"
        )
        if REPOSITORY_RE.fullmatch(component_repository) is None:
            fail("component_repository_invalid")
        component_sha = component.get("source_sha")
        component_digest = component.get("artifact_digest")
        if component_sha is not None:
            require_sha(component_sha, "component_source_sha_invalid")
        if component_digest is not None:
            require_digest(component_digest, "component_artifact_digest_invalid")
        if component_sha is None and component_digest is None:
            fail("component_immutable_identity_missing")
        key = (component_repository, component_sha, component_digest)
        if key in bom_identities:
            fail("component_bom_duplicate")
        bom_identities.add(key)
        bom_order.append(key)
        if component_repository == repository and component_sha == source_sha:
            if candidate_bom_entry is not None:
                fail("candidate_component_bom_ambiguous")
            candidate_bom_entry = component
    if candidate_bom_entry is None:
        fail("candidate_missing_from_component_bom")
    if (
        artifact_digest is not None
        and candidate_bom_entry.get("artifact_digest") != artifact_digest
    ):
        fail("candidate_artifact_digest_mismatch_in_component_bom")
    if bom_order != sorted(bom_order, key=lambda item: tuple(value or "" for value in item)):
        fail("component_bom_not_canonical")
    bom_digest = require_digest(components.get("bom_digest"), "bom_digest_invalid")
    if bom_digest != canonical_bom_digest(bom):
        fail("bom_digest_content_mismatch")
    if bom_digest != controls.bom_digest:
        fail("bom_digest_identity_mismatch")

    validation = require_mapping(root.get("validation"), "validation_invalid")
    profile = require_string(validation.get("profile"), "validation_profile_invalid")
    if profile not in {"heavy", "application_acceptance", "combined"}:
        fail("validation_profile_invalid")
    targets = require_list(validation.get("targets"), "validation_targets_missing")
    for target in targets:
        if not isinstance(target, str) or SAFE_NAME_RE.fullmatch(target) is None:
            fail("validation_target_invalid")
    cells = require_list(validation.get("cells"), "validation_cells_missing")
    cell_names: set[str] = set()
    for cell in cells:
        item = require_mapping(cell, "validation_cell_invalid")
        name = require_string(item.get("name"), "validation_cell_name_invalid")
        if SAFE_NAME_RE.fullmatch(name) is None or name in cell_names:
            fail("validation_cell_name_invalid")
        cell_names.add(name)
        if item.get("status") != "success":
            fail("validation_cell_not_success")
        target = require_string(item.get("target"), "validation_cell_target_invalid")
        if target not in targets:
            fail("validation_cell_target_invalid")

    results = require_list(root.get("results"), "results_missing")
    result_cells: set[str] = set()
    for result in results:
        item = require_mapping(result, "result_invalid")
        cell = require_string(item.get("cell"), "result_cell_invalid")
        if cell not in cell_names or cell in result_cells:
            fail("result_cell_invalid")
        result_cells.add(cell)
        if item.get("status") != "success":
            fail("result_not_success")
        require_reference(item.get("result_reference"), "result_reference_invalid")
        require_reference(item.get("log_reference"), "log_reference_invalid")
        require_reference(item.get("evidence_reference"), "evidence_reference_invalid")
    if result_cells != cell_names:
        fail("results_incomplete")

    lifecycle = require_mapping(root.get("lifecycle"), "lifecycle_invalid")
    started_at = parse_timestamp(lifecycle.get("started_at"), "started_at_invalid")
    ended_at = parse_timestamp(lifecycle.get("ended_at"), "ended_at_invalid")
    expires_at = parse_timestamp(lifecycle.get("expires_at"), "expires_at_invalid")
    if not started_at <= ended_at <= expires_at:
        fail("lifecycle_order_invalid")
    if expires_at > ended_at + timedelta(hours=allowed_age):
        fail("evidence_expiry_exceeds_policy")
    cleanup = require_mapping(lifecycle.get("cleanup"), "cleanup_invalid")
    if cleanup.get("status") != "success":
        fail("cleanup_not_success")
    require_reference(cleanup.get("reference"), "cleanup_reference_invalid")

    revocation = require_mapping(root.get("revocation"), "revocation_invalid")
    if revocation.get("status") != "not_revoked":
        fail("evidence_revoked")
    revocation_checked_at = parse_timestamp(
        revocation.get("checked_at"), "revocation_checked_at_invalid"
    )

    github_run = require_mapping(root.get("github_run"), "github_run_invalid")
    if github_run.get("repository") != "lightning-it/modulix-validation":
        fail("github_run_repository_invalid")
    run_id = github_run.get("run_id")
    attempt = github_run.get("run_attempt")
    if not isinstance(run_id, int) or run_id <= 0 or not isinstance(attempt, int) or attempt <= 0:
        fail("github_run_identity_invalid")
    require_reference(github_run.get("url"), "github_run_url_invalid")
    github_workflow_sha = require_sha(
        github_run.get("workflow_sha"), "github_workflow_sha_invalid"
    )
    if github_workflow_sha != validation_workflow_sha:
        fail("github_workflow_identity_mismatch")

    provenance = require_mapping(root.get("provenance"), "provenance_invalid")
    require_reference(provenance.get("attestation_reference"), "attestation_reference_invalid")
    subject_digest = require_digest(
        provenance.get("subject_digest"), "attestation_subject_digest_invalid"
    )
    if require_sha(provenance.get("source_sha"), "attestation_source_sha_invalid") != source_sha:
        fail("attestation_source_identity_mismatch")
    if artifact_digest is not None and subject_digest != artifact_digest:
        fail("attestation_subject_identity_mismatch")

    current = (now or datetime.now(UTC)).astimezone(UTC)
    if ended_at > current:
        fail("run_completed_in_future")
    if revocation_checked_at < ended_at:
        fail("revocation_checked_before_completion")
    if revocation_checked_at > current:
        fail("revocation_checked_in_future")
    if current > expires_at:
        fail("evidence_expired")


def shadow_manifest(repository: str, source_sha: str, git_tree: str, now: datetime) -> dict[str, Any]:
    """Create a non-releaseable wiring artifact; it asserts no test success."""

    if REPOSITORY_RE.fullmatch(repository) is None:
        fail("expected_repository_invalid")
    require_sha(source_sha, "expected_source_sha_invalid")
    require_sha(git_tree, "expected_git_tree_invalid")
    timestamp = now.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "modulix-validation-evidence",
        "mode": "shadow",
        "release_eligible": False,
        "outcome": "not_executed",
        "candidate": {
            "repository": repository,
            "source_sha": source_sha,
            "git_tree": git_tree,
        },
        "shadow": {
            "reason": "wiring-only; no Heavy or Application Acceptance execution occurred",
            "created_at": timestamp,
        },
    }


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError("evidence_json_invalid") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    verify = commands.add_parser(
        "semantic-verify",
        help="fail closed for the v1 semantic contract; does not verify attestation trust",
    )
    verify.add_argument("--evidence", required=True, type=Path)
    verify.add_argument("--repository", required=True)
    verify.add_argument("--source-sha", required=True)
    verify.add_argument("--git-tree")
    verify.add_argument("--artifact-digest")
    verify.add_argument("--policy-sha", required=True)
    verify.add_argument("--matrix-sha", required=True)
    verify.add_argument("--validation-workflow-sha", required=True)
    verify.add_argument("--bom-digest", required=True)
    verify.add_argument("--max-age-hours", type=int, default=DEFAULT_MAX_AGE_HOURS)

    shadow = commands.add_parser("shadow-manifest", help="create non-releaseable wiring evidence")
    shadow.add_argument("--output", required=True, type=Path)
    shadow.add_argument("--repository", required=True)
    shadow.add_argument("--source-sha", required=True)
    shadow.add_argument("--git-tree", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "semantic-verify":
            validate_evidence(
                load_json(args.evidence),
                ExpectedIdentity(
                    repository=args.repository,
                    source_sha=args.source_sha,
                    git_tree=args.git_tree,
                    artifact_digest=args.artifact_digest,
                ),
                ExpectedControls(
                    policy_sha=args.policy_sha,
                    matrix_sha=args.matrix_sha,
                    validation_workflow_sha=args.validation_workflow_sha,
                    bom_digest=args.bom_digest,
                ),
                max_age_hours=args.max_age_hours,
            )
            print(
                "Evidence satisfies the v1 semantic contract only; "
                "cryptographic attestation trust was not verified."
            )
        else:
            payload = shadow_manifest(
                args.repository, args.source_sha, args.git_tree, datetime.now(UTC)
            )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"Wrote non-releaseable shadow manifest: {args.output}")
    except EvidenceError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
