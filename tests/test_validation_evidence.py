from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / ".github/scripts/validation-evidence.py"
SPEC = importlib.util.spec_from_file_location("validation_evidence", SCRIPT)
assert SPEC is not None
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

SHA = "a" * 40
TREE = "b" * 40
POLICY_SHA = "c" * 40
MATRIX_SHA = "d" * 40
WORKFLOW_SHA = "e" * 40
ARTIFACT_DIGEST = "sha256:" + "f" * 64
NOW = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)


def evidence() -> dict:
    started = NOW - timedelta(hours=1)
    ended = NOW - timedelta(minutes=30)
    expires = NOW + timedelta(hours=35)
    timestamp = lambda value: value.isoformat().replace("+00:00", "Z")
    payload = {
        "schema_version": 1,
        "kind": "modulix-validation-evidence",
        "mode": "executed",
        "release_eligible": True,
        "outcome": "success",
        "candidate": {
            "repository": "lightning-it/ansible-collection-supplementary",
            "source_sha": SHA,
            "git_tree": TREE,
            "artifact_digest": ARTIFACT_DIGEST,
        },
        "policy": {
            "policy_sha": POLICY_SHA,
            "matrix_sha": MATRIX_SHA,
            "validation_workflow_sha": WORKFLOW_SHA,
            "max_age_hours": 36,
        },
        "components": {
            "bom": [
                {
                    "repository": "lightning-it/ansible-collection-supplementary",
                    "source_sha": SHA,
                    "artifact_digest": ARTIFACT_DIGEST,
                },
                {
                    "repository": "lightning-it/modulix-automation",
                    "source_sha": "1" * 40,
                },
            ]
        },
        "validation": {
            "profile": "combined",
            "targets": ["rhel-10"],
            "cells": [
                {"name": "keycloak-rhel10", "target": "rhel-10", "status": "success"}
            ],
        },
        "results": [
            {
                "cell": "keycloak-rhel10",
                "status": "success",
                "result_reference": "artifact://result.json",
                "log_reference": "https://github.com/lightning-it/modulix-validation/actions/runs/1",
                "evidence_reference": "artifact://evidence.tar.gz",
            }
        ],
        "lifecycle": {
            "started_at": timestamp(started),
            "ended_at": timestamp(ended),
            "expires_at": timestamp(expires),
            "cleanup": {"status": "success", "reference": "artifact://cleanup.json"},
        },
        "revocation": {"status": "not_revoked", "checked_at": timestamp(ended)},
        "github_run": {
            "repository": "lightning-it/modulix-validation",
            "run_id": 12345,
            "run_attempt": 1,
            "url": "https://github.com/lightning-it/modulix-validation/actions/runs/12345",
            "workflow_sha": WORKFLOW_SHA,
        },
        "provenance": {
            "attestation_reference": "github://attestations/12345",
            "subject_digest": ARTIFACT_DIGEST,
            "source_sha": SHA,
        },
    }
    payload["components"]["bom_digest"] = MODULE.canonical_bom_digest(
        payload["components"]["bom"]
    )
    return payload


class ValidationEvidenceTests(unittest.TestCase):
    def expected(self, *, git_tree=TREE, artifact_digest=ARTIFACT_DIGEST) -> object:
        return MODULE.ExpectedIdentity(
            "lightning-it/ansible-collection-supplementary",
            SHA,
            git_tree=git_tree,
            artifact_digest=artifact_digest,
        )

    def controls(self) -> object:
        return self.controls_for(evidence())

    def controls_for(self, payload: dict) -> object:
        return MODULE.ExpectedControls(
            policy_sha=POLICY_SHA,
            matrix_sha=MATRIX_SHA,
            validation_workflow_sha=WORKFLOW_SHA,
            bom_digest=payload["components"]["bom_digest"],
        )

    def verify(self, payload: dict, *, expected=None, controls=None) -> None:
        MODULE.validate_evidence(
            payload,
            expected or self.expected(),
            controls or self.controls(),
            now=NOW,
        )

    def assert_rejected(self, payload: dict, code: str) -> None:
        with self.assertRaisesRegex(MODULE.EvidenceError, f"^{code}$"):
            self.verify(payload)

    def test_success_for_exact_candidate_with_full_contract(self):
        self.verify(evidence())

    def test_candidate_identity_mismatch_fails_closed(self):
        payload = evidence()
        payload["candidate"]["source_sha"] = "0" * 40
        self.assert_rejected(payload, "candidate_identity_mismatch")

    def test_tree_only_identity_mismatch_fails_closed(self):
        payload = evidence()
        payload["candidate"]["git_tree"] = "0" * 40
        with self.assertRaisesRegex(
            MODULE.EvidenceError, "^candidate_immutable_identity_mismatch$"
        ):
            self.verify(payload, expected=self.expected(artifact_digest=None))

    def test_digest_only_identity_mismatch_fails_closed(self):
        payload = evidence()
        payload["candidate"]["artifact_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(
            MODULE.EvidenceError, "^candidate_immutable_identity_mismatch$"
        ):
            self.verify(payload, expected=self.expected(git_tree=None))

    def test_both_identity_values_must_match_when_both_are_expected(self):
        payload = evidence()
        payload["candidate"]["git_tree"] = "0" * 40
        self.assert_rejected(payload, "candidate_immutable_identity_mismatch")

        payload = evidence()
        payload["candidate"]["artifact_digest"] = "sha256:" + "0" * 64
        self.assert_rejected(payload, "candidate_immutable_identity_mismatch")

    def test_expired_evidence_fails_closed(self):
        payload = evidence()
        payload["lifecycle"]["expires_at"] = "2026-07-31T11:59:59Z"
        self.assert_rejected(payload, "evidence_expired")

    def test_revoked_evidence_fails_closed(self):
        payload = evidence()
        payload["revocation"]["status"] = "revoked"
        self.assert_rejected(payload, "evidence_revoked")

    def test_skipped_or_partial_results_fail_closed(self):
        skipped = evidence()
        skipped["validation"]["cells"][0]["status"] = "skipped"
        self.assert_rejected(skipped, "validation_cell_not_success")

        partial = evidence()
        partial["results"] = []
        self.assert_rejected(partial, "results_missing")

    def test_cleanup_failure_fails_closed(self):
        payload = evidence()
        payload["lifecycle"]["cleanup"]["status"] = "failed"
        self.assert_rejected(payload, "cleanup_not_success")

    def test_workflow_and_attestation_must_bind_to_the_candidate(self):
        payload = evidence()
        payload["github_run"]["workflow_sha"] = "0" * 40
        self.assert_rejected(payload, "github_workflow_identity_mismatch")

        payload = evidence()
        payload["provenance"]["source_sha"] = "0" * 40
        self.assert_rejected(payload, "attestation_source_identity_mismatch")

    def test_controls_and_canonical_bom_are_independently_bound(self):
        payload = evidence()
        payload["policy"]["policy_sha"] = "0" * 40
        self.assert_rejected(payload, "policy_identity_mismatch")

        payload = evidence()
        payload["policy"]["matrix_sha"] = "0" * 40
        self.assert_rejected(payload, "matrix_identity_mismatch")

        payload = evidence()
        payload["policy"]["validation_workflow_sha"] = "0" * 40
        self.assert_rejected(payload, "validation_workflow_identity_mismatch")

        payload = evidence()
        payload["components"]["bom"][1]["source_sha"] = "2" * 40
        self.assert_rejected(payload, "bom_digest_content_mismatch")

        payload = evidence()
        wrong_controls = MODULE.ExpectedControls(
            policy_sha=POLICY_SHA,
            matrix_sha=MATRIX_SHA,
            validation_workflow_sha=WORKFLOW_SHA,
            bom_digest="sha256:" + "0" * 64,
        )
        with self.assertRaisesRegex(MODULE.EvidenceError, "^bom_digest_identity_mismatch$"):
            self.verify(payload, controls=wrong_controls)

    def test_candidate_bom_entry_must_bind_the_exact_artifact_digest(self):
        for candidate_digest in (None, "sha256:" + "0" * 64):
            payload = evidence()
            if candidate_digest is None:
                del payload["components"]["bom"][0]["artifact_digest"]
            else:
                payload["components"]["bom"][0]["artifact_digest"] = candidate_digest
            payload["components"]["bom_digest"] = MODULE.canonical_bom_digest(
                payload["components"]["bom"]
            )
            with self.assertRaisesRegex(
                MODULE.EvidenceError,
                "^candidate_artifact_digest_mismatch_in_component_bom$",
            ):
                self.verify(payload, controls=self.controls_for(payload))

    def test_policy_may_only_be_stricter_than_36_hour_default(self):
        payload = evidence()
        payload["policy"]["max_age_hours"] = 12
        payload["lifecycle"]["expires_at"] = "2026-08-02T00:00:00Z"
        self.assert_rejected(payload, "evidence_expiry_exceeds_policy")

        payload = evidence()
        payload["policy"]["max_age_hours"] = 37
        self.assert_rejected(payload, "policy_max_age_invalid")

    def test_future_completion_or_revocation_check_fails_closed(self):
        payload = evidence()
        payload["lifecycle"]["ended_at"] = "2026-07-31T12:00:01Z"
        self.assert_rejected(payload, "run_completed_in_future")

        payload = evidence()
        payload["revocation"]["checked_at"] = "2026-07-31T11:29:59Z"
        self.assert_rejected(payload, "revocation_checked_before_completion")

        payload = evidence()
        payload["revocation"]["checked_at"] = "2026-07-31T12:00:01Z"
        self.assert_rejected(payload, "revocation_checked_in_future")

    def test_shadow_manifest_cannot_be_used_as_release_evidence(self):
        shadow = MODULE.shadow_manifest(
            "lightning-it/ansible-collection-supplementary", SHA, TREE, NOW
        )
        self.assertFalse(shadow["release_eligible"])
        self.assert_rejected(shadow, "shadow_or_non_release_evidence")

    def test_schema_and_shadow_workflow_remain_non_privileged_and_non_releaseable(self):
        root = Path(__file__).parents[1]
        schema = json.loads(
            (root / "schemas/validation-evidence-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        workflow = (
            root / ".github/workflows/validation-evidence-shadow.yml"
        ).read_text(encoding="utf-8")
        verifier = (root / ".github/scripts/validation-evidence.py").read_text(
            encoding="utf-8"
        )

        self.assertEqual(schema["properties"]["schema_version"]["const"], 1)
        self.assertFalse(schema["additionalProperties"])
        self.assertFalse(schema["$defs"]["candidate"]["additionalProperties"])
        self.assertIn("source_sha", schema["$defs"]["candidate"]["required"])
        self.assertIn("bom_digest", schema["$defs"]["components"]["required"])
        self.assertFalse(schema["$defs"]["lifecycle"]["additionalProperties"])
        self.assertIn("schedule:", workflow)
        self.assertIn("github.event.repository.default_branch", workflow)
        self.assertIn("runs-on: ubuntu-latest", workflow)
        self.assertNotIn("self-hosted", workflow)
        self.assertNotIn("environment:", workflow)
        self.assertNotIn("secrets:", workflow)
        self.assertIn("shadow-manifest", workflow)
        self.assertIn("semantic-verify", workflow)
        self.assertIn("--policy-sha", workflow)
        self.assertIn("--bom-digest", workflow)
        self.assertIn("not a release check", workflow)
        self.assertIn('"release_eligible": False', verifier)
        self.assertIn('"outcome": "not_executed"', verifier)
