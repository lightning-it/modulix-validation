import hashlib
import importlib.util
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "mlx90-collection-candidate-validation.py"
WORKFLOW_PATH = (
    ROOT / ".github" / "workflows" / "mlx90-collection-candidate-validation.yml"
)
PRODUCER_REQUEST_FIXTURE_PATH = (
    ROOT / "tests" / "fixtures" / "mlx90-producer-collection-validation-request-v2.json"
)
PRODUCER_REQUEST_FIXTURE_ID = (
    "f4401218fce1a5806ccaf4ebc0aa0c274b38da1a9139f8aa81dafd4ad35f7292"
)
SPEC = importlib.util.spec_from_file_location("mlx90_candidate_validation", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def actor():
    return {
        "login": MODULE.APP_ACTOR,
        "id": MODULE.APP_ACTOR_ID,
        "type": "Bot",
    }


def request_fixture():
    return {
        "apiVersion": MODULE.REQUEST_API_VERSION,
        "kind": MODULE.REQUEST_KIND,
        "source": {
            "actor": MODULE.APP_ACTOR,
            "actorId": MODULE.APP_ACTOR_ID,
            "actorType": "Bot",
            "event": "workflow_dispatch",
            "ref": "refs/heads/main",
            "repository": MODULE.SOURCE_REPOSITORY,
            "runAttempt": 1,
            "runId": 123456,
            "sha": "b" * 40,
            "workflow": MODULE.SOURCE_WORKFLOW,
        },
        "security": {"evidenceId": "MLX90-SECURITY-001", "humanActions": 0},
        "candidate": {
            "name": "lit-supplementary-3.2.4.tar.gz",
            "sha256": "sha256:" + "c" * 64,
            "size": 4096,
            "version": "3.2.4",
            "nexus": {
                "repository": "mlx90-security-candidates",
                "repositoryUrl": (
                    "https://nexus.example.invalid/repository/"
                    "mlx90-security-candidates"
                ),
                "url": (
                    "https://nexus.example.invalid/repository/"
                    "mlx90-security-candidates/api/v3/plugin/ansible/content/"
                    "published/collections/artifacts/"
                    "lit-supplementary-3.2.4.tar.gz"
                ),
            },
        },
        "controller": {
            "repository": MODULE.CONTROLLER_REPOSITORY,
            "ref": MODULE.CONTROLLER_REF,
            "sha": "a" * 40,
            "workflow": MODULE.CONTROLLER_WORKFLOW,
        },
    }


def run_fixture(*, controller=False):
    request = request_fixture()
    return {
        "id": 777 if controller else request["source"]["runId"],
        "run_attempt": 2 if controller else request["source"]["runAttempt"],
        "event": "workflow_dispatch",
        "path": MODULE.CONTROLLER_WORKFLOW if controller else MODULE.SOURCE_WORKFLOW,
        "head_sha": (
            request["controller"]["sha"] if controller else request["source"]["sha"]
        ),
        "head_branch": "main",
        "status": "in_progress",
        "conclusion": None,
        "repository": {
            "full_name": (
                MODULE.CONTROLLER_REPOSITORY if controller else MODULE.SOURCE_REPOSITORY
            )
        },
        "head_repository": {
            "full_name": (
                MODULE.CONTROLLER_REPOSITORY if controller else MODULE.SOURCE_REPOSITORY
            )
        },
        "actor": actor(),
        "triggering_actor": actor(),
    }


class CandidateValidationUnitTests(unittest.TestCase):
    def canonical_request(self):
        request = request_fixture()
        payload = MODULE.canonical_compact(request)
        request_id = hashlib.sha256(payload.encode()).hexdigest()
        return request, payload, request_id

    def test_exact_v2_request_and_both_run_identities_pass(self):
        request, payload, request_id = self.canonical_request()
        validated = MODULE.validate_request(
            payload,
            request_id,
            controller_sha=request["controller"]["sha"],
            repository=MODULE.CONTROLLER_REPOSITORY,
            ref=MODULE.CONTROLLER_REF,
            actor=MODULE.APP_ACTOR,
            actor_id=MODULE.APP_ACTOR_ID,
            triggering_actor=MODULE.APP_ACTOR,
        )
        self.assertEqual(request, validated)
        MODULE.validate_source_run(run_fixture(), validated)
        MODULE.validate_controller_run(
            run_fixture(controller=True), validated, run_id=777, run_attempt=2
        )

    def test_canonical_producer_v2_fixture_passes_and_round_trips_in_receipt(self):
        fixture_bytes = PRODUCER_REQUEST_FIXTURE_PATH.read_text(encoding="utf-8")
        request = json.loads(fixture_bytes)
        self.assertEqual(MODULE.canonical_pretty(request), fixture_bytes)
        payload = MODULE.canonical_compact(request)
        request_id = hashlib.sha256(payload.encode()).hexdigest()
        self.assertEqual(PRODUCER_REQUEST_FIXTURE_ID, request_id)

        validated = MODULE.validate_request(
            payload,
            request_id,
            controller_sha=request["controller"]["sha"],
            repository=MODULE.CONTROLLER_REPOSITORY,
            ref=MODULE.CONTROLLER_REF,
            actor=MODULE.APP_ACTOR,
            actor_id=MODULE.APP_ACTOR_ID,
            triggering_actor=MODULE.APP_ACTOR,
        )
        receipt = MODULE.build_receipt(
            validated,
            request_id,
            run_id=777,
            run_attempt=2,
            controller_sha=request["controller"]["sha"],
            actor=MODULE.APP_ACTOR,
            actor_id=MODULE.APP_ACTOR_ID,
        )

        self.assertEqual(
            request["source"],
            receipt["validation"]["observations"]["sourceRun"],
        )
        self.assertEqual(
            "https://nexus.example.invalid/nexus/service/repository/"
            "mlx90-security-candidates",
            request["candidate"]["nexus"]["repositoryUrl"],
        )

    def test_source_identity_is_exactly_the_producer_v2_contract(self):
        request, _payload, _request_id = self.canonical_request()
        mutations = {
            "actor": "someone-else[bot]",
            "actorId": 1,
            "actorType": "User",
            "event": "push",
            "ref": "refs/heads/develop",
            "repository": MODULE.CONTROLLER_REPOSITORY,
            "workflow": MODULE.CONTROLLER_WORKFLOW,
        }
        for key, replacement in mutations.items():
            candidate = json.loads(json.dumps(request))
            candidate["source"][key] = replacement
            payload = MODULE.canonical_compact(candidate)
            request_id = hashlib.sha256(payload.encode()).hexdigest()
            with self.subTest(field=key), self.assertRaisesRegex(
                MODULE.ContractError, "source identity"
            ):
                MODULE.validate_request(
                    payload,
                    request_id,
                    controller_sha=request["controller"]["sha"],
                    repository=MODULE.CONTROLLER_REPOSITORY,
                    ref=MODULE.CONTROLLER_REF,
                    actor=MODULE.APP_ACTOR,
                    actor_id=MODULE.APP_ACTOR_ID,
                    triggering_actor=MODULE.APP_ACTOR,
                )

    def test_noncanonical_or_tampered_request_is_rejected(self):
        request, payload, request_id = self.canonical_request()
        arguments = {
            "controller_sha": request["controller"]["sha"],
            "repository": MODULE.CONTROLLER_REPOSITORY,
            "ref": MODULE.CONTROLLER_REF,
            "actor": MODULE.APP_ACTOR,
            "actor_id": MODULE.APP_ACTOR_ID,
            "triggering_actor": MODULE.APP_ACTOR,
        }
        with self.assertRaisesRegex(MODULE.ContractError, "canonical compact"):
            MODULE.validate_request(json.dumps(request), request_id, **arguments)
        with self.assertRaisesRegex(MODULE.ContractError, "request ID"):
            MODULE.validate_request(payload, "0" * 64, **arguments)
        with self.assertRaisesRegex(MODULE.ContractError, "App/main"):
            MODULE.validate_request(payload, request_id, **{**arguments, "actor_id": 1})

    def test_nexus_origin_and_evidence_id_are_fail_closed(self):
        request, _payload, _request_id = self.canonical_request()
        for mutation in ("nexus", "evidence"):
            value = json.loads(json.dumps(request))
            if mutation == "nexus":
                value["candidate"]["nexus"]["url"] = "https://elsewhere.invalid/a"
            else:
                value["security"]["evidenceId"] = "historical-dry-run"
            payload = MODULE.canonical_compact(value)
            request_id = hashlib.sha256(payload.encode()).hexdigest()
            with self.subTest(mutation=mutation), self.assertRaises(
                MODULE.ContractError
            ):
                MODULE.validate_request(
                    payload,
                    request_id,
                    controller_sha=request["controller"]["sha"],
                    repository=MODULE.CONTROLLER_REPOSITORY,
                    ref=MODULE.CONTROLLER_REF,
                    actor=MODULE.APP_ACTOR,
                    actor_id=MODULE.APP_ACTOR_ID,
                    triggering_actor=MODULE.APP_ACTOR,
                )

    def test_app_identity_and_token_scope_are_exact(self):
        MODULE.validate_app_token_scope(
            [MODULE.SOURCE_REPOSITORY],
            app_slug=MODULE.APP_SLUG,
            installation_id=MODULE.APP_INSTALLATION_ID,
        )
        for repositories, app_slug, installation_id in (
            (
                [MODULE.SOURCE_REPOSITORY, MODULE.CONTROLLER_REPOSITORY],
                MODULE.APP_SLUG,
                MODULE.APP_INSTALLATION_ID,
            ),
            ([MODULE.SOURCE_REPOSITORY], "another-app", MODULE.APP_INSTALLATION_ID),
            ([MODULE.SOURCE_REPOSITORY], MODULE.APP_SLUG, 1),
        ):
            with self.assertRaises(MODULE.ContractError):
                MODULE.validate_app_token_scope(
                    repositories,
                    app_slug=app_slug,
                    installation_id=installation_id,
                )

    def test_receipt_is_exactly_bound_to_successful_profiles(self):
        request, _payload, request_id = self.canonical_request()
        receipt = MODULE.build_receipt(
            request,
            request_id,
            run_id=777,
            run_attempt=2,
            controller_sha=request["controller"]["sha"],
            actor=MODULE.APP_ACTOR,
            actor_id=MODULE.APP_ACTOR_ID,
        )
        self.assertEqual(
            {
                "candidateUnchanged": True,
                "galaxyPublicationAuthorized": True,
                "releaseEligible": True,
            },
            receipt["decision"],
        )
        self.assertEqual(0, receipt["validation"]["humanActions"])
        self.assertEqual(
            request["source"], receipt["validation"]["observations"]["sourceRun"]
        )

    def test_validated_request_file_requires_canonical_pretty_bytes(self):
        request, _payload, request_id = self.canonical_request()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "request.json"
            path.write_text(MODULE.canonical_pretty(request), encoding="utf-8")
            self.assertEqual(
                request, MODULE.validated_request_from_file(path, request_id)
            )
            path.write_text(json.dumps(request), encoding="utf-8")
            with self.assertRaisesRegex(MODULE.ContractError, "not canonical"):
                MODULE.validated_request_from_file(path, request_id)

    def test_nexus_readback_accepts_only_the_exact_collection_bytes(self):
        request = request_fixture()
        stream = io.BytesIO()
        manifest = json.dumps(
            {
                "collection_info": {
                    "namespace": "lit",
                    "name": "supplementary",
                    "version": "3.2.4",
                }
            }
        ).encode()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            item = tarfile.TarInfo("MANIFEST.json")
            item.size = len(manifest)
            archive.addfile(item, io.BytesIO(manifest))
        candidate_bytes = stream.getvalue()
        request["candidate"]["size"] = len(candidate_bytes)
        request["candidate"]["sha256"] = (
            "sha256:" + hashlib.sha256(candidate_bytes).hexdigest()
        )

        class Response:
            status = 200

            def __init__(self):
                self.stream = io.BytesIO(candidate_bytes)

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def geturl(self):
                return request["candidate"]["nexus"]["url"]

            def read(self, size):
                return self.stream.read(size)

        opener = mock.Mock()
        opener.open.return_value = Response()
        environment = {
            "NEXUS_GALAXY_USERNAME": "fixture-user",
            "NEXUS_GALAXY_PASSWORD": "fixture-password",
            "NEXUS_GALAXY_REPOSITORY": request["candidate"]["nexus"]["repository"],
            "NEXUS_GALAXY_REPOSITORY_URL": request["candidate"]["nexus"][
                "repositoryUrl"
            ],
        }
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ, environment, clear=False
        ), mock.patch.object(
            MODULE.urllib.request, "build_opener", return_value=opener
        ):
            output = Path(temporary) / "candidate"
            result = MODULE.download_candidate(request, output)
            self.assertEqual(candidate_bytes, result.read_bytes())
            self.assertEqual(1, opener.open.call_count)


class CandidateValidationWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.workflow = yaml.safe_load(cls.text)

    def test_workflow_has_only_the_two_required_dispatch_inputs(self):
        trigger = self.workflow.get("on", self.workflow.get(True))
        self.assertEqual({"workflow_dispatch"}, set(trigger))
        inputs = trigger["workflow_dispatch"]["inputs"]
        self.assertEqual({"request_id", "request_json"}, set(inputs))
        self.assertTrue(all(item["required"] is True for item in inputs.values()))
        self.assertEqual(
            "MLX-90 collection candidate validation", self.workflow["name"]
        )

    def test_exact_jobs_and_security_environment_are_required(self):
        jobs = self.workflow["jobs"]
        self.assertEqual("Validate immutable request", jobs["validate"]["name"])
        self.assertEqual("Nexus exact-byte readback", jobs["nexus-readback"]["name"])
        self.assertEqual("Sign validation receipt", jobs["receipt"]["name"])
        self.assertTrue(jobs["heavy"]["name"].startswith("Heavy / "))
        self.assertTrue(
            jobs["application-acceptance"]["name"].startswith(
                "Application Acceptance / "
            )
        )
        for job in ("validate", "nexus-readback", "receipt"):
            self.assertEqual(
                "mlx90-security-candidate-validation",
                jobs[job]["environment"]["name"],
            )
        self.assertEqual(
            ["self-hosted", "linux", "x64", "incus"],
            jobs["nexus-readback"]["runs-on"],
        )

    def test_both_real_profiles_consume_the_same_nexus_artifact(self):
        jobs = self.workflow["jobs"]
        for job, profile in (
            ("heavy", "heavy"),
            ("application-acceptance", "application_acceptance"),
        ):
            self.assertEqual(
                "./.github/workflows/collection-quality-profile.yml",
                jobs[job]["uses"],
            )
            self.assertEqual(profile, jobs[job]["with"]["profile"])
            self.assertIn(
                "needs.nexus-readback.outputs.candidate-artifact",
                jobs[job]["with"]["candidate-artifact"],
            )
            self.assertEqual(
                MODULE.SOURCE_REPOSITORY, jobs[job]["with"]["source-repository"]
            )
            self.assertEqual(
                "release-automation-app", jobs[job]["with"]["source-token-mode"]
            )

    def test_heavy_and_application_run_in_parallel_after_nexus(self):
        jobs = self.workflow["jobs"]
        expected_profile_needs = {"validate", "nexus-readback"}
        self.assertEqual(expected_profile_needs, set(jobs["heavy"]["needs"]))
        self.assertEqual(
            expected_profile_needs,
            set(jobs["application-acceptance"]["needs"]),
        )
        self.assertEqual(
            {"validate", "nexus-readback", "heavy", "application-acceptance"},
            set(jobs["receipt"]["needs"]),
        )

    def test_controller_critical_path_is_bounded_to_255_minutes(self):
        jobs = self.workflow["jobs"]
        delegated_workflow = yaml.safe_load(
            (
                ROOT / ".github" / "workflows" / "collection-quality-profile.yml"
            ).read_text(encoding="utf-8")
        )
        delegated_jobs = delegated_workflow["jobs"]
        critical_path_minutes = sum(
            (
                jobs["validate"]["timeout-minutes"],
                jobs["nexus-readback"]["timeout-minutes"],
                delegated_jobs["validate-inputs"]["timeout-minutes"],
                delegated_jobs["profile-cells"]["timeout-minutes"],
                jobs["receipt"]["timeout-minutes"],
            )
        )
        self.assertEqual(255, critical_path_minutes)

    def test_no_transition_bypass_force_or_human_approval_path(self):
        for forbidden in (
            "collection-release-transition",
            "continue-on-error",
            "pull_request_target",
            "git push --force",
            "--force-with-lease",
            "required_reviewers",
        ):
            self.assertNotIn(forbidden, self.text)
        self.assertIn("permission-actions: read", self.text)
        self.assertIn("id-token: write", self.text)
        self.assertIn("cosign sign-blob", self.text)

    def test_installation_evidence_uses_only_supported_token_endpoint(self):
        self.assertIn("installation/repositories?per_page=100", self.text)
        self.assertNotIn("gh api /installation", self.text)
        self.assertNotIn('--installation "$EVIDENCE_ROOT/installation.json"', self.text)


if __name__ == "__main__":
    unittest.main()
