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
DAG_VALIDATOR_PATH = ROOT / ".github/scripts/mlx90-verify-container-workflow-dag.py"
DAG_ERROR = "container workflow publisher DAG is not exact"
VALID_DAG = (
    'jobs: {build: {name: "Build & push image to Quay.io"}, '
    'upload-trivy-sarif: {name: "Upload Trivy release gate SARIF", needs: build}, '
    'attach-release-evidence: {name: "Attach signed release evidence", '
    "needs: [build, upload-trivy-sarif]}}\n"
)
JOB_NAMES = (
    ("build", "Build & push image to Quay.io"),
    ("upload-trivy-sarif", "Upload Trivy release gate SARIF"),
    ("attach-release-evidence", "Attach signed release evidence"),
)


class Mlx90PublishAttemptContractTests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
        self.script = SCRIPT_PATH.read_text(encoding="utf-8")
        self.dag_validator = DAG_VALIDATOR_PATH.read_text(encoding="utf-8")

    def _run_github_api(self, arguments, stdin=b""):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            driver = root / "driver.sh"
            driver.write_text(
                self.script[: self.script.index("\n# Validate the complete SemVer")] + r'''
gh() {
  printf '%s\0' "$@" >"${GITHUB_API_TEST_ARGUMENTS:?}"
  cat >"${GITHUB_API_TEST_STDIN:?}"
}
github_api "$@"
''', encoding="utf-8"
            )
            args_path, stdin_path = root / "arguments.bin", root / "stdin.bin"
            completed = subprocess.run(
                ["bash", str(driver), *arguments],
                cwd=ROOT,
                env={**os.environ, "GITHUB_API_TEST_ARGUMENTS": str(args_path),
                     "GITHUB_API_TEST_STDIN": str(stdin_path), "RUNNER_TEMP": str(root)},
                input=stdin, capture_output=True, check=False,
            )
            forwarded = []
            if args_path.exists():
                forwarded = args_path.read_bytes().split(b"\0")
            if forwarded[-1:] == [b""]:
                forwarded.pop()
            return completed, forwarded, (
                stdin_path.read_bytes() if stdin_path.exists() else None
            )

    def _run_dag(self, workflow_text):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            driver = root / "driver.sh"
            driver.write_text(
                self.script[: self.script.index("\nverify_mode() {")]
                + '\nverify_container_workflow_dag "$1"\n',
                encoding="utf-8"
            )
            workflow = root / "container-build-publish.yml"
            workflow.write_text(workflow_text, encoding="utf-8")
            return subprocess.run(
                ["bash", str(driver), str(workflow)],
                cwd=ROOT,
                env={**os.environ, "RUNNER_TEMP": str(root)},
                capture_output=True, text=True, check=False,
            )

    def _assert_dag_results(self, accepted, *workflows):
        for workflow in workflows:
            with self.subTest(workflow=workflow):
                completed = self._run_dag(workflow)
                if accepted:
                    self.assertEqual(0, completed.returncode, completed.stderr)
                else:
                    self.assertNotEqual(0, completed.returncode)
                    self.assertIn(DAG_ERROR, completed.stderr)

    def test_container_evidence_and_publisher_attempts_are_independent(self):
        required_contract = '''--container-publish-run-attempt "$INPUT_CONTAINER_PUBLISH_RUN_ATTEMPT"
GITHUB_REST_API_VERSION="2026-03-10"
.target_commitish == $sha
.immutable == true
.author.login == $actor
releases/tags/${INPUT_CONTAINER_RELEASE_TAG}
and .event == "workflow_dispatch"
/attempts/${container_evidence_run_attempt}
/attempts/${INPUT_CONTAINER_PUBLISH_RUN_ATTEMPT}
/git/trees/${INPUT_CONSUMER_MERGE_SHA}?recursive=1
/git/blobs/${container_workflow_blob_sha}
"Build & push image to Quay.io"
"Attach signed release evidence"
and .actor.login == $actor
and .triggering_actor.login == $actor
and .status == "completed"
and .conclusion == "success"
publishRunAttempt: $publish_run_attempt
workflowBlobSha: $workflow_blob_sha
publisherNeeds: ["build", "upload-trivy-sarif"]'''
        for required in required_contract.splitlines():
            with self.subTest(required=required):
                self.assertIn(required, self.script)
        self.assertNotIn("container_sarif_job", self.script)
        self.assertNotIn('--arg name "Upload Trivy release gate SARIF"', self.script)
        container_identity = self.script.index(
            'container_identity="https://github.com/${CONSUMER_REPOSITORY}/"')
        signature = self.script.index("  cosign verify-blob ", container_identity)
        evidence_attempt = self.script.index('container_evidence_run_attempt="$(jq -er', signature)
        publisher_run = self.script.index('container_run="$(github_api \\', evidence_attempt)
        self.assertEqual([signature, evidence_attempt, publisher_run],
                         sorted((signature, evidence_attempt, publisher_run)))

    def test_every_rest_release_request_uses_the_versioned_api_wrapper(self):
        self.assertIn('readonly GITHUB_REST_API_VERSION="2026-03-10"', self.script)
        wrapper_start = self.script.index("github_api() {")
        wrapper_end = self.script.index("\n}\n", wrapper_start) + 3
        wrapper = self.script[wrapper_start:wrapper_end]
        self.assertIn("  gh api \\", wrapper)
        self.assertIn('--header "X-GitHub-Api-Version: ${GITHUB_REST_API_VERSION}"', wrapper)
        self.assertEqual(1, len(re.findall(r"\bgh api\b", self.script)))

        logical_script = re.sub(r"\\\n[ \t]*", " ", self.script)
        release_requests = [line for line in logical_script.splitlines()
                            if re.search(r'repos/\$\{[^}]+\}/releases(?:/|"|$)', line)]
        self.assertEqual(16, len(release_requests))
        for request in release_requests:
            with self.subTest(request=request):
                self.assertIn("github_api", request)
                self.assertNotIn("gh api", request)

        upload_start = self.script.index("upload_release_asset_by_id() {")
        upload_end = self.script.index("\n}\n", upload_start)
        self.assertIn("  github_api \\", self.script[upload_start:upload_end])

        outside_wrapper = self.script[:wrapper_start] + self.script[wrapper_end:]
        override = re.compile(r"x-github-api-version", re.IGNORECASE)
        self.assertNotRegex(outside_wrapper, override)
        mutated = outside_wrapper.replace('container_release="$(github_api \\',
            'container_release="$(github_api \\\n    --header=x-github-api-version:2099-01-01 \\', 1)
        self.assertNotEqual(outside_wrapper, mutated)
        with self.assertRaises(AssertionError):
            self.assertNotRegex(mutated, override)

    def test_github_api_preserves_allowed_arguments_headers_and_stdin(self):
        arguments = (
            "--paginate|-iH|Accept: application/vnd.github+json|-H|"
            "Accept: application/vnd.github+json|--header|Content-Type: application/json|"
            "--header=If-None-Match: synthetic-etag|-HUser-Agent: mlx90-finalizer|"
            "--jq|.immutable|--input|-|repos/lightning-it/modulix-validation/releases/42"
        ).split("|")
        stdin = b'{"probe":"exact"}\n\x00binary-tail\n'
        completed, forwarded, captured_input = self._run_github_api(arguments, stdin)
        self.assertEqual(0, completed.returncode)
        self.assertEqual([b"api", b"--header", b"X-GitHub-Api-Version: 2026-03-10",
                          *(argument.encode() for argument in arguments)], forwarded)
        self.assertEqual(stdin, captured_input)

    def test_github_api_rejects_every_version_header_override_form(self):
        endpoint = "repos/lightning-it/modulix-validation/releases/42"
        overrides = (
            ("-H", "X-GitHub-Api-Version: 2022-11-28"),
            ("--header", "x-github-api-version: 2022-11-28"),
            ("--header=X-GITHUB-API-VERSION: 2022-11-28",),
            ("-Hx-GiThUb-ApI-vErSiOn:2022-11-28",),
            ("-H=X-GitHub-Api-Version:2022-11-28",),
            ("--header", " \tX-GitHub-Api-Version \t: 2022-11-28"),
            ("-iH", "X-GitHub-Api-Version: 2022-11-28"),
            ("-iH=X-GitHub-Api-Version:2022-11-28",),
            ("-iHX-GitHub-Api-Version:2022-11-28",),
            ("-iiHX-gItHuB-aPi-VeRsIoN:2022-11-28",),
        )
        for override in overrides:
            arguments = [*override, endpoint]
            with self.subTest(arguments=arguments):
                completed, forwarded, captured_input = self._run_github_api(
                    arguments, b"must-not-be-forwarded")
                self.assertNotEqual(0, completed.returncode)
                self.assertIsNone(captured_input)
                self.assertEqual([], forwarded)
                self.assertIn(b"GitHub API version header override is forbidden",
                              completed.stderr)

    def test_container_workflow_dag_accepts_exact_attach_retry_contract(self):
        self._assert_dag_results(
            True,
            VALID_DAG,
            json.dumps(yaml.safe_load(VALID_DAG)),
            json.dumps({"name": "& and * inside a quoted scalar are not YAML graph syntax",
                        **yaml.safe_load(VALID_DAG)}),
            'name: "<<"\n' + VALID_DAG,
            "name: '<<'\n" + VALID_DAG,
            'name: "\\u003c\\u003c"\n' + VALID_DAG,
            '"<<": harmless\n' + VALID_DAG,
        )

    def test_required_job_name_inventory_is_exact(self):
        self.assertTrue(all(f'"{job}": "{name}"' in self.dag_validator
                            for job, name in JOB_NAMES))

    def test_required_live_job_names_are_unique(self):
        names = [name for _, name in JOB_NAMES]
        self.assertEqual(len(names), len(set(names)))

    def test_live_job_lookups_use_governed_display_names(self):
        self.assertTrue(all(f'    "{name}" \\' in self.script
                            for _, name in (JOB_NAMES[0], JOB_NAMES[2])))

    def test_container_workflow_dag_rejects_mutations_and_yaml_abuse(self):
        replace = VALID_DAG.replace
        needs = "needs: [build, upload-trivy-sarif]"
        build = 'build: {name: "Build & push image to Quay.io"}'
        upload = 'name: "Upload Trivy release gate SARIF", needs: build'
        invalid = [
            replace(needs, "needs: [build]"),
            replace(
                "attach-release-evidence:",
                "attach-release-evidence: {}, attach-release-evidence:",
            ),
            "jobs: {build: {}, attach-release-evidence: "
            "{needs: [build, upload-trivy-sarif]}}\n",
            replace(
                needs + "}", needs + ", if: always()}",
            ),
            replace(
                build, build[:-1] + ", continue-on-error: true}",
            ),
            replace(
                needs + "}", needs + ', "if": always()}',
            ),
            replace(
                needs + "}", needs + ", " + needs + "}",
            ),
            replace(needs, "needs: build"),
            replace(needs, "needs: [build, true]"),
            replace(
                upload, upload + ", continue-on-error: false",
            ),
            replace(
                build, build[:-1] + ', "continue-on-error": false}',
            ),
            (
                "jobs: {build: &build-job {}, upload-trivy-sarif: "
                "{needs: build}, publisher-template: &publisher-job "
                "{needs: [build, upload-trivy-sarif], if: always()}, "
                "attach-release-evidence: *publisher-job}\n"
            ),
            replace(build, "build: []"),
            "jobs: []\n",
        ]
        for job_name, display_name in JOB_NAMES:
            needle = f'name: "{display_name}"'
            invalid += [
                VALID_DAG.replace(needle, replacement, 1)
                for replacement in (
                    "opaque: true",
                    "name: true",
                    'name: "${{ github.job }}"',
                )
            ]
            invalid += [
                VALID_DAG.replace(display_name, display_name + "!", 1),
                VALID_DAG.replace(
                    "jobs: {",
                    f'jobs: {{unguarded-{job_name}: {{name: "{display_name}"}}, ',
                    1,
                ),
            ]
        first, second = (name for _, name in JOB_NAMES[:2])
        swapped = VALID_DAG.replace(first, "$SWAP", 1)
        invalid.append(swapped.replace(second, first, 1).replace("$SWAP", second, 1))
        invalid += [
            "publisher-defaults: &publisher-defaults "
            "{needs: [build, upload-trivy-sarif]}\n"
            "jobs: {build: {}, upload-trivy-sarif: {needs: build}, "
            "attach-release-evidence: {<<: *publisher-defaults, "
            "needs: [build, upload-trivy-sarif]}}\n",
            "unused: &unused {}\n" + VALID_DAG,
            "shared: &shared [build, upload-trivy-sarif]\n"
            "jobs: {build: {}, upload-trivy-sarif: {needs: build}, "
            "attach-release-evidence: {needs: *shared}}\n",
            "defaults: {<<: {continue-on-error: false}}\n" + VALID_DAG,
            "level-0: &level-0 [literal, literal, literal, literal]\n"
            "level-1: &level-1 [*level-0, *level-0, *level-0, *level-0]\n"
            "level-2: &level-2 [*level-1, *level-1, *level-1, *level-1]\n"
            "level-3: [*level-2, *level-2, *level-2, *level-2]\n"
            + VALID_DAG,
        ]
        tagged_job = (
            "jobs:\n  build: {}\n  upload-trivy-sarif: {needs: build}\n"
            "  attach-release-evidence:\n    $TAG defaults: "
            "{needs: [build, upload-trivy-sarif]}\n"
        )
        tagged = [
            tagged_job.replace("$TAG", tag)
            for tag in (
                "!!merge",
                "!<tag:yaml.org,2002:merge>",
                "!core!merge",
            )
        ] + [
            "name: !!str explicitly-tagged\n" + VALID_DAG,
            "name: !application-specific explicitly-tagged\n" + VALID_DAG,
        ]
        tagged[2] = "%TAG !core! tag:yaml.org,2002:\n---\n" + tagged[2]
        excessive = VALID_DAG + "".join(
            f"ignored-{index}: value\n" for index in range(15_000)
        )
        self.assertLess(len(excessive.encode("utf-8")), 1_048_576)
        self.assertEqual(41, len(invalid) + len(tagged) + 1)
        self._assert_dag_results(False, *invalid, *tagged, excessive)

    def test_container_workflow_dag_uses_strict_structural_yaml(self):
        inventory = '''StrictWorkflowLoader
construct_unique_mapping
reject_yaml_graph_features
MAX_YAML_TOKENS
AnchorToken
AliasToken
TagToken
token.style is None
token.value == "<<"
REQUIRED_JOB_NAMES = {
"build"
"upload-trivy-sarif"
"attach-release-evidence"
candidate.get("name") == display_name
job.get("name") != display_name
owners != 1
PUBLISHER_NEEDS = ["build", "upload-trivy-sarif"]
if "if" in publisher:
if "continue-on-error" in job:'''
        for required in inventory.splitlines():
            with self.subTest(required=required):
                self.assertIn(required, self.dag_validator)
        self.assertIn(
            'python3 -I -B "$CONTAINER_WORKFLOW_DAG_VALIDATOR" "$workflow"',
            self.script,
        )
        install_step = next(
            step
            for step in self.workflow["jobs"]["verify"]["steps"]
            if step.get("name") == "Install hash-locked final-acceptance parser"
        )
        self.assertIn("--require-hashes", install_step["run"])
        self.assertIn("requirements-validation.lock", install_step["run"])
