import json
import re
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "scripts" / "lit-ci-profile.sh"
PROFILE_COMMAND = "scripts/lit-ci-profile.sh repository-quality"


class CiProfileContractTests(unittest.TestCase):
    def test_push_ready_and_required_jobs_use_one_exact_profile(self):
        config = json.loads(
            (ROOT / ".lit" / "push-ready.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            [
                {
                    "name": "repository-quality-profile",
                    "command": [
                        "scripts/lit-ci-profile.sh",
                        "repository-quality",
                    ],
                }
            ],
            config["checks"],
        )
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/repository-quality.yml").read_text(
                encoding="utf-8"
            )
        )
        quality = workflow["jobs"]["quality"]
        self.assertEqual(30, quality["timeout-minutes"])
        self.assertEqual(0, quality["steps"][0]["with"]["fetch-depth"])
        self.assertEqual(
            "develop",
            workflow.get("env", {}).get("AUTHORITATIVE_BASE_BRANCH"),
        )
        self.assertIn(
            "refs/heads/${AUTHORITATIVE_BASE_BRANCH}:"
            "refs/remotes/origin/${AUTHORITATIVE_BASE_BRANCH}",
            quality["steps"][1]["run"],
        )
        self.assertIn(
            'echo "::add-mask::$auth_header"',
            quality["steps"][1]["run"],
        )
        quality_runs = [
            step["run"] for step in quality["steps"] if "run" in step
        ]
        self.assertEqual(PROFILE_COMMAND, quality_runs[-1])

        contracts = yaml.safe_load(
            (ROOT / ".github/workflows/validation-contracts.yml").read_text(
                encoding="utf-8"
            )
        )["jobs"]["contracts"]
        self.assertEqual(30, contracts["timeout-minutes"])
        self.assertEqual(0, contracts["steps"][0]["with"]["fetch-depth"])
        self.assertFalse(
            contracts["steps"][0]["with"]["persist-credentials"]
        )
        self.assertIn(
            "refs/heads/develop:refs/remotes/origin/develop",
            contracts["steps"][1]["run"],
        )
        self.assertIn(
            'echo "::add-mask::$auth_header"',
            contracts["steps"][1]["run"],
        )
        contract_runs = [
            step["run"] for step in contracts["steps"] if "run" in step
        ]
        self.assertEqual(PROFILE_COMMAND, contract_runs[-1])

    def test_profile_is_fail_closed_and_hash_lock_bound(self):
        profile = PROFILE.read_text(encoding="utf-8")
        for contract in (
            'readonly PROFILE_NAME="repository-quality"',
            'WUNDER_DEVTOOLS_DOCKER_SOCKET=disabled',
            'WUNDER_DEVTOOLS_RUN_AS_HOST_UID=1',
            'WUNDER_DEVTOOLS_WORKSPACE_MODE=ro',
            'WUNDER_DEVTOOLS_PRIVILEGED=0',
            'WUNDER_DEVTOOLS_NETWORK="$network_mode"',
            "--require-hashes",
            "requirements-validation.lock",
            ".github/requirements/collection-quality-profile.lock",
            "scripts/lit-push-ready.py instructions",
            "scripts/lit-repository-quality.py",
            "python -m unittest discover",
            "shellcheck",
            "actionlint --version",
            "actionlint",
            'git diff --check "$merge_base"...HEAD --',
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, profile)
        self.assertNotIn("mapfile", profile)
        self.assertNotIn("readarray", profile)
        self.assertRegex(
            (ROOT / "requirements-validation.lock").read_text(encoding="utf-8"),
            re.compile(r"(?m)^PyYAML==6\.0\.3 \\$"),
        )

    def test_remote_gaps_are_structured_and_unique(self):
        gaps = json.loads(
            (ROOT / ".lit" / "push-ready.json").read_text(encoding="utf-8")
        )["remote_only_checks"]
        self.assertEqual(len(gaps), len({gap["id"] for gap in gaps}))
        for gap in gaps:
            self.assertEqual(
                {"id", "workflow", "job", "reason", "owner"},
                set(gap),
            )

    def test_collection_release_transition_is_an_explicit_noop(self):
        workflow = (
            ROOT / ".github/workflows/collection-release-transition.yml"
        ).read_text(encoding="utf-8")
        self.assertIn('"mode": "transition-noop"', workflow)
        self.assertIn('"release_eligible": False', workflow)
        self.assertIn('"heavy_executed": False', workflow)
        self.assertIn('"galaxy_publication_executed": False', workflow)
        self.assertIn("ansible-galaxy collection publish", workflow)
        self.assertNotIn("collection-quality-profile.yml", workflow)


if __name__ == "__main__":
    unittest.main()
