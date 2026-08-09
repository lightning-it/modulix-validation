"""Security and repository-integration contracts for the live PGE audit."""

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "pge-confluence-conformance.yml"
SCRIPT_PATH = ROOT / ".github" / "scripts" / "pge-confluence-conformance.py"
CONFIG_PATH = ROOT / "inventories" / "pge" / "confluence-conformance.json"
DOC_PATH = ROOT / "docs" / "pge-confluence-conformance.md"
CANONICAL_EXCLUDED_ROOTS = (
    "2466709560",
    "2466709570",
    "2466742273",
    "2529591386",
    "2555117613",
    "2582740996",
    "2583199745",
    "2592931842",
    "2592997395",
    "2643886387",
    "2654437655",
    "2657157546",
    "2643918897",
    "2644181060",
    "2644279357",
    "2655617036",
    "2655191041",
    "2657124644",
    "2657124745",
    "2657190262",
    "2657222989",
    "2654863391",
    "2583036012",
    "2654863375",
    "2583166998",
    "2583494733",
    "2544861185",
    "2582872140",
    "2583035993",
    "2659024919",
    "2659024935",
    "2659024951",
    "2659024960",
    "2657157163",
    "2657157144",
    "2657157153",
    "2657124419",
    "2657878257",
    "2657681868",
    "2657124373",
    "2657910852",
    "2654372249",
    "2654928926",
    "2657616382",
    "2657682098",
    "2654765182",
    "2657682038",
    "2467103857",
    "2654961748",
    "2655649794",
    "2655060068",
    "2654437866",
    "2654437893",
    "2655027208",
    "2654699537",
    "2654765058",
    "2472181762",
    "2654994466",
    "2655060032",
    "2588999722",
    "2589261876",
    "2589229119",
    "2589229157",
    "2589327361",
    "2589261965",
    "2589261975",
    "2883092927",
    "2886992029",
    "2589294593",
)


class PgeConfluenceWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.workflow = yaml.safe_load(cls.workflow_text)

    def test_workflow_is_manual_read_only_and_main_only(self) -> None:
        self.assertIn("workflow_dispatch:", self.workflow_text)
        self.assertNotRegex(self.workflow_text, r"(?m)^\s+(?:push|pull_request|schedule):")
        self.assertEqual({"contents": "read"}, self.workflow["permissions"])
        authorize = self.workflow["jobs"]["authorize"]
        guard = authorize["steps"][0]["run"]
        self.assertIn('test "${GITHUB_REPOSITORY}" = "${EXPECTED_REPOSITORY}"', guard)
        self.assertIn('test "${GITHUB_REF}" = "refs/heads/main"', guard)
        self.assertEqual(
            "lightning-it/modulix-validation",
            authorize["steps"][0]["env"]["EXPECTED_REPOSITORY"],
        )

    def test_audit_uses_protected_environment_and_pinned_actions(self) -> None:
        audit = self.workflow["jobs"]["audit"]
        self.assertEqual("pge-confluence-read-only", audit["environment"]["name"])
        self.assertEqual("authorize", audit["needs"])
        action_steps = [step for step in audit["steps"] if "uses" in step]
        self.assertTrue(action_steps)
        for step in action_steps:
            with self.subTest(step=step["name"]):
                self.assertRegex(step["uses"], r"@[0-9a-f]{40}$")
        checkout = action_steps[0]
        self.assertFalse(checkout["with"]["persist-credentials"])

    def test_secrets_are_step_scoped_to_the_live_audit(self) -> None:
        audit = self.workflow["jobs"]["audit"]
        self.assertNotIn("env", audit)
        secret_steps = [
            step
            for step in audit["steps"]
            if "secrets." in json.dumps(step, sort_keys=True)
        ]
        self.assertEqual(1, len(secret_steps))
        self.assertEqual(
            "Run the bounded read-only Confluence audit",
            secret_steps[0]["name"],
        )
        self.assertEqual(
            {
                "PGE_CONFLUENCE_API_TOKEN",
                "PGE_CONFLUENCE_USER_EMAIL",
            },
            {
                key
                for key, value in secret_steps[0]["env"].items()
                if "secrets." in value
            },
        )

    def test_workflow_has_no_arbitrary_root_or_snapshot_and_uploads_redacted_reports(self) -> None:
        inputs = self.workflow[True]["workflow_dispatch"]["inputs"]
        self.assertEqual({"audit_scope", "warnings_as_errors"}, set(inputs))
        self.assertEqual(
            [
                "all",
                "pge-product-baseline",
                "pge-templates-and-catalog",
                "lit-pis-engagement",
            ],
            inputs["audit_scope"]["options"],
        )
        baseline_case = self.workflow_text.split("pge-product-baseline)", 1)[1].split(
            ";;", 1
        )[0]
        self.assertIn("--target pge-canonical-product", baseline_case)
        self.assertIn("--target pge-product-decisions", baseline_case)
        self.assertIn("--target pge-template-library", baseline_case)
        self.assertIn("--target pge-artifact-catalog", baseline_case)
        self.assertNotIn("--snapshot-out", self.workflow_text)
        self.assertIn("--redact-details", self.workflow_text)
        self.assertIn("${RUNNER_TEMP}/pge-confluence-conformance", self.workflow_text)
        upload = self.workflow["jobs"]["audit"]["steps"][-1]
        self.assertIn("conformance-report.*", upload["with"]["path"])
        self.assertEqual(14, upload["with"]["retention-days"])

    def test_live_client_is_get_only_and_never_accepts_token_arguments(self) -> None:
        script = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn('method="GET"', script)
        self.assertNotIn('method="POST"', script)
        self.assertNotIn('method="PUT"', script)
        self.assertNotIn('method="DELETE"', script)
        self.assertNotIn("--token", script)
        self.assertIn('os.environ.get("PGE_CONFLUENCE_API_TOKEN", "")', script)

    def test_inventory_fixes_roots_profiles_counts_and_alignment(self) -> None:
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        self.assertEqual(1, config["schema_version"])
        self.assertEqual(
            "https://wiki.cloud.l-it.io",
            config["allowed_confluence_origin"],
        )
        targets = {item["name"]: item for item in config["targets"]}
        self.assertEqual(
            {
                "pge-canonical-product",
                "pge-product-decisions",
                "pge-template-library",
                "pge-artifact-catalog",
                "lit-pis-engagement",
            },
            set(targets),
        )
        self.assertEqual("001-036", targets["pge-product-decisions"]["expected_decision_set"])
        for current in targets.values():
            self.assertIn(current["traversal"], {"recursive", "page-only"})
            if "expected_page_count" in current:
                self.assertGreater(current["expected_page_count"], 0)
        canonical = targets["pge-canonical-product"]
        self.assertEqual("2875654145", canonical["root_page_id"])
        self.assertEqual(792, canonical["expected_page_count"])
        self.assertEqual(
            {
                "direct_validated": 52,
                "delegated": 51,
                "disposition_excluded": 689,
            },
            canonical["expected_classification_counts"],
        )
        self.assertEqual(
            CANONICAL_EXCLUDED_ROOTS,
            tuple(canonical["excluded_subtree_root_ids"]),
        )
        self.assertEqual(
            {("2892759041", 12), ("2892890133", 10)},
            {
                (authority["page_id"], authority["version"])
                for authority in canonical["exclusion_authorities"]
            },
        )
        self.assertEqual(
            [
                {
                    "root_page_id": "2882765966",
                    "target_name": "pge-product-decisions",
                },
                {
                    "root_page_id": "2891710468",
                    "target_name": "pge-template-library",
                },
            ],
            canonical["delegated_subtree_targets"],
        )
        self.assertEqual(40, targets["pge-product-decisions"]["expected_page_count"])
        self.assertEqual(11, targets["pge-template-library"]["expected_page_count"])
        self.assertEqual(1, targets["pge-artifact-catalog"]["expected_page_count"])
        self.assertEqual("page-only", targets["pge-artifact-catalog"]["traversal"])
        self.assertEqual(389, targets["lit-pis-engagement"]["expected_page_count"])
        self.assertEqual(1, len(config["alignments"]))
        alignment = config["alignments"][0]
        self.assertEqual("pge-artifact-template-alignment", alignment["name"])
        self.assertEqual("pge-template-library", alignment["template_target"])
        self.assertEqual("pge-artifact-catalog", alignment["catalog_target"])
        self.assertEqual(2, len(alignment["product_source_artifacts"]))

    def test_docs_forbid_shell_history_tokens_and_git_ignores_evidence(self) -> None:
        documentation = DOC_PATH.read_text(encoding="utf-8")
        self.assertIn("Never paste,", documentation)
        self.assertIn("op run --env-file=", documentation)
        self.assertNotRegex(
            documentation,
            re.compile(r"(?m)^(?:export\s+)?PGE_CONFLUENCE_API_TOKEN="),
        )
        ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
        for entry in ("evidence/", "snapshots/", ".pge-conformance/"):
            self.assertIn(entry, ignored)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("docs/pge-confluence-conformance.md", readme)


if __name__ == "__main__":
    unittest.main()
