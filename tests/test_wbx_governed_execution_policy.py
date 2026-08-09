"""Static tests for the Wunderbox governed-execution binding.

These tests do not invoke Ansible, a provider, an inventory plugin, or a host.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies" / "wunderbox" / "root-of-trust-policy.json"
TEMPLATE_PATH = ROOT / "policies" / "wunderbox" / "gate-manifest.template.json"
ADAPTER_PATH = ROOT / "scripts" / "wbx-governed-exec.py"
SPEC = importlib.util.spec_from_file_location("wbx_governed_exec", ADAPTER_PATH)
assert SPEC and SPEC.loader
ADAPTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADAPTER)
RENDERER_PATH = ROOT / "scripts" / "render-wbx-gate-manifest-template.py"
RENDERER_SPEC = importlib.util.spec_from_file_location(
    "render_wbx_gate_manifest", RENDERER_PATH
)
assert RENDERER_SPEC and RENDERER_SPEC.loader
RENDERER = importlib.util.module_from_spec(RENDERER_SPEC)
RENDERER_SPEC.loader.exec_module(RENDERER)


class WunderboxPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        cls.template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))

    def test_action_and_attempt_are_the_only_execution_selectors(self):
        option_strings = {
            option
            for action in ADAPTER.build_parser()._actions
            for option in action.option_strings
        }
        self.assertIn("--action-id", option_strings)
        self.assertIn("--attempt", option_strings)
        for forbidden in (
            "--target",
            "--inventory",
            "--playbook",
            "--gate",
            "--impact",
            "--command",
            "--tags",
            "--execution-image",
        ):
            self.assertNotIn(forbidden, option_strings)

    def test_action_prefixes_are_unique_and_required_vars_are_bound(self):
        actions = self.policy["actions"]
        prefixes = [action["record_prefix"] for action in actions.values()]
        self.assertEqual(len(prefixes), len(set(prefixes)))
        for action in actions.values():
            required = set(action.get("required_extra_vars", []))
            self.assertEqual(required, set(action.get("extra_var_bindings", {})))

    def test_known_side_effecting_actions_are_not_classified_as_read_only(self):
        expected = {
            "prepare_installimage_plan": "security_relevant",
            "installimage_plan": "security_relevant",
            "cis_audit": "security_relevant",
            "vault_plan": "security_relevant",
            "first_encrypted_boot": "availability",
            "bootstrap_unlock": "recovery",
            "first_boot_reconnect": "security_relevant",
            "installed_acceptance": "availability",
        }
        for action_id, impact in expected.items():
            self.assertEqual(self.policy["actions"][action_id]["impact"], impact)

    def test_live_actions_cannot_run_under_safety_hold(self):
        for action in self.policy["actions"].values():
            if action["gate"] == "WBX-G3":
                self.assertFalse(action.get("allowed_under_safety_hold", False))

    def test_desktop_integrated_onepassword_actions_are_fail_closed(self):
        expected = {
            "recovery_metadata_plan",
            "prepare_installimage_plan",
            "prepare_installimage_apply",
            "installimage_plan",
            "bootstrap_unlock",
        }
        for action_id in expected:
            action = self.policy["actions"][action_id]
            self.assertEqual(action["implementation_status"], "blocked")
            self.assertEqual(
                action["implementation_blocker"],
                "blocked_missing_desktop_integrated_onepassword_controller_runtime",
            )

        # installimage_plan is secret-free, but not independently valid: its
        # verified Dropbear hook is produced by the blocked prepare action.
        self.assertEqual(
            self.policy["actions"]["installimage_plan"]["implementation_status"],
            self.policy["actions"]["prepare_installimage_plan"][
                "implementation_status"
            ],
        )

    def test_install_apply_is_blocked_without_secret_safe_orchestrator(self):
        apply = self.policy["actions"]["installimage_apply"]

        self.assertEqual(apply["implementation_status"], "blocked")
        self.assertEqual(
            apply["implementation_blocker"],
            "dedicated_secret_safe_onepassword_installimage_orchestrator_missing",
        )

    def test_onepassword_agent_and_signed_approval_transport_are_explicit(self):
        for action_id in ("prepare_installimage_plan", "prepare_installimage_apply"):
            self.assertIs(
                self.policy["actions"][action_id]["requires_ssh_agent"], True
            )
        unlock = self.policy["actions"]["bootstrap_unlock"]
        self.assertFalse(unlock["requires_ssh_private_key"])
        self.assertTrue(unlock["requires_ssh_agent"])
        self.assertEqual(
            unlock["extra_var_bindings"]["hetzner_bootstrap_unlock_approval"],
            {
                "kind": "signed_approval_transport",
                "field": "onepassword_approval",
            },
        )
        self.assertEqual(
            unlock["extra_var_bindings"][
                "hetzner_bootstrap_unlock_dropbear_fingerprint"
            ]["field"],
            "approved_dropbear_fingerprint",
        )
        self.assertEqual(
            unlock["extra_var_bindings"][
                "hetzner_bootstrap_unlock_known_hosts_sha256"
            ]["field"],
            "approved_dropbear_known_hosts_sha256",
        )
        self.assertIn(
            "approved_dropbear_known_hosts_sha256",
            self.template["authorizations"][
                "REPLACE_WITH_EACH_POLICY_ACTION_ID"
            ],
        )
        self.assertIn(
            "signature",
            self.template["authorizations"][
                "REPLACE_WITH_EACH_POLICY_ACTION_ID"
            ]["onepassword_approval"],
        )

    def test_every_persisted_callback_artifact_has_a_projection(self):
        for action in self.policy["actions"].values():
            if action.get("expected_artifact"):
                self.assertTrue(action.get("artifact_projection_paths"))

    def test_policy_contains_no_real_environment_identity(self):
        text = POLICY_PATH.read_text(encoding="utf-8").lower()
        for private_literal in (
            "wunderbox01",
            "136.243.38.174",
            "3035773",
            "153.53.58.197",
            "rené osorio",
            "dirk egert",
        ):
            self.assertNotIn(private_literal, text)

    def test_manifest_template_is_deliberately_non_executable(self):
        self.assertEqual(self.template["manifest_status"], "TEMPLATE")
        self.assertTrue(self.template["safety_hold"])
        self.assertEqual(
            self.template["authorizations"]["REPLACE_WITH_EACH_POLICY_ACTION_ID"]["status"],
            "NOT_APPROVED",
        )

    def test_renderer_expands_the_complete_nonapproved_action_matrix(self):
        rendered = RENDERER.render()
        self.assertEqual(set(rendered["authorizations"]), set(self.policy["actions"]))
        self.assertEqual(
            {entry["status"] for entry in rendered["authorizations"].values()},
            {"NOT_APPROVED"},
        )
        expected_blockers = {
            "recovery_metadata_plan": (
                "blocked_missing_desktop_integrated_onepassword_controller_runtime"
            ),
            "prepare_installimage_plan": (
                "blocked_missing_desktop_integrated_onepassword_controller_runtime"
            ),
            "prepare_installimage_apply": (
                "blocked_missing_desktop_integrated_onepassword_controller_runtime"
            ),
            "installimage_plan": (
                "blocked_missing_desktop_integrated_onepassword_controller_runtime"
            ),
            "bootstrap_unlock": (
                "blocked_missing_desktop_integrated_onepassword_controller_runtime"
            ),
            "installimage_apply": (
                "dedicated_secret_safe_onepassword_installimage_orchestrator_missing"
            ),
        }
        rendered_blocked = {
            action_id: entry["implementation_blocker"]
            for action_id, entry in rendered["authorizations"].items()
            if entry.get("implementation_status") == "BLOCKED"
        }
        self.assertEqual(rendered_blocked, expected_blockers)
        action_ids = list(rendered["authorizations"])
        self.assertIsNot(
            rendered["authorizations"][action_ids[0]]["onepassword_approval"],
            rendered["authorizations"][action_ids[1]]["onepassword_approval"],
        )
        self.assertEqual(len(rendered["policy_sha256"]), 64)

    def test_adapter_builds_only_the_fixed_policy_and_repository_set(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            automation = root / "automation"
            (automation / "scripts").mkdir(parents=True)
            (automation / "scripts" / "governed-ansible-exec.py").write_text(
                "#!/usr/bin/env python3\n", encoding="utf-8"
            )
            args = argparse.Namespace(
                automation_repo=automation,
                inventory_repo=root / "inventory",
                foundational_repo=root / "foundational",
                ubuntu_repo=root / "ubuntu",
                operations_repo=root / "operations",
                gate_manifest=root / "manifest.json",
                gate_signature=root / "manifest.sig",
                allowed_signers=root / "allowed_signers",
                action_id="target_inventory_projection",
                attempt=1,
                operator="operator",
                reviewer="reviewer",
                purpose="test",
                jira="TEST-1",
                extra_vars=None,
                evidence_dir=root / "evidence",
            )
            command = ADAPTER.build_core_command(args)
        self.assertIn(str(POLICY_PATH), command)
        repo_values = [
            command[index + 1]
            for index, value in enumerate(command)
            if value == "--repo"
        ]
        self.assertEqual(
            {value.split("=", 1)[0] for value in repo_values},
            {"automation", "inventory", "foundational", "ubuntu", "validation", "operations"},
        )
        self.assertNotIn("--target", command)
        self.assertNotIn("--playbook", command)


if __name__ == "__main__":
    unittest.main()
