from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


SCRIPT = Path(__file__).parents[1] / ".github/scripts/workbench-public-acceptance.py"
SPEC = importlib.util.spec_from_file_location("workbench_public_acceptance", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class FakeExecutor:
    def __init__(self, failures=None, second_changed=0):
        self.failures = set(failures or [])
        self.second_changed = second_changed
        self.calls = []

    def run_phase(self, name, playbook, cmdline="", extra_vars=None, timeout_seconds=None):
        self.calls.append((name, playbook, cmdline, dict(extra_vars or {}), timeout_seconds))
        failed = name in self.failures
        changed = self.second_changed if name == "deployment-second" else 0
        if name == "deployment-first":
            changed = 5
        return MODULE.PhaseResult(
            name=name,
            status="failed" if failed else "successful",
            rc=1 if failed else 0,
            duration_seconds=0.01,
            stats={
                "ok": 1,
                "changed": changed,
                "failures": 1 if failed else 0,
                "unreachable": 0,
                "skipped": 0,
                "rescued": 0,
                "ignored": 0,
            },
        )


def create_contract():
    root = Path("/workspace")
    return MODULE.Contract(
        suite="workbench-public-acceptance",
        matrix_digest="0" * 64,
        workspace=root,
        target=MODULE.EXPECTED_TARGET,
        target_address=MODULE.EXPECTED_ADDRESS,
        inventory_group=MODULE.EXPECTED_GROUP,
        ssh_port=MODULE.EXPECTED_PORT,
        ansible_user=MODULE.EXPECTED_USER,
        automation_root=root / "modulix-automation",
        inventory_root=root / "ansible-inventory-lit",
        inventory=root / "ansible-inventory-lit/inventories/pub/inventory.yml",
        ansible_config=root / "modulix-automation/ansible/ansible.cfg",
        deployment_playbook=root / "modulix-automation/deploy.yml",
        validation_playbook=root / "modulix-automation/validate.yml",
        acceptance_playbook=root / "modulix-automation/accept.yml",
        cleanup_playbook=root / "modulix-automation/cleanup.yml",
        profiles=MODULE.EXPECTED_PROFILES,
        profile_variable=MODULE.EXPECTED_PROFILE_VARIABLE,
        run_id_variable=MODULE.EXPECTED_RUN_ID_VARIABLE,
        phase_timeout_seconds=300,
        cleanup_timeout_seconds=120,
    )


class WorkbenchAcceptanceTests(unittest.TestCase):
    def test_profile_selection_is_bounded_and_ordered(self):
        selected = MODULE.select_profiles("application,tiny", MODULE.EXPECTED_PROFILES)
        self.assertEqual(selected, ("tiny", "application"))
        with self.assertRaises(MODULE.HarnessError):
            MODULE.select_profiles("tiny,unknown", MODULE.EXPECTED_PROFILES)

    def test_run_identifier_matches_automation_cleanup_contract(self):
        MODULE.validate_run_id("gh-123-a1")
        with self.assertRaises(MODULE.HarnessError):
            MODULE.validate_run_id("GH-123-A1")
        with self.assertRaises(MODULE.HarnessError):
            MODULE.validate_run_id("a" * 25)

    def test_sensitive_environment_is_not_forwarded(self):
        contract = create_contract()
        with tempfile.TemporaryDirectory() as collections:
            source = {
                "PATH": os.environ["PATH"],
                "HOME": "/tmp/controller",
                "GITHUB_ACTIONS": "true",
                "GITHUB_TOKEN": "do-not-forward",
                "WORKBENCH_PASSWORD": "do-not-forward",
                "SSH_AUTH_SOCK": "/tmp/agent.sock",
            }
            child = MODULE.build_child_environment(source, contract, collections)
        self.assertNotIn("GITHUB_TOKEN", child)
        self.assertNotIn("WORKBENCH_PASSWORD", child)
        self.assertNotIn("SSH_AUTH_SOCK", child)
        self.assertEqual(child["ANSIBLE_HOST_KEY_CHECKING"], "True")

    def test_process_environment_is_replaced_not_merged(self):
        environment = {"PATH": "/usr/bin", "UNRECOGNIZED_RUNTIME_VALUE": "discard"}
        MODULE.replace_process_environment(environment, {"PATH": "/usr/bin"})
        self.assertEqual(environment, {"PATH": "/usr/bin"})

    def test_controller_must_be_github_hosted_and_not_the_target(self):
        contract = create_contract()
        with self.assertRaises(MODULE.HarnessError):
            MODULE.validate_controller_environment(
                {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"},
                contract,
            )
        with self.assertRaises(MODULE.HarnessError):
            MODULE.validate_controller_environment(
                {
                    "GITHUB_ACTIONS": "true",
                    "RUNNER_ENVIRONMENT": "github-hosted",
                    "RUNNER_NAME": MODULE.EXPECTED_TARGET,
                },
                contract,
            )

    def test_inventory_payload_requires_exact_target_contract(self):
        contract = create_contract()
        payload = {
            "_meta": {
                "hostvars": {
                    MODULE.EXPECTED_TARGET: {
                        "ansible_host": MODULE.EXPECTED_ADDRESS,
                        "ansible_port": "{{ openssh_server_primary_port }}",
                        "openssh_server_primary_port": MODULE.EXPECTED_PORT,
                        "ansible_user": MODULE.EXPECTED_USER,
                        "ansible_password": None,
                        "ansible_become_password": None,
                        "deploy_ssh_private_key_path": MODULE.EXPECTED_DEPLOY_KEY_PATH,
                        "ansible_private_key_file": MODULE.EXPECTED_DEPLOY_KEY_TEMPLATE,
                        "hetzner_baremetal_rescue_known_hosts_path": (
                            MODULE.EXPECTED_KNOWN_HOSTS_TEMPLATE
                        ),
                        "ansible_ssh_common_args": MODULE.EXPECTED_SSH_COMMON_ARGS,
                        "workbench_enabled": True,
                        "workbench_target_hostname": MODULE.EXPECTED_TARGET,
                    }
                }
            },
            MODULE.EXPECTED_GROUP: {"hosts": [MODULE.EXPECTED_TARGET]},
        }
        MODULE.validate_inventory_payload(payload, contract)
        payload["_meta"]["hostvars"][MODULE.EXPECTED_TARGET]["openssh_server_primary_port"] = 1905.1
        with self.assertRaises(MODULE.HarnessError):
            MODULE.validate_inventory_payload(payload, contract)
        payload["_meta"]["hostvars"][MODULE.EXPECTED_TARGET]["openssh_server_primary_port"] = MODULE.EXPECTED_PORT
        payload["_meta"]["hostvars"][MODULE.EXPECTED_TARGET]["ansible_host"] = "192.0.2.1"
        with self.assertRaises(MODULE.HarnessError):
            MODULE.validate_inventory_payload(payload, contract)

    def test_inventory_payload_rejects_local_connection_or_extra_group_host(self):
        contract = create_contract()
        variables = {
            "ansible_host": MODULE.EXPECTED_ADDRESS,
            "ansible_port": MODULE.EXPECTED_PORT,
            "ansible_user": MODULE.EXPECTED_USER,
            "ansible_password": None,
            "ansible_become_password": None,
            "deploy_ssh_private_key_path": MODULE.EXPECTED_DEPLOY_KEY_PATH,
            "ansible_private_key_file": MODULE.EXPECTED_DEPLOY_KEY_TEMPLATE,
            "hetzner_baremetal_rescue_known_hosts_path": MODULE.EXPECTED_KNOWN_HOSTS_TEMPLATE,
            "ansible_ssh_common_args": MODULE.EXPECTED_SSH_COMMON_ARGS,
            "workbench_enabled": True,
            "workbench_target_hostname": MODULE.EXPECTED_TARGET,
        }
        payload = {
            "_meta": {"hostvars": {MODULE.EXPECTED_TARGET: variables}},
            MODULE.EXPECTED_GROUP: {"hosts": [MODULE.EXPECTED_TARGET]},
        }
        variables["ansible_connection"] = "local"
        with self.assertRaises(MODULE.HarnessError):
            MODULE.validate_inventory_payload(payload, contract)
        variables.pop("ansible_connection")
        payload[MODULE.EXPECTED_GROUP]["hosts"].append("other.example.invalid")
        with self.assertRaises(MODULE.HarnessError):
            MODULE.validate_inventory_payload(payload, contract)

        payload[MODULE.EXPECTED_GROUP]["hosts"] = [MODULE.EXPECTED_TARGET]
        variables["deploy_ssh_private_key_path"] = ".ssh/another-key"
        with self.assertRaises(MODULE.HarnessError):
            MODULE.validate_inventory_payload(payload, contract)

    def test_second_deployment_must_be_idempotent_and_cleanup_still_runs(self):
        contract = create_contract()
        executor = FakeExecutor(second_changed=1)
        outcome = MODULE.execute_full(executor, contract, ("tiny", "heavy"), "gh-123-a1")
        self.assertEqual(outcome.error_code, "second_deployment_not_idempotent")
        self.assertFalse(outcome.successful)
        names = [call[0] for call in executor.calls]
        self.assertEqual(names[-2:], ["cleanup-tiny", "cleanup-heavy"])
        self.assertEqual([call[4] for call in executor.calls[-2:]], [120, 120])
        self.assertNotIn("validation", names)

    def test_cleanup_is_unconditional_after_phase_failure(self):
        contract = create_contract()
        executor = FakeExecutor(failures={"deployment-check"})
        outcome = MODULE.execute_full(executor, contract, MODULE.EXPECTED_PROFILES, "gh-123-a1")
        self.assertEqual(outcome.error_code, "phase_failed_deployment-check")
        names = [call[0] for call in executor.calls]
        self.assertEqual(
            names[-3:],
            ["cleanup-tiny", "cleanup-heavy", "cleanup-application"],
        )
        self.assertTrue(outcome.cleanup_succeeded)

    def test_checked_in_matrix_rejects_target_drift(self):
        matrix = yaml.safe_load(
            (Path(__file__).parents[1] / "inventories/acceptance/workbench-public.yml").read_text(
                encoding="utf-8"
            )
        )
        matrix["target"]["hostname"] = "another.example.invalid"
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            automation = workspace / "modulix-automation"
            inventory_root = workspace / "ansible-inventory-lit"
            files = [
                automation / matrix["paths"]["ansible_config"],
                automation / matrix["paths"]["deployment_playbook"],
                automation / matrix["paths"]["validation_playbook"],
                automation / matrix["paths"]["acceptance_playbook"],
                automation / matrix["paths"]["cleanup_playbook"],
                inventory_root / matrix["paths"]["inventory"],
            ]
            for path in files:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            matrix_path = workspace / "matrix.yml"
            matrix_path.write_text(yaml.safe_dump(matrix), encoding="utf-8")
            with self.assertRaises(MODULE.HarnessError):
                MODULE.load_contract(matrix_path, workspace)

            matrix["target"]["hostname"] = MODULE.EXPECTED_TARGET
            original_deployment_playbook = matrix["paths"]["deployment_playbook"]
            matrix["paths"]["deployment_playbook"] = matrix["paths"]["cleanup_playbook"]
            matrix_path.write_text(yaml.safe_dump(matrix), encoding="utf-8")
            with self.assertRaises(MODULE.HarnessError) as context:
                MODULE.load_contract(matrix_path, workspace)
            self.assertEqual(context.exception.code, "path_contract_invalid")

            matrix["paths"]["deployment_playbook"] = original_deployment_playbook
            acceptance_playbook = automation / matrix["paths"]["acceptance_playbook"]
            acceptance_playbook.unlink()
            matrix_path.write_text(yaml.safe_dump(matrix), encoding="utf-8")
            with self.assertRaises(MODULE.HarnessError) as context:
                MODULE.load_contract(matrix_path, workspace)
            self.assertEqual(context.exception.code, "acceptance_playbook_missing")

    def test_ansible_runner_stats_are_aggregated_without_host_names(self):
        totals = MODULE.validate_and_aggregate_stats(
            {
                "processed": {MODULE.EXPECTED_TARGET: 1},
                "ok": {
                    MODULE.EXPECTED_TARGET: 7,
                },
                "changed": {MODULE.EXPECTED_TARGET: 1},
                "failures": {},
                "dark": {},
                "skipped": {},
                "rescued": {},
                "ignored": {},
            },
            MODULE.EXPECTED_TARGET,
        )
        self.assertEqual(totals["ok"], 7)
        self.assertEqual(totals["changed"], 1)
        self.assertEqual(totals["unreachable"], 0)
        self.assertNotIn(MODULE.EXPECTED_TARGET, totals)

    def test_ansible_runner_stats_require_exactly_the_target(self):
        with self.assertRaises(MODULE.HarnessError):
            MODULE.validate_and_aggregate_stats({}, MODULE.EXPECTED_TARGET)
        with self.assertRaises(MODULE.HarnessError):
            MODULE.validate_and_aggregate_stats(
                {
                    "processed": {"other.example.invalid": 1},
                    "ok": {"other.example.invalid": 1},
                    "changed": {},
                    "failures": {},
                    "dark": {},
                    "skipped": {},
                    "rescued": {},
                    "ignored": {},
                },
                MODULE.EXPECTED_TARGET,
            )

    def test_evidence_task_labels_drop_sensitive_or_dynamic_names(self):
        self.assertEqual(
            MODULE.sanitize_task_label("Validate exact Workbench target"),
            "Validate exact Workbench target",
        )
        self.assertIsNone(MODULE.sanitize_task_label("Use token {{ runtime_token }}"))
        self.assertIsNone(MODULE.sanitize_task_label("Call https://private.example.invalid"))


if __name__ == "__main__":
    unittest.main()
