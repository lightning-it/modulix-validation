#!/usr/bin/env python3
"""Run the bounded public Workbench acceptance contract without retaining raw output."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml


EXPECTED_TARGET = "wbn01.prd.edge.pub.l-it.io"
EXPECTED_ADDRESS = "195.201.173.85"
EXPECTED_GROUP = "ubuntu_workbenches"
EXPECTED_PORT = 1905
EXPECTED_USER = "svc_ansible"
EXPECTED_DEPLOY_KEY_PATH = ".ssh/id_ed25519_lit_codex_deploy"
EXPECTED_DEPLOY_KEY_TEMPLATE = (
    "{{ lookup('ansible.builtin.env', 'HOME') }}/{{ deploy_ssh_private_key_path }}"
)
EXPECTED_KNOWN_HOSTS_TEMPLATE = (
    "{{ ( lookup('ansible.builtin.env', 'PWD') | default('/runner/project', true) ) "
    "~ '/.tmp/hetzner-baremetal-known-hosts' }}"
)
EXPECTED_SSH_COMMON_ARGS = (
    "-o UserKnownHostsFile={{ hetzner_baremetal_rescue_known_hosts_path }} "
    "-o StrictHostKeyChecking=yes -o IdentitiesOnly=yes"
)
EXPECTED_AUTOMATION_ROOT = Path("modulix-automation")
EXPECTED_INVENTORY_ROOT = Path("ansible-inventory-lit")
EXPECTED_INVENTORY = Path("inventories/pub/inventory.yml")
EXPECTED_ANSIBLE_CONFIG = Path("ansible/ansible.cfg")
EXPECTED_DEPLOYMENT_PLAYBOOK = Path(
    "ansible/runbooks/50-applications/workbench/20-ubuntu-setup.yml"
)
EXPECTED_VALIDATION_PLAYBOOK = Path(
    "ansible/runbooks/50-applications/workbench/30-validate.yml"
)
EXPECTED_ACCEPTANCE_PLAYBOOK = Path(
    "ansible/runbooks/50-applications/workbench/40-acceptance.yml"
)
EXPECTED_CLEANUP_PLAYBOOK = Path(
    "ansible/runbooks/50-applications/workbench/50-cleanup.yml"
)
EXPECTED_PROFILES = ("tiny", "heavy", "application")
EXPECTED_PROFILE_VARIABLE = "workbench_acceptance_profile"
EXPECTED_RUN_ID_VARIABLE = "workbench_acceptance_run_id"
EXPECTED_MATRIX = Path("modulix-validation-lit/inventories/acceptance/workbench-public.yml")
SAFE_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,23}$")
SAFE_TASK_LABEL = re.compile(r"[^A-Za-z0-9 ._:/()=+-]")
SENSITIVE_ENV_PARTS = (
    "TOKEN",
    "PASSWORD",
    "PASSPHRASE",
    "SECRET",
    "PRIVATE_KEY",
    "CREDENTIAL",
    "AUTHORIZATION",
    "VAULT",
)
SENSITIVE_ENV_EXACT = {"SSH_AUTH_SOCK", "SSH_AGENT_PID", "GITHUB_TOKEN"}
SAFE_ENV_NAMES = {
    "CI",
    "GITHUB_ACTIONS",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LOGNAME",
    "NO_COLOR",
    "PATH",
    "RUNNER_ENVIRONMENT",
    "RUNNER_NAME",
    "TERM",
    "TMPDIR",
    "TZ",
    "USER",
}
STAT_KEYS = ("ok", "changed", "failures", "unreachable", "skipped", "rescued", "ignored")


class HarnessError(RuntimeError):
    """A safe, code-only harness failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Contract:
    suite: str
    matrix_digest: str
    workspace: Path
    target: str
    target_address: str
    inventory_group: str
    ssh_port: int
    ansible_user: str
    automation_root: Path
    inventory_root: Path
    inventory: Path
    ansible_config: Path
    deployment_playbook: Path
    validation_playbook: Path
    acceptance_playbook: Path
    cleanup_playbook: Path
    profiles: tuple[str, ...]
    profile_variable: str
    run_id_variable: str
    phase_timeout_seconds: int
    cleanup_timeout_seconds: int


@dataclass
class PhaseResult:
    name: str
    status: str
    rc: int
    duration_seconds: float
    stats: dict[str, int] = field(default_factory=dict)
    checks: list[dict[str, str]] = field(default_factory=list)


@dataclass
class ExecutionOutcome:
    results: list[PhaseResult]
    error_code: str | None
    cleanup_attempted: bool
    cleanup_succeeded: bool

    @property
    def successful(self) -> bool:
        return self.error_code is None and self.cleanup_succeeded


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def require_mapping(value: Any, code: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise HarnessError(code)
    return value


def require_exact_keys(value: Mapping[str, Any], expected: set[str], code: str) -> None:
    if set(value) != expected:
        raise HarnessError(code)


def compact_string(value: Any) -> str:
    return " ".join(value.split()) if isinstance(value, str) else ""


def resolve_workspace_member(workspace: Path, relative: Any, code: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise HarnessError(code)
    candidate = (workspace / relative).resolve()
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise HarnessError(code) from exc
    if not candidate.is_dir():
        raise HarnessError(code)
    return candidate


def resolve_existing_file(root: Path, relative: Any, code: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise HarnessError(code)
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise HarnessError(code) from exc
    if not candidate.is_file():
        raise HarnessError(code)
    return candidate


def load_contract(matrix_path: Path, workspace: Path) -> Contract:
    workspace = workspace.resolve()
    if not workspace.is_dir():
        raise HarnessError("workspace_missing")
    try:
        matrix_bytes = matrix_path.read_bytes()
        data = yaml.safe_load(matrix_bytes)
    except (OSError, yaml.YAMLError) as exc:
        raise HarnessError("matrix_unreadable") from exc

    root = require_mapping(data, "matrix_invalid")
    require_exact_keys(
        root,
        {"schema_version", "suite", "controller", "target", "paths", "acceptance", "ansible"},
        "matrix_schema_invalid",
    )
    if root["schema_version"] != 1 or root["suite"] != "workbench-public-acceptance":
        raise HarnessError("matrix_identity_invalid")

    controller = require_mapping(root["controller"], "controller_contract_invalid")
    require_exact_keys(controller, {"runner_environment"}, "controller_contract_invalid")
    if controller["runner_environment"] != "github-hosted":
        raise HarnessError("controller_contract_invalid")

    target = require_mapping(root["target"], "target_contract_invalid")
    require_exact_keys(
        target,
        {"hostname", "address", "inventory_group", "ssh_port", "ansible_user"},
        "target_contract_invalid",
    )
    if target != {
        "hostname": EXPECTED_TARGET,
        "address": EXPECTED_ADDRESS,
        "inventory_group": EXPECTED_GROUP,
        "ssh_port": EXPECTED_PORT,
        "ansible_user": EXPECTED_USER,
    }:
        raise HarnessError("target_contract_invalid")

    paths = require_mapping(root["paths"], "path_contract_invalid")
    require_exact_keys(
        paths,
        {
            "automation_root",
            "inventory_root",
            "inventory",
            "ansible_config",
            "deployment_playbook",
            "validation_playbook",
            "acceptance_playbook",
            "cleanup_playbook",
        },
        "path_contract_invalid",
    )
    if paths != {
        "automation_root": str(EXPECTED_AUTOMATION_ROOT),
        "inventory_root": str(EXPECTED_INVENTORY_ROOT),
        "inventory": str(EXPECTED_INVENTORY),
        "ansible_config": str(EXPECTED_ANSIBLE_CONFIG),
        "deployment_playbook": str(EXPECTED_DEPLOYMENT_PLAYBOOK),
        "validation_playbook": str(EXPECTED_VALIDATION_PLAYBOOK),
        "acceptance_playbook": str(EXPECTED_ACCEPTANCE_PLAYBOOK),
        "cleanup_playbook": str(EXPECTED_CLEANUP_PLAYBOOK),
    }:
        raise HarnessError("path_contract_invalid")

    automation_root = resolve_workspace_member(workspace, paths["automation_root"], "automation_root_invalid")
    inventory_root = resolve_workspace_member(workspace, paths["inventory_root"], "inventory_root_invalid")
    inventory = resolve_existing_file(inventory_root, paths["inventory"], "inventory_missing")
    ansible_config = resolve_existing_file(automation_root, paths["ansible_config"], "ansible_config_missing")
    deployment_playbook = resolve_existing_file(
        automation_root, paths["deployment_playbook"], "deployment_playbook_missing"
    )
    validation_playbook = resolve_existing_file(
        automation_root, paths["validation_playbook"], "validation_playbook_missing"
    )
    acceptance_playbook = resolve_existing_file(
        automation_root, paths["acceptance_playbook"], "acceptance_playbook_missing"
    )
    cleanup_playbook = resolve_existing_file(automation_root, paths["cleanup_playbook"], "cleanup_playbook_missing")

    acceptance = require_mapping(root["acceptance"], "acceptance_contract_invalid")
    require_exact_keys(
        acceptance,
        {"profiles", "profile_variable", "run_id_variable"},
        "acceptance_contract_invalid",
    )
    profiles = acceptance["profiles"]
    if not isinstance(profiles, list) or tuple(profiles) != EXPECTED_PROFILES:
        raise HarnessError("acceptance_profiles_invalid")
    if acceptance["profile_variable"] != EXPECTED_PROFILE_VARIABLE:
        raise HarnessError("acceptance_profile_variable_invalid")
    if acceptance["run_id_variable"] != EXPECTED_RUN_ID_VARIABLE:
        raise HarnessError("acceptance_run_id_variable_invalid")

    ansible = require_mapping(root["ansible"], "ansible_contract_invalid")
    require_exact_keys(
        ansible,
        {"phase_timeout_seconds", "cleanup_timeout_seconds"},
        "ansible_contract_invalid",
    )
    timeout = ansible["phase_timeout_seconds"]
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 60 <= timeout <= 14400:
        raise HarnessError("ansible_timeout_invalid")
    cleanup_timeout = ansible["cleanup_timeout_seconds"]
    if (
        not isinstance(cleanup_timeout, int)
        or isinstance(cleanup_timeout, bool)
        or not 60 <= cleanup_timeout <= 1800
        or cleanup_timeout > timeout
    ):
        raise HarnessError("cleanup_timeout_invalid")

    return Contract(
        suite=root["suite"],
        matrix_digest=hashlib.sha256(matrix_bytes).hexdigest(),
        workspace=workspace,
        target=target["hostname"],
        target_address=target["address"],
        inventory_group=target["inventory_group"],
        ssh_port=target["ssh_port"],
        ansible_user=target["ansible_user"],
        automation_root=automation_root,
        inventory_root=inventory_root,
        inventory=inventory,
        ansible_config=ansible_config,
        deployment_playbook=deployment_playbook,
        validation_playbook=validation_playbook,
        acceptance_playbook=acceptance_playbook,
        cleanup_playbook=cleanup_playbook,
        profiles=tuple(profiles),
        profile_variable=acceptance["profile_variable"],
        run_id_variable=acceptance["run_id_variable"],
        phase_timeout_seconds=timeout,
        cleanup_timeout_seconds=cleanup_timeout,
    )


def validate_controller_environment(environ: Mapping[str, str], contract: Contract) -> None:
    if environ.get("GITHUB_ACTIONS", "").lower() != "true":
        raise HarnessError("github_actions_required")
    if environ.get("RUNNER_ENVIRONMENT", "").lower() != "github-hosted":
        raise HarnessError("github_hosted_runner_required")
    local_names = {
        environ.get("RUNNER_NAME", "").strip().lower(),
        socket.gethostname().strip().lower(),
        socket.getfqdn().strip().lower(),
    }
    target_names = {contract.target.lower(), contract.target.split(".", 1)[0].lower()}
    if any(name in target_names for name in local_names if name):
        raise HarnessError("target_must_not_be_runner")


def is_sensitive_environment_name(name: str) -> bool:
    upper = name.upper()
    if upper in SENSITIVE_ENV_EXACT:
        return True
    return any(part in upper for part in SENSITIVE_ENV_PARTS) or upper.endswith("_KEY")


def purge_sensitive_environment(environ: dict[str, str]) -> None:
    for name in tuple(environ):
        if is_sensitive_environment_name(name):
            environ.pop(name, None)


def replace_process_environment(environ: dict[str, str], safe_environment: Mapping[str, str]) -> None:
    environ.clear()
    environ.update(safe_environment)


def build_child_environment(
    source: Mapping[str, str], contract: Contract, collections_path: str
) -> dict[str, str]:
    collection_entries = [Path(item).resolve() for item in collections_path.split(os.pathsep) if item]
    if not collection_entries or any(not item.is_dir() for item in collection_entries):
        raise HarnessError("collections_path_invalid")
    child = {name: source[name] for name in SAFE_ENV_NAMES if name in source}
    child.update(
        {
            "ANSIBLE_CONFIG": str(contract.ansible_config),
            "ANSIBLE_COLLECTIONS_PATH": os.pathsep.join(str(item) for item in collection_entries),
            "ANSIBLE_DISPLAY_ARGS_TO_STDOUT": "False",
            "ANSIBLE_HOST_KEY_CHECKING": "True",
            "ANSIBLE_NOCOLOR": "True",
            "ANSIBLE_RETRY_FILES_ENABLED": "False",
            "ANSIBLE_SSH_ARGS": "-o ControlMaster=no",
            "ANSIBLE_TRANSPORT": "ssh",
            "NO_COLOR": "1",
            "PWD": str(contract.workspace),
        }
    )
    if "TMPDIR" in child:
        ansible_home = Path(child["TMPDIR"]) / "ansible-home"
        ansible_local_temp = Path(child["TMPDIR"]) / "ansible-local"
        ansible_home.mkdir(parents=True, exist_ok=True, mode=0o700)
        ansible_local_temp.mkdir(parents=True, exist_ok=True, mode=0o700)
        child["ANSIBLE_HOME"] = str(ansible_home)
        child["ANSIBLE_LOCAL_TEMP"] = str(ansible_local_temp)
    if any(is_sensitive_environment_name(name) for name in child):
        raise HarnessError("sensitive_environment_not_removed")
    return child


def validate_inventory_payload(payload: Any, contract: Contract) -> None:
    inventory = require_mapping(payload, "inventory_output_invalid")
    group = require_mapping(inventory.get(contract.inventory_group), "inventory_group_missing")
    hosts = group.get("hosts")
    if hosts != [contract.target]:
        raise HarnessError("inventory_target_missing")
    metadata = require_mapping(inventory.get("_meta"), "inventory_metadata_missing")
    hostvars = require_mapping(metadata.get("hostvars"), "inventory_hostvars_missing")
    variables = require_mapping(hostvars.get(contract.target), "inventory_target_vars_missing")
    if variables.get("ansible_host") != contract.target_address:
        raise HarnessError("inventory_target_address_mismatch")
    if variables.get("ansible_user") != contract.ansible_user:
        raise HarnessError("inventory_target_user_mismatch")
    ansible_connection = variables.get("ansible_connection", "ssh")
    if not isinstance(ansible_connection, str) or ansible_connection not in {"ssh", "smart"}:
        raise HarnessError("inventory_target_connection_invalid")
    explicit_inventory_hostname = variables.get("inventory_hostname")
    if explicit_inventory_hostname is not None and explicit_inventory_hostname != contract.target:
        raise HarnessError("inventory_target_hostname_mismatch")
    if variables.get("ansible_password") is not None or variables.get("ansible_become_password") is not None:
        raise HarnessError("inventory_password_auth_invalid")
    if (
        variables.get("deploy_ssh_private_key_path") != EXPECTED_DEPLOY_KEY_PATH
        or compact_string(variables.get("ansible_private_key_file")) != EXPECTED_DEPLOY_KEY_TEMPLATE
        or compact_string(variables.get("hetzner_baremetal_rescue_known_hosts_path"))
        != EXPECTED_KNOWN_HOSTS_TEMPLATE
        or compact_string(variables.get("ansible_ssh_common_args")) != EXPECTED_SSH_COMMON_ARGS
    ):
        raise HarnessError("inventory_ssh_credentials_invalid")
    raw_port = variables.get("ansible_port")
    if raw_port == "{{ openssh_server_primary_port }}":
        raw_port = variables.get("openssh_server_primary_port")
    if isinstance(raw_port, bool):
        raise HarnessError("inventory_target_port_mismatch")
    if isinstance(raw_port, int):
        actual_port = raw_port
    elif isinstance(raw_port, str) and raw_port.isdigit():
        actual_port = int(raw_port)
    else:
        raise HarnessError("inventory_target_port_mismatch")
    if actual_port != contract.ssh_port:
        raise HarnessError("inventory_target_port_mismatch")
    if variables.get("workbench_enabled") is not True:
        raise HarnessError("inventory_workbench_not_enabled")
    if variables.get("workbench_target_hostname") != contract.target:
        raise HarnessError("inventory_workbench_contract_mismatch")


def validate_inventory(contract: Contract, child_environment: Mapping[str, str]) -> None:
    binary = shutil.which("ansible-inventory", path=child_environment.get("PATH"))
    if binary is None:
        raise HarnessError("ansible_inventory_missing")
    try:
        completed = subprocess.run(
            [binary, "-i", str(contract.inventory), "--list"],
            cwd=contract.workspace,
            env=dict(child_environment),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HarnessError("inventory_preflight_failed") from exc
    if completed.returncode != 0 or len(completed.stdout) > 10 * 1024 * 1024:
        raise HarnessError("inventory_preflight_failed")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise HarnessError("inventory_output_invalid") from exc
    validate_inventory_payload(payload, contract)


def sanitize_task_label(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    compact = " ".join(value.split())
    if not compact:
        return None
    upper = compact.upper()
    if (
        is_sensitive_environment_name(upper.replace(" ", "_"))
        or "://" in compact
        or "@" in compact
        or "{{" in compact
        or "}}" in compact
    ):
        return None
    return SAFE_TASK_LABEL.sub("?", compact)[:160]


def aggregate_stats(raw_stats: Any) -> dict[str, int]:
    totals = {key: 0 for key in STAT_KEYS}
    if not isinstance(raw_stats, dict):
        return totals
    runner_keys = set(STAT_KEYS) | {"dark", "processed"}
    if set(raw_stats) & runner_keys:
        for key in STAT_KEYS:
            source_key = "dark" if key == "unreachable" and "dark" in raw_stats else key
            values = raw_stats.get(source_key, {})
            if isinstance(values, dict):
                totals[key] = sum(
                    value
                    for value in values.values()
                    if isinstance(value, int) and not isinstance(value, bool) and value >= 0
                )
            elif isinstance(values, int) and not isinstance(values, bool) and values >= 0:
                totals[key] = values
        return totals
    for host_stats in raw_stats.values():
        if not isinstance(host_stats, dict):
            continue
        for key in STAT_KEYS:
            value = host_stats.get(key, 0)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                totals[key] += value
    return totals


def validate_and_aggregate_stats(raw_stats: Any, expected_host: str) -> dict[str, int]:
    """Validate one-target Runner stats before discarding the host key."""

    stats = require_mapping(raw_stats, "runner_stats_invalid")
    runner_fields = {
        "skipped",
        "ok",
        "dark",
        "failures",
        "ignored",
        "rescued",
        "processed",
        "changed",
    }
    if set(stats) == runner_fields:
        processed = require_mapping(stats["processed"], "runner_stats_invalid")
        processed_count = processed.get(expected_host)
        if (
            set(processed) != {expected_host}
            or not isinstance(processed_count, int)
            or isinstance(processed_count, bool)
            or processed_count != 1
        ):
            raise HarnessError("runner_stats_target_invalid")
        for field in runner_fields - {"processed"}:
            values = require_mapping(stats[field], "runner_stats_invalid")
            if not set(values).issubset({expected_host}):
                raise HarnessError("runner_stats_target_invalid")
            if any(
                not isinstance(value, int) or isinstance(value, bool) or value < 0
                for value in values.values()
            ):
                raise HarnessError("runner_stats_invalid")
        return aggregate_stats(stats)

    if set(stats) != {expected_host}:
        raise HarnessError("runner_stats_target_invalid")
    host_stats = require_mapping(stats[expected_host], "runner_stats_invalid")
    if set(host_stats) != set(STAT_KEYS):
        raise HarnessError("runner_stats_invalid")
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in host_stats.values()
    ):
        raise HarnessError("runner_stats_invalid")
    return aggregate_stats(stats)


class RunnerExecutor:
    """Run Ansible through ansible-runner while retaining only bounded summaries."""

    def __init__(self, contract: Contract, child_environment: Mapping[str, str]):
        self.contract = contract
        self.child_environment = dict(child_environment)

    def run_phase(
        self,
        name: str,
        playbook: Path,
        cmdline: str = "",
        extra_vars: Mapping[str, str] | None = None,
        timeout_seconds: int | None = None,
    ) -> PhaseResult:
        import ansible_runner  # Imported only after sensitive environment values are purged.

        checks: list[dict[str, str]] = []
        seen_checks: set[tuple[str, str, str]] = set()

        def event_handler(event: Mapping[str, Any]) -> bool:
            event_name = event.get("event")
            persist_stats_only = event_name == "playbook_on_stats"
            status_by_event = {
                "runner_on_failed": "failed",
                "runner_on_ok": "ok",
                "runner_on_skipped": "skipped",
                "runner_on_unreachable": "unreachable",
            }
            if event_name not in status_by_event:
                return persist_stats_only
            event_data = event.get("event_data")
            if not isinstance(event_data, dict):
                return persist_stats_only
            action = str(event_data.get("task_action", "")).rsplit(".", 1)[-1]
            if action not in {"assert", "command"}:
                return persist_stats_only
            label = sanitize_task_label(event_data.get("task"))
            if label is None:
                return persist_stats_only
            item = (action, label, status_by_event[event_name])
            if item not in seen_checks and len(checks) < 200:
                seen_checks.add(item)
                checks.append({"action": item[0], "label": item[1], "status": item[2]})
            return persist_stats_only

        started = time.monotonic()
        stats: dict[str, int] = {key: 0 for key in STAT_KEYS}
        status = "error"
        rc = 1
        try:
            relative_playbook = playbook.relative_to(self.contract.workspace)
            with tempfile.TemporaryDirectory(prefix=f"workbench-{name}-") as private_data_dir:
                os.chmod(private_data_dir, 0o700)
                result = ansible_runner.run(
                    private_data_dir=private_data_dir,
                    project_dir=str(self.contract.workspace),
                    artifact_dir=str(Path(private_data_dir) / "artifacts"),
                    inventory=str(self.contract.inventory),
                    playbook=str(relative_playbook),
                    limit=self.contract.target,
                    extravars=dict(extra_vars or {}),
                    cmdline=cmdline,
                    envvars=self.child_environment,
                    event_handler=event_handler,
                    quiet=True,
                    suppress_ansible_output=True,
                    suppress_output_file=True,
                    rotate_artifacts=1,
                    timeout=(
                        self.contract.phase_timeout_seconds
                        if timeout_seconds is None
                        else timeout_seconds
                    ),
                )
                status = str(getattr(result, "status", "error"))
                rc_value = getattr(result, "rc", 1)
                rc = rc_value if isinstance(rc_value, int) else 1
                raw_stats = getattr(result, "stats", None)
                if cmdline == "--syntax-check":
                    stats = aggregate_stats(raw_stats)
                else:
                    stats = validate_and_aggregate_stats(raw_stats, self.contract.target)
        except Exception:  # The raw exception may contain controller or module data and is never retained.
            status = "error"
            rc = 1
        return PhaseResult(
            name=name,
            status=status,
            rc=rc,
            duration_seconds=round(time.monotonic() - started, 3),
            stats=stats,
            checks=checks,
        )


def require_phase_success(result: PhaseResult) -> None:
    if (
        result.status != "successful"
        or result.rc != 0
        or result.stats.get("failures", 0) != 0
        or result.stats.get("unreachable", 0) != 0
    ):
        raise HarnessError(f"phase_failed_{result.name}")


def profile_extra_vars(contract: Contract, profile: str, run_id: str) -> dict[str, str]:
    return {contract.profile_variable: profile, contract.run_id_variable: run_id}


def execute_cleanup_profiles(
    executor: RunnerExecutor,
    contract: Contract,
    profiles: Sequence[str],
    run_id: str,
) -> tuple[list[PhaseResult], bool]:
    results: list[PhaseResult] = []
    successful = True
    for profile in profiles:
        result = executor.run_phase(
            f"cleanup-{profile}",
            contract.cleanup_playbook,
            extra_vars=profile_extra_vars(contract, profile, run_id),
            timeout_seconds=contract.cleanup_timeout_seconds,
        )
        results.append(result)
        try:
            require_phase_success(result)
        except HarnessError:
            successful = False
    return results, successful


def execute_full(
    executor: RunnerExecutor,
    contract: Contract,
    profiles: Sequence[str],
    run_id: str,
) -> ExecutionOutcome:
    results: list[PhaseResult] = []
    error_code: str | None = None
    sample_vars = profile_extra_vars(contract, profiles[0], run_id)

    def run_required(
        name: str,
        playbook: Path,
        cmdline: str = "",
        extra_vars: Mapping[str, str] | None = None,
    ) -> PhaseResult:
        result = executor.run_phase(name, playbook, cmdline=cmdline, extra_vars=extra_vars)
        results.append(result)
        require_phase_success(result)
        return result

    try:
        run_required("syntax-deployment", contract.deployment_playbook, cmdline="--syntax-check")
        run_required("syntax-validation", contract.validation_playbook, cmdline="--syntax-check")
        run_required(
            "syntax-acceptance",
            contract.acceptance_playbook,
            cmdline="--syntax-check",
            extra_vars=sample_vars,
        )
        run_required(
            "syntax-cleanup",
            contract.cleanup_playbook,
            cmdline="--syntax-check",
            extra_vars=sample_vars,
        )
        run_required("deployment-check", contract.deployment_playbook, cmdline="--check")
        run_required("deployment-first", contract.deployment_playbook)
        second = run_required("deployment-second", contract.deployment_playbook)
        if second.stats.get("changed", 0) != 0:
            raise HarnessError("second_deployment_not_idempotent")
        validation = run_required("validation", contract.validation_playbook)
        if validation.stats.get("changed", 0) != 0:
            raise HarnessError("validation_not_read_only")
        for profile in profiles:
            run_required(
                f"acceptance-{profile}",
                contract.acceptance_playbook,
                extra_vars=profile_extra_vars(contract, profile, run_id),
            )
    except HarnessError as exc:
        error_code = exc.code
    finally:
        cleanup_results, cleanup_succeeded = execute_cleanup_profiles(executor, contract, profiles, run_id)
        results.extend(cleanup_results)

    if not cleanup_succeeded and error_code is None:
        error_code = "cleanup_failed"
    return ExecutionOutcome(
        results=results,
        error_code=error_code,
        cleanup_attempted=True,
        cleanup_succeeded=cleanup_succeeded,
    )


def execute_cleanup_only(
    executor: RunnerExecutor,
    contract: Contract,
    profiles: Sequence[str],
    run_id: str,
) -> ExecutionOutcome:
    results, cleanup_succeeded = execute_cleanup_profiles(executor, contract, profiles, run_id)
    return ExecutionOutcome(
        results=results,
        error_code=None if cleanup_succeeded else "cleanup_failed",
        cleanup_attempted=True,
        cleanup_succeeded=cleanup_succeeded,
    )


def select_profiles(value: str, allowed: Sequence[str]) -> tuple[str, ...]:
    if value == "all":
        return tuple(allowed)
    requested = tuple(item.strip() for item in value.split(",") if item.strip())
    if not requested or len(set(requested)) != len(requested):
        raise HarnessError("profile_selection_invalid")
    if any(item not in allowed for item in requested):
        raise HarnessError("profile_selection_invalid")
    return tuple(item for item in allowed if item in requested)


def validate_run_id(value: str) -> None:
    if not SAFE_RUN_ID.fullmatch(value):
        raise HarnessError("run_id_invalid")


def phase_evidence(result: PhaseResult) -> dict[str, Any]:
    return {
        "name": result.name,
        "status": result.status,
        "rc": result.rc,
        "duration_seconds": result.duration_seconds,
        "stats": {key: result.stats.get(key, 0) for key in STAT_KEYS},
        "checks": result.checks,
    }


def write_evidence(path: Path, evidence: Mapping[str, Any]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.tmp")
    payload = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    temporary.write_text(payload, encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--matrix", required=True, type=Path)
    parser.add_argument("--collections-path", required=True)
    parser.add_argument("--profiles", default="all")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--confirmation", required=True)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--cleanup-only", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    started_at = utc_now()
    outcome = ExecutionOutcome([], "initialization_failed", False, False)
    contract: Contract | None = None
    profiles: tuple[str, ...] = ()
    safe_error_code = "initialization_failed"

    try:
        workspace = args.workspace.resolve()
        expected_matrix = (workspace / EXPECTED_MATRIX).resolve()
        try:
            expected_matrix.relative_to(workspace)
        except ValueError as exc:
            raise HarnessError("matrix_path_invalid") from exc
        if args.matrix.resolve() != expected_matrix:
            raise HarnessError("matrix_path_invalid")
        contract = load_contract(expected_matrix, workspace)
        if args.confirmation != contract.target:
            raise HarnessError("target_confirmation_invalid")
        validate_run_id(args.run_id)
        profiles = select_profiles(args.profiles, contract.profiles)
        validate_controller_environment(os.environ, contract)
        purge_sensitive_environment(os.environ)
        child_environment = build_child_environment(os.environ, contract, args.collections_path)
        replace_process_environment(os.environ, child_environment)
        validate_inventory(contract, child_environment)
        executor = RunnerExecutor(contract, child_environment)
        if args.cleanup_only:
            outcome = execute_cleanup_only(executor, contract, profiles, args.run_id)
        else:
            outcome = execute_full(executor, contract, profiles, args.run_id)
        safe_error_code = outcome.error_code or ""
    except HarnessError as exc:
        safe_error_code = exc.code
        outcome = ExecutionOutcome(outcome.results, exc.code, outcome.cleanup_attempted, outcome.cleanup_succeeded)
    except Exception:
        safe_error_code = "internal_error"
        outcome = ExecutionOutcome(outcome.results, safe_error_code, outcome.cleanup_attempted, False)

    evidence = {
        "schema_version": 1,
        "suite": contract.suite if contract else "workbench-public-acceptance",
        "mode": "cleanup-only" if args.cleanup_only else "full",
        "started_at": started_at,
        "completed_at": utc_now(),
        "successful": outcome.successful,
        "error_code": outcome.error_code,
        "controller": "github-hosted",
        "target": EXPECTED_TARGET,
        "run_id": args.run_id if SAFE_RUN_ID.fullmatch(args.run_id) else "invalid",
        "profiles": list(profiles),
        "matrix_sha256": contract.matrix_digest if contract else None,
        "cleanup_attempted": outcome.cleanup_attempted,
        "cleanup_succeeded": outcome.cleanup_succeeded,
        "phases": [phase_evidence(result) for result in outcome.results],
    }
    try:
        write_evidence(args.evidence, evidence)
    except OSError:
        print("ERROR: sanitized evidence could not be written.", file=sys.stderr)
        return 1

    for result in outcome.results:
        print(
            f"{result.name}: status={result.status} rc={result.rc} "
            f"changed={result.stats.get('changed', 0)} "
            f"failures={result.stats.get('failures', 0)} "
            f"unreachable={result.stats.get('unreachable', 0)}"
        )
    if not outcome.successful:
        print(f"ERROR: Workbench acceptance failed ({safe_error_code}).", file=sys.stderr)
        return 1
    print("Workbench acceptance completed with sanitized evidence only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
