#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
validation_dir="$(cd "${script_dir}/../.." && pwd)"
incus_lifecycle_playbook="${validation_dir}/.github/playbooks/aap-incus-instance.yml"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: required command not found: $1" >&2
    exit 1
  }
}

memory_to_mib() {
  python3 - "$1" <<'PY'
import re
import sys

value = sys.argv[1].strip()
match = re.fullmatch(r"([0-9]+)([A-Za-z]+)?", value)
if not match:
    raise SystemExit(f"invalid memory value: {value}")

amount = int(match.group(1))
unit = (match.group(2) or "MiB").lower()
factors = {
    "m": 1,
    "mb": 1,
    "mi": 1,
    "mib": 1,
    "g": 1024,
    "gb": 1024,
    "gi": 1024,
    "gib": 1024,
}

if unit not in factors:
    raise SystemExit(f"unsupported memory unit: {value}")

print(amount * factors[unit])
PY
}

bool_value() {
  case "${1:-}" in
    true|TRUE|yes|YES|1|on|ON) printf 'true\n' ;;
    false|FALSE|no|NO|0|off|OFF) printf 'false\n' ;;
    *)
      echo "ERROR: invalid boolean value: ${1:-<empty>}" >&2
      exit 1
      ;;
  esac
}

yaml_single_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"
}

dns_label_value() {
  printf '%s' "$1" |
    tr '[:upper:]_' '[:lower:]-' |
    sed -E 's/[^a-z0-9-]+/-/g; s/^-+//; s/-+$//; s/-+/-/g'
}

generate_password() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 24
  else
    date -u "+AAPCi-%Y%m%d%H%M%S-%N"
  fi
}

write_ansible_config() {
  local config_file="$1"
  local collections_path="$2"
  local roles_path="$3"

  cat > "${config_file}" <<EOF
[defaults]
collections_path = ${collections_path}
roles_path = ${roles_path}
remote_tmp = ~/.ansible/tmp
stdout_callback = default
host_key_checking = False
retry_files_enabled = False

[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=60m -o ControlPath=/tmp/ansible-ssh-%h-%p-%r
pipelining = True

[inventory]
EOF
}

ensure_ansible_tools() {
  local ansible_core_version="${AAP_CI_ANSIBLE_CORE_VERSION:-2.18.14}"
  local venv_dir="${AAP_CI_VENV_DIR:-${HOME}/.cache/aap-ci/ansible-core-${ansible_core_version}}"

  if command -v ansible-playbook >/dev/null 2>&1 &&
    command -v ansible-galaxy >/dev/null 2>&1 &&
    command -v ansible >/dev/null 2>&1; then
    return
  fi

  if [ ! -x "${venv_dir}/bin/ansible-playbook" ] ||
    [ ! -x "${venv_dir}/bin/ansible-galaxy" ] ||
    [ ! -x "${venv_dir}/bin/ansible" ]; then
    python3 -m venv "${venv_dir}"
    "${venv_dir}/bin/python" -m pip install --upgrade pip
    "${venv_dir}/bin/python" -m pip install \
      "ansible-core==${ansible_core_version}" \
      jmespath \
      PyYAML
  fi

  export PATH="${venv_dir}/bin:${PATH}"
}

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "ERROR: required environment variable is empty: ${name}" >&2
    exit 1
  fi
}

canonical_path() {
  readlink -m "$1"
}

incus_cli() {
  local argv=(incus --force-local)

  if [ -n "${incus_project:-}" ]; then
    argv+=(--project "${incus_project}")
  fi

  "${argv[@]}" "$@"
}

instance_status() {
  incus_cli list "${instance_name}" -c s --format csv 2>/dev/null |
    head -n 1 |
    tr -d '\r'
}

instance_ip_address() {
  incus_cli list "${instance_name}" --format json | python3 -c '
import json
import sys

instances = json.load(sys.stdin)
addresses = []
for instance in instances:
    for interface in instance.get("state", {}).get("network", {}).values():
        for address in interface.get("addresses", []):
            value = address.get("address", "")
            if address.get("family") == "inet" and value != "127.0.0.1":
                addresses.append(value)
if addresses:
    print(sorted(addresses)[0])
    raise SystemExit(0)
raise SystemExit(1)
' 2>/dev/null || true
}

write_guest_inventory() {
  local ip_address="$1"

  cat > "${inventory_path}" <<EOF
---
all:
  children:
    aaps:
      hosts:
        ${guest_hostname}:
          ansible_host: "${ip_address}"
          ansible_user: ${INCUS_SSH_USER}
          ansible_become: true
          ansible_python_interpreter: /usr/bin/python3
          ansible_ssh_private_key_file: "${INCUS_SSH_PRIVATE_KEY_FILE}"
          ansible_ssh_common_args: "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
EOF
  chmod 0600 "${inventory_path}"
}

run_incus_lifecycle() {
  local action="$1"

  AAP_CI_INCUS_ACTION="${action}" ansible-playbook \
    -i localhost, \
    -c local \
    "${incus_lifecycle_playbook}"
}

preflight_incus_capacity() {
  local prefix="${AAP_CI_INSTANCE_PREFIX:-aap-ci-}"
  local stale_instances
  local available_mib
  local required_mib
  local headroom_mib="${AAP_CI_HOST_MEMORY_HEADROOM_MIB:-4096}"

  stale_instances="$(incus_cli list --format csv -c n | awk -v prefix="${prefix}" 'index($0, prefix) == 1')"
  if [ -n "${stale_instances}" ]; then
    echo "ERROR: stale AAP CI Incus instances exist and must be cleaned before a new run:" >&2
    printf '%s\n' "${stale_instances}" >&2
    exit 1
  fi

  available_mib="$(awk '/MemAvailable:/ { print int($2 / 1024) }' /proc/meminfo)"
  required_mib="$(memory_to_mib "${INCUS_VM_MEMORY}")"

  if [ "${available_mib}" -lt $((required_mib + headroom_mib)) ]; then
    echo "ERROR: insufficient runner memory for Incus AAP CI VM." >&2
    echo "Available: ${available_mib} MiB; required VM: ${required_mib} MiB; required host headroom: ${headroom_mib} MiB." >&2
    exit 1
  fi
}

active_child_pid=""

run_with_heartbeat() {
  local description="$1"
  local interval="${AAP_CI_HEARTBEAT_INTERVAL_SECONDS:-120}"
  local rc

  shift

  if ! [[ "${interval}" =~ ^[0-9]+$ ]] || [ "${interval}" -lt 1 ]; then
    echo "ERROR: AAP_CI_HEARTBEAT_INTERVAL_SECONDS must be a positive integer." >&2
    return 2
  fi

  "$@" &
  active_child_pid=$!

  while kill -0 "${active_child_pid}" >/dev/null 2>&1; do
    sleep "${interval}" || true
    if kill -0 "${active_child_pid}" >/dev/null 2>&1; then
      printf '%s still running at %s.\n' \
        "${description}" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    fi
  done

  wait "${active_child_pid}"
  rc=$?
  active_child_pid=""
  return "${rc}"
}

extract_ansible_json_field() {
  local field="$1"

  python3 -c '
import json
import sys

field = sys.argv[1]
raw = sys.stdin.read()
if "=>" not in raw:
    raise SystemExit("missing Ansible JSON payload")
payload = raw.split("=>", 1)[1].strip()
data = json.loads(payload)
for part in field.split("."):
    if not isinstance(data, dict):
        data = None
        break
    data = data.get(part)
if isinstance(data, bool):
    print("true" if data else "false")
elif data is None:
    print("")
else:
    print(data)
' "${field}"
}

poll_aap_installer() {
  local jid_path="$1"
  local timeout="${AAP_CI_INSTALLER_POLL_TIMEOUT_SECONDS:-14400}"
  local interval="${AAP_CI_INSTALLER_POLL_INTERVAL_SECONDS:-60}"
  local start_ts
  local now_ts
  local deadline_ts
  local jid=""
  local jid_output
  local jid_rc
  local poll_output
  local poll_rc
  local finished
  local remote_rc

  if ! [[ "${timeout}" =~ ^[0-9]+$ ]] || [ "${timeout}" -lt 1 ]; then
    echo "ERROR: AAP_CI_INSTALLER_POLL_TIMEOUT_SECONDS must be a positive integer." >&2
    return 2
  fi

  if ! [[ "${interval}" =~ ^[0-9]+$ ]] || [ "${interval}" -lt 1 ]; then
    echo "ERROR: AAP_CI_INSTALLER_POLL_INTERVAL_SECONDS must be a positive integer." >&2
    return 2
  fi

  start_ts="$(date +%s)"
  deadline_ts=$((start_ts + timeout))

  echo "Waiting for native AAP installer async job id at ${jid_path}."
  while [ -z "${jid}" ]; do
    now_ts="$(date +%s)"
    if [ "${now_ts}" -ge "${deadline_ts}" ]; then
      echo "ERROR: timed out waiting for native AAP installer async job id." >&2
      return 124
    fi

    jid_output="$(
      ansible \
        -i "${inventory_path}" \
        aaps \
        -b \
        -m ansible.builtin.shell \
        -a "test -s '${jid_path}' && printf 'AAP_CI_INSTALLER_JID=' && cat '${jid_path}'" \
        -o 2>&1
    )"
    jid_rc=$?
    if [ "${jid_rc}" -eq 0 ]; then
      jid="$(printf '%s\n' "${jid_output}" | sed -n 's/.*AAP_CI_INSTALLER_JID=//p' | tail -n 1 | tr -d '\r')"
    fi

    if [ -z "${jid}" ]; then
      echo "AAP installer async job id is not available yet at $(date -u +%Y-%m-%dT%H:%M:%SZ)."
      sleep "${interval}" || true
    fi
  done

  echo "Polling native AAP installer async job ${jid}."
  while true; do
    now_ts="$(date +%s)"
    if [ "${now_ts}" -ge "${deadline_ts}" ]; then
      echo "ERROR: native AAP installer async job ${jid} did not finish within ${timeout} seconds." >&2
      return 124
    fi

    poll_output="$(
      ansible \
        -i "${inventory_path}" \
        aaps \
        -b \
        --become-user "${install_user}" \
        -m ansible.builtin.async_status \
        -a "jid=${jid}" \
        -o 2>&1
    )"
    poll_rc=$?
    finished="$(printf '%s' "${poll_output}" | extract_ansible_json_field finished 2>/dev/null || true)"
    remote_rc="$(printf '%s' "${poll_output}" | extract_ansible_json_field rc 2>/dev/null || true)"

    echo "AAP installer async status at $(date -u +%Y-%m-%dT%H:%M:%SZ): finished=${finished:-unknown} rc=${remote_rc:-pending}."

    if [ "${finished}" = "true" ] || [ "${finished}" = "1" ]; then
      if [ "${remote_rc:-0}" -ne 0 ]; then
        echo "ERROR: native AAP installer async job ${jid} failed with rc=${remote_rc}." >&2
        return "${remote_rc}"
      fi

      echo "Native AAP installer async job ${jid} finished successfully."
      return 0
    fi

    if [ "${poll_rc}" -ne 0 ] && [ -z "${finished}" ]; then
      echo "ERROR: unable to read native AAP installer async job status." >&2
      printf '%s\n' "${poll_output}" >&2
      return "${poll_rc}"
    fi

    sleep "${interval}" || true
  done
}

clear_aap_installer_jid() {
  local jid_path="$1"

  ansible \
    -i "${inventory_path}" \
    aaps \
    -b \
    -m ansible.builtin.file \
    -a "path=${jid_path} state=absent" \
    >/dev/null 2>&1 || true
}

collect_failure_diagnostics() {
  local diagnostics_script="${work_dir:-/tmp}/aap-ci-diagnostics.sh"
  local log_lines="${AAP_CI_DIAGNOSTICS_LOG_LINES:-220}"

  if [ "${AAP_CI_COLLECT_FAILURE_DIAGNOSTICS:-true}" != "true" ]; then
    return
  fi

  if [ -z "${inventory_path:-}" ] || [ ! -f "${inventory_path}" ]; then
    return
  fi

  if ! command -v ansible >/dev/null 2>&1; then
    return
  fi

  echo "::group::AAP failure diagnostics"
  cat > "${diagnostics_script}" <<'EOS'
#!/usr/bin/env bash
set -o pipefail

redact() {
  sed -E 's/((password|passwd|token|secret|key)[[:alnum:]_ -]*[=:][[:space:]]*)[^[:space:]"'"'"']+/\1[REDACTED]/Ig'
}

echo "== host =="
hostname -f || hostname
date -u

echo "== memory =="
free -h || true

echo "== disk =="
df -h / /tmp /home /opt 2>/dev/null || df -h || true

echo "== installer processes =="
pgrep -af 'ansible-playbook|podman container run|awx-manage|pulpcore|aap-eda|aap-gateway|automation' \
  | redact \
  | tail -n 80 \
  || true

install_user="${AAP_CI_INSTALL_USER:-svc_aap}"
install_user_home="${AAP_CI_INSTALL_USER_HOME:-/appl/home/${install_user}}"

echo "== podman containers =="
if command -v podman >/dev/null 2>&1 && id "${install_user}" >/dev/null 2>&1; then
  sudo -u "${install_user}" podman ps --format json \
    | python3 -c 'import json,sys
data=json.load(sys.stdin)
for item in sorted(data, key=lambda c: (c.get("Names") or [c.get("Name", "")])[0]):
    name=(item.get("Names") or [item.get("Name", "")])[0]
    print(name + " " + item.get("Status", ""))' \
    || true
fi

echo "== failed user services =="
if id "${install_user}" >/dev/null 2>&1; then
  uid="$(id -u "${install_user}")"
  sudo -u "${install_user}" XDG_RUNTIME_DIR="/run/user/${uid}" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${uid}/bus" \
    systemctl --user --failed --no-pager \
    || true
fi

echo "== installer logs =="
find "${install_user_home}/aap" /opt/aap /var/log -maxdepth 5 -type f \
  \( -name 'aap_install.log' -o -name '*.log' -o -name '*.out' -o -name '*.err' \) \
  -mmin -240 2>/dev/null \
  | sort \
  | while IFS= read -r file; do
      echo "-- ${file}"
      grep -Ein 'failed|fatal|error|traceback|exception|unreachable|recap|async' "${file}" \
        | tail -n "${AAP_CI_DIAGNOSTIC_LOG_LINES:-220}" \
        | redact \
        || true
    done
EOS

  chmod 0600 "${diagnostics_script}" || true
  ansible \
    -i "${inventory_path}" \
    aaps \
    -m ansible.builtin.copy \
    -a "src=${diagnostics_script} dest=/tmp/aap-ci-diagnostics.sh mode=0700" \
    || true
  ansible \
    -i "${inventory_path}" \
    aaps \
    -m ansible.builtin.shell \
    -a "AAP_CI_DIAGNOSTIC_LOG_LINES='${log_lines}' AAP_CI_INSTALL_USER='${install_user}' AAP_CI_INSTALL_USER_HOME='${install_user_home}' /tmp/aap-ci-diagnostics.sh" \
    || true
  ansible \
    -i "${inventory_path}" \
    aaps \
    -m ansible.builtin.file \
    -a "path=/tmp/aap-ci-diagnostics.sh state=absent" \
    || true
  echo "::endgroup::"
}

collect_incus_diagnostics() {
  if [ -z "${instance_name:-}" ]; then
    return
  fi

  if ! incus_cli info "${instance_name}" >/dev/null 2>&1; then
    return
  fi

  echo "::group::Incus failure diagnostics"
  incus_cli list "${instance_name}" --format yaml || true
  incus_cli info "${instance_name}" --show-log || true
  incus_cli config show "${instance_name}" || true
  incus_cli console "${instance_name}" --show-log || true
  echo "::endgroup::"
}

wait_for_incus_guest_ready() {
  local attempts="${AAP_CI_INSTANCE_BOOT_ATTEMPTS:-2}"
  local retry_delay="${AAP_CI_INSTANCE_BOOT_RETRY_DELAY_SECONDS:-30}"
  local attempt=1
  local deadline
  local ip_address=""
  local rc=1
  local ssh_options=(
    -o BatchMode=yes
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ConnectTimeout=5
    -i "${INCUS_SSH_PRIVATE_KEY_FILE}"
  )

  if ! [[ "${attempts}" =~ ^[0-9]+$ ]] || [ "${attempts}" -lt 1 ]; then
    echo "ERROR: AAP_CI_INSTANCE_BOOT_ATTEMPTS must be a positive integer." >&2
    return 2
  fi

  if ! [[ "${retry_delay}" =~ ^[0-9]+$ ]]; then
    echo "ERROR: AAP_CI_INSTANCE_BOOT_RETRY_DELAY_SECONDS must be a non-negative integer." >&2
    return 2
  fi

  while [ "${attempt}" -le "${attempts}" ]; do
    echo "Waiting for Incus guest readiness attempt ${attempt}/${attempts}."
    deadline=$((SECONDS + instance_wait_timeout))

    while [ "${SECONDS}" -lt "${deadline}" ]; do
      if [ "$(instance_status)" = "RUNNING" ]; then
        break
      fi
      sleep 2
    done

    ip_address=""
    while [ "${SECONDS}" -lt "${deadline}" ]; do
      ip_address="$(instance_ip_address)"
      if [ -n "${ip_address}" ]; then
        break
      fi
      sleep 2
    done

    while [ "${SECONDS}" -lt "${deadline}" ] && [ -n "${ip_address}" ]; do
      if ssh "${ssh_options[@]}" "${INCUS_SSH_USER}@${ip_address}" true >/dev/null 2>&1; then
        break
      fi
      sleep 5
    done

    if [ -n "${ip_address}" ] &&
      ssh "${ssh_options[@]}" "${INCUS_SSH_USER}@${ip_address}" true >/dev/null 2>&1; then
      if ssh "${ssh_options[@]}" "${INCUS_SSH_USER}@${ip_address}" \
        'if command -v cloud-init >/dev/null 2>&1; then sudo -n cloud-init status --wait; fi'; then
        write_guest_inventory "${ip_address}"
        echo "Incus guest is ready: ${instance_name} (${ip_address})."
        return 0
      fi
    fi

    rc=1

    echo "Incus guest readiness attempt ${attempt}/${attempts} failed with rc=${rc}."
    collect_incus_diagnostics

    if [ "${attempt}" -lt "${attempts}" ]; then
      echo "Force-restarting Incus instance ${instance_name} before the next readiness attempt."
      incus_cli restart -f "${instance_name}" || true
      sleep "${retry_delay}" || true
    fi

    attempt=$((attempt + 1))
  done

  return "${rc}"
}

best_effort_rhsm_cleanup() {
  if ! incus_cli info "${instance_name}" >/dev/null 2>&1; then
    return 0
  fi

  incus_cli exec "${instance_name}" -- /bin/sh -eu -c '
if ! command -v subscription-manager >/dev/null 2>&1; then
  exit 0
fi
if subscription-manager identity >/dev/null 2>&1; then
  subscription-manager unregister || true
fi
subscription-manager clean || true
' || true
}

cleanup() {
  local rc="${1:-$?}"
  local destroy_rc=0
  local rhel_teardown_rc=1
  local rhel_teardown_complete=false

  set +e
  trap - EXIT INT TERM
  if [ -n "${active_child_pid:-}" ] && kill -0 "${active_child_pid}" >/dev/null 2>&1; then
    echo "Stopping active child process ${active_child_pid} before cleanup."
    kill "${active_child_pid}" >/dev/null 2>&1 || true
    wait "${active_child_pid}" >/dev/null 2>&1 || true
    active_child_pid=""
  fi

  if [ -n "${instance_name:-}" ] && [ -n "${supplementary_dir:-}" ]; then
    echo "Running AAP Incus CI cleanup for ${instance_name} with deploy rc=${rc}."

    if [ "${rc}" -ne 0 ]; then
      echo "Collecting AAP failure diagnostics before teardown."
      collect_failure_diagnostics
      collect_incus_diagnostics
    fi

    if [ -f "${inventory_path:-}" ] && command -v ansible-playbook >/dev/null 2>&1; then
      echo "Running RHEL teardown for ${instance_name}."
      (
        cd "${supplementary_dir}" &&
          ansible-playbook \
            -i "${inventory_path}" \
            playbooks/rhel_teardown.yml \
            -e rhel_guest_target=aaps
      )
      rhel_teardown_rc=$?
      if [ "${rhel_teardown_rc}" -eq 0 ]; then
        rhel_teardown_complete=true
      else
        echo "WARNING: RHEL teardown failed with rc=${rhel_teardown_rc}; destroy will try best-effort RHSM cleanup."
      fi
    fi

    if [ "${destroy_instance:-true}" = "true" ]; then
      echo "Destroying Incus instance ${instance_name}."
      if [ "${rhel_teardown_complete}" != "true" ]; then
        echo "Running best-effort RHSM cleanup through Incus before destroy."
        best_effort_rhsm_cleanup
      fi

      if run_incus_lifecycle destroy; then
        destroy_rc=0
      else
        destroy_rc=$?
      fi
      if [ "${destroy_rc}" -ne 0 ]; then
        echo "ERROR: failed to destroy Incus instance ${instance_name}." >&2
      elif [ -n "${work_dir:-}" ] && [ -d "${work_dir}" ]; then
        rm -rf "${work_dir}"
      fi
    fi
  fi

  if [ "${rc}" -eq 0 ] && [ "${destroy_rc}" -ne 0 ]; then
    return "${destroy_rc}"
  fi

  return "${rc}"
}

require_env MATRIX_NAME
require_env AAP_VERSION
require_env RHEL_MAJOR
require_env INCUS_IMAGE
require_env AAP_BUNDLE_FILE
require_env RHSM_ORG_ID
require_env RHSM_ACTIVATION_KEY
require_env AUTOMATION_DIR
require_env SUPPLEMENTARY_DIR
require_env UBUNTU_DIR

: "${MATRIX_NAME:?}"
: "${AAP_VERSION:?}"
: "${RHEL_MAJOR:?}"
: "${INCUS_IMAGE:?}"
: "${AAP_BUNDLE_FILE:?}"
: "${RHSM_ORG_ID:?}"
: "${RHSM_ACTIVATION_KEY:?}"
: "${AUTOMATION_DIR:?}"
: "${SUPPLEMENTARY_DIR:?}"
: "${UBUNTU_DIR:?}"

require_cmd incus
require_cmd python3
require_cmd ssh
require_cmd ssh-keygen

automation_dir="$(canonical_path "${AUTOMATION_DIR}")"
supplementary_dir="$(canonical_path "${SUPPLEMENTARY_DIR}")"
ubuntu_dir="$(canonical_path "${UBUNTU_DIR}")"
automation_ansible_dir="${automation_dir}/ansible"
work_dir="$(canonical_path "${AAP_CI_WORK_DIR:-${RUNNER_TEMP:-/tmp}/aap-incus-ci}")"
destroy_instance="$(bool_value "${AAP_CI_DESTROY_INSTANCE:-true}")"
install_requirements="$(bool_value "${AAP_CI_INSTALL_REQUIREMENTS:-true}")"
hub_seed_collections="$(bool_value "${AAP_CI_HUB_SEED_COLLECTIONS:-false}")"
instance_wait_timeout="${AAP_CI_INSTANCE_WAIT_TIMEOUT:-600}"
incus_project="${AAP_CI_INCUS_PROJECT:-default}"
install_user="${AAP_CI_INSTALL_USER:-svc_aap}"
install_user_home="${AAP_CI_INSTALL_USER_HOME:-/appl/home/${install_user}}"
run_attempt="${GITHUB_RUN_ATTEMPT:-1}"
run_id="${GITHUB_RUN_ID:-local}"
instance_name="${AAP_CI_INSTANCE_NAME:-aap-ci-${MATRIX_NAME}-${run_id}-${run_attempt}}"
short_run_id="$(dns_label_value "${run_id}")"
short_run_id="${short_run_id: -6}"
guest_hostname="${AAP_CI_GUEST_HOSTNAME:-a${AAP_VERSION//./}r${RHEL_MAJOR}-${short_run_id}-${run_attempt}}"
guest_fqdn="${AAP_CI_GUEST_FQDN:-${guest_hostname}.${AAP_CI_FQDN_SUFFIX:-incus.local}}"
expires_at="${AAP_CI_EXPIRES_AT:-$(python3 - <<'PY'
from datetime import datetime, timedelta, timezone

print((datetime.now(timezone.utc) + timedelta(hours=8)).isoformat().replace('+00:00', 'Z'))
PY
)}"
inventory_path="${work_dir}/${instance_name}.yml"
vars_path="${work_dir}/${instance_name}-vars.yml"
ansible_config_path="${work_dir}/ansible-ci.cfg"
admin_password="${AAP_CI_ADMIN_PASSWORD:-$(generate_password)}"

echo "Starting AAP Incus matrix entry ${MATRIX_NAME}: AAP ${AAP_VERSION} on RHEL ${RHEL_MAJOR}."

case "${RHEL_MAJOR}" in
  9|10) ;;
  *)
    echo "ERROR: unsupported RHEL_MAJOR=${RHEL_MAJOR}; expected 9 or 10." >&2
    exit 1
    ;;
esac

case "${AAP_VERSION}" in
  2.7) ;;
  *)
    echo "ERROR: unsupported AAP_VERSION=${AAP_VERSION}; current lit.supplementary.aap_deploy supports 2.7." >&2
    exit 1
    ;;
esac

if ! [[ "${guest_hostname}" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]; then
  echo "ERROR: AAP_CI_GUEST_HOSTNAME must be a DNS-safe label: ${guest_hostname}" >&2
  exit 1
fi

if [ "${#guest_hostname}" -gt 22 ]; then
  echo "ERROR: AAP_CI_GUEST_HOSTNAME must be 22 characters or shorter for AAP EDA queue safety: ${guest_hostname}" >&2
  exit 1
fi

if ! [[ "${install_user}" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
  echo "ERROR: AAP_CI_INSTALL_USER is not a valid Linux account name: ${install_user}" >&2
  exit 1
fi

if [[ "${install_user_home}" != /* ]]; then
  echo "ERROR: AAP_CI_INSTALL_USER_HOME must be an absolute path: ${install_user_home}" >&2
  exit 1
fi

if [ ! -d "${automation_ansible_dir}" ]; then
  echo "ERROR: automation ansible checkout not found: ${automation_ansible_dir}" >&2
  exit 1
fi

if [ ! -d "${supplementary_dir}" ]; then
  echo "ERROR: supplementary checkout not found: ${supplementary_dir}" >&2
  exit 1
fi

if [ ! -d "${ubuntu_dir}" ]; then
  echo "ERROR: Ubuntu collection checkout not found: ${ubuntu_dir}" >&2
  exit 1
fi

if [ ! -f "${incus_lifecycle_playbook}" ]; then
  echo "ERROR: AAP Incus lifecycle playbook not found: ${incus_lifecycle_playbook}" >&2
  exit 1
fi

ensure_ansible_tools
require_cmd ansible-galaxy
require_cmd ansible-playbook

if ! incus_cli info >/dev/null 2>&1; then
  echo "ERROR: incus client cannot reach an Incus daemon or remote." >&2
  exit 1
fi

if [ ! -e /dev/kvm ]; then
  echo "ERROR: Incus VM validation requires /dev/kvm on the runner." >&2
  exit 1
fi

if ! incus_cli image info "${INCUS_IMAGE}" >/dev/null 2>&1; then
  echo "ERROR: Incus image alias does not exist: ${INCUS_IMAGE}" >&2
  exit 1
fi

mkdir -p "${work_dir}"
chmod 0700 "${work_dir}"

if [ -z "${INCUS_SSH_PUBLIC_KEY_FILE:-}" ] || [ -z "${INCUS_SSH_PRIVATE_KEY_FILE:-}" ]; then
  ssh_key="${work_dir}/id_ed25519"
  if [ ! -f "${ssh_key}" ]; then
    ssh-keygen -t ed25519 -N "" -f "${ssh_key}" -C "aap-incus-ci" >/dev/null
  fi
  export INCUS_SSH_PRIVATE_KEY_FILE="${INCUS_SSH_PRIVATE_KEY_FILE:-${ssh_key}}"
  export INCUS_SSH_PUBLIC_KEY_FILE="${INCUS_SSH_PUBLIC_KEY_FILE:-${ssh_key}.pub}"
fi

case "${RHEL_MAJOR}" in
  9)
    export INCUS_RHEL98_IMAGE="${INCUS_IMAGE}"
    export INCUS_RHEL9_IMAGE="${INCUS_IMAGE}"
    ;;
  10)
    export INCUS_RHEL10_IMAGE="${INCUS_IMAGE}"
    ;;
esac

export INCUS_SSH_USER="${INCUS_SSH_USER:-cloud-user}"
export INCUS_VM_CPU="${INCUS_VM_CPU:-4}"
export INCUS_VM_MEMORY="${INCUS_VM_MEMORY:-20GiB}"
export INCUS_VM_ROOT_SIZE="${INCUS_VM_ROOT_SIZE:-70GiB}"
export AAP_CI_INCUS_PROJECT="${incus_project}"
export AAP_CI_INSTANCE_NAME="${instance_name}"
export AAP_CI_GUEST_HOSTNAME="${guest_hostname}"
export AAP_CI_GUEST_FQDN="${guest_fqdn}"
export AAP_CI_EXPIRES_AT="${expires_at}"
export RHSM_ORG_ID
export RHSM_ACTIVATION_KEY
export AAP_BUNDLE_FILE
export ANSIBLE_COLLECTIONS_PATH="${automation_ansible_dir}/collections-dev:${automation_ansible_dir}/collections:/usr/share/ansible/collections:/usr/share/automation-controller/collections:/runner/collections"
write_ansible_config \
  "${ansible_config_path}" \
  "${ANSIBLE_COLLECTIONS_PATH}" \
  "${automation_ansible_dir}/roles:/usr/share/ansible/roles:/runner/roles"
export ANSIBLE_CONFIG="${ansible_config_path}"

if [ ! -f "${AAP_BUNDLE_FILE}" ]; then
  echo "ERROR: AAP bundle not found: ${AAP_BUNDLE_FILE}" >&2
  exit 1
fi

preflight_incus_capacity

if [ "${install_requirements}" = "true" ]; then
  SOURCE_ROOT="$(dirname "${automation_dir}")" \
    TARGET_PATH="${automation_ansible_dir}/collections-dev" \
    REQUIREMENTS_FILE="${automation_ansible_dir}/collections/requirements.yml" \
    "${automation_ansible_dir}/scripts/install-local-collections" \
      foundational \
      rhel \
      ubuntu \
      supplementary
  RH_COLLECTIONS_TARGET="${automation_ansible_dir}/collections-dev" \
    RH_COLLECTIONS_REQUIREMENTS_FILE="${automation_ansible_dir}/collections/requirements-rh.yml" \
    "${automation_ansible_dir}/scripts/install-rh-collections"
fi

trap cleanup EXIT
trap 'cleanup 130; exit 130' INT
trap 'cleanup 143; exit 143' TERM

run_incus_lifecycle create
wait_for_incus_guest_ready

ansible-playbook \
  -i "${inventory_path}" \
  "${supplementary_dir}/playbooks/rhel_prepare.yml" \
  -e rhel_guest_target=aaps \
  -e '{"virtual_guest_manage_qemu_guest_agent": false}'

cat > "${vars_path}" <<EOF
---
aap_password_require_component_inputs: false
aap_admin_password_input: $(yaml_single_quote "${admin_password}")

aap_preflight_expected_ansible_user: $(yaml_single_quote "${INCUS_SSH_USER}")
aap_preflight_check_dns: false
aap_preflight_check_vault: false
aap_preflight_check_ansible_vault: false
aap_deploy_install_user: $(yaml_single_quote "${install_user}")
aap_deploy_install_user_home: $(yaml_single_quote "${install_user_home}")
aap_deploy_topology: growth
aap_deploy_setup_download_version: "$(printf '%s' "${AAP_VERSION}")"
aap_deploy_gateway_main_url: "https://{{ ansible_host }}"
aap_deploy_validate_certs: false
aap_prepare_bundle_src: "$(printf '%s' "${AAP_BUNDLE_FILE}")"
aap_deploy_manage_download_unpack: true
aap_deploy_run_installer: true
aap_deploy_run_verify: true
aap_deploy_installer_wait: false
aap_deploy_installer_async_jid_path: /opt/aap/logs/aap_installer_async_jid
aap_deploy_setup_install_extra_vars:
  hub_seed_collections: ${hub_seed_collections}
virtual_guest_manage_qemu_guest_agent: false
EOF
chmod 0600 "${vars_path}"

ansible-playbook \
  -i "${inventory_path}" \
  "${automation_ansible_dir}/runbooks/50-applications/aap/06-base-os-prepare.yml" \
  -e @"${vars_path}"

installer_async_jid_path="/opt/aap/logs/aap_installer_async_jid"
deploy_rc=0
installer_attempt=1
installer_max_attempts="${AAP_CI_INSTALLER_MAX_ATTEMPTS:-2}"
installer_retry_delay="${AAP_CI_INSTALLER_RETRY_DELAY_SECONDS:-300}"

if ! [[ "${installer_max_attempts}" =~ ^[0-9]+$ ]] || [ "${installer_max_attempts}" -lt 1 ]; then
  echo "ERROR: AAP_CI_INSTALLER_MAX_ATTEMPTS must be a positive integer." >&2
  exit 2
fi

if ! [[ "${installer_retry_delay}" =~ ^[0-9]+$ ]]; then
  echo "ERROR: AAP_CI_INSTALLER_RETRY_DELAY_SECONDS must be a non-negative integer." >&2
  exit 2
fi

set +e

while [ "${installer_attempt}" -le "${installer_max_attempts}" ]; do
  echo "Starting native AAP installer attempt ${installer_attempt}/${installer_max_attempts}."
  clear_aap_installer_jid "${installer_async_jid_path}"

  if [ "${installer_attempt}" -eq 1 ]; then
    run_with_heartbeat \
      "AAP deploy start playbook" \
      ansible-playbook \
        -i "${inventory_path}" \
        "${automation_ansible_dir}/runbooks/50-applications/aap/10-deploy.yml" \
        -e @"${vars_path}" \
        --tags aap_deploy
  else
    run_with_heartbeat \
      "AAP deploy retry playbook" \
      ansible-playbook \
        -i "${inventory_path}" \
        "${automation_ansible_dir}/runbooks/50-applications/aap/10-deploy.yml" \
        -e @"${vars_path}" \
        -e '{"aap_deploy_skip_if_runtime_active": false, "aap_deploy_reset_partial_install_enabled": true}' \
        --tags aap_deploy
  fi
  deploy_rc=$?

  if [ "${deploy_rc}" -ne 0 ]; then
    break
  fi

  poll_aap_installer "${installer_async_jid_path}"
  deploy_rc=$?

  if [ "${deploy_rc}" -eq 0 ]; then
    break
  fi

  if [ "${installer_attempt}" -lt "${installer_max_attempts}" ]; then
    echo "Native AAP installer attempt ${installer_attempt} failed with rc=${deploy_rc}; retrying after ${installer_retry_delay} seconds."
    sleep "${installer_retry_delay}" || true
  fi

  installer_attempt=$((installer_attempt + 1))
done

if [ "${deploy_rc}" -ne 0 ]; then
  echo "Native AAP installer did not finish successfully after ${installer_attempt}/${installer_max_attempts} attempt(s)."
fi

if [ "${deploy_rc}" -eq 0 ]; then
  run_with_heartbeat \
    "AAP deployment verification playbook" \
    ansible-playbook \
      -i "${inventory_path}" \
      "${automation_ansible_dir}/runbooks/50-applications/aap/10-deploy.yml" \
      -e @"${vars_path}" \
      -e '{"aap_deploy_installer_wait": true, "aap_deploy_run_installer": false, "aap_deploy_manage_download_unpack": false}' \
      --tags aap_deploy
  deploy_rc=$?
fi

trap - EXIT INT TERM
cleanup "${deploy_rc}"
cleanup_rc=$?
if [ "${deploy_rc}" -eq 0 ] && [ "${cleanup_rc}" -ne 0 ]; then
  exit "${cleanup_rc}"
fi
exit "${deploy_rc}"
