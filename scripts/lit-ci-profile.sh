#!/usr/bin/env bash
set -euo pipefail

readonly PROFILE_NAME="repository-quality"
readonly BASE_REF="refs/remotes/origin/develop"
readonly DEVTOOLS_WRAPPER="scripts/wunder-devtools-ee.sh"

fail_closed() {
  printf 'Error: %s\n' "$1" >&2
  exit 1
}

if [ "$#" -ne 1 ] || [ "$1" != "$PROFILE_NAME" ]; then
  printf 'Usage: %s %s\n' "${0##*/}" "$PROFILE_NAME" >&2
  exit 2
fi

export LC_ALL=C
umask 077

case "$(uname -s)" in
  Darwin) expected_engine="docker" ;;
  Linux)
    if [ -r /etc/os-release ] && grep -Eq '^ID="?rhel"?$' /etc/os-release; then
      expected_engine="podman"
    else
      expected_engine="docker"
    fi
    ;;
  *) fail_closed "repository-quality supports only macOS and Linux hosts" ;;
esac
case "$(uname -m)" in
  x86_64|amd64|arm64|aarch64) ;;
  *) fail_closed "unsupported host architecture: $(uname -m)" ;;
esac
if [ -n "${WUNDER_CONTAINER_ENGINE:-}" ] \
  && [ "$WUNDER_CONTAINER_ENGINE" != "$expected_engine" ]
then
  fail_closed "this host requires container engine $expected_engine"
fi
readonly CONTAINER_ENGINE="$expected_engine"

repository_root="$(git rev-parse --show-toplevel 2>/dev/null)" \
  || fail_closed "run the profile from a Git worktree"
repository_root="$(cd "$repository_root" && pwd -P)"
cd "$repository_root"

for required_path in \
  "$DEVTOOLS_WRAPPER" \
  "scripts/lit-push-ready.py" \
  "scripts/lit-repository-quality.py" \
  "requirements-validation.lock" \
  ".github/requirements/collection-quality-profile.lock"
do
  [ -f "$required_path" ] && [ ! -L "$required_path" ] \
    || fail_closed "required regular profile input is missing: $required_path"
done

[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] \
  || fail_closed "repository-quality requires a clean committed worktree"
git show-ref --verify --quiet "$BASE_REF" \
  || fail_closed "missing authoritative base ref: $BASE_REF"
merge_base="$(git merge-base "$BASE_REF" HEAD)" \
  || fail_closed "cannot resolve authoritative merge base"
[ -n "$merge_base" ] || fail_closed "authoritative merge base is empty"

fingerprint() {
  {
    git rev-parse HEAD
    git write-tree
    git status --porcelain=v1 --untracked-files=all -z
    git diff --no-ext-diff --no-textconv --binary HEAD --
  } | git hash-object --stdin
}

initial_fingerprint="$(fingerprint)" \
  || fail_closed "cannot fingerprint initial worktree"

run_devtools() {
  network_mode="$1"
  shift
  env \
    CONTAINER_HOME=/tmp/wunder \
    WUNDER_DEVTOOLS_CAP_ADD= \
    WUNDER_DEVTOOLS_DOCKER_SOCKET=disabled \
    WUNDER_DEVTOOLS_FORWARD_VAGRANT_SSH=disabled \
    WUNDER_DEVTOOLS_MOUNT_SOURCE_ROOT=disabled \
    WUNDER_DEVTOOLS_NETWORK="$network_mode" \
    WUNDER_DEVTOOLS_PRIVILEGED=0 \
    WUNDER_DEVTOOLS_RUN_AS_HOST_UID=1 \
    WUNDER_DEVTOOLS_WORKSPACE_MODE=ro \
    WUNDER_CONTAINER_ENGINE="$CONTAINER_ENGINE" \
    CI=true \
    GITHUB_ACTIONS= \
    "$DEVTOOLS_WRAPPER" "$@"
}

printf '==> Install hash-locked validation runtimes and run contracts\n'
run_devtools bridge bash -euc '
  python3.11 -m venv /tmp/validation-contract
  /tmp/validation-contract/bin/python -m pip install \
    --disable-pip-version-check \
    --no-input \
    --require-hashes \
    --requirement requirements-validation.lock
  /tmp/validation-contract/bin/python scripts/lit-push-ready.py instructions
  /tmp/validation-contract/bin/python scripts/lit-repository-quality.py
  /tmp/validation-contract/bin/python -m unittest discover \
    -s tests -p "test_*.py"

  python3.11 -m venv /tmp/packer-runtime-lock
  /tmp/packer-runtime-lock/bin/python -m pip install \
    --disable-pip-version-check \
    --no-input \
    --require-hashes \
    --requirement .github/requirements/collection-quality-profile.lock
'

printf '==> Validate shell and GitHub Actions contracts offline\n'
run_devtools none actionlint --version
# The variables in this command are intentionally expanded inside the container.
# shellcheck disable=SC2016
run_devtools none bash -euc '
  shopt -s nullglob
  shell_paths=(.github/scripts/*.sh scripts/*.sh)
  if [ "${#shell_paths[@]}" -gt 0 ]; then
    shellcheck "${shell_paths[@]}"
  fi
  actionlint
'

printf '==> Validate committed and local diffs\n'
git diff --check "$merge_base"...HEAD --
git diff --check
git diff --cached --check

final_fingerprint="$(fingerprint)" \
  || fail_closed "cannot fingerprint final worktree"
[ "$initial_fingerprint" = "$final_fingerprint" ] \
  || fail_closed "repository-quality profile changed the Git worktree"

printf 'Validation repository-quality profile passed.\n'
