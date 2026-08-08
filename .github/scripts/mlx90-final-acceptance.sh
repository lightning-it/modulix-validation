#!/usr/bin/env bash
set -euo pipefail

readonly PRODUCER_REPOSITORY="lightning-it/ansible-collection-supplementary"
readonly PRODUCER_WORKFLOW=".github/workflows/collection-ci.yml"
readonly PRODUCER_WORKFLOW_NAME="Collection CI"
readonly PRODUCER_VALIDATION_JOB="Collection / Release Validation"
readonly CONSUMER_REPOSITORY="lightning-it/container-ee-wunder-ansible-ubi9"
readonly COPILOT_REVIEW_WORKFLOW=".github/workflows/copilot-review.yml"
readonly COPILOT_REVIEW_WORKFLOW_NAME="Copilot review gate"
readonly COPILOT_REVIEW_JOB_NAME="Successful Copilot review"
readonly FINALIZER_REPOSITORY="lightning-it/modulix-validation"
readonly FINALIZER_WORKFLOW=".github/workflows/mlx90-final-acceptance.yml"
readonly PROFILES="acceptance/mlx90/profiles.json"
readonly POLICY_VALIDATOR=".mlx90-policy/security-release/v1/validate.py"
readonly FINALIZER="scripts/finalize-mlx90-delivery.py"
readonly DELIVERY_VALIDATOR="scripts/validate-mlx90-delivery.py"
readonly CONTAINER_WORKFLOW_DAG_VALIDATOR=".github/scripts/mlx90-verify-container-workflow-dag.py"
readonly EVIDENCE_ROOT="${RUNNER_TEMP:?}/mlx90-final-evidence"
readonly INPUT_ROOT="${RUNNER_TEMP:?}/mlx90-final-inputs"
readonly RECEIPT_ROOT="${RUNNER_TEMP:?}/mlx90-verification-receipts"
readonly ISSUER="https://token.actions.githubusercontent.com"
readonly GITHUB_REST_API_VERSION="2026-03-10"
readonly SEMVER_MAX_LENGTH=255
readonly RELEASE_ASSET_MAX_BYTES=10485760
readonly CONTAINER_SBOM_ASSET_MAX_BYTES=67108864
declare -a EVIDENCE_ARGS=()
declare -a IDENTITY_ARGS=()

fail_closed() {
  printf 'Error: %s\n' "$1" >&2
  exit 1
}

require_value() {
  local name="$1"
  [ -n "${!name:-}" ] || fail_closed "${name} is required"
}

github_api() {
  local argument
  for argument in "$@"; do
    case "$argument" in
      *[Xx]-[Gg][Ii][Tt][Hh][Uu][Bb]-[Aa][Pp][Ii]-[Vv][Ee][Rr][Ss][Ii][Oo][Nn]*)
        fail_closed "GitHub API version header override is forbidden"
        ;;
    esac
  done
  gh api \
    --header "X-GitHub-Api-Version: ${GITHUB_REST_API_VERSION}" \
    "$@"
}

resolve_pull_request_merge_sha() {
  local repository="$1"
  local pull_request="$2"
  local pull_request_number merged_at
  [[ "$repository" =~ ^lightning-it/[A-Za-z0-9._-]+$ ]] \
    || fail_closed "pull-request repository is invalid"
  pull_request_number="$(jq -er '
    .number
    | select(type == "number" and floor == . and . > 0)
  ' <<<"$pull_request")" \
    || fail_closed "pull-request number is invalid"
  merged_at="$(jq -er '
    .merged_at
    | select(type == "string" and test(
        "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
      ))
  ' <<<"$pull_request")" \
    || fail_closed "pull-request merge timestamp is invalid"
  github_api --paginate \
    "repos/${repository}/issues/${pull_request_number}/events?per_page=100" \
    | jq -ser \
      --arg actor "lightning-it-release-automation[bot]" \
      --arg merged_at "$merged_at" '
    [.[][] | select(.event == "merged")] as $merged
    | if ($merged | length) != 1 then
        error("pull-request must have exactly one merged event")
      elif $merged[0].created_at != $merged_at then
        error("pull-request merge event timestamp does not match")
      elif $merged[0].actor.login != $actor then
        error("pull-request merge event actor is not the release App")
      elif ($merged[0].commit_id | type) != "string"
        or ($merged[0].commit_id | test("^[0-9a-f]{40}$") | not) then
        error("pull-request merge event commit is invalid")
      else
        {commitSha: $merged[0].commit_id, actor: $merged[0].actor.login}
      end
  '
}

workflow_approval_history() {
  local repository="$1"
  local run_id="$2"
  local reviews
  [[ "$repository" =~ ^lightning-it/[A-Za-z0-9._-]+$ ]] \
    || fail_closed "workflow approval repository is invalid"
  [[ "$run_id" =~ ^[1-9][0-9]*$ ]] \
    || fail_closed "workflow approval run ID is invalid"
  reviews="$(github_api "repos/${repository}/actions/runs/${run_id}/approvals")" \
    || fail_closed "workflow approval history is unavailable"
  jq -e 'type == "array" and length == 0' <<<"$reviews" >/dev/null \
    || fail_closed "workflow run contains a human environment approval"
  printf '%s\n' "$reviews"
}

# Validate the complete SemVer 2.0.0 grammar without interpreting any numeric
# identifier as a shell integer. Numeric build identifiers may have leading
# zeroes; numeric core and prerelease identifiers may not.
is_semver() {
  local LC_ALL=C
  local value="$1"
  local build=""
  local prerelease=""
  local core
  local identifier
  local -a identifiers=()

  [ "${#value}" -ge 1 ] || return 1
  [ "${#value}" -le "$SEMVER_MAX_LENGTH" ] || return 1
  [[ "$value" =~ ^[0-9A-Za-z.+-]+$ ]] || return 1
  if [[ "$value" == *+* ]]; then
    build="${value#*+}"
    value="${value%%+*}"
    [[ -n "$build" && "$build" != *+* ]] || return 1
    [[ "$build" != .* && "$build" != *. && "$build" != *..* ]] \
      || return 1
    IFS='.' read -r -a identifiers <<<"$build"
    for identifier in "${identifiers[@]}"; do
      [[ "$identifier" =~ ^[0-9A-Za-z-]+$ ]] || return 1
    done
  fi

  if [[ "$value" == *-* ]]; then
    prerelease="${value#*-}"
    core="${value%%-*}"
    [[ -n "$prerelease" ]] || return 1
    [[ "$prerelease" != .* \
      && "$prerelease" != *. \
      && "$prerelease" != *..* ]] || return 1
    IFS='.' read -r -a identifiers <<<"$prerelease"
    for identifier in "${identifiers[@]}"; do
      [[ "$identifier" =~ ^[0-9A-Za-z-]+$ ]] || return 1
      if [[ "$identifier" =~ ^[0-9]+$ ]]; then
        [[ "$identifier" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
      fi
    done
  else
    core="$value"
  fi

  [[ "$core" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

list_release_assets() {
  local repository="$1"
  local release_id="$2"
  [[ "$repository" =~ ^lightning-it/[A-Za-z0-9._-]+$ ]] \
    || fail_closed "release asset repository is invalid"
  [[ "$release_id" =~ ^[1-9][0-9]*$ ]] \
    || fail_closed "release ID is invalid"
  github_api --paginate \
    "repos/${repository}/releases/${release_id}/assets?per_page=100" \
    | jq -sc 'add // []'
}

release_asset_max_bytes() {
  local repository="$1"
  local asset_name="$2"
  if [ "$repository" = "$CONSUMER_REPOSITORY" ]; then
    case "$asset_name" in
      sbom.cdx.json|sbom-bootstrap.cdx.json|sbom-certified.cdx.json|sbom-public.cdx.json)
        printf '%s\n' "$CONTAINER_SBOM_ASSET_MAX_BYTES"
        return
        ;;
    esac
  fi
  printf '%s\n' "$RELEASE_ASSET_MAX_BYTES"
}

canonical_consumed_asset_snapshot() {
  local repository="$1"
  local release_id="$2"
  local release_assets="$3"
  local expected_urls="$4"
  jq -ecS \
    --arg repository "$repository" \
    --arg consumer_repository "$CONSUMER_REPOSITORY" \
    --argjson release_id "$release_id" \
    --argjson release_asset_max_bytes "$RELEASE_ASSET_MAX_BYTES" \
    --argjson container_sbom_asset_max_bytes \
      "$CONTAINER_SBOM_ASSET_MAX_BYTES" \
    --argjson expected_urls "$expected_urls" '
      ($expected_urls | sort | unique) as $expected
      | if ($expected_urls | length) != ($expected | length) then
          error("consumed release asset URLs must be unique")
        else
          .
        end
      | [
          .[]
          | select(.browser_download_url as $url | $expected | index($url))
          | {
              id: .id,
              name: .name,
              url: .browser_download_url,
              state: .state,
              size: .size
            }
        ] as $assets
      | if ($assets | length) != ($expected | length) then
          error("release does not contain each consumed asset exactly once")
        elif any($assets[];
          (.id | type) != "number"
          or (.id | floor) != .id
          or .id <= 0
          or (.name | type) != "string"
          or .name == ""
          or (.url | type) != "string"
          or .state != "uploaded"
          or (.size | type) != "number"
          or (.size | floor) != .size
          or .size <= 0
          or .size > (
            if $repository == $consumer_repository
              and (.name == "sbom.cdx.json"
                or .name == "sbom-bootstrap.cdx.json"
                or .name == "sbom-certified.cdx.json"
                or .name == "sbom-public.cdx.json")
            then $container_sbom_asset_max_bytes
            else $release_asset_max_bytes
            end
          )
        ) then
          error("consumed release asset metadata is invalid")
        elif ([$assets[].id] | unique | length) != ($assets | length)
          or ([$assets[].name] | unique | length) != ($assets | length)
          or ([$assets[].url] | unique | length) != ($assets | length) then
          error("consumed release asset metadata is not unique")
        else
          {
            repository: $repository,
            releaseId: $release_id,
            assets: ($assets | sort_by(.url))
          }
        end
    ' <<<"$release_assets"
}

canonical_release_asset_metadata() {
  local release_assets="$1"
  jq -ecS '
    [
      .[]
      | {
          id: .id,
          name: .name,
          url: .browser_download_url,
          state: .state,
          size: .size
        }
    ] as $assets
    | if any($assets[];
        (.id | type) != "number"
        or (.id | floor) != .id
        or .id <= 0
        or (.name | type) != "string"
        or (.name | test("^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")) != true
        or (.url | type) != "string"
        or (.url | startswith("https://github.com/")) != true
        or .state != "uploaded"
        or (.size | type) != "number"
        or (.size | floor) != .size
        or .size <= 0
        or .size > 10485760
      ) then
        error("release asset metadata is invalid")
      elif ([$assets[].id] | unique | length) != ($assets | length)
        or ([$assets[].name] | unique | length) != ($assets | length)
        or ([$assets[].url] | unique | length) != ($assets | length) then
        error("release asset metadata is not unique")
      else
        $assets | sort_by(.name)
      end
  ' <<<"$release_assets"
}

download_release_assets_and_compare() {
  local repository="$1"
  local assets="$2"
  local source_root="$3"
  local output_root="$4"
  local asset asset_id asset_name asset_size
  [ ! -e "$output_root" ] && [ ! -L "$output_root" ] \
    || fail_closed "release asset verification directory already exists"
  install -d -m 0700 "$output_root"
  while IFS= read -r asset; do
    [ -n "$asset" ] || continue
    asset_id="$(jq -er '.id' <<<"$asset")"
    asset_name="$(jq -er '.name' <<<"$asset")"
    asset_size="$(jq -er '.size' <<<"$asset")"
    download_release_asset_by_id \
      "$repository" "$asset_id" "$asset_size" "$asset_name" \
      "$output_root/$asset_name"
    cmp "$source_root/$asset_name" "$output_root/$asset_name" \
      || fail_closed "persisted release asset differs: ${asset_name}"
  done < <(jq -c '.[]' <<<"$assets")
}

asset_snapshot_digest() {
  local snapshot="$1"
  printf '%s' "$snapshot" | sha256sum | awk '{print "sha256:" $1}'
}

download_release_asset_by_id() {
  local repository="$1"
  local asset_id="$2"
  local asset_size="$3"
  local asset_name="$4"
  local output="$5"
  local max_bytes
  [[ "$repository" =~ ^lightning-it/[A-Za-z0-9._-]+$ ]] \
    || fail_closed "release asset repository is invalid"
  [[ "$asset_id" =~ ^[1-9][0-9]*$ ]] \
    || fail_closed "release asset ID is invalid"
  [[ "$asset_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$ ]] \
    || fail_closed "release asset name is invalid"
  max_bytes="$(release_asset_max_bytes "$repository" "$asset_name")"
  [[ "$asset_size" =~ ^[1-9][0-9]*$ ]] \
    && [ "$asset_size" -le "$max_bytes" ] \
    || fail_closed "release asset size is invalid or exceeds its bound"
  [ ! -e "$output" ] && [ ! -L "$output" ] \
    || fail_closed "release asset download output already exists"
  github_api \
    --header 'Accept: application/octet-stream' \
    "repos/${repository}/releases/assets/${asset_id}" \
    >"$output"
  [ -s "$output" ] || fail_closed "downloaded release asset is empty"
  [ "$(wc -c <"$output" | tr -d '[:space:]')" = "$asset_size" ] \
    || fail_closed "downloaded release asset size differs from live metadata"
}

upload_release_asset_by_id() {
  local repository="$1"
  local release_id="$2"
  local upload_url_template="$3"
  local source="$4"
  local asset_name expected_upload_url upload_url
  [[ "$repository" =~ ^lightning-it/[A-Za-z0-9._-]+$ ]] \
    || fail_closed "release asset repository is invalid"
  [[ "$release_id" =~ ^[1-9][0-9]*$ ]] \
    || fail_closed "release ID is invalid"
  [ -f "$source" ] && [ ! -L "$source" ] \
    || fail_closed "release asset upload source is invalid"
  asset_name="${source##*/}"
  [[ "$asset_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$ ]] \
    || fail_closed "release asset upload name is invalid"
  [ "$(wc -c <"$source" | tr -d '[:space:]')" -le 10485760 ] \
    || fail_closed "release asset upload exceeds 10 MiB"
  expected_upload_url="https://uploads.github.com/repos/${repository}/"
  expected_upload_url+="releases/${release_id}/assets{?name,label}"
  [ "$upload_url_template" = "$expected_upload_url" ] \
    || fail_closed "release upload URL does not bind the numeric release ID"
  upload_url="${upload_url_template%%\{*}?name=${asset_name}"
  github_api \
    --method POST \
    --header 'Accept: application/vnd.github+json' \
    --header 'Content-Type: application/octet-stream' \
    --input "$source" \
    --silent \
    "$upload_url"
}

redownload_snapshot_and_compare() {
  local snapshot="$1"
  local bindings="$2"
  local output_root="$3"
  local repository asset asset_id asset_name asset_size asset_url output
  local binding_count
  repository="$(jq -er '.repository' <<<"$snapshot")"
  [ ! -e "$output_root" ] && [ ! -L "$output_root" ] \
    || fail_closed "final release asset comparison path already exists"
  install -d -m 0700 "$output_root"
  while IFS= read -r asset; do
    [ -n "$asset" ] || continue
    asset_id="$(jq -er '.id' <<<"$asset")"
    asset_name="$(jq -er '.name' <<<"$asset")"
    asset_size="$(jq -er '.size' <<<"$asset")"
    asset_url="$(jq -er '.url' <<<"$asset")"
    output="$output_root/${asset_id}"
    download_release_asset_by_id \
      "$repository" "$asset_id" "$asset_size" "$asset_name" "$output"
    binding_count="$(jq --arg url "$asset_url" \
      '[.[] | select(.url == $url)] | length' <<<"$bindings")"
    [ "$binding_count" -gt 0 ] \
      || fail_closed "final asset snapshot has no local consumed-file binding"
    while IFS= read -r binding; do
      [ -n "$binding" ] || continue
      cmp "$output" "$binding" \
        || fail_closed "final release asset differs from consumed bytes"
    done < <(jq -r --arg url "$asset_url" \
      '.[] | select(.url == $url) | .path' <<<"$bindings")
  done < <(jq -c '.assets[]' <<<"$snapshot")
}

download_release_asset() {
  local url="$1"
  local output="$2"
  local repository prefix remainder tag asset release release_assets
  local asset_metadata asset_id asset_size max_bytes release_id
  case "$url" in
    https://github.com/lightning-it/ansible-collection-supplementary/releases/download/*)
      repository="lightning-it/ansible-collection-supplementary"
      ;;
    https://github.com/lightning-it/container-ee-wunder-ansible-ubi9/releases/download/*)
      repository="lightning-it/container-ee-wunder-ansible-ubi9"
      ;;
    *) fail_closed "release asset URL is outside the MLX-90 repository allowlist" ;;
  esac
  prefix="https://github.com/${repository}/releases/download/"
  remainder="${url#"$prefix"}"
  tag="${remainder%%/*}"
  asset="${remainder#*/}"
  [ -n "$tag" ] && [ -n "$asset" ] && [ "$asset" != "$remainder" ] \
    && [[ "$tag" != */* ]] && [[ "$asset" != */* ]] \
    || fail_closed "release asset URL is not canonical"
  release="$(github_api "repos/${repository}/releases/tags/${tag}")"
  release_id="$(jq -er '.id' <<<"$release")"
  release_assets="$(list_release_assets "$repository" "$release_id")"
  asset_metadata="$(jq -ec --arg url "$url" '[
    .[]
    | select(.state == "uploaded" and .browser_download_url == $url)
  ] | if length == 1 then .[0] else error(
    "release must contain exactly one matching uploaded asset"
  ) end' <<<"$release_assets")"
  asset_id="$(jq -er '.id' <<<"$asset_metadata")"
  asset_size="$(jq -er '.size' <<<"$asset_metadata")"
  max_bytes="$(release_asset_max_bytes "$repository" "$asset")"
  [[ "$asset_id" =~ ^[1-9][0-9]*$ ]] \
    && [[ "$asset_size" =~ ^[1-9][0-9]*$ ]] \
    && [ "$asset_size" -le "$max_bytes" ] \
    || fail_closed "release asset metadata is invalid or exceeds its bound"
  download_release_asset_by_id \
    "$repository" "$asset_id" "$asset_size" "$asset" "$output"
}

verify_reference() {
  local url="$1"
  local digest="$2"
  local output="$3"
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || fail_closed "invalid immutable reference digest"
  download_release_asset "$url" "$output"
  [ "sha256:$(sha256sum "$output" | awk '{print $1}')" = "$digest" ] \
    || fail_closed "immutable reference digest mismatch"
}

validate_quay_bearer_challenge() {
  local headers="$1"
  local repository="$2"
  python3 - "$headers" "$repository" <<'PY'
import re
import sys
from pathlib import Path


header_path = Path(sys.argv[1])
expected_repository = sys.argv[2]
try:
    raw_headers = header_path.read_bytes()
except OSError:
    raise SystemExit(1)
if not raw_headers or len(raw_headers) > 65_536 or b"\x00" in raw_headers:
    raise SystemExit(1)
try:
    header_text = raw_headers.decode("ascii")
except UnicodeDecodeError:
    raise SystemExit(1)

blocks = [
    block
    for block in re.split(r"\r?\n\r?\n", header_text)
    if block.strip()
]
if not blocks:
    raise SystemExit(1)
lines = blocks[-1].splitlines()
if not lines or re.fullmatch(
    r"HTTP/(?:1\.[01]|2|3) 401(?:[ \t][\x20-\x7e]*)?", lines[0]
) is None:
    raise SystemExit(1)

challenges = []
for line in lines[1:]:
    if not line or line[0] in " \t" or ":" not in line:
        raise SystemExit(1)
    name, value = line.split(":", 1)
    if re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is None:
        raise SystemExit(1)
    if name.lower() == "www-authenticate":
        challenges.append(value.strip())
if len(challenges) != 1:
    raise SystemExit(1)

scheme = re.match(r"(?i:Bearer)[ \t]+", challenges[0])
if scheme is None:
    raise SystemExit(1)
parameters = challenges[0][scheme.end() :]
parameter = re.compile(
    r'([A-Za-z][A-Za-z0-9_-]*)[ \t]*=[ \t]*"([^"\\\r\n]*)"'
)
parsed = {}
position = 0
while position < len(parameters):
    while position < len(parameters) and parameters[position] in " \t":
        position += 1
    match = parameter.match(parameters, position)
    if match is None:
        raise SystemExit(1)
    key = match.group(1).lower()
    if key in parsed:
        raise SystemExit(1)
    parsed[key] = match.group(2)
    position = match.end()
    while position < len(parameters) and parameters[position] in " \t":
        position += 1
    if position == len(parameters):
        break
    if parameters[position] != ",":
        raise SystemExit(1)
    position += 1
    if position == len(parameters):
        raise SystemExit(1)

expected = {
    "realm": "https://quay.io/v2/auth",
    "service": "quay.io",
    "scope": f"repository:{expected_repository}:pull",
}
if parsed != expected:
    raise SystemExit(1)
PY
}

download_quay_blob() {
  local image="$1"
  local digest="$2"
  local expected_size="$3"
  local output="$4"
  local repository headers curl_status token_response token
  [[ "$image" =~ ^quay\.io/[a-z0-9]+([._-][a-z0-9]+)*/[a-z0-9]+([._/-][a-z0-9]+)*$ ]] \
    || fail_closed "BuildKit blob image is outside the Quay allowlist"
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || fail_closed "BuildKit blob digest is invalid"
  [[ "$expected_size" =~ ^[1-9][0-9]*$ ]] \
    && [ "$expected_size" -le 67108864 ] \
    || fail_closed "BuildKit blob size is invalid or exceeds 64 MiB"
  [ ! -e "$output" ] && [ ! -L "$output" ] \
    || fail_closed "BuildKit blob output already exists"
  repository="${image#quay.io/}"
  headers="$(mktemp "${output}.headers.XXXXXX")" \
    || fail_closed "cannot create BuildKit response header snapshot"
  if curl \
    --disable \
    --fail \
    --remove-on-error \
    --silent \
    --show-error \
    --proto '=https' \
    --proto-redir '=https' \
    --location \
    --max-redirs 1 \
    --tlsv1.2 \
    --max-time 300 \
    --max-filesize 67108864 \
    --dump-header "$headers" \
    --output "$output" \
    "https://quay.io/v2/${repository}/blobs/${digest}"
  then
    rm -f -- "$headers"
  else
    curl_status=$?
    if [ "$curl_status" -ne 22 ] \
      || ! validate_quay_bearer_challenge \
        "$headers" "$repository" 2>/dev/null
    then
      rm -f -- "$headers"
      fail_closed "Quay blob request did not return the required Bearer challenge"
    fi
    rm -f -- "$headers"
    set +x
    if ! token_response="$(curl \
      --disable \
      --fail \
      --remove-on-error \
      --silent \
      --show-error \
      --proto '=https' \
      --tlsv1.2 \
      --max-time 30 \
      --max-filesize 65536 \
      --get \
      --data-urlencode 'service=quay.io' \
      --data-urlencode "scope=repository:${repository}:pull" \
      'https://quay.io/v2/auth')"
    then
      fail_closed "anonymous Quay pull-token request failed"
    fi
    if ! token="$(jq -er '
      if type == "object"
        and (.token | type) == "string"
        and (.token | length) >= 1
        and (.token | length) <= 8192
        and (.token | test("^[A-Za-z0-9._~-]+$"))
      then .token
      else error("invalid anonymous pull token")
      end
    ' <<<"$token_response" 2>/dev/null)"
    then
      unset token_response
      fail_closed "anonymous Quay pull-token response is invalid"
    fi
    unset token_response
    if ! printf 'oauth2-bearer = "%s"\n' "$token" \
      | curl \
        --disable \
        --config - \
        --fail \
        --remove-on-error \
        --silent \
        --show-error \
        --proto '=https' \
        --proto-redir '=https' \
        --location \
        --max-redirs 1 \
        --tlsv1.2 \
        --max-time 300 \
        --max-filesize 67108864 \
        --output "$output" \
        "https://quay.io/v2/${repository}/blobs/${digest}"
    then
      unset token
      fail_closed "authenticated anonymous Quay blob request failed"
    fi
    unset token
  fi
  [ -s "$output" ] \
    || fail_closed "downloaded BuildKit blob is empty"
  [ -f "$output" ] && [ ! -L "$output" ] \
    || fail_closed "downloaded BuildKit blob is not a regular file"
  [ "$(wc -c <"$output" | tr -d '[:space:]')" = "$expected_size" ] \
    || fail_closed "downloaded BuildKit blob size differs from its descriptor"
  [ "sha256:$(sha256sum "$output" | awk '{print $1}')" = "$digest" ] \
    || fail_closed "downloaded BuildKit blob digest differs from its descriptor"
}

resolve_tag_commit() {
  local repository="$1"
  local tag="$2"
  local reference object_type object_sha
  reference="$(github_api "repos/${repository}/git/ref/tags/${tag}")"
  object_type="$(jq -er '.object.type' <<<"$reference")"
  object_sha="$(jq -er '.object.sha' <<<"$reference")"
  case "$object_type" in
    commit) printf '%s\n' "$object_sha" ;;
    tag)
      github_api "repos/${repository}/git/tags/${object_sha}" --jq '.object.sha'
      ;;
    *) fail_closed "release tag does not resolve to a commit" ;;
  esac
}

verify_container_workflow_dag() {
  local workflow="$1"
  [ -f "$workflow" ] && [ ! -L "$workflow" ] \
    || fail_closed "container workflow is not a regular file"
  [ "$(wc -c <"$workflow" | tr -d '[:space:]')" -le 1048576 ] \
    || fail_closed "container workflow exceeds its size limit"
  [ -f "$CONTAINER_WORKFLOW_DAG_VALIDATOR" ] \
    && [ ! -L "$CONTAINER_WORKFLOW_DAG_VALIDATOR" ] \
    || fail_closed "container workflow DAG validator is not a regular file"
  python3 -I -B "$CONTAINER_WORKFLOW_DAG_VALIDATOR" "$workflow" \
    >/dev/null 2>&1 \
    || fail_closed "container workflow publisher DAG is not exact"
}

verify_container_run_identity() {
  local attempt="$1"
  local success_required="$2"
  jq -e \
    --arg actor "lightning-it-release-automation[bot]" \
    --argjson attempt "$attempt" \
    --argjson run_id "$INPUT_CONTAINER_RELEASE_RUN_ID" \
    --arg repository "$CONSUMER_REPOSITORY" \
    --arg sha "$INPUT_CONSUMER_MERGE_SHA" \
    --arg tag "$INPUT_CONTAINER_RELEASE_TAG" \
    --argjson success_required "$success_required" '
      .id == $run_id
      and .run_attempt == $attempt
      and .repository.full_name == $repository
      and .head_repository.full_name == $repository
      and .actor.login == $actor
      and .triggering_actor.login == $actor
      and .event == "workflow_dispatch"
      and .path == ".github/workflows/container-build-publish.yml"
      and .head_sha == $sha
      and .head_branch == $tag
      and .status == "completed"
      and (if $success_required then .conclusion == "success" else
        (.conclusion as $conclusion | ([
          "success", "failure", "neutral", "cancelled", "skipped",
          "timed_out", "action_required", "stale", "startup_failure"
        ] | index($conclusion)) != null)
      end)
    ' >/dev/null
}

select_successful_job() {
  local name="$1"
  local multiplicity_error="$2"
  local conclusion_error="$3"
  jq -ec --arg name "$name" \
    --arg multiplicity_error "$multiplicity_error" \
    --arg conclusion_error "$conclusion_error" '
      [.[] | select(.name == $name)]
      | if length != 1 then error($multiplicity_error)
        elif .[0].status != "completed" or .[0].conclusion != "success"
        then error($conclusion_error)
        else .[0]
        end
    '
}

identity_args() {
  IDENTITY_ARGS=(
    --correlation-id "$INPUT_CORRELATION_ID"
    --producer-evidence-url "$INPUT_PRODUCER_EVIDENCE_URL"
    --producer-evidence-bundle-url "$INPUT_PRODUCER_EVIDENCE_BUNDLE_URL"
    --producer-evidence-sha256 "$INPUT_PRODUCER_EVIDENCE_SHA256"
    --consumer-pr "$INPUT_CONSUMER_PR"
    --consumer-head-sha "$INPUT_CONSUMER_HEAD_SHA"
    --consumer-merge-sha "$INPUT_CONSUMER_MERGE_SHA"
    --container-release-id "$INPUT_CONTAINER_RELEASE_ID"
    --container-release-tag "$INPUT_CONTAINER_RELEASE_TAG"
    --container-release-run-id "$INPUT_CONTAINER_RELEASE_RUN_ID"
    --container-publish-run-attempt "$INPUT_CONTAINER_PUBLISH_RUN_ATTEMPT"
  )
}

write_receipt() {
  local receipt_id="$1"
  local checked_at="$2"
  local observations="$3"
  local observation_path="$INPUT_ROOT/${receipt_id}-observations.json"
  [[ "$receipt_id" =~ ^[a-z0-9-]+$ ]] \
    || fail_closed "verification receipt ID is invalid"
  [ ! -e "$observation_path" ] && [ ! -L "$observation_path" ] \
    || fail_closed "verification receipt observations already exist"
  printf '%s\n' "$observations" >"$observation_path"
  python3 "$FINALIZER" write-receipt \
    "${IDENTITY_ARGS[@]}" \
    "${EVIDENCE_ARGS[@]}" \
    --workflow-sha "$GITHUB_SHA" \
    --run-id "$GITHUB_RUN_ID" \
    --run-attempt "$GITHUB_RUN_ATTEMPT" \
    --receipt-id "$receipt_id" \
    --observations "$observation_path" \
    --checked-at "$checked_at" \
    --output "$RECEIPT_ROOT/${receipt_id}.json"
}

verify_mode() {
  local required
  for required in \
    GH_TOKEN \
    GITHUB_ACTOR \
    GITHUB_TRIGGERING_ACTOR \
    GITHUB_OUTPUT \
    GITHUB_REF \
    GITHUB_REPOSITORY \
    GITHUB_RUN_ATTEMPT \
    GITHUB_RUN_ID \
    GITHUB_SHA \
    APP_INSTALLATION_ID \
    APP_SLUG \
    INPUT_CORRELATION_ID \
    INPUT_PRODUCER_EVIDENCE_URL \
    INPUT_PRODUCER_EVIDENCE_BUNDLE_URL \
    INPUT_PRODUCER_EVIDENCE_SHA256 \
    INPUT_CONSUMER_PR \
    INPUT_CONSUMER_HEAD_SHA \
    INPUT_CONSUMER_MERGE_SHA \
    INPUT_CONTAINER_RELEASE_ID \
    INPUT_CONTAINER_RELEASE_TAG \
    INPUT_CONTAINER_RELEASE_RUN_ID \
    INPUT_CONTAINER_PUBLISH_RUN_ATTEMPT
  do
    require_value "$required"
  done
  [ "$GITHUB_REPOSITORY" = "$FINALIZER_REPOSITORY" ] \
    || fail_closed "unexpected finalizer repository"
  [ "$GITHUB_REF" = "refs/heads/main" ] \
    || fail_closed "final acceptance must run from protected main"
  [ "$GITHUB_ACTOR" = "lightning-it-release-automation[bot]" ] \
    || fail_closed "only the release automation App may dispatch final acceptance"
  [ "$GITHUB_TRIGGERING_ACTOR" = "lightning-it-release-automation[bot]" ] \
    || fail_closed "only the release automation App may trigger final acceptance"
  [ "$APP_SLUG" = "lightning-it-release-automation" ] \
    || fail_closed "final acceptance App slug is invalid"
  [ "$APP_INSTALLATION_ID" = "148019054" ] \
    || fail_closed "final acceptance App installation ID is invalid"
  [[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]] \
    || fail_closed "finalizer workflow SHA is invalid"
  for required in \
    INPUT_CONSUMER_PR \
    INPUT_CONTAINER_RELEASE_ID \
    INPUT_CONTAINER_RELEASE_RUN_ID \
    INPUT_CONTAINER_PUBLISH_RUN_ATTEMPT
  do
    [[ "${!required}" =~ ^[1-9][0-9]*$ ]] \
      || fail_closed "${required} must be a canonical positive integer"
  done
  [ -f "$PROFILES" ] && [ ! -L "$PROFILES" ] \
    || fail_closed "fixed acceptance profile allowlist is missing"
  [ -f "$POLICY_VALIDATOR" ] && [ ! -L "$POLICY_VALIDATOR" ] \
    || fail_closed "pinned canonical policy validator is missing"

  umask 077
  for required in "$INPUT_ROOT" "$EVIDENCE_ROOT" "$RECEIPT_ROOT"; do
    [ ! -e "$required" ] && [ ! -L "$required" ] \
      || fail_closed "fresh verification output path already exists: ${required}"
  done
  install -d -m 0700 "$INPUT_ROOT" "$EVIDENCE_ROOT" "$RECEIPT_ROOT"
  identity_args
  python3 "$FINALIZER" validate-inputs "${IDENTITY_ARGS[@]}"

  local producer_evidence producer_bundle producer_sha producer_tag
  local producer_version producer_candidate_name
  local producer_identity producer_release expected_collection_digest
  local producer_tag_commit
  local producer_evidence_checked_at producer_identity_checked_at
  local producer_revocation_checked_at producer_cosign_checked_at
  local producer_materials_checked_at producer_central_ci_checked_at
  local producer_release_id producer_ci_run_id producer_ci_run_attempt
  local producer_ci_run producer_ci_jobs producer_validation_gate
  local producer_release_assets
  local producer_consumed_urls producer_asset_bindings
  local producer_initial_asset_snapshot producer_initial_asset_snapshot_digest
  producer_evidence="$INPUT_ROOT/producer-evidence.json"
  producer_bundle="$INPUT_ROOT/producer-evidence.json.sigstore.json"
  download_release_asset "$INPUT_PRODUCER_EVIDENCE_URL" "$producer_evidence"
  download_release_asset "$INPUT_PRODUCER_EVIDENCE_BUNDLE_URL" "$producer_bundle"
  [ "$(sha256sum "$producer_evidence" | awk '{print $1}')" \
      = "$INPUT_PRODUCER_EVIDENCE_SHA256" ] \
    || fail_closed "producer evidence digest differs from the dispatch identity"
  producer_sha="$(jq -er '.producer.sourceSha' "$producer_evidence")"
  [[ "$producer_sha" =~ ^[0-9a-f]{40}$ ]] \
    || fail_closed "producer evidence source SHA is invalid"
  producer_identity="https://github.com/${PRODUCER_REPOSITORY}/"
  producer_identity+=".github/workflows/collection-publish.yml@refs/heads/main"
  cosign verify-blob \
    --bundle "$producer_bundle" \
    --certificate-oidc-issuer "$ISSUER" \
    --certificate-identity "$producer_identity" \
    --certificate-github-workflow-sha "$producer_sha" \
    "$producer_evidence"
  python3 "$POLICY_VALIDATOR" \
    "$producer_evidence" \
    --consumer "$CONSUMER_REPOSITORY" \
    --head-sha "$INPUT_CONSUMER_HEAD_SHA"
  producer_evidence_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

  producer_tag="$(python3 - "$INPUT_PRODUCER_EVIDENCE_URL" <<'PY'
import sys
from urllib.parse import urlsplit

print(urlsplit(sys.argv[1]).path.split('/')[5])
PY
  )"
  producer_tag_commit="$(resolve_tag_commit \
    "$PRODUCER_REPOSITORY" "$producer_tag")"
  [ "$producer_tag_commit" = "$producer_sha" ] \
    || fail_closed "producer release tag is not bound to producer source SHA"
  producer_release="$(github_api \
    "repos/${PRODUCER_REPOSITORY}/releases/tags/${producer_tag}")"
  jq -e --arg tag "$producer_tag" \
    '.tag_name == $tag and .draft == false and .prerelease == false' \
    <<<"$producer_release" >/dev/null
  producer_release_id="$(jq -er '.id' <<<"$producer_release")"
  producer_release_assets="$(list_release_assets \
    "$PRODUCER_REPOSITORY" "$producer_release_id")"
  producer_identity_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

  local evidence_id revocation_count
  evidence_id="$(jq -er '.metadata.id' "$producer_evidence")"
  revocation_count="$(jq \
    --arg id "$evidence_id" '[
      .[].name
      | select(
          . == "security-release-revocation.json"
          or . == ("security-release-revocation-" + $id + ".json")
        )
    ] | length' <<<"$producer_release_assets")"
  [ "$revocation_count" -eq 0 ] \
    || fail_closed "producer release contains revocation evidence"
  producer_revocation_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

  expected_collection_digest="$(jq -er '.artifact.digest' "$producer_evidence")"
  producer_version="$(jq -er '.artifact.version' "$producer_evidence")"
  is_semver "$producer_version" \
    || fail_closed "producer evidence version is invalid"
  producer_candidate_name="lit-supplementary-${producer_version}.tar.gz"
  mapfile -t collection_assets < <(jq -r --arg name "$producer_candidate_name" '
    [.[] | select(.name == $name)]
    | if length == 1 then .[0].browser_download_url else empty end
  ' <<<"$producer_release_assets")
  [ "${#collection_assets[@]}" -eq 1 ] \
    || fail_closed "producer release must contain the exact collection tarball"
  verify_reference \
    "${collection_assets[0]}" \
    "$expected_collection_digest" \
    "$INPUT_ROOT/producer-collection.tar.gz"

  local producer_reference reference_url reference_digest
  for producer_reference in signature sbom provenance; do
    reference_url="$(jq -er --arg name "$producer_reference" \
      '.artifact[$name].url' "$producer_evidence")"
    reference_digest="$(jq -er --arg name "$producer_reference" \
      '.artifact[$name].digest' "$producer_evidence")"
    verify_reference \
      "$reference_url" \
      "$reference_digest" \
      "$INPUT_ROOT/producer-${producer_reference}.json"
  done
  local producer_candidate_identity
  producer_candidate_identity="https://github.com/${PRODUCER_REPOSITORY}/"
  producer_candidate_identity+=".github/workflows/collection-ci.yml@refs/heads/main"
  cosign verify-blob \
    --bundle "$INPUT_ROOT/producer-signature.json" \
    --certificate-oidc-issuer "$ISSUER" \
    --certificate-identity "$producer_candidate_identity" \
    --certificate-github-workflow-sha "$producer_sha" \
    "$INPUT_ROOT/producer-collection.tar.gz"
  producer_cosign_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  python3 "$FINALIZER" verify-producer-materials \
    --producer-evidence "$producer_evidence" \
    --collection "$INPUT_ROOT/producer-collection.tar.gz" \
    --sbom "$INPUT_ROOT/producer-sbom.json" \
    --provenance "$INPUT_ROOT/producer-provenance.json"
  producer_materials_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

  producer_consumed_urls="$(jq -cn \
    --arg evidence "$INPUT_PRODUCER_EVIDENCE_URL" \
    --arg bundle "$INPUT_PRODUCER_EVIDENCE_BUNDLE_URL" \
    --arg collection "${collection_assets[0]}" \
    --arg signature "$(jq -er '.artifact.signature.url' "$producer_evidence")" \
    --arg sbom "$(jq -er '.artifact.sbom.url' "$producer_evidence")" \
    --arg provenance "$(jq -er '.artifact.provenance.url' \
      "$producer_evidence")" \
    '[$evidence, $bundle, $collection, $signature, $sbom, $provenance]')"
  [ "$(jq 'length' <<<"$producer_consumed_urls")" -eq 6 ] \
    || fail_closed "producer consumed asset URL set is not exact"
  producer_asset_bindings="$(jq -cn \
    --arg evidence_url "$INPUT_PRODUCER_EVIDENCE_URL" \
    --arg evidence_path "$producer_evidence" \
    --arg bundle_url "$INPUT_PRODUCER_EVIDENCE_BUNDLE_URL" \
    --arg bundle_path "$producer_bundle" \
    --arg collection_url "${collection_assets[0]}" \
    --arg collection_path "$INPUT_ROOT/producer-collection.tar.gz" \
    --arg signature_url "$(jq -er '.artifact.signature.url' \
      "$producer_evidence")" \
    --arg signature_path "$INPUT_ROOT/producer-signature.json" \
    --arg sbom_url "$(jq -er '.artifact.sbom.url' "$producer_evidence")" \
    --arg sbom_path "$INPUT_ROOT/producer-sbom.json" \
    --arg provenance_url "$(jq -er '.artifact.provenance.url' \
      "$producer_evidence")" \
    --arg provenance_path "$INPUT_ROOT/producer-provenance.json" '[
      {url: $evidence_url, path: $evidence_path},
      {url: $bundle_url, path: $bundle_path},
      {url: $collection_url, path: $collection_path},
      {url: $signature_url, path: $signature_path},
      {url: $sbom_url, path: $sbom_path},
      {url: $provenance_url, path: $provenance_path}
    ]')"
  producer_initial_asset_snapshot="$(canonical_consumed_asset_snapshot \
    "$PRODUCER_REPOSITORY" "$producer_release_id" \
    "$producer_release_assets" "$producer_consumed_urls")"
  producer_initial_asset_snapshot_digest="$(asset_snapshot_digest \
    "$producer_initial_asset_snapshot")"
  producer_revocation_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

  producer_ci_run_id="$(jq -er '.workflow_run_id' \
    "$INPUT_ROOT/producer-provenance.json")"
  producer_ci_run_attempt="$(jq -er '.workflow_attempt' \
    "$INPUT_ROOT/producer-provenance.json")"
  [[ "$producer_ci_run_id" =~ ^[1-9][0-9]*$ ]] \
    || fail_closed "producer provenance workflow run ID is not canonical"
  [[ "$producer_ci_run_attempt" =~ ^[1-9][0-9]*$ ]] \
    || fail_closed "producer provenance workflow attempt is not canonical"
  producer_ci_run="$(github_api \
    "repos/${PRODUCER_REPOSITORY}/actions/runs/${producer_ci_run_id}/attempts/${producer_ci_run_attempt}")"
  jq -e \
    --arg actor "lightning-it-release-automation[bot]" \
    --argjson run_id "$producer_ci_run_id" \
    --argjson run_attempt "$producer_ci_run_attempt" \
    --arg repository "$PRODUCER_REPOSITORY" \
    --arg workflow "$PRODUCER_WORKFLOW" \
    --arg workflow_name "$PRODUCER_WORKFLOW_NAME" \
    --arg sha "$producer_sha" '
      .id == $run_id
      and .run_attempt == $run_attempt
      and .repository.full_name == $repository
      and .head_repository.full_name == $repository
      and .name == $workflow_name
      and .path == $workflow
      and .event == "push"
      and .actor.login == $actor
      and .triggering_actor.login == $actor
      and .head_branch == "main"
      and .head_sha == $sha
      and .status == "completed"
      and .conclusion == "success"
    ' <<<"$producer_ci_run" >/dev/null \
    || fail_closed "producer provenance run is not the exact successful main CI attempt"
  producer_ci_jobs="$(
    github_api --paginate \
      "repos/${PRODUCER_REPOSITORY}/actions/runs/${producer_ci_run_id}/attempts/${producer_ci_run_attempt}/jobs?per_page=100" \
      | jq -sc '[.[].jobs[]]'
  )"
  producer_validation_gate="$(jq -ec \
    --arg name "$PRODUCER_VALIDATION_JOB" '
      [.[] | select(.name == $name)]
      | if length != 1 then
          error("producer CI must contain exactly one central validation job")
        elif .[0].status != "completed" or .[0].conclusion != "success" then
          error("producer central validation job did not complete successfully")
        else
          .[0]
        end
    ' <<<"$producer_ci_jobs")"
  producer_central_ci_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

  local consumer_pr consumer_pr_merge consumer_pr_merge_event consumer_pr_merge_sha
  local consumer_pr_ancestry consumer_merge consumer_base_sha
  local consumer_main_branch consumer_main_sha consumer_main_ancestry
  local consumer_main_rules consumer_main_rules_observations
  local consumer_main_rules_digest
  local consumer_release_prs consumer_release_pr
  local consumer_release_pr_merge_event consumer_release_pr_merge_sha
  local container_release container_release_by_tag
  local container_run container_evidence_run tag_commit
  local container_evidence_jobs container_publish_jobs
  local container_build_job container_publisher_job
  local container_evidence_run_attempt
  local container_workflow_blob container_workflow_blob_sha
  local container_workflow_entry container_workflow_path
  local consumer_identity_checked_at container_release_checked_at
  local container_revocation_checked_at container_cosign_checked_at
  local container_release_assets
  local container_consumed_urls container_asset_bindings
  local container_initial_asset_snapshot container_initial_asset_snapshot_digest
  local consumer_ai_check consumer_ai_job consumer_ai_run
  local consumer_ai_run_id consumer_ai_run_attempt
  consumer_pr="$(github_api \
    "repos/${CONSUMER_REPOSITORY}/pulls/${INPUT_CONSUMER_PR}")"
  jq -e \
    --argjson pull_request "$INPUT_CONSUMER_PR" \
    --arg head "$INPUT_CONSUMER_HEAD_SHA" \
    --arg repository "$CONSUMER_REPOSITORY" '
      .number == $pull_request
      and .state == "closed"
      and .merged_at != null
      and .base.ref == "main"
      and .head.repo.full_name == $repository
      and .head.sha == $head
    ' <<<"$consumer_pr" >/dev/null \
    || fail_closed "consumer pull-request identity is invalid"
  consumer_pr_merge_event="$(resolve_pull_request_merge_sha \
    "$CONSUMER_REPOSITORY" "$consumer_pr")" \
    || fail_closed "consumer pull-request merge event is invalid"
  consumer_pr_merge_sha="$(jq -er '.commitSha' <<<"$consumer_pr_merge_event")"

  consumer_ai_check="$(github_api --paginate \
    "repos/${CONSUMER_REPOSITORY}/commits/${INPUT_CONSUMER_HEAD_SHA}/check-runs?per_page=100" \
    | jq -sec \
      --arg head "$INPUT_CONSUMER_HEAD_SHA" \
      --arg job_name "$COPILOT_REVIEW_JOB_NAME" '
      [
        .[].check_runs[]
        | select(
            .name == $job_name
            and .head_sha == $head
            and .status == "completed"
            and .conclusion == "success"
            and .app.id == 15368
          )
        | {id, name, headSha: .head_sha, status, conclusion, appId: .app.id}
      ]
      | if length == 1 then .[0]
        else error("exactly one successful current-head AI check is required")
        end
    ')" || fail_closed "consumer current-head AI review check is invalid"
  consumer_ai_job="$(github_api \
    "repos/${CONSUMER_REPOSITORY}/actions/jobs/$(jq -er '.id' \
      <<<"$consumer_ai_check")")"
  jq -e \
    --argjson id "$(jq -er '.id' <<<"$consumer_ai_check")" \
    --arg head "$INPUT_CONSUMER_HEAD_SHA" \
    --arg job_name "$COPILOT_REVIEW_JOB_NAME" \
    --arg workflow_name "$COPILOT_REVIEW_WORKFLOW_NAME" \
    --arg check_url "https://api.github.com/repos/${CONSUMER_REPOSITORY}/check-runs/$(jq -er '.id' <<<"$consumer_ai_check")" '
      .id == $id
      and (.run_id | type == "number" and floor == . and . > 0)
      and (.run_attempt | type == "number" and floor == . and . > 0)
      and .workflow_name == $workflow_name
      and .head_sha == $head
      and .name == $job_name
      and .status == "completed"
      and .conclusion == "success"
      and .check_run_url == $check_url
    ' <<<"$consumer_ai_job" >/dev/null \
    || fail_closed "consumer current-head AI review job is invalid"
  consumer_ai_run_id="$(jq -er '.run_id' <<<"$consumer_ai_job")"
  consumer_ai_run_attempt="$(jq -er '.run_attempt' <<<"$consumer_ai_job")"
  consumer_ai_run="$(github_api \
    "repos/${CONSUMER_REPOSITORY}/actions/runs/${consumer_ai_run_id}/attempts/${consumer_ai_run_attempt}")"
  jq -e \
    --argjson run_id "$consumer_ai_run_id" \
    --argjson run_attempt "$consumer_ai_run_attempt" \
    --arg actor "lightning-it-release-automation[bot]" \
    --arg head "$INPUT_CONSUMER_HEAD_SHA" \
    --arg repository "$CONSUMER_REPOSITORY" \
    --arg workflow "$COPILOT_REVIEW_WORKFLOW" \
    --arg workflow_name "$COPILOT_REVIEW_WORKFLOW_NAME" '
      .id == $run_id
      and .run_attempt == $run_attempt
      and .name == $workflow_name
      and .path == $workflow
      and .event == "pull_request"
      and .head_sha == $head
      and .repository.full_name == $repository
      and .head_repository.full_name == $repository
      and .actor.login == $actor
      and .triggering_actor.login == $actor
      and .status == "completed"
      and .conclusion == "success"
    ' <<<"$consumer_ai_run" >/dev/null \
    || fail_closed "consumer current-head AI review workflow run is invalid"
  consumer_ai_check="$(jq -c \
    --argjson workflow_run_id "$consumer_ai_run_id" \
    --argjson workflow_run_attempt "$consumer_ai_run_attempt" \
    --arg workflow_name "$COPILOT_REVIEW_WORKFLOW_NAME" \
    --arg workflow_path "$COPILOT_REVIEW_WORKFLOW" \
    --arg workflow_actor "lightning-it-release-automation[bot]" '
      . + {
        workflowRunId: $workflow_run_id,
        workflowRunAttempt: $workflow_run_attempt,
        workflowName: $workflow_name,
        workflowPath: $workflow_path,
        workflowEvent: "pull_request",
        workflowActor: $workflow_actor,
        workflowTriggeringActor: $workflow_actor
      }
    ' <<<"$consumer_ai_check")"
  consumer_pr_ancestry="$(github_api \
    "repos/${CONSUMER_REPOSITORY}/compare/${consumer_pr_merge_sha}...${INPUT_CONSUMER_MERGE_SHA}")"
  jq -e \
    --arg pull_request_merge "$consumer_pr_merge_sha" \
    --arg release_source "$INPUT_CONSUMER_MERGE_SHA" '
      .base_commit.sha == $pull_request_merge
      and .merge_base_commit.sha == $pull_request_merge
      and .behind_by == 0
      and (
        if $pull_request_merge == $release_source then
          .status == "identical" and .ahead_by == 0
        else
          .status == "ahead" and .ahead_by > 0
        end
      )
    ' <<<"$consumer_pr_ancestry" >/dev/null \
    || fail_closed \
      "consumer pull-request merge is not an ancestor of the release source"
  consumer_main_branch="$(github_api \
    "repos/${CONSUMER_REPOSITORY}/branches/main")"
  jq -e '
    .name == "main"
    and .protected == true
    and (.commit.sha | type == "string")
    and (.commit.sha | test("^[0-9a-f]{40}$"))
  ' <<<"$consumer_main_branch" >/dev/null \
    || fail_closed "consumer main branch is not protected"
  consumer_main_sha="$(jq -er '.commit.sha' <<<"$consumer_main_branch")"
  # GitHub's "Get rules for a branch" endpoint requires only the App token's
  # implicit Metadata read permission.  Do not replace it with the similarly
  # named branch-protection endpoint, which requires Administration read.
  # https://docs.github.com/rest/repos/rules#get-rules-for-a-branch
  consumer_main_rules="$(
    github_api --paginate \
      "repos/${CONSUMER_REPOSITORY}/rules/branches/main?per_page=100" \
      | jq -sc '[.[][]]'
  )"
  jq -e '
    type == "array"
    and any(.[]; .type == "non_fast_forward")
    and any(.[]; .type == "deletion")
    and any(.[];
      .type == "pull_request"
      and .parameters.dismiss_stale_reviews_on_push == true
      and .parameters.required_review_thread_resolution == true
    )
    and any(.[];
      .type == "required_status_checks"
      and .parameters.strict_required_status_checks_policy == true
      and any(.parameters.required_status_checks[];
        .context == "Successful Copilot review"
      )
    )
  ' <<<"$consumer_main_rules" >/dev/null \
    || fail_closed "consumer main branch rules are not fail-closed"
  consumer_main_rules_observations="$(jq -ec '
    [
      .[]
      | select(.type == "non_fast_forward"
          or .type == "deletion"
          or .type == "pull_request"
          or .type == "required_status_checks")
      | {
          type,
          parameters: (.parameters // null),
          rulesetSourceType: .ruleset_source_type,
          rulesetSource: .ruleset_source,
          rulesetId: .ruleset_id
        }
    ] | sort_by(.type, .rulesetId)
  ' <<<"$consumer_main_rules")"
  consumer_main_rules_digest="sha256:$(
    jq -cS . <<<"$consumer_main_rules_observations" \
      | tr -d '\n' \
      | sha256sum \
      | awk '{print $1}'
  )"
  consumer_main_ancestry="$(github_api \
    "repos/${CONSUMER_REPOSITORY}/compare/${INPUT_CONSUMER_MERGE_SHA}...${consumer_main_sha}")"
  jq -e \
    --arg release_source "$INPUT_CONSUMER_MERGE_SHA" \
    --arg protected_main "$consumer_main_sha" '
      .base_commit.sha == $release_source
      and .merge_base_commit.sha == $release_source
      and .behind_by == 0
      and (
        if $release_source == $protected_main then
          .status == "identical" and .ahead_by == 0
        else
          .status == "ahead" and .ahead_by > 0
        end
      )
    ' <<<"$consumer_main_ancestry" >/dev/null \
    || fail_closed \
      "consumer release source is not on the protected main lineage"
  container_release="$(github_api \
    "repos/${CONSUMER_REPOSITORY}/releases/${INPUT_CONTAINER_RELEASE_ID}")"
  jq -e \
    --argjson id "$INPUT_CONTAINER_RELEASE_ID" \
    --arg actor "lightning-it-release-automation[bot]" \
    --arg sha "$INPUT_CONSUMER_MERGE_SHA" \
    --arg tag "$INPUT_CONTAINER_RELEASE_TAG" '
      .id == $id
      and .draft == false
      and .prerelease == false
      and .tag_name == $tag
      and .target_commitish == $sha
      and .immutable == true
      and .author.login == $actor
    ' <<<"$container_release" >/dev/null
  container_release_by_tag="$(github_api \
    "repos/${CONSUMER_REPOSITORY}/releases/tags/${INPUT_CONTAINER_RELEASE_TAG}")"
  jq -e \
    --argjson id "$INPUT_CONTAINER_RELEASE_ID" \
    --arg actor "lightning-it-release-automation[bot]" \
    --arg sha "$INPUT_CONSUMER_MERGE_SHA" \
    --arg tag "$INPUT_CONTAINER_RELEASE_TAG" '
      .id == $id
      and .draft == false
      and .prerelease == false
      and .tag_name == $tag
      and .target_commitish == $sha
      and .immutable == true
      and .author.login == $actor
    ' <<<"$container_release_by_tag" >/dev/null
  tag_commit="$(resolve_tag_commit \
    "$CONSUMER_REPOSITORY" "$INPUT_CONTAINER_RELEASE_TAG")"
  [ "$tag_commit" = "$INPUT_CONSUMER_MERGE_SHA" ] \
    || fail_closed "container release tag is not bound to consumer merge SHA"
  container_release_assets="$(list_release_assets \
    "$CONSUMER_REPOSITORY" "$INPUT_CONTAINER_RELEASE_ID")"

  local container_evidence_url container_bundle_url
  container_evidence_url="$(jq -er '[
    .[] | select(.name == "mlx90-container-evidence.json")
  ] | if length == 1 then .[0].browser_download_url else error(
    "exactly one mlx90-container-evidence.json asset is required"
  ) end' <<<"$container_release_assets")"
  container_bundle_url="$(jq -er '[
    .[] | select(.name == "mlx90-container-evidence.json.sigstore.json")
  ] | if length == 1 then .[0].browser_download_url else error(
    "exactly one mlx90 container evidence bundle is required"
  ) end' <<<"$container_release_assets")"
  download_release_asset "$container_evidence_url" \
    "$INPUT_ROOT/mlx90-container-evidence.json"
  download_release_asset "$container_bundle_url" \
    "$INPUT_ROOT/mlx90-container-evidence.json.sigstore.json"

  local container_revocation_count
  container_revocation_count="$(jq \
    --arg id "$evidence_id" '[
      .[].name
      | select(
          . == "mlx90-container-revocation.json"
          or . == "security-release-revocation.json"
          or . == ("security-release-revocation-" + $id + ".json")
        )
    ] | length' <<<"$container_release_assets")"
  [ "$container_revocation_count" -eq 0 ] \
    || fail_closed "container release contains revocation evidence"
  container_revocation_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

  local container_identity
  container_identity="https://github.com/${CONSUMER_REPOSITORY}/"
  container_identity+=".github/workflows/container-build-publish.yml@"
  container_identity+="refs/tags/${INPUT_CONTAINER_RELEASE_TAG}"
  cosign verify-blob \
    --bundle "$INPUT_ROOT/mlx90-container-evidence.json.sigstore.json" \
    --certificate-oidc-issuer "$ISSUER" \
    --certificate-identity "$container_identity" \
    --certificate-github-workflow-sha "$INPUT_CONSUMER_MERGE_SHA" \
    "$INPUT_ROOT/mlx90-container-evidence.json"
  container_cosign_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  consumer_merge="$(github_api \
    "repos/${CONSUMER_REPOSITORY}/commits/${INPUT_CONSUMER_MERGE_SHA}")"
  consumer_release_prs="$(github_api \
    "repos/${CONSUMER_REPOSITORY}/commits/${INPUT_CONSUMER_MERGE_SHA}/pulls")"
  consumer_release_pr="$(jq -ec \
    --arg actor "lightning-it-release-automation[bot]" \
    --arg repository "$CONSUMER_REPOSITORY" '
      [
        .[]
        | select(
            .state == "closed"
            and .merged_at != null
            and .base.ref == "main"
            and .head.repo.full_name == $repository
            and .user.login == $actor
          )
      ]
      | if length == 1 then .[0]
        else error("exactly one release promotion pull request is required")
        end
    ' <<<"$consumer_release_prs")" \
    || fail_closed "consumer release source is not an exact main promotion"
  consumer_release_pr_merge_event="$(resolve_pull_request_merge_sha \
    "$CONSUMER_REPOSITORY" "$consumer_release_pr")" \
    || fail_closed "consumer release promotion merge event is invalid"
  consumer_release_pr_merge_sha="$(jq -er \
    '.commitSha' <<<"$consumer_release_pr_merge_event")"
  [ "$consumer_release_pr_merge_sha" = "$INPUT_CONSUMER_MERGE_SHA" ] \
    || fail_closed "consumer release source is not an exact main promotion"
  consumer_pr_merge="$(github_api \
    "repos/${CONSUMER_REPOSITORY}/commits/${consumer_pr_merge_sha}")"
  consumer_base_sha="$(jq -er '.consumer.baseSha' \
    "$INPUT_ROOT/mlx90-container-evidence.json")"
  jq -e \
    --arg base "$consumer_base_sha" \
    --arg head "$INPUT_CONSUMER_HEAD_SHA" \
    --arg merge "$consumer_pr_merge_sha" '
      .sha == $merge
      and (.parents | length) == 2
      and .parents[0].sha == $base
      and .parents[1].sha == $head
    ' <<<"$consumer_pr_merge" >/dev/null \
    || fail_closed "consumer pull-request merge topology is invalid"
  [ "$(jq -er '.base.sha' <<<"$consumer_pr")" = "$consumer_base_sha" ] \
    || fail_closed "consumer pull-request base SHA is not evidence-bound"
  jq -e \
    --arg merge "$INPUT_CONSUMER_MERGE_SHA" '
      .sha == $merge
      and (.parents | length) == 2
      and all(.parents[]; .sha | test("^[0-9a-f]{40}$"))
    ' <<<"$consumer_merge" >/dev/null \
    || fail_closed "consumer release source merge topology is invalid"
  jq -e \
    --arg base "$(jq -er '.base.sha' <<<"$consumer_release_pr")" \
    --arg head "$(jq -er '.head.sha' <<<"$consumer_release_pr")" \
    --arg merge "$INPUT_CONSUMER_MERGE_SHA" '
      .sha == $merge
      and (.parents | length) == 2
      and .parents[0].sha == $base
      and .parents[1].sha == $head
    ' <<<"$consumer_merge" >/dev/null \
    || fail_closed "consumer release promotion merge topology is invalid"
  container_workflow_path=".github/workflows/container-build-publish.yml"
  container_workflow_entry="$(github_api \
    "repos/${CONSUMER_REPOSITORY}/git/trees/${INPUT_CONSUMER_MERGE_SHA}?recursive=1" \
    | jq -ec --arg path "$container_workflow_path" '
        if .truncated != false then
          error("container source tree response is truncated")
        else
          [.tree[] | select(.path == $path)]
          | if length != 1
              or .[0].mode != "100644"
              or .[0].type != "blob"
              or (.[0].sha | test("^[0-9a-f]{40}$")) != true then
              error("container workflow must be one regular Git blob")
            else
              .[0]
            end
        end
      ')"
  container_workflow_blob_sha="$(jq -er '.sha' \
    <<<"$container_workflow_entry")"
  container_workflow_blob="$(github_api \
    "repos/${CONSUMER_REPOSITORY}/git/blobs/${container_workflow_blob_sha}")"
  jq -e '
    .encoding == "base64"
    and (.size | type == "number" and floor == . and . > 0 and . <= 1048576)
    and (.content | type == "string" and length > 0)
  ' <<<"$container_workflow_blob" >/dev/null \
    || fail_closed "container workflow blob response is invalid"
  jq -er '.content' <<<"$container_workflow_blob" \
    | base64 --decode >"$INPUT_ROOT/container-build-publish.yml"
  [ "$(wc -c <"$INPUT_ROOT/container-build-publish.yml" \
      | tr -d '[:space:]')" = "$(jq -er '.size' \
      <<<"$container_workflow_blob")" ] \
    || fail_closed "container workflow blob size mismatch"
  verify_container_workflow_dag "$INPUT_ROOT/container-build-publish.yml"
  container_evidence_run_attempt="$(jq -er '.release.workflowRunAttempt' \
    "$INPUT_ROOT/mlx90-container-evidence.json")"
  [[ "$container_evidence_run_attempt" =~ ^[1-9][0-9]*$ ]] \
    || fail_closed "container evidence workflow attempt is not canonical"
  [ "$container_evidence_run_attempt" -le \
      "$INPUT_CONTAINER_PUBLISH_RUN_ATTEMPT" ] \
    || fail_closed "container evidence attempt is later than publisher attempt"

  container_evidence_run="$(github_api \
    "repos/${CONSUMER_REPOSITORY}/actions/runs/${INPUT_CONTAINER_RELEASE_RUN_ID}/attempts/${container_evidence_run_attempt}")"
  verify_container_run_identity "$container_evidence_run_attempt" false \
    <<<"$container_evidence_run" \
    || fail_closed "container evidence run attempt identity is invalid"
  container_evidence_jobs="$(
    github_api --paginate \
      "repos/${CONSUMER_REPOSITORY}/actions/runs/${INPUT_CONTAINER_RELEASE_RUN_ID}/attempts/${container_evidence_run_attempt}/jobs?per_page=100" \
      | jq -sc '[.[].jobs[]]'
  )"
  container_build_job="$(select_successful_job \
    "Build & push image to Quay.io" \
    "container evidence attempt must contain exactly one build job" \
    "container evidence build job did not complete successfully" \
    <<<"$container_evidence_jobs")"

  container_run="$(github_api \
    "repos/${CONSUMER_REPOSITORY}/actions/runs/${INPUT_CONTAINER_RELEASE_RUN_ID}/attempts/${INPUT_CONTAINER_PUBLISH_RUN_ATTEMPT}")"
  verify_container_run_identity "$INPUT_CONTAINER_PUBLISH_RUN_ATTEMPT" true \
    <<<"$container_run" \
    || fail_closed "container publisher run attempt is not exact and successful"
  container_publish_jobs="$(
    github_api --paginate \
      "repos/${CONSUMER_REPOSITORY}/actions/runs/${INPUT_CONTAINER_RELEASE_RUN_ID}/attempts/${INPUT_CONTAINER_PUBLISH_RUN_ATTEMPT}/jobs?per_page=100" \
      | jq -sc '[.[].jobs[]]'
  )"
  container_publisher_job="$(select_successful_job \
    "Attach signed release evidence" \
    "container publisher attempt must contain exactly one publisher job" \
    "container publisher job did not complete successfully" \
    <<<"$container_publish_jobs")"
  container_release_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  consumer_identity_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

  EVIDENCE_ARGS=(
    --producer-evidence "$producer_evidence"
    --container-evidence "$INPUT_ROOT/mlx90-container-evidence.json"
    --profiles "$PROFILES"
  )
  python3 "$FINALIZER" preflight \
    "${IDENTITY_ARGS[@]}" \
    "${EVIDENCE_ARGS[@]}"

  container_consumed_urls="$(jq -cn \
    --arg evidence "$container_evidence_url" \
    --arg bundle "$container_bundle_url" \
    --argjson references "$(jq -ec '[
      .variants
      | to_entries[]
      | .value.signature.url, .value.sbom.url, .value.provenance.url
    ] | sort | unique' "$INPUT_ROOT/mlx90-container-evidence.json")" \
    '([$evidence, $bundle] + $references) | sort | unique')"
  [ "$(jq 'length' <<<"$container_consumed_urls")" -eq 9 ] \
    || fail_closed "container consumed asset URL set is not exact"
  container_asset_bindings="$(jq -cn \
    --arg evidence_url "$container_evidence_url" \
    --arg evidence_path "$INPUT_ROOT/mlx90-container-evidence.json" \
    --arg bundle_url "$container_bundle_url" \
    --arg bundle_path "$INPUT_ROOT/mlx90-container-evidence.json.sigstore.json" \
    --arg input_root "$INPUT_ROOT" \
    --argjson variants "$(jq -ec '.variants' \
      "$INPUT_ROOT/mlx90-container-evidence.json")" '[
      {url: $evidence_url, path: $evidence_path},
      {url: $bundle_url, path: $bundle_path},
      ($variants | to_entries[] as $variant |
        {url: $variant.value.signature.url,
          path: ($input_root + "/" + $variant.key + "-signature-evidence.json")},
        {url: $variant.value.sbom.url,
          path: ($input_root + "/" + $variant.key + "-sbom-evidence.json")},
        {url: $variant.value.provenance.url,
          path: ($input_root + "/" + $variant.key + "-provenance-evidence.json")}
      )
    ]')"
  container_initial_asset_snapshot="$(canonical_consumed_asset_snapshot \
    "$CONSUMER_REPOSITORY" "$INPUT_CONTAINER_RELEASE_ID" \
    "$container_release_assets" "$container_consumed_urls")"
  container_initial_asset_snapshot_digest="$(asset_snapshot_digest \
    "$container_initial_asset_snapshot")"
  container_revocation_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

  local producer_approval_history review_gate_approval_history
  local container_approval_history
  local finalizer_approval_history zero_touch_checked_at
  producer_approval_history="$(workflow_approval_history \
    "$PRODUCER_REPOSITORY" "$producer_ci_run_id")"
  review_gate_approval_history="$(workflow_approval_history \
    "$CONSUMER_REPOSITORY" "$consumer_ai_run_id")"
  container_approval_history="$(workflow_approval_history \
    "$CONSUMER_REPOSITORY" "$INPUT_CONTAINER_RELEASE_RUN_ID")"
  finalizer_approval_history="$(workflow_approval_history \
    "$FINALIZER_REPOSITORY" "$GITHUB_RUN_ID")"
  zero_touch_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

  local producer_evidence_digest producer_bundle_digest collection_bundle_digest
  local container_bundle_digest producer_release_url
  producer_evidence_digest="sha256:$(sha256sum "$producer_evidence" \
    | awk '{print $1}')"
  producer_bundle_digest="sha256:$(sha256sum "$producer_bundle" \
    | awk '{print $1}')"
  collection_bundle_digest="sha256:$(sha256sum \
    "$INPUT_ROOT/producer-signature.json" | awk '{print $1}')"
  container_bundle_digest="sha256:$(sha256sum \
    "$INPUT_ROOT/mlx90-container-evidence.json.sigstore.json" | awk '{print $1}')"
  producer_release_url="$(jq -er '.html_url' <<<"$producer_release")"

  write_receipt producer-evidence "$producer_evidence_checked_at" "$(jq -cn \
    --arg evidence_id "$evidence_id" \
    --arg evidence_url "$INPUT_PRODUCER_EVIDENCE_URL" \
    --arg evidence_digest "$producer_evidence_digest" \
    --arg source_sha "$producer_sha" '{
      evidenceId: $evidence_id,
      evidenceUrl: $evidence_url,
      evidenceDigest: $evidence_digest,
      sourceSha: $source_sha
    }')"
  write_receipt producer-identity "$producer_identity_checked_at" "$(jq -cn \
    --argjson release_id "$producer_release_id" \
    --arg release_tag "$(jq -er '.tag_name' <<<"$producer_release")" \
    --arg release_url "$producer_release_url" \
    --arg tag_commit "$producer_tag_commit" \
    --argjson draft "$(jq -er '.draft' <<<"$producer_release")" \
    --argjson prerelease "$(jq -er '.prerelease' <<<"$producer_release")" '{
      releaseId: $release_id,
      releaseTag: $release_tag,
      releaseUrl: $release_url,
      tagCommit: $tag_commit,
      draft: $draft,
      prerelease: $prerelease
    }')"
  write_receipt producer-revocation-initial \
    "$producer_revocation_checked_at" "$(jq -cn \
    --argjson release_id "$producer_release_id" \
    --arg evidence_id "$evidence_id" \
    --argjson count "$revocation_count" \
    --argjson asset_snapshot "$producer_initial_asset_snapshot" \
    --arg asset_snapshot_digest "$producer_initial_asset_snapshot_digest" '{
      releaseId: $release_id,
      evidenceId: $evidence_id,
      revocationAssetCount: $count,
      assetSnapshot: $asset_snapshot,
      assetSnapshotDigest: $asset_snapshot_digest
    }')"
  write_receipt producer-cosign "$producer_cosign_checked_at" "$(jq -cn \
    --arg evidence_bundle "$producer_bundle_digest" \
    --arg collection_bundle "$collection_bundle_digest" \
    --arg evidence_identity "$producer_identity" \
    --arg collection_identity "$producer_candidate_identity" \
    --arg source_sha "$producer_sha" '{
      evidenceBundleDigest: $evidence_bundle,
      collectionBundleDigest: $collection_bundle,
      evidenceIdentity: $evidence_identity,
      collectionIdentity: $collection_identity,
      sourceSha: $source_sha
    }')"
  write_receipt producer-materials "$producer_materials_checked_at" "$(jq -cn \
    --arg collection_digest "sha256:$(sha256sum \
      "$INPUT_ROOT/producer-collection.tar.gz" | awk '{print $1}')" \
    --arg sbom_digest "sha256:$(sha256sum \
      "$INPUT_ROOT/producer-sbom.json" | awk '{print $1}')" \
    --arg provenance_digest "sha256:$(sha256sum \
      "$INPUT_ROOT/producer-provenance.json" | awk '{print $1}')" \
    --arg version "$producer_version" \
    --argjson workflow_run_id "$producer_ci_run_id" \
    --argjson workflow_run_attempt "$producer_ci_run_attempt" '{
      collectionDigest: $collection_digest,
      sbomDigest: $sbom_digest,
      provenanceDigest: $provenance_digest,
      version: $version,
      workflowRunId: $workflow_run_id,
      workflowRunAttempt: $workflow_run_attempt
    }')"
  write_receipt producer-central-ci "$producer_central_ci_checked_at" "$(jq -cn \
    --arg provenance_digest "sha256:$(sha256sum \
      "$INPUT_ROOT/producer-provenance.json" | awk '{print $1}')" \
    --arg source_sha "$producer_sha" \
    --argjson workflow_run_id "$producer_ci_run_id" \
    --argjson workflow_run_attempt "$producer_ci_run_attempt" \
    --arg workflow_run_url "$(jq -er '.html_url' <<<"$producer_ci_run")" \
    --arg workflow_name "$(jq -er '.name' <<<"$producer_ci_run")" \
    --arg workflow_path "$(jq -er '.path' <<<"$producer_ci_run")" \
    --arg run_repository "$(jq -er '.repository.full_name' \
      <<<"$producer_ci_run")" \
    --arg head_repository "$(jq -er '.head_repository.full_name' \
      <<<"$producer_ci_run")" \
    --arg event "$(jq -er '.event' <<<"$producer_ci_run")" \
    --arg head_branch "$(jq -er '.head_branch' <<<"$producer_ci_run")" \
    --arg head_sha "$(jq -er '.head_sha' <<<"$producer_ci_run")" \
    --arg status "$(jq -er '.status' <<<"$producer_ci_run")" \
    --arg conclusion "$(jq -er '.conclusion' <<<"$producer_ci_run")" \
    --argjson gate_job_id "$(jq -er '.id' <<<"$producer_validation_gate")" \
    --arg gate_job_name "$(jq -er '.name' <<<"$producer_validation_gate")" \
    --arg gate_job_status "$(jq -er '.status' <<<"$producer_validation_gate")" \
    --arg gate_job_conclusion "$(jq -er '.conclusion' \
      <<<"$producer_validation_gate")" '{
      provenanceDigest: $provenance_digest,
      sourceSha: $source_sha,
      workflowRunId: $workflow_run_id,
      workflowRunAttempt: $workflow_run_attempt,
      workflowRunUrl: $workflow_run_url,
      workflowName: $workflow_name,
      workflowPath: $workflow_path,
      runRepository: $run_repository,
      headRepository: $head_repository,
      event: $event,
      headBranch: $head_branch,
      headSha: $head_sha,
      status: $status,
      conclusion: $conclusion,
      gateJobId: $gate_job_id,
      gateJobName: $gate_job_name,
      gateJobStatus: $gate_job_status,
      gateJobConclusion: $gate_job_conclusion
    }')"
  write_receipt consumer-identity "$consumer_identity_checked_at" "$(jq -cn \
    --argjson pull_request "$(jq -er '.number' <<<"$consumer_pr")" \
    --arg state "$(jq -er '.state' <<<"$consumer_pr")" \
    --arg merged_at "$(jq -er '.merged_at' <<<"$consumer_pr")" \
    --arg base_ref "$(jq -er '.base.ref' <<<"$consumer_pr")" \
    --arg base_sha "$consumer_base_sha" \
    --arg head_repository "$(jq -er '.head.repo.full_name' <<<"$consumer_pr")" \
    --arg head_sha "$(jq -er '.head.sha' <<<"$consumer_pr")" \
    --arg pull_request_merge_sha "$consumer_pr_merge_sha" \
    --argjson pull_request_merge_parents "$(jq -ec '[.parents[].sha]' \
      <<<"$consumer_pr_merge")" \
    --arg merge_sha "$INPUT_CONSUMER_MERGE_SHA" \
    --argjson merge_parents "$(jq -ec '[.parents[].sha]' \
      <<<"$consumer_merge")" \
    --arg ancestry_status "$(jq -er '.status' \
      <<<"$consumer_pr_ancestry")" \
    --argjson ancestry_ahead_by "$(jq -er '.ahead_by' \
      <<<"$consumer_pr_ancestry")" \
    --argjson ancestry_behind_by "$(jq -er '.behind_by' \
      <<<"$consumer_pr_ancestry")" \
    --arg ancestry_merge_base_sha "$(jq -er '.merge_base_commit.sha' \
      <<<"$consumer_pr_ancestry")" \
    --arg protected_main_sha "$consumer_main_sha" \
    --argjson protected_main_protected "$(jq -er '.protected' \
      <<<"$consumer_main_branch")" \
    --arg protected_main_ancestry_status "$(jq -er '.status' \
      <<<"$consumer_main_ancestry")" \
    --argjson protected_main_ahead_by "$(jq -er '.ahead_by' \
      <<<"$consumer_main_ancestry")" \
    --argjson protected_main_behind_by "$(jq -er '.behind_by' \
      <<<"$consumer_main_ancestry")" \
    --arg protected_main_merge_base_sha "$(jq -er '.merge_base_commit.sha' \
      <<<"$consumer_main_ancestry")" \
    --argjson protected_main_rules "$consumer_main_rules_observations" \
    --arg protected_main_rules_digest "$consumer_main_rules_digest" \
    --argjson release_promotion_pull_request "$(jq -er '.number' \
      <<<"$consumer_release_pr")" \
    --arg release_promotion_merged_at "$(jq -er '.merged_at' \
      <<<"$consumer_release_pr")" \
    --arg release_promotion_base_sha "$(jq -er '.base.sha' \
      <<<"$consumer_release_pr")" \
    --arg release_promotion_head_repository "$(jq -er '.head.repo.full_name' \
      <<<"$consumer_release_pr")" \
    --arg release_promotion_head_sha "$(jq -er '.head.sha' \
      <<<"$consumer_release_pr")" \
    --arg release_promotion_author "$(jq -er '.user.login' \
      <<<"$consumer_release_pr")" \
    --arg release_promotion_merge_sha "$consumer_release_pr_merge_sha" \
    --argjson release_promotion_merge_parents "$(jq -ec '[.parents[].sha]' \
      <<<"$consumer_merge")" '{
      pullRequest: $pull_request,
      state: $state,
      mergedAt: $merged_at,
      baseRef: $base_ref,
      baseSha: $base_sha,
      headRepository: $head_repository,
      headSha: $head_sha,
      pullRequestMergeSha: $pull_request_merge_sha,
      pullRequestMergeParents: $pull_request_merge_parents,
      mergeSha: $merge_sha,
      mergeParents: $merge_parents,
      ancestryStatus: $ancestry_status,
      ancestryAheadBy: $ancestry_ahead_by,
      ancestryBehindBy: $ancestry_behind_by,
      ancestryMergeBaseSha: $ancestry_merge_base_sha,
      protectedMainSha: $protected_main_sha,
      protectedMainProtected: $protected_main_protected,
      protectedMainAncestryStatus: $protected_main_ancestry_status,
      protectedMainAheadBy: $protected_main_ahead_by,
      protectedMainBehindBy: $protected_main_behind_by,
      protectedMainMergeBaseSha: $protected_main_merge_base_sha,
      protectedMainRules: $protected_main_rules,
      protectedMainRulesDigest: $protected_main_rules_digest,
      releasePromotionPullRequest: $release_promotion_pull_request,
      releasePromotionMergedAt: $release_promotion_merged_at,
      releasePromotionBaseSha: $release_promotion_base_sha,
      releasePromotionHeadRepository: $release_promotion_head_repository,
      releasePromotionHeadSha: $release_promotion_head_sha,
      releasePromotionAuthor: $release_promotion_author,
      releasePromotionMergeSha: $release_promotion_merge_sha,
      releasePromotionMergeParents: $release_promotion_merge_parents
    }')"
  write_receipt container-release "$container_release_checked_at" "$(jq -cn \
    --argjson release_id "$(jq -er '.id' <<<"$container_release")" \
    --arg release_tag "$(jq -er '.tag_name' <<<"$container_release")" \
    --arg release_url "$(jq -er '.html_url' <<<"$container_release")" \
    --argjson draft "$(jq -er '.draft' <<<"$container_release")" \
    --argjson prerelease "$(jq -er '.prerelease' <<<"$container_release")" \
    --arg source_sha "$tag_commit" \
    --argjson workflow_run_id "$(jq -er '.id' <<<"$container_evidence_run")" \
    --argjson workflow_run_attempt "$container_evidence_run_attempt" \
    --argjson publish_run_attempt "$INPUT_CONTAINER_PUBLISH_RUN_ATTEMPT" \
    --arg run_repository "$(jq -er '.repository.full_name' <<<"$container_run")" \
    --arg head_repository "$(jq -er '.head_repository.full_name' \
      <<<"$container_run")" \
    --arg event "$(jq -er '.event' <<<"$container_run")" \
    --arg workflow_path "$(jq -er '.path' <<<"$container_run")" \
    --arg workflow_blob_sha "$container_workflow_blob_sha" \
    --arg head_sha "$(jq -er '.head_sha' <<<"$container_run")" \
    --arg head_branch "$(jq -er '.head_branch' <<<"$container_run")" \
    --arg actor "$(jq -er '.actor.login' <<<"$container_run")" \
    --arg evidence_triggering_actor "$(jq -er \
      '.triggering_actor.login' <<<"$container_evidence_run")" \
    --arg publish_triggering_actor "$(jq -er \
      '.triggering_actor.login' <<<"$container_run")" \
    --argjson immutable "$(jq -er '.immutable' <<<"$container_release")" \
    --arg target_commitish "$(jq -er '.target_commitish' \
      <<<"$container_release")" \
    --arg author "$(jq -er '.author.login' <<<"$container_release")" \
    --arg evidence_run_status "$(jq -er '.status' \
      <<<"$container_evidence_run")" \
    --arg evidence_run_conclusion "$(jq -er '.conclusion' \
      <<<"$container_evidence_run")" \
    --arg status "$(jq -er '.status' <<<"$container_run")" \
    --arg conclusion "$(jq -er '.conclusion' <<<"$container_run")" \
    --argjson build_job_id "$(jq -er '.id' <<<"$container_build_job")" \
    --arg build_job_name "$(jq -er '.name' <<<"$container_build_job")" \
    --arg build_job_status "$(jq -er '.status' <<<"$container_build_job")" \
    --arg build_job_conclusion "$(jq -er '.conclusion' \
      <<<"$container_build_job")" \
    --argjson publisher_job_id "$(jq -er '.id' \
      <<<"$container_publisher_job")" \
    --arg publisher_job_name "$(jq -er '.name' \
      <<<"$container_publisher_job")" \
    --arg publisher_job_status "$(jq -er '.status' \
      <<<"$container_publisher_job")" \
    --arg publisher_job_conclusion "$(jq -er '.conclusion' \
      <<<"$container_publisher_job")" '{
      releaseId: $release_id,
      releaseTag: $release_tag,
      releaseUrl: $release_url,
      draft: $draft,
      prerelease: $prerelease,
      sourceSha: $source_sha,
      workflowRunId: $workflow_run_id,
      workflowRunAttempt: $workflow_run_attempt,
      publishRunAttempt: $publish_run_attempt,
      runRepository: $run_repository,
      headRepository: $head_repository,
      event: $event,
      workflowPath: $workflow_path,
      workflowBlobSha: $workflow_blob_sha,
      publisherNeeds: ["build", "upload-trivy-sarif"],
      headSha: $head_sha,
      headBranch: $head_branch,
      actor: $actor,
      evidenceTriggeringActor: $evidence_triggering_actor,
      publishTriggeringActor: $publish_triggering_actor,
      immutable: $immutable,
      targetCommitish: $target_commitish,
      author: $author,
      evidenceRunStatus: $evidence_run_status,
      evidenceRunConclusion: $evidence_run_conclusion,
      status: $status,
      conclusion: $conclusion,
      buildJobId: $build_job_id,
      buildJobName: $build_job_name,
      buildJobStatus: $build_job_status,
      buildJobConclusion: $build_job_conclusion,
      publisherJobId: $publisher_job_id,
      publisherJobName: $publisher_job_name,
      publisherJobStatus: $publisher_job_status,
      publisherJobConclusion: $publisher_job_conclusion
    }')"
  write_receipt container-revocation-initial \
    "$container_revocation_checked_at" "$(jq -cn \
    --argjson release_id "$INPUT_CONTAINER_RELEASE_ID" \
    --arg evidence_id "$evidence_id" \
    --argjson count "$container_revocation_count" \
    --argjson asset_snapshot "$container_initial_asset_snapshot" \
    --arg asset_snapshot_digest "$container_initial_asset_snapshot_digest" '{
      releaseId: $release_id,
      evidenceId: $evidence_id,
      revocationAssetCount: $count,
      assetSnapshot: $asset_snapshot,
      assetSnapshotDigest: $asset_snapshot_digest
    }')"
  write_receipt container-cosign "$container_cosign_checked_at" "$(jq -cn \
    --arg bundle_digest "$container_bundle_digest" \
    --arg identity "$container_identity" \
    --arg source_sha "$INPUT_CONSUMER_MERGE_SHA" '{
      bundleDigest: $bundle_digest,
      identity: $identity,
      sourceSha: $source_sha
    }')"
  write_receipt zero-touch "$zero_touch_checked_at" "$(jq -cn \
    --arg app_slug "$APP_SLUG" \
    --argjson app_installation_id "$APP_INSTALLATION_ID" \
    --arg finalizer_repository "$FINALIZER_REPOSITORY" \
    --argjson finalizer_run_id "$GITHUB_RUN_ID" \
    --arg finalizer_actor "$GITHUB_ACTOR" \
    --arg finalizer_triggering_actor "$GITHUB_TRIGGERING_ACTOR" \
    --arg consumer_repository "$CONSUMER_REPOSITORY" \
    --argjson consumer_pull_request "$INPUT_CONSUMER_PR" \
    --arg consumer_merge_actor "$(jq -er '.actor' \
      <<<"$consumer_pr_merge_event")" \
    --arg consumer_merge_sha "$consumer_pr_merge_sha" \
    --argjson promotion_pull_request "$(jq -er '.number' \
      <<<"$consumer_release_pr")" \
    --arg promotion_merge_actor "$(jq -er '.actor' \
      <<<"$consumer_release_pr_merge_event")" \
    --arg promotion_merge_sha "$consumer_release_pr_merge_sha" \
    --argjson current_head_review_gate "$consumer_ai_check" \
    --argjson producer_run_id "$producer_ci_run_id" \
    --argjson producer_reviews "$producer_approval_history" \
    --argjson review_gate_run_id "$consumer_ai_run_id" \
    --argjson review_gate_reviews "$review_gate_approval_history" \
    --argjson container_run_id "$INPUT_CONTAINER_RELEASE_RUN_ID" \
    --argjson container_reviews "$container_approval_history" \
    --argjson finalizer_reviews "$finalizer_approval_history" '{
      humanActions: 0,
      app: {
        slug: $app_slug,
        installationId: $app_installation_id
      },
      finalizer: {
        repository: $finalizer_repository,
        runId: $finalizer_run_id,
        actor: $finalizer_actor,
        triggeringActor: $finalizer_triggering_actor
      },
      mergeEvents: [
        {
          purpose: "consumer-change",
          repository: $consumer_repository,
          pullRequest: $consumer_pull_request,
          actor: $consumer_merge_actor,
          commitSha: $consumer_merge_sha
        },
        {
          purpose: "main-promotion",
          repository: $consumer_repository,
          pullRequest: $promotion_pull_request,
          actor: $promotion_merge_actor,
          commitSha: $promotion_merge_sha
        }
      ],
      currentHeadReviewGate: $current_head_review_gate,
      workflowApprovalHistory: [
        {
          repository: "lightning-it/ansible-collection-supplementary",
          runId: $producer_run_id,
          reviews: $producer_reviews
        },
        {
          repository: "lightning-it/container-ee-wunder-ansible-ubi9",
          runId: $review_gate_run_id,
          reviews: $review_gate_reviews
        },
        {
          repository: "lightning-it/container-ee-wunder-ansible-ubi9",
          runId: $container_run_id,
          reviews: $container_reviews
        },
        {
          repository: "lightning-it/modulix-validation",
          runId: $finalizer_run_id,
          reviews: $finalizer_reviews
        }
      ]
    }')"

  local collection version profile profile_json
  collection="$(jq -er '.artifact.collection' "$producer_evidence")"
  version="$(jq -er '.artifact.version' "$producer_evidence")"
  profile="$(jq -er '.acceptance.profile' "$producer_evidence")"
  profile_json="$(python3 "$FINALIZER" profile-command \
    --profiles "$PROFILES" \
    --profile "$profile")"
  mapfile -t profile_command < <(jq -er '.[]' <<<"$profile_json")
  [ "${#profile_command[@]}" -gt 0 ] \
    || fail_closed "fixed acceptance profile command is empty"

  local variant image manifest image_ref index_path installed_path resolved
  local attestation reference_file attestation_root attestation_digest
  local platform platform_digest safe_platform attestation_manifest_path
  local predicate_name predicate_type layer_descriptor layer_digest layer_size
  local statement_path
  local candidate_run_attempt candidate_tag live_tag_digest
  local receipt_checked_at live_signature_digest tag_digests platform_digests
  local buildkit_platforms repo_digests installed_state installed_version
  local installed_observation_path
  candidate_run_attempt="$(jq -er '
    .release.workflowRunAttempt
    | select(type == "number" and floor == . and . > 0)
  ' "$INPUT_ROOT/mlx90-container-evidence.json")"
  candidate_tag="mlx90-candidate-${INPUT_CONSUMER_MERGE_SHA}-${INPUT_CONTAINER_RELEASE_RUN_ID}-${candidate_run_attempt}"
  for variant in public certified bootstrap; do
    image="$(jq -er --arg variant "$variant" \
      '.variants[$variant].image' \
      "$INPUT_ROOT/mlx90-container-evidence.json")"
    manifest="$(jq -er --arg variant "$variant" \
      '.variants[$variant].manifestDigest' \
      "$INPUT_ROOT/mlx90-container-evidence.json")"
    image_ref="${image}@${manifest}"
    index_path="$INPUT_ROOT/${variant}-index.json"
    docker buildx imagetools inspect --raw "$image_ref" >"$index_path"
    [ "sha256:$(sha256sum "$index_path" | awk '{print $1}')" = "$manifest" ] \
      || fail_closed "raw ${variant} OCI index digest differs from evidence"
    python3 "$FINALIZER" verify-index \
      --container-evidence "$INPUT_ROOT/mlx90-container-evidence.json" \
      --variant "$variant" \
      --index "$index_path"
    receipt_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    platform_digests="$(jq -ec '[
      .manifests[]
      | select(
          (.platform.os == "linux")
          and (.platform.architecture == "amd64"
            or .platform.architecture == "arm64")
        )
      | {
          key: (.platform.os + "/" + .platform.architecture),
          value: .digest
        }
    ] | from_entries' "$index_path")"
    write_receipt "${variant}-oci-index" "$receipt_checked_at" "$(jq -cn \
      --arg variant "$variant" \
      --arg image "$image" \
      --arg manifest "$manifest" \
      --argjson platforms "$platform_digests" '{
        variant: $variant,
        image: $image,
        manifestDigest: $manifest,
        indexDigest: $manifest,
        platformDigests: $platforms
      }')"

    cosign verify \
      --certificate-identity "$container_identity" \
      --certificate-oidc-issuer "$ISSUER" \
      --certificate-github-workflow-sha "$INPUT_CONSUMER_MERGE_SHA" \
      "$image_ref" >"$INPUT_ROOT/${variant}-signature-live.json"
    receipt_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    live_signature_digest="sha256:$(sha256sum \
      "$INPUT_ROOT/${variant}-signature-live.json" | awk '{print $1}')"
    write_receipt "${variant}-cosign" "$receipt_checked_at" "$(jq -cn \
      --arg variant "$variant" \
      --arg image "$image" \
      --arg manifest "$manifest" \
      --arg signature_digest "$live_signature_digest" \
      --arg identity "$container_identity" \
      --arg source_sha "$INPUT_CONSUMER_MERGE_SHA" '{
        variant: $variant,
        image: $image,
        manifestDigest: $manifest,
        liveSignatureDigest: $signature_digest,
        identity: $identity,
        sourceSha: $source_sha
      }')"

    live_tag_digest="$(docker buildx imagetools inspect \
      "${image}:${candidate_tag}" --format '{{ .Manifest.Digest }}')"
    [ "$live_tag_digest" = "$manifest" ] \
      || fail_closed \
        "${variant} immutable candidate tag differs from accepted index"
    tag_digests="$(jq -cn \
      --arg tag "$candidate_tag" \
      --arg digest "$live_tag_digest" \
      '{($tag): $digest}')"
    receipt_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    write_receipt "${variant}-immutable-tags" "$receipt_checked_at" "$(jq -cn \
      --arg variant "$variant" \
      --arg image "$image" \
      --arg manifest "$manifest" \
      --argjson tags "$tag_digests" '{
        variant: $variant,
        image: $image,
        manifestDigest: $manifest,
        tagDigests: $tags
      }')"

    attestation_root="$INPUT_ROOT/${variant}-buildkit-attestations"
    install -d -m 0700 "$attestation_root"
    for platform in linux/amd64 linux/arm64; do
      safe_platform="${platform//\//-}"
      platform_digest="$(jq -er \
        --arg variant "$variant" \
        --arg platform "$platform" \
        '.variants[$variant].platformDigests[$platform]' \
        "$INPUT_ROOT/mlx90-container-evidence.json")"
      attestation_digest="$(jq -er \
        --arg target "$platform_digest" '
          [.manifests[] | select(
            .platform.os == "unknown"
            and .platform.architecture == "unknown"
            and .annotations["vnd.docker.reference.type"]
              == "attestation-manifest"
            and .annotations["vnd.docker.reference.digest"] == $target
          )]
          | if length == 1 then .[0].digest
            else error("exact attestation manifest is not unique")
            end
        ' "$index_path")"
      attestation_manifest_path="$attestation_root/${safe_platform}-manifest.json"
      docker buildx imagetools inspect --raw \
        "${image}@${attestation_digest}" >"$attestation_manifest_path"
      for predicate_name in spdx slsa; do
        case "$predicate_name" in
          spdx) predicate_type="https://spdx.dev/Document" ;;
          slsa) predicate_type="https://slsa.dev/provenance/v1" ;;
          *) fail_closed "unsupported BuildKit predicate" ;;
        esac
        layer_descriptor="$(jq -ec \
          --arg predicate "$predicate_type" '
            [.layers[] | select(
              .mediaType == "application/vnd.in-toto+json"
              and .annotations["in-toto.io/predicate-type"] == $predicate
            )]
            | if length == 1 then .[0] | {digest, size}
              else error("exact BuildKit predicate layer is not unique")
              end
          ' "$attestation_manifest_path")"
        layer_digest="$(jq -er '.digest' <<<"$layer_descriptor")"
        layer_size="$(jq -er '.size' <<<"$layer_descriptor")"
        statement_path="$attestation_root/${safe_platform}-${predicate_name}.json"
        download_quay_blob \
          "$image" "$layer_digest" "$layer_size" "$statement_path"
      done
    done
    python3 "$FINALIZER" verify-buildkit-attestations \
      --container-evidence "$INPUT_ROOT/mlx90-container-evidence.json" \
      --variant "$variant" \
      --index "$index_path" \
      --attestation-root "$attestation_root"
    receipt_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    buildkit_platforms="$(jq -cn \
      --arg amd64_platform "$(jq -er '.["linux/amd64"]' \
        <<<"$platform_digests")" \
      --arg amd64_manifest "sha256:$(sha256sum \
        "$attestation_root/linux-amd64-manifest.json" | awk '{print $1}')" \
      --arg amd64_spdx "sha256:$(sha256sum \
        "$attestation_root/linux-amd64-spdx.json" | awk '{print $1}')" \
      --arg amd64_slsa "sha256:$(sha256sum \
        "$attestation_root/linux-amd64-slsa.json" | awk '{print $1}')" \
      --arg arm64_platform "$(jq -er '.["linux/arm64"]' \
        <<<"$platform_digests")" \
      --arg arm64_manifest "sha256:$(sha256sum \
        "$attestation_root/linux-arm64-manifest.json" | awk '{print $1}')" \
      --arg arm64_spdx "sha256:$(sha256sum \
        "$attestation_root/linux-arm64-spdx.json" | awk '{print $1}')" \
      --arg arm64_slsa "sha256:$(sha256sum \
        "$attestation_root/linux-arm64-slsa.json" | awk '{print $1}')" '{
        "linux/amd64": {
          platformDigest: $amd64_platform,
          attestationManifestDigest: $amd64_manifest,
          spdxDigest: $amd64_spdx,
          slsaDigest: $amd64_slsa
        },
        "linux/arm64": {
          platformDigest: $arm64_platform,
          attestationManifestDigest: $arm64_manifest,
          spdxDigest: $arm64_spdx,
          slsaDigest: $arm64_slsa
        }
      }')"
    write_receipt "${variant}-buildkit" "$receipt_checked_at" "$(jq -cn \
      --arg variant "$variant" \
      --arg image "$image" \
      --arg manifest "$manifest" \
      --argjson platforms "$buildkit_platforms" '{
        variant: $variant,
        image: $image,
        manifestDigest: $manifest,
        indexDigest: $manifest,
        platforms: $platforms
      }')"

    for attestation in signature sbom provenance; do
      reference_url="$(jq -er \
        --arg variant "$variant" \
        --arg name "$attestation" \
        '.variants[$variant][$name].url' \
        "$INPUT_ROOT/mlx90-container-evidence.json")"
      reference_digest="$(jq -er \
        --arg variant "$variant" \
        --arg name "$attestation" \
        '.variants[$variant][$name].digest' \
        "$INPUT_ROOT/mlx90-container-evidence.json")"
      reference_file="$INPUT_ROOT/${variant}-${attestation}-evidence.json"
      verify_reference "$reference_url" "$reference_digest" "$reference_file"
    done
    python3 "$FINALIZER" verify-container-materials \
      --container-evidence "$INPUT_ROOT/mlx90-container-evidence.json" \
      --variant "$variant" \
      --signature "$INPUT_ROOT/${variant}-signature-evidence.json" \
      --live-signature "$INPUT_ROOT/${variant}-signature-live.json" \
      --sbom "$INPUT_ROOT/${variant}-sbom-evidence.json" \
      --provenance "$INPUT_ROOT/${variant}-provenance-evidence.json"
    receipt_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    write_receipt "${variant}-materials" "$receipt_checked_at" "$(jq -cn \
      --arg variant "$variant" \
      --arg image "$image" \
      --arg manifest "$manifest" \
      --arg signature_digest "sha256:$(sha256sum \
        "$INPUT_ROOT/${variant}-signature-evidence.json" | awk '{print $1}')" \
      --arg live_signature_digest "$live_signature_digest" \
      --arg sbom_digest "sha256:$(sha256sum \
        "$INPUT_ROOT/${variant}-sbom-evidence.json" | awk '{print $1}')" \
      --arg provenance_digest "sha256:$(sha256sum \
        "$INPUT_ROOT/${variant}-provenance-evidence.json" | awk '{print $1}')" '{
        variant: $variant,
        image: $image,
        manifestDigest: $manifest,
        signatureDigest: $signature_digest,
        liveSignatureDigest: $live_signature_digest,
        sbomDigest: $sbom_digest,
        provenanceDigest: $provenance_digest
      }')"

    docker pull "$image_ref"
    resolved="$(docker image inspect \
      "$image_ref" \
      --format '{{join .RepoDigests "\n"}}')"
    grep -Fxq "$image_ref" <<<"$resolved" \
      || fail_closed "pulled ${variant} image is not bound to its manifest digest"
    receipt_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    repo_digests="$(jq -Rsc 'split("\n") | map(select(length > 0))' \
      <<<"$resolved")"
    write_receipt "${variant}-pull" "$receipt_checked_at" "$(jq -cn \
      --arg variant "$variant" \
      --arg image "$image" \
      --arg manifest "$manifest" \
      --arg image_ref "$image_ref" \
      --argjson repo_digests "$repo_digests" '{
        variant: $variant,
        image: $image,
        manifestDigest: $manifest,
        pulledImage: $image_ref,
        repoDigests: $repo_digests
      }')"
    installed_path="$INPUT_ROOT/${variant}-installed-collection.json"
    docker run --rm "$image_ref" \
      ansible-galaxy collection list --format json \
      >"$installed_path"
    installed_observation_path="$INPUT_ROOT/${variant}-installed-observation.json"
    if [ "$variant" = "bootstrap" ]; then
      python3 "$FINALIZER" verify-installed \
        --result "$installed_path" \
        --collection "$collection" \
        --observation-output "$installed_observation_path" \
        --expect-absent
    else
      python3 "$FINALIZER" verify-installed \
        --result "$installed_path" \
        --collection "$collection" \
        --observation-output "$installed_observation_path" \
        --version "$version"
    fi
    installed_state="$(jq -er '.state' "$installed_observation_path")"
    installed_version="$(jq -c '.installedVersion' \
      "$installed_observation_path")"
    receipt_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    write_receipt "${variant}-installed" "$receipt_checked_at" "$(jq -cn \
      --arg variant "$variant" \
      --arg image_ref "$image_ref" \
      --arg collection "$(jq -er '.collection' "$installed_observation_path")" \
      --arg state "$installed_state" \
      --argjson installed_version "$installed_version" \
      --arg profile "$profile" '{
        variant: $variant,
        imageRef: $image_ref,
        collection: $collection,
        state: $state,
        installedVersion: $installed_version,
        profile: $profile
      }')"
    if [ "$variant" != "bootstrap" ]; then
      docker run --rm "$image_ref" "${profile_command[@]}"
      receipt_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
      write_receipt "${variant}-profile" "$receipt_checked_at" "$(jq -cn \
        --arg variant "$variant" \
        --arg image_ref "$image_ref" \
        --arg profile "$profile" \
        --argjson command "$profile_json" '{
          variant: $variant,
          imageRef: $image_ref,
          profile: $profile,
          command: $command
        }')"
    fi
  done

  local final_producer_release final_container_release final_producer_revocations
  local final_container_revocations final_revocation_checked_at
  local final_producer_assets final_container_assets
  local final_producer_tag_commit final_container_tag_commit
  local final_producer_asset_snapshot final_container_asset_snapshot
  local final_producer_asset_snapshot_digest final_container_asset_snapshot_digest
  local stored_producer_initial_asset_snapshot_digest
  local stored_container_initial_asset_snapshot_digest
  stored_producer_initial_asset_snapshot_digest="$(jq -er \
    '.observations.assetSnapshotDigest' \
    "$RECEIPT_ROOT/producer-revocation-initial.json")"
  stored_container_initial_asset_snapshot_digest="$(jq -er \
    '.observations.assetSnapshotDigest' \
    "$RECEIPT_ROOT/container-revocation-initial.json")"
  final_producer_release="$(github_api \
    "repos/${PRODUCER_REPOSITORY}/releases/tags/${producer_tag}")"
  final_container_release="$(github_api \
    "repos/${CONSUMER_REPOSITORY}/releases/${INPUT_CONTAINER_RELEASE_ID}")"
  jq -e \
    --argjson id "$producer_release_id" \
    --arg tag "$producer_tag" \
    '.id == $id and .tag_name == $tag and .draft == false and .prerelease == false' \
    <<<"$final_producer_release" >/dev/null
  jq -e \
    --argjson id "$INPUT_CONTAINER_RELEASE_ID" \
    --arg tag "$INPUT_CONTAINER_RELEASE_TAG" \
    '.id == $id and .tag_name == $tag and .draft == false and .prerelease == false' \
    <<<"$final_container_release" >/dev/null
  final_producer_assets="$(list_release_assets \
    "$PRODUCER_REPOSITORY" "$(jq -er '.id' <<<"$final_producer_release")")"
  final_container_assets="$(list_release_assets \
    "$CONSUMER_REPOSITORY" "$(jq -er '.id' <<<"$final_container_release")")"
  final_producer_tag_commit="$(resolve_tag_commit \
    "$PRODUCER_REPOSITORY" "$producer_tag")"
  final_container_tag_commit="$(resolve_tag_commit \
    "$CONSUMER_REPOSITORY" "$INPUT_CONTAINER_RELEASE_TAG")"
  [ "$final_producer_tag_commit" = "$producer_sha" ] \
    || fail_closed "final producer release tag no longer binds the source SHA"
  [ "$final_container_tag_commit" = "$INPUT_CONSUMER_MERGE_SHA" ] \
    || fail_closed "final container release tag no longer binds the merge SHA"
  final_producer_asset_snapshot="$(canonical_consumed_asset_snapshot \
    "$PRODUCER_REPOSITORY" "$producer_release_id" \
    "$final_producer_assets" "$producer_consumed_urls")"
  final_container_asset_snapshot="$(canonical_consumed_asset_snapshot \
    "$CONSUMER_REPOSITORY" "$INPUT_CONTAINER_RELEASE_ID" \
    "$final_container_assets" "$container_consumed_urls")"
  final_producer_asset_snapshot_digest="$(asset_snapshot_digest \
    "$final_producer_asset_snapshot")"
  final_container_asset_snapshot_digest="$(asset_snapshot_digest \
    "$final_container_asset_snapshot")"
  [ "$final_producer_asset_snapshot_digest" \
      = "$stored_producer_initial_asset_snapshot_digest" ] \
    || fail_closed "producer consumed release asset snapshot changed during verification"
  [ "$final_container_asset_snapshot_digest" \
      = "$stored_container_initial_asset_snapshot_digest" ] \
    || fail_closed "container consumed release asset snapshot changed during verification"
  redownload_snapshot_and_compare \
    "$final_producer_asset_snapshot" "$producer_asset_bindings" \
    "$INPUT_ROOT/final-producer-assets"
  redownload_snapshot_and_compare \
    "$final_container_asset_snapshot" "$container_asset_bindings" \
    "$INPUT_ROOT/final-container-assets"
  final_producer_release="$(github_api \
    "repos/${PRODUCER_REPOSITORY}/releases/tags/${producer_tag}")"
  final_container_release="$(github_api \
    "repos/${CONSUMER_REPOSITORY}/releases/${INPUT_CONTAINER_RELEASE_ID}")"
  jq -e \
    --argjson id "$producer_release_id" \
    --arg tag "$producer_tag" \
    '.id == $id and .tag_name == $tag and .draft == false and .prerelease == false' \
    <<<"$final_producer_release" >/dev/null
  jq -e \
    --argjson id "$INPUT_CONTAINER_RELEASE_ID" \
    --arg tag "$INPUT_CONTAINER_RELEASE_TAG" \
    '.id == $id and .tag_name == $tag and .draft == false and .prerelease == false' \
    <<<"$final_container_release" >/dev/null
  final_producer_assets="$(list_release_assets \
    "$PRODUCER_REPOSITORY" "$producer_release_id")"
  final_container_assets="$(list_release_assets \
    "$CONSUMER_REPOSITORY" "$INPUT_CONTAINER_RELEASE_ID")"
  final_producer_tag_commit="$(resolve_tag_commit \
    "$PRODUCER_REPOSITORY" "$producer_tag")"
  final_container_tag_commit="$(resolve_tag_commit \
    "$CONSUMER_REPOSITORY" "$INPUT_CONTAINER_RELEASE_TAG")"
  [ "$final_producer_tag_commit" = "$producer_sha" ] \
    || fail_closed "final producer release tag changed during asset verification"
  [ "$final_container_tag_commit" = "$INPUT_CONSUMER_MERGE_SHA" ] \
    || fail_closed "final container release tag changed during asset verification"
  final_producer_asset_snapshot="$(canonical_consumed_asset_snapshot \
    "$PRODUCER_REPOSITORY" "$producer_release_id" \
    "$final_producer_assets" "$producer_consumed_urls")"
  final_container_asset_snapshot="$(canonical_consumed_asset_snapshot \
    "$CONSUMER_REPOSITORY" "$INPUT_CONTAINER_RELEASE_ID" \
    "$final_container_assets" "$container_consumed_urls")"
  final_producer_asset_snapshot_digest="$(asset_snapshot_digest \
    "$final_producer_asset_snapshot")"
  final_container_asset_snapshot_digest="$(asset_snapshot_digest \
    "$final_container_asset_snapshot")"
  [ "$final_producer_asset_snapshot_digest" \
      = "$stored_producer_initial_asset_snapshot_digest" ] \
    || fail_closed "producer release assets changed during final re-download"
  [ "$final_container_asset_snapshot_digest" \
      = "$stored_container_initial_asset_snapshot_digest" ] \
    || fail_closed "container release assets changed during final re-download"
  final_producer_revocations="$(jq \
    --arg id "$evidence_id" '[
      .[].name
      | select(
          . == "security-release-revocation.json"
          or . == ("security-release-revocation-" + $id + ".json")
        )
    ] | length' <<<"$final_producer_assets")"
  final_container_revocations="$(jq \
    --arg id "$evidence_id" '[
      .[].name
      | select(
          . == "mlx90-container-revocation.json"
          or . == "security-release-revocation.json"
          or . == ("security-release-revocation-" + $id + ".json")
        )
    ] | length' <<<"$final_container_assets")"
  [ "$final_producer_revocations" -eq 0 ] \
    && [ "$final_container_revocations" -eq 0 ] \
    || fail_closed "final live revocation check found revocation evidence"
  final_revocation_checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  write_receipt final-revocation "$final_revocation_checked_at" "$(jq -cn \
    --argjson producer_release_id "$(jq -er '.id' \
      <<<"$final_producer_release")" \
    --arg producer_release_tag "$(jq -er '.tag_name' \
      <<<"$final_producer_release")" \
    --argjson container_release_id "$(jq -er '.id' \
      <<<"$final_container_release")" \
    --arg container_release_tag "$(jq -er '.tag_name' \
      <<<"$final_container_release")" \
    --arg producer_tag_commit "$final_producer_tag_commit" \
    --arg container_tag_commit "$final_container_tag_commit" \
    --arg evidence_id "$evidence_id" \
    --argjson producer_count "$final_producer_revocations" \
    --argjson container_count "$final_container_revocations" \
    --arg producer_initial_snapshot "$stored_producer_initial_asset_snapshot_digest" \
    --arg producer_final_snapshot "$final_producer_asset_snapshot_digest" \
    --arg container_initial_snapshot "$stored_container_initial_asset_snapshot_digest" \
    --arg container_final_snapshot "$final_container_asset_snapshot_digest" \
    --argjson producer_assets "$final_producer_asset_snapshot" \
    --argjson container_assets "$final_container_asset_snapshot" '{
      producerReleaseId: $producer_release_id,
      producerReleaseTag: $producer_release_tag,
      containerReleaseId: $container_release_id,
      containerReleaseTag: $container_release_tag,
      producerTagCommit: $producer_tag_commit,
      containerTagCommit: $container_tag_commit,
      evidenceId: $evidence_id,
      producerRevocationAssetCount: $producer_count,
      containerRevocationAssetCount: $container_count,
      producerInitialAssetSnapshotDigest: $producer_initial_snapshot,
      producerFinalAssetSnapshotDigest: $producer_final_snapshot,
      containerInitialAssetSnapshotDigest: $container_initial_snapshot,
      containerFinalAssetSnapshotDigest: $container_final_snapshot,
      producerAssets: $producer_assets,
      containerAssets: $container_assets
    }')"

  local delivered acceptance finalizer_identity evidence_digest
  python3 "$FINALIZER" write-report \
    "${IDENTITY_ARGS[@]}" \
    "${EVIDENCE_ARGS[@]}" \
    --workflow-sha "$GITHUB_SHA" \
    --run-id "$GITHUB_RUN_ID" \
    --run-attempt "$GITHUB_RUN_ATTEMPT" \
    --receipts "$RECEIPT_ROOT" \
    --receipt-bundle-output \
      "$EVIDENCE_ROOT/mlx90-verification-receipts.json" \
    --output "$EVIDENCE_ROOT/mlx90-verification-report.json"
  delivered="$EVIDENCE_ROOT/security-release-delivered.json"
  acceptance="$EVIDENCE_ROOT/mlx90-final-acceptance.json"
  python3 "$FINALIZER" finalize \
    "${IDENTITY_ARGS[@]}" \
    "${EVIDENCE_ARGS[@]}" \
    --verification-report "$EVIDENCE_ROOT/mlx90-verification-report.json" \
    --receipt-bundle "$EVIDENCE_ROOT/mlx90-verification-receipts.json" \
    --workflow-sha "$GITHUB_SHA" \
    --run-id "$GITHUB_RUN_ID" \
    --run-attempt "$GITHUB_RUN_ATTEMPT" \
    --delivered-output "$delivered" \
    --acceptance-output "$acceptance"
  python3 "$POLICY_VALIDATOR" \
    "$delivered" \
    --consumer "$CONSUMER_REPOSITORY" \
    --head-sha "$INPUT_CONSUMER_HEAD_SHA" \
    --require-delivered
  python3 "$DELIVERY_VALIDATOR" "$acceptance"

  (
    cd "$EVIDENCE_ROOT"
    sha256sum \
      security-release-delivered.json \
      mlx90-final-acceptance.json \
      mlx90-verification-receipts.json \
      mlx90-verification-report.json \
      >SHA256SUMS
    cosign sign-blob \
      --yes \
      --bundle SHA256SUMS.sigstore.json \
      SHA256SUMS
  )
  finalizer_identity="https://github.com/${FINALIZER_REPOSITORY}/"
  finalizer_identity+="${FINALIZER_WORKFLOW}@refs/heads/main"
  cosign verify-blob \
    --bundle "$EVIDENCE_ROOT/SHA256SUMS.sigstore.json" \
    --certificate-oidc-issuer "$ISSUER" \
    --certificate-identity "$finalizer_identity" \
    --certificate-github-workflow-sha "$GITHUB_SHA" \
    "$EVIDENCE_ROOT/SHA256SUMS"
  evidence_digest="$(sha256sum "$acceptance" | awk '{print $1}')"
  printf 'evidence-tag=v0.0.0-mlx90.%s\n' "${evidence_digest:0:16}" \
    >>"$GITHUB_OUTPUT"
}

persist_mode() {
  require_value GH_TOKEN
  require_value EVIDENCE_TAG
  require_value GITHUB_ACTOR
  require_value GITHUB_TRIGGERING_ACTOR
  require_value GITHUB_REF
  require_value GITHUB_REPOSITORY
  require_value GITHUB_RUN_ATTEMPT
  require_value GITHUB_RUN_ID
  require_value GITHUB_SHA
  require_value GITHUB_OUTPUT
  [ "$GITHUB_REPOSITORY" = "$FINALIZER_REPOSITORY" ] \
    || fail_closed "unexpected persistence repository"
  [ "$GITHUB_REF" = "refs/heads/main" ] \
    || fail_closed "final evidence may persist only from protected main"
  [ "$GITHUB_ACTOR" = "lightning-it-release-automation[bot]" ] \
    || fail_closed "only the release automation App may persist final evidence"
  [ "$GITHUB_TRIGGERING_ACTOR" = "lightning-it-release-automation[bot]" ] \
    || fail_closed "only the release automation App may trigger persistence"
  [[ "$EVIDENCE_TAG" =~ ^v0\.0\.0-mlx90\.[0-9a-f]{16}$ ]] \
    || fail_closed "derived evidence tag is invalid"
  [[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]] \
    || fail_closed "persistence workflow SHA is invalid"
  [ -d "$EVIDENCE_ROOT" ] && [ ! -L "$EVIDENCE_ROOT" ] \
    || fail_closed "signed evidence directory is missing"

  local expected_files actual_files finalizer_sha finalizer_run_id
  local finalizer_run_attempt
  expected_files=$'SHA256SUMS\nSHA256SUMS.sigstore.json\n'
  expected_files+=$'mlx90-final-acceptance.json\n'
  expected_files+=$'mlx90-verification-receipts.json\n'
  expected_files+=$'mlx90-verification-report.json\n'
  expected_files+='security-release-delivered.json'
  actual_files="$(find "$EVIDENCE_ROOT" -maxdepth 1 -type f -printf '%f\n' | sort)"
  [ "$actual_files" = "$expected_files" ] \
    || fail_closed "signed final evidence file set is not exact"
  (
    cd "$EVIDENCE_ROOT"
    sha256sum --check SHA256SUMS
  )
  finalizer_sha="$(jq -er '.finalizer.workflowSha' \
    "$EVIDENCE_ROOT/mlx90-final-acceptance.json")"
  finalizer_run_id="$(jq -er '.finalizer.runId' \
    "$EVIDENCE_ROOT/mlx90-final-acceptance.json")"
  finalizer_run_attempt="$(jq -er '.finalizer.runAttempt' \
    "$EVIDENCE_ROOT/mlx90-final-acceptance.json")"
  [ "$finalizer_sha" = "$GITHUB_SHA" ] \
    || fail_closed "signed evidence was created by a different workflow SHA"
  [ "$finalizer_run_id" = "$GITHUB_RUN_ID" ] \
    || fail_closed "signed evidence was created by a different workflow run"
  [ "$finalizer_run_attempt" = "$GITHUB_RUN_ATTEMPT" ] \
    || fail_closed "signed evidence was created by a different run attempt"
  local finalizer_identity
  finalizer_identity="https://github.com/${FINALIZER_REPOSITORY}/"
  finalizer_identity+="${FINALIZER_WORKFLOW}@refs/heads/main"
  cosign verify-blob \
    --bundle "$EVIDENCE_ROOT/SHA256SUMS.sigstore.json" \
    --certificate-oidc-issuer "$ISSUER" \
    --certificate-identity "$finalizer_identity" \
    --certificate-github-workflow-sha "$GITHUB_SHA" \
    "$EVIDENCE_ROOT/SHA256SUMS"

  local evidence_id release_id release_json release_assets release_asset_metadata
  local release_dir draft_dir verified_draft_dir filename release_title release_notes
  local expected_asset_names existing_asset_names asset_metadata release_upload_url
  local published_asset_metadata
  local -a evidence_files
  evidence_files=(
    SHA256SUMS
    SHA256SUMS.sigstore.json
    mlx90-final-acceptance.json
    mlx90-verification-receipts.json
    mlx90-verification-report.json
    security-release-delivered.json
  )
  evidence_id="$(jq -er '.securityEvidenceId' \
    "$EVIDENCE_ROOT/mlx90-final-acceptance.json")"
  release_title="MLX-90 final acceptance ${evidence_id}"
  release_notes="Signed immutable MLX-90 final-acceptance evidence."
  release_notes+=" No secret values are included."
  release_notes+=" Owner: ${GITHUB_REPOSITORY}@${GITHUB_SHA};"
  release_notes+=" workflow run ${GITHUB_RUN_ID}, attempt ${GITHUB_RUN_ATTEMPT}."
  release_dir="${RUNNER_TEMP:?}/mlx90-persisted-evidence"
  draft_dir="${RUNNER_TEMP:?}/mlx90-existing-draft-evidence"
  verified_draft_dir="${RUNNER_TEMP:?}/mlx90-verified-draft-evidence"
  for filename in "$release_dir" "$draft_dir" "$verified_draft_dir"; do
    [ ! -e "$filename" ] && [ ! -L "$filename" ] \
      || fail_closed "fresh persistence verification path already exists"
  done
  expected_asset_names="$(printf '%s\n' "${evidence_files[@]}" \
    | jq -Rsc 'split("\n") | map(select(length > 0)) | sort')"
  if release_json="$(github_api \
    "repos/${FINALIZER_REPOSITORY}/releases/tags/${EVIDENCE_TAG}" 2>/dev/null)"
  then
    jq -e \
      --arg body "$release_notes" \
      --arg name "$release_title" \
      --arg sha "$GITHUB_SHA" \
      --arg tag "$EVIDENCE_TAG" '
        .prerelease == false
        and .tag_name == $tag
        and .target_commitish == $sha
        and .name == $name
        and .body == $body
      ' <<<"$release_json" >/dev/null \
      || fail_closed "existing evidence release is not owned by this run"
  else
    release_json="$(jq -cn \
      --arg body "$release_notes" \
      --arg name "$release_title" \
      --arg sha "$GITHUB_SHA" \
      --arg tag "$EVIDENCE_TAG" '{
        tag_name: $tag,
        target_commitish: $sha,
        name: $name,
        body: $body,
        draft: true,
        prerelease: false,
        make_latest: "false"
      }' | github_api \
        --method POST \
        "repos/${FINALIZER_REPOSITORY}/releases" \
        --input -)"
  fi
  release_id="$(jq -er '.id' <<<"$release_json")"
  [[ "$release_id" =~ ^[1-9][0-9]*$ ]] \
    || fail_closed "evidence release ID is invalid"
  release_upload_url="$(jq -er '.upload_url' <<<"$release_json")"
  release_assets="$(list_release_assets "$FINALIZER_REPOSITORY" "$release_id")"
  release_asset_metadata="$(canonical_release_asset_metadata "$release_assets")"
  existing_asset_names="$(jq -c '[.[].name] | sort' \
    <<<"$release_asset_metadata")"
  jq -e \
    --argjson actual "$existing_asset_names" \
    --argjson expected "$expected_asset_names" \
    '($actual - $expected) == []' <<<"{}" >/dev/null \
    || fail_closed "evidence release contains an unexpected asset"

  if jq -e '.draft == true' <<<"$release_json" >/dev/null; then
    install -d -m 0700 "$draft_dir"
    for filename in "${evidence_files[@]}"; do
      asset_metadata="$(jq -ec --arg name "$filename" '[
        .[] | select(.name == $name)
      ]' <<<"$release_asset_metadata")"
      if [ "$(jq 'length' <<<"$asset_metadata")" -eq 1 ]; then
        download_release_asset_by_id \
          "$FINALIZER_REPOSITORY" \
          "$(jq -er '.[0].id' <<<"$asset_metadata")" \
          "$(jq -er '.[0].size' <<<"$asset_metadata")" \
          "$filename" \
          "$draft_dir/$filename"
        cmp "$EVIDENCE_ROOT/$filename" "$draft_dir/$filename" \
          || fail_closed "existing draft asset differs: ${filename}"
      else
        upload_release_asset_by_id \
          "$FINALIZER_REPOSITORY" "$release_id" "$release_upload_url" \
          "$EVIDENCE_ROOT/$filename"
      fi
    done
    release_json="$(github_api \
      "repos/${FINALIZER_REPOSITORY}/releases/${release_id}")"
    jq -e \
      --argjson id "$release_id" \
      --arg body "$release_notes" \
      --arg name "$release_title" \
      --arg sha "$GITHUB_SHA" \
      --arg tag "$EVIDENCE_TAG" '
        .id == $id
        and .draft == true
        and .prerelease == false
        and .tag_name == $tag
        and .target_commitish == $sha
        and .name == $name
        and .body == $body
      ' <<<"$release_json" >/dev/null \
      || fail_closed "draft evidence release ownership changed"
    release_assets="$(list_release_assets \
      "$FINALIZER_REPOSITORY" "$release_id")"
    release_asset_metadata="$(canonical_release_asset_metadata "$release_assets")"
    [ "$(jq -c '[.[].name] | sort' <<<"$release_asset_metadata")" \
        = "$expected_asset_names" ] \
      || fail_closed "draft evidence release asset set is not exact"
    download_release_assets_and_compare \
      "$FINALIZER_REPOSITORY" "$release_asset_metadata" \
      "$EVIDENCE_ROOT" "$verified_draft_dir"
    [ "$(find "$verified_draft_dir" -maxdepth 1 -type f -printf '%f\n' \
        | sort)" = "$expected_files" ] \
      || fail_closed "downloaded draft evidence asset set is not exact"
    (
      cd "$verified_draft_dir"
      sha256sum --check SHA256SUMS
    )
    cosign verify-blob \
      --bundle "$verified_draft_dir/SHA256SUMS.sigstore.json" \
      --certificate-oidc-issuer "$ISSUER" \
      --certificate-identity "$finalizer_identity" \
      --certificate-github-workflow-sha "$GITHUB_SHA" \
      "$verified_draft_dir/SHA256SUMS"
    release_json="$(jq -cn '{draft: false, make_latest: "false"}' \
      | github_api \
        --method PATCH \
        "repos/${FINALIZER_REPOSITORY}/releases/${release_id}" \
        --input -)"
  fi

  release_json="$(github_api \
    "repos/${FINALIZER_REPOSITORY}/releases/${release_id}")"
  jq -e \
    --argjson id "$release_id" \
    --arg body "$release_notes" \
    --arg name "$release_title" \
    --arg sha "$GITHUB_SHA" \
    --arg tag "$EVIDENCE_TAG" '
      .id == $id
      and .draft == false
      and .prerelease == false
      and .immutable == true
      and .tag_name == $tag
      and .target_commitish == $sha
      and .name == $name
      and .body == $body
    ' <<<"$release_json" >/dev/null \
    || fail_closed "published evidence release is not exact and immutable"
  release_assets="$(list_release_assets \
    "$FINALIZER_REPOSITORY" "$release_id")"
  published_asset_metadata="$(canonical_release_asset_metadata "$release_assets")"
  [ "$(jq -c '[.[].name] | sort' <<<"$published_asset_metadata")" \
      = "$expected_asset_names" ] \
    || fail_closed "published evidence release asset set differs"
  [ "$(resolve_tag_commit "$FINALIZER_REPOSITORY" "$EVIDENCE_TAG")" \
      = "$GITHUB_SHA" ] \
    || fail_closed "published evidence tag points to another workflow SHA"

  download_release_assets_and_compare \
    "$FINALIZER_REPOSITORY" "$published_asset_metadata" \
    "$EVIDENCE_ROOT" "$release_dir"
  [ "$(find "$release_dir" -maxdepth 1 -type f -printf '%f\n' | sort)" \
      = "$expected_files" ] \
    || fail_closed "persisted evidence release asset set differs"
  release_json="$(github_api \
    "repos/${FINALIZER_REPOSITORY}/releases/${release_id}")"
  jq -e --argjson id "$release_id" \
    '.id == $id and .draft == false and .prerelease == false and .immutable == true' \
    <<<"$release_json" >/dev/null \
    || fail_closed "evidence release lost immutable published state"
  release_assets="$(list_release_assets \
    "$FINALIZER_REPOSITORY" "$release_id")"
  release_asset_metadata="$(canonical_release_asset_metadata "$release_assets")"
  [ "$release_asset_metadata" = "$published_asset_metadata" ] \
    || fail_closed "immutable evidence release assets changed during verification"
  (
    cd "$release_dir"
    sha256sum --check SHA256SUMS
  )
  cosign verify-blob \
    --bundle "$release_dir/SHA256SUMS.sigstore.json" \
    --certificate-oidc-issuer "$ISSUER" \
    --certificate-identity "$finalizer_identity" \
    --certificate-github-workflow-sha "$GITHUB_SHA" \
    "$release_dir/SHA256SUMS"
  python3 "$DELIVERY_VALIDATOR" \
    "$release_dir/mlx90-final-acceptance.json"
  local durable_receipt_digest durable_receipt_size durable_receipt_url
  local durable_report_digest durable_report_url durable_release_url
  durable_receipt_digest="sha256:$(sha256sum \
    "$release_dir/mlx90-verification-receipts.json" | awk '{print $1}')"
  durable_receipt_size="$(wc -c \
    <"$release_dir/mlx90-verification-receipts.json" | tr -d '[:space:]')"
  [ "$(jq -er '.receiptBundle.digest' \
      "$release_dir/mlx90-final-acceptance.json")" = "$durable_receipt_digest" ] \
    || fail_closed "durable acceptance receipt bundle digest mismatch"
  [ "$(jq -er '.receiptBundle.assetName' \
      "$release_dir/mlx90-final-acceptance.json")" \
      = "mlx90-verification-receipts.json" ] \
    || fail_closed "durable acceptance receipt bundle asset name mismatch"
  [ "$(jq -er '.receiptBundle.size' \
      "$release_dir/mlx90-final-acceptance.json")" = "$durable_receipt_size" ] \
    || fail_closed "durable acceptance receipt bundle size mismatch"
  local durable_acceptance_url durable_acceptance_digest
  local durable_consumer_merge durable_container_tag
  durable_release_url="$(jq -er '.html_url' <<<"$release_json")"
  durable_acceptance_url="$(jq -er \
    --arg name "mlx90-final-acceptance.json" '[
      .[] | select(.name == $name)
    ] | if length == 1 then .[0].url else error(
      "final acceptance asset URL is not unique"
    ) end' <<<"$release_asset_metadata")"
  durable_report_url="$(jq -er \
    --arg name "mlx90-verification-report.json" '[
      .[] | select(.name == $name)
    ] | if length == 1 then .[0].url else error(
      "verification report asset URL is not unique"
    ) end' <<<"$release_asset_metadata")"
  durable_receipt_url="$(jq -er \
    --arg name "mlx90-verification-receipts.json" '[
      .[] | select(.name == $name)
    ] | if length == 1 then .[0].url else error(
      "receipt bundle asset URL is not unique"
    ) end' <<<"$release_asset_metadata")"
  [ "$durable_release_url" \
      = "https://github.com/${FINALIZER_REPOSITORY}/releases/tag/${EVIDENCE_TAG}" ] \
    || fail_closed "live evidence release URL is not canonical"
  [ "$durable_acceptance_url" \
      = "https://github.com/${FINALIZER_REPOSITORY}/releases/download/${EVIDENCE_TAG}/mlx90-final-acceptance.json" ] \
    || fail_closed "live final acceptance asset URL is not canonical"
  [ "$durable_report_url" \
      = "https://github.com/${FINALIZER_REPOSITORY}/releases/download/${EVIDENCE_TAG}/mlx90-verification-report.json" ] \
    || fail_closed "live verification report asset URL is not canonical"
  [ "$durable_receipt_url" \
      = "https://github.com/${FINALIZER_REPOSITORY}/releases/download/${EVIDENCE_TAG}/mlx90-verification-receipts.json" ] \
    || fail_closed "live receipt bundle asset URL is not canonical"
  durable_acceptance_digest="sha256:$(sha256sum \
    "$release_dir/mlx90-final-acceptance.json" | awk '{print $1}')"
  durable_report_digest="sha256:$(sha256sum \
    "$release_dir/mlx90-verification-report.json" | awk '{print $1}')"
  durable_consumer_merge="$(jq -er '.consumer.mergeSha' \
    "$release_dir/mlx90-final-acceptance.json")"
  durable_container_tag="$(jq -er '.container.releaseTag' \
    "$release_dir/mlx90-final-acceptance.json")"
  jq -e \
    --arg merge "$durable_consumer_merge" \
    --arg tag "$durable_container_tag" '
      .status == "delivered"
      and .consumer.mergeSha == $merge
      and .container.sourceSha == $merge
      and .container.releaseTag == $tag
  ' "$release_dir/mlx90-final-acceptance.json" >/dev/null
  {
    echo "final_acceptance_url=$durable_acceptance_url"
    echo "final_acceptance_sha256=$durable_acceptance_digest"
    echo "evidence_release_tag=$EVIDENCE_TAG"
    echo "evidence_release_url=$durable_release_url"
    echo "verification_report_url=$durable_report_url"
    echo "verification_report_sha256=$durable_report_digest"
    echo "receipt_bundle_url=$durable_receipt_url"
    echo "receipt_bundle_sha256=$durable_receipt_digest"
    echo "consumer_merge_sha=$durable_consumer_merge"
    echo "container_release_tag=$durable_container_tag"
  } >>"$GITHUB_OUTPUT"
  printf 'Persisted MLX-90 evidence: %s\n' "$durable_release_url"
}

callback_mode() {
  local required
  for required in \
    APP_INSTALLATION_ID \
    APP_SLUG \
    CONSUMER_MERGE_SHA \
    CONTAINER_RELEASE_TAG \
    FINAL_ACCEPTANCE_SHA256 \
    FINAL_ACCEPTANCE_URL \
    GH_TOKEN \
    GITHUB_ACTOR \
    GITHUB_TRIGGERING_ACTOR \
    GITHUB_REF \
    GITHUB_REPOSITORY
  do
    require_value "$required"
  done
  [ "$GITHUB_REPOSITORY" = "$FINALIZER_REPOSITORY" ] \
    || fail_closed "unexpected callback repository"
  [ "$GITHUB_REF" = "refs/heads/main" ] \
    || fail_closed "post-delivery callback must run from protected main"
  [ "$GITHUB_ACTOR" = "lightning-it-release-automation[bot]" ] \
    || fail_closed "only the release automation App may dispatch promotion"
  [ "$GITHUB_TRIGGERING_ACTOR" = "lightning-it-release-automation[bot]" ] \
    || fail_closed "only the release automation App may trigger promotion"
  [ "$APP_SLUG" = "lightning-it-release-automation" ] \
    || fail_closed "post-delivery callback App slug is invalid"
  [ "$APP_INSTALLATION_ID" = "148019054" ] \
    || fail_closed "post-delivery callback App installation is invalid"
  [[ "$FINAL_ACCEPTANCE_URL" =~ ^https://github\.com/lightning-it/modulix-validation/releases/download/v0\.0\.0-mlx90\.[0-9a-f]{16}/mlx90-final-acceptance\.json$ ]] \
    || fail_closed "final acceptance URL is invalid"
  [[ "$FINAL_ACCEPTANCE_SHA256" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || fail_closed "final acceptance digest is invalid"
  [[ "$CONSUMER_MERGE_SHA" =~ ^[0-9a-f]{40}$ ]] \
    || fail_closed "callback consumer merge SHA is invalid"
  [[ "$CONTAINER_RELEASE_TAG" == v* ]] \
    || fail_closed "callback container release tag is invalid"
  is_semver "${CONTAINER_RELEASE_TAG#v}" \
    || fail_closed "callback container release tag is invalid"
  local acceptance_hex derived_evidence_tag expected_url actual_repositories
  acceptance_hex="${FINAL_ACCEPTANCE_SHA256#sha256:}"
  derived_evidence_tag="v0.0.0-mlx90.${acceptance_hex:0:16}"
  expected_url="https://github.com/${FINALIZER_REPOSITORY}/"
  expected_url+="releases/download/${derived_evidence_tag}/"
  expected_url+="mlx90-final-acceptance.json"
  [ "$FINAL_ACCEPTANCE_URL" = "$expected_url" ] \
    || fail_closed "final acceptance URL does not derive from its digest"
  actual_repositories="$(
    github_api --paginate \
      "installation/repositories?per_page=100" \
      | jq -sc '[.[].repositories[].full_name] | sort | unique'
  )"
  jq -e \
    --argjson actual "$actual_repositories" \
    '$actual == [
      "lightning-it/container-ee-wunder-ansible-ubi9"
    ]' <<<"{}" >/dev/null \
    || fail_closed "post-delivery callback token repository scope is invalid"
  local dispatch
  dispatch="$(jq -cn \
    --arg acceptance_digest "$FINAL_ACCEPTANCE_SHA256" \
    --arg acceptance_url "$FINAL_ACCEPTANCE_URL" \
    --arg merge "$CONSUMER_MERGE_SHA" \
    --arg tag "$CONTAINER_RELEASE_TAG" '
      {
        ref: "main",
        inputs: {
          final_acceptance_url: $acceptance_url,
          final_acceptance_sha256: $acceptance_digest,
          consumer_merge_sha: $merge,
          container_release_tag: $tag
        }
      }
    ')"
  jq -e '
    (keys | sort) == ["inputs", "ref"]
    and .ref == "main"
    and (.inputs | keys | sort) == [
      "consumer_merge_sha",
      "container_release_tag",
      "final_acceptance_sha256",
      "final_acceptance_url"
    ]
  ' <<<"$dispatch" >/dev/null
  github_api \
    --method POST \
    "repos/${CONSUMER_REPOSITORY}/actions/workflows/security-release-promote-tags.yml/dispatches" \
    --input - <<<"$dispatch"
  printf 'Dispatched post-delivery promotion: https://github.com/%s/actions/workflows/%s\n' \
    "$CONSUMER_REPOSITORY" "security-release-promote-tags.yml"
}

if [ "$#" -ne 1 ]; then
  fail_closed "usage: ${0##*/} verify|persist|callback"
fi
case "$1" in
  verify) verify_mode ;;
  persist) persist_mode ;;
  callback) callback_mode ;;
  *) fail_closed "usage: ${0##*/} verify|persist|callback" ;;
esac
