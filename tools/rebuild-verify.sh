#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
Usage: $0 --repo-url <repo-url> --ref <git-ref> --expected-provenance-url <url>
USAGE
}

REPO_URL=""
REF=""
EXPECTED_PROVENANCE_URL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-url) REPO_URL="$2"; shift 2 ;;
    --ref) REF="$2"; shift 2 ;;
    --expected-provenance-url|--provenance-url|--release-url) EXPECTED_PROVENANCE_URL="$2"; shift 2 ;;
    *) usage; exit 1 ;;
  esac
done

[[ -n "$REPO_URL" && -n "$REF" && -n "$EXPECTED_PROVENANCE_URL" ]] || { usage; exit 1; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${WORK_DIR:-$ROOT_DIR/build/rebuild-verify}"
CHECKOUT_DIR="$WORK_DIR/repo"
EXPECTED_JSON="$WORK_DIR/expected-provenance.json"
ACTUAL_JSON="$WORK_DIR/actual-provenance.json"
OUTPUT_DIR="$WORK_DIR/output"

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR" "$OUTPUT_DIR"

git clone "$REPO_URL" "$CHECKOUT_DIR" >/dev/null 2>&1
git -C "$CHECKOUT_DIR" checkout "$REF" >/dev/null 2>&1

curl -fsSL "$EXPECTED_PROVENANCE_URL" -o "$EXPECTED_JSON"

INSTALL_ROOT="$WORK_DIR/nitro-cli"
NITRO_CLI_BIN="$CHECKOUT_DIR/tools/install-nitro-cli.sh"
NITRO_CLI_SOURCE_TAG="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["nitro_cli_source_tag"])' "$EXPECTED_JSON")"
INSTALL_ROOT="$INSTALL_ROOT" NITRO_CLI_SOURCE_TAG="$NITRO_CLI_SOURCE_TAG" "$NITRO_CLI_BIN" >/dev/null
export PATH="$INSTALL_ROOT/bin:$PATH"

IMAGE_TAG="rebuild-verify:$(date +%s)"
IMAGE_DIGEST_PLACEHOLDER="sha256:rebuild-verify-local"

pushd "$CHECKOUT_DIR" >/dev/null
IMAGE_TAG="$IMAGE_TAG" scripts/build-enclave.sh "$OUTPUT_DIR" >/dev/null
DOCKER_VERSION="$(docker --version | sed 's/^Docker version //; s/,.*//')"
RUST_VERSION="$(rustc --version | awk '{print $2}')"
CARGO_VERSION="$(cargo --version | awk '{print $2}')"
python3 tools/generate_provenance.py \
  --workload-id "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["workload_id"])' "$EXPECTED_JSON")" \
  --repo-url "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["repo_url"])' "$EXPECTED_JSON")" \
  --project-repo-url "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["project_repo_url"])' "$EXPECTED_JSON")" \
  --release-tag "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["release_tag"])' "$EXPECTED_JSON")" \
  --commit-sha "$(git rev-parse HEAD)" \
  --oci-image-digest "$IMAGE_DIGEST_PLACEHOLDER" \
  --eif-path "$OUTPUT_DIR/ztbrowser-enclave.eif" \
  --describe-eif-path "$OUTPUT_DIR/describe-eif.json" \
  --release-url "$EXPECTED_PROVENANCE_URL" \
  --nitro-cli-version "$(nitro-cli --version | awk '{print $NF}')" \
  --nitro-cli-source-repo "https://github.com/aws/aws-nitro-enclaves-cli.git" \
  --nitro-cli-source-tag "$NITRO_CLI_SOURCE_TAG" \
  --docker-version "$DOCKER_VERSION" \
  --rust-version "$RUST_VERSION" \
  --cargo-version "$CARGO_VERSION" \
  --output-path "$ACTUAL_JSON"
popd >/dev/null

python3 - <<'PY' "$EXPECTED_JSON" "$ACTUAL_JSON"
import json, sys
expected = json.load(open(sys.argv[1]))
actual = json.load(open(sys.argv[2]))
keys = [
  'workload_id', 'repo_url', 'project_repo_url', 'release_tag', 'commit_sha',
  'eif_sha256', 'describe_eif_sha256', 'pcr0', 'pcr1', 'pcr2', 'pcr8', 'nitro_cli_source_tag'
]
mismatches = []
for key in keys:
    if expected.get(key) != actual.get(key):
        mismatches.append((key, expected.get(key), actual.get(key)))
if mismatches:
    print(json.dumps({'ok': False, 'mismatches': mismatches}, indent=2))
    raise SystemExit(1)
print(json.dumps({'ok': True, 'checked_keys': keys}, indent=2))
PY
