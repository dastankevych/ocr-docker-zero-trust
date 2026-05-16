#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/build}"
IMAGE_REF="${COCO_IMAGE_REF:-ocr-demo:local}"
DEPLOY_IMAGE_DIGEST="${COCO_DEPLOY_IMAGE_DIGEST:-}"
PLATFORM="${COCO_IMAGE_PLATFORM:-linux/amd64}"
OCI_ARCHIVE="$OUT_DIR/coco-workload.oci.tar"
DIGEST_PATH="$OUT_DIR/coco-image-digest.txt"
REF_PATH="$OUT_DIR/coco-image-ref.txt"
ARCHIVE_SHA_PATH="$OUT_DIR/coco-workload.oci.tar.sha256"
BUILDER_NAME="${COCO_BUILDER_NAME:-ztinfra-coco-builder}"
created_builder=0

mkdir -p "$OUT_DIR"

if ! docker buildx version >/dev/null 2>&1; then
  echo "docker buildx is required to build reproducible CoCo OCI artifacts" >&2
  exit 1
fi

if ! docker buildx inspect "$BUILDER_NAME" >/dev/null 2>&1; then
  docker buildx create --name "$BUILDER_NAME" --driver docker-container --use >/dev/null
  created_builder=1
else
  docker buildx use "$BUILDER_NAME" >/dev/null
fi

cleanup() {
  if [[ "$created_builder" == "1" ]]; then
    docker buildx rm "$BUILDER_NAME" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "[1/3] Building CoCo workload image as OCI archive: $OCI_ARCHIVE"
docker buildx build \
  --builder "$BUILDER_NAME" \
  --platform "$PLATFORM" \
  --file "$ROOT_DIR/Dockerfile" \
  --tag "$IMAGE_REF" \
  --output "type=oci,dest=$OCI_ARCHIVE" \
  "$ROOT_DIR"

echo "[2/3] Computing CoCo workload OCI manifest digest"
oci_manifest_digest="$(python3 - "$OCI_ARCHIVE" <<'PY'
import json
import tarfile
import sys

with tarfile.open(sys.argv[1]) as archive:
    index = json.load(archive.extractfile('index.json'))
digest = index['manifests'][0]['digest']
print(digest)
PY
)"
if [[ -z "$DEPLOY_IMAGE_DIGEST" ]]; then
  DEPLOY_IMAGE_DIGEST="$oci_manifest_digest"
fi
if [[ "$IMAGE_REF" == *@sha256:* ]]; then
  deploy_image_ref="$IMAGE_REF"
else
  deploy_image_ref="${IMAGE_REF}@${DEPLOY_IMAGE_DIGEST}"
fi

printf '%s\n' "$DEPLOY_IMAGE_DIGEST" > "$DIGEST_PATH"
printf '%s\n' "$deploy_image_ref" > "$REF_PATH"
printf '%s\n' "$oci_manifest_digest" > "$OUT_DIR/coco-oci-manifest-digest.txt"

echo "[3/3] Computing OCI archive checksum"
sha256sum "$OCI_ARCHIVE" > "$ARCHIVE_SHA_PATH"

echo "CoCo deployment image digest: $DEPLOY_IMAGE_DIGEST"
echo "CoCo deployment image ref: $deploy_image_ref"
echo "CoCo OCI manifest digest: $oci_manifest_digest"
echo "Saved digest to $DIGEST_PATH"
echo "Saved ref to $REF_PATH"
echo "Saved OCI archive checksum to $ARCHIVE_SHA_PATH"
