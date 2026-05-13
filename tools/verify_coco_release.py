#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--release-manifest', required=True)
    parser.add_argument('--runtime-config', required=True)
    parser.add_argument('--initdata', required=True)
    parser.add_argument('--coco-image-digest', required=True)
    parser.add_argument('--oci-archive', required=False)
    args = parser.parse_args()

    manifest = json.loads(Path(args.release_manifest).read_text())
    runtime_config = json.loads(Path(args.runtime_config).read_text())
    image_digest = Path(args.coco_image_digest).read_text().strip()
    initdata_hash = sha256_file(Path(args.initdata))

    coco_entries = [
        entry for entry in manifest['accepted_realizations']
        if entry.get('platform') == 'aws_coco_snp'
    ]
    if len(coco_entries) != 1:
        raise SystemExit(f'expected one aws_coco_snp realization, found {len(coco_entries)}')

    identity = coco_entries[0]['identity']['value']
    checks = {
        'manifest_image_digest': identity['image_digest'] == image_digest,
        'runtime_image_digest': runtime_config['image_digest'] == image_digest,
        'manifest_initdata_hash': identity['initdata_hash'] == initdata_hash,
        'runtime_initdata_hash': runtime_config['initdata_hash'] == initdata_hash,
        'coco_lowered_from_source_container': coco_entries[0].get('lowered_from', {}).get('type') == 'source_container',
    }
    if args.oci_archive:
        expected_archive_sha = Path(f'{args.oci_archive}.sha256')
        if expected_archive_sha.exists():
            expected = expected_archive_sha.read_text().split()[0]
            checks['oci_archive_sha256'] = sha256_file(Path(args.oci_archive)) == expected

    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        print(json.dumps({'ok': False, 'failed': failed, 'checks': checks}, indent=2))
        raise SystemExit(1)

    print(json.dumps({
        'ok': True,
        'service': manifest['service'],
        'release_id': manifest['release_id'],
        'image_digest': image_digest,
        'initdata_hash': initdata_hash,
        'checks': checks,
    }, indent=2))


if __name__ == '__main__':
    main()
