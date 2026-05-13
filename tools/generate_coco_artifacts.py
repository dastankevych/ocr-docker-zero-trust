#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path

from generate_release_manifest import load_service_config, stable_json


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--service-config', required=True)
    parser.add_argument('--release-id', required=True)
    parser.add_argument('--coco-image-digest', required=True)
    parser.add_argument('--initdata-path', required=True)
    parser.add_argument('--runtime-config-path', required=True)
    args = parser.parse_args()

    service_config = load_service_config(Path(args.service_config))
    coco = service_config.get('coco', {}) if isinstance(service_config.get('coco'), dict) else {}
    service = service_config.get('service')
    if not service:
        raise SystemExit('service is required in service config')

    initdata = {
        'schema_version': 1,
        'service': service,
        'release_id': args.release_id,
        'platform': coco.get('platform', 'aws_coco_snp'),
        'image_digest': args.coco_image_digest,
        'aa_evidence_url': coco.get('aa_evidence_url', 'http://127.0.0.1:8006/aa/evidence'),
        'attestation_path': coco.get('attestation_path', '/.well-known/attestation'),
    }

    initdata_path = Path(args.initdata_path)
    initdata_path.write_bytes(stable_json(initdata) + b'\n')
    initdata_hash = sha256_file(initdata_path)
    identity_hint = f"coco_image_initdata:{args.coco_image_digest}:{initdata_hash}"

    runtime_config = {
        'service': service,
        'release_id': args.release_id,
        'platform': initdata['platform'],
        'image_digest': args.coco_image_digest,
        'initdata_hash': initdata_hash,
        'identity_hint': identity_hint,
        'aa_evidence_url': initdata['aa_evidence_url'],
        'attestation_path': initdata['attestation_path'],
        'facts_url': 'https://facts-db.onrender.com',
        'workload_pubkey': None,
    }
    Path(args.runtime_config_path).write_text(json.dumps(runtime_config, indent=2) + '\n')


if __name__ == '__main__':
    main()
