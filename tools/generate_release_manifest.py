#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path


def stable_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')


def sha256_hex_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def load_service_config(path: Path) -> dict:
    config: dict[str, object] = {}
    current_section: str | None = None
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        if line.endswith(':') and ':' not in line[:-1]:
            current_section = line[:-1]
            config[current_section] = {}
            continue
        key, _, value = raw_line.partition(':')
        if not _:
            continue
        key = key.strip()
        value = value.strip()
        if current_section and raw_line.startswith('  '):
            section = config.setdefault(current_section, {})
            if isinstance(section, dict):
                section[key] = value
        else:
            current_section = None
            config[key] = value
    return config


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--service-config', required=True)
    parser.add_argument('--provenance', required=True)
    parser.add_argument('--release-url', required=True)
    parser.add_argument('--coco-image-digest', required=True)
    parser.add_argument('--coco-initdata-path', required=True)
    parser.add_argument('--manifest-path', required=True)
    parser.add_argument('--coco-runtime-config-path', required=True)
    args = parser.parse_args()

    service_config = load_service_config(Path(args.service_config))
    provenance = json.loads(Path(args.provenance).read_text())
    coco = service_config.get('coco', {}) if isinstance(service_config.get('coco'), dict) else {}

    release_id = provenance['release_tag']
    service = service_config.get('service') or provenance['repo_url'].rstrip('/').split('/')[-1]
    initdata_hash = sha256_file(Path(args.coco_initdata_path))
    identity_hint = f"coco_image_initdata:{args.coco_image_digest}:{initdata_hash}"

    runtime_config = {
        'service': service,
        'release_id': release_id,
        'platform': coco.get('platform', 'aws_coco_snp'),
        'image_digest': args.coco_image_digest,
        'initdata_hash': initdata_hash,
        'identity_hint': identity_hint,
        'aa_evidence_url': coco.get('aa_evidence_url', 'http://127.0.0.1:8006/aa/evidence'),
        'attestation_path': coco.get('attestation_path', '/.well-known/attestation'),
        'facts_url': 'https://facts-db.onrender.com',
        'workload_pubkey': None,
    }

    manifest = {
        'schema_version': 1,
        'service': service,
        'release_id': release_id,
        'repo_url': provenance['repo_url'],
        'project_repo_url': provenance['project_repo_url'],
        'release_url': args.release_url,
        'source_image_digest': provenance['oci_image_digest'],
        'source_container': {
            'image_digest': provenance['oci_image_digest'],
            'dockerfile': 'Dockerfile',
            'lockfile': 'Cargo.lock',
            'description': 'Canonical source container. Nitro EIF and CoCo workload deployment are lowered from this container image/build context.',
            'coco_image_ref': 'coco-image-ref.txt',
        },
        'legacy_workload_id': provenance['workload_id'],
        'canonical': True,
        'notes': f"Canonical release manifest for {release_id} from {provenance['repo_url']}",
        'accepted_realizations': [
            {
                'platform': 'aws_nitro_eif',
                'identity': {
                    'type': 'eif_pcr_set',
                    'value': {
                        'pcr0': provenance['pcr0'],
                        'pcr1': provenance['pcr1'],
                        'pcr2': provenance['pcr2'],
                        'pcr8': provenance.get('pcr8'),
                    },
                },
                'assets': {
                    'eif': 'ztbrowser-enclave.eif',
                    'describe_eif': 'describe-eif.json',
                    'provenance': 'provenance.json',
                },
                'lowered_from': {
                    'type': 'source_container',
                    'image_digest': provenance['oci_image_digest'],
                },
            },
            {
                'platform': runtime_config['platform'],
                'identity': {
                    'type': 'coco_image_initdata',
                    'value': {
                        'image_digest': args.coco_image_digest,
                        'initdata_hash': initdata_hash,
                    },
                },
                'assets': {
                    'runtime_config': 'coco-runtime-config.json',
                    'initdata': 'coco-initdata.json',
                    'image_digest': 'coco-image-digest.txt',
                    'image_ref': 'coco-image-ref.txt',
                    'image_oci_archive': 'coco-workload.oci.tar',
                },
                'lowered_from': {
                    'type': 'source_container',
                    'image_digest': provenance['oci_image_digest'],
                },
            },
        ],
    }

    Path(args.coco_runtime_config_path).write_text(json.dumps(runtime_config, indent=2) + '\n')
    Path(args.manifest_path).write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    main()
