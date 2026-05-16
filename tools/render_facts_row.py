#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--release-manifest', required=True)
    args = parser.parse_args()
    manifest = json.loads(Path(args.release_manifest).read_text())
    nitro = next(
        entry
        for entry in manifest['accepted_realizations']
        if entry.get('platform') == 'aws_nitro_eif' and entry.get('identity', {}).get('type') == 'eif_pcr_set'
    )
    release = {
        'service': manifest['service'],
        'release_id': manifest['release_id'],
        'repo_url': manifest['repo_url'],
        'project_repo_url': manifest['project_repo_url'],
        'release_url': manifest['release_url'],
        'source_image_digest': manifest['source_image_digest'],
        'legacy_workload_id': manifest.get('legacy_workload_id'),
        'canonical': bool(manifest.get('canonical', True)),
        'notes': manifest.get('notes'),
        'accepted_realizations': manifest['accepted_realizations'],
        'legacy_projection': {
            'workload_id': manifest.get('legacy_workload_id') or f"{manifest['service']}-aws-nitro",
            'repo_url': manifest['repo_url'],
            'project_repo_url': manifest['project_repo_url'],
            'oci_image_digest': manifest['source_image_digest'],
            'pcr0': nitro['identity']['value']['pcr0'],
            'pcr1': nitro['identity']['value']['pcr1'],
            'pcr2': nitro['identity']['value']['pcr2'],
            'pcr8': nitro['identity']['value'].get('pcr8'),
            'release_tag': manifest['release_id'],
            'release_url': manifest['release_url'],
            'canonical': bool(manifest.get('canonical', True)),
            'notes': manifest.get('notes'),
        },
    }
    print(json.dumps(release, indent=2))


if __name__ == '__main__':
    main()
