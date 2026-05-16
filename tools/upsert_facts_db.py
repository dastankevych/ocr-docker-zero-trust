#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def normalize_db(payload: object) -> dict:
    if isinstance(payload, dict):
        releases = payload.get('releases')
        if isinstance(releases, list):
            return {
                'schema_version': int(payload.get('schema_version', 2)),
                'releases': releases,
            }
        raise SystemExit('Facts DB object is missing a releases list')

    if isinstance(payload, list):
        releases = []
        for row in payload:
            if not isinstance(row, dict):
                continue
            releases.append(
                {
                    'service': row.get('repo_url', '').rstrip('/').split('/')[-1] or row.get('workload_id', 'unknown-service'),
                    'release_id': row.get('release_tag') or row.get('workload_id'),
                    'repo_url': row.get('repo_url'),
                    'project_repo_url': row.get('project_repo_url'),
                    'release_url': row.get('release_url'),
                    'source_image_digest': row.get('oci_image_digest'),
                    'legacy_workload_id': row.get('workload_id'),
                    'canonical': bool(row.get('canonical', False)),
                    'notes': row.get('notes'),
                    'accepted_realizations': [
                        {
                            'platform': 'aws_nitro_eif',
                            'identity': {
                                'type': 'eif_pcr_set',
                                'value': {
                                    'pcr0': row.get('pcr0'),
                                    'pcr1': row.get('pcr1'),
                                    'pcr2': row.get('pcr2'),
                                    'pcr8': row.get('pcr8'),
                                },
                            },
                        }
                    ],
                    'legacy_projection': row,
                }
            )
        return {'schema_version': 2, 'releases': releases}

    raise SystemExit('Facts DB must be a JSON array or object')


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--facts-db', required=True)
    parser.add_argument('--facts-row', required=True)
    args = parser.parse_args()

    db_path = Path(args.facts_db)
    release = json.loads(Path(args.facts_row).read_text())
    db = normalize_db(json.loads(db_path.read_text()))

    updated = False
    for index, existing in enumerate(db['releases']):
        if existing.get('service') == release['service'] and existing.get('release_id') == release['release_id']:
            db['releases'][index] = release
            updated = True
            break
    if not updated:
        db['releases'].append(release)

    db['releases'].sort(key=lambda item: (str(item.get('service', '')), str(item.get('release_id', ''))))
    db_path.write_text(json.dumps(db, indent=2) + '\n')


if __name__ == '__main__':
    main()
