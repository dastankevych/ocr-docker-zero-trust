#!/usr/bin/env python3
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--workload-id', required=True)
    parser.add_argument('--repo-url', required=True)
    parser.add_argument('--project-repo-url', required=True)
    parser.add_argument('--release-tag', required=True)
    parser.add_argument('--commit-sha', required=True)
    parser.add_argument('--oci-image-digest', required=True)
    parser.add_argument('--eif-path', required=True)
    parser.add_argument('--describe-eif-path', required=True)
    parser.add_argument('--release-url', required=True)
    parser.add_argument('--nitro-cli-version', required=True)
    parser.add_argument('--nitro-cli-source-repo', required=True)
    parser.add_argument('--nitro-cli-source-tag', required=True)
    parser.add_argument('--docker-version', default='')
    parser.add_argument('--rust-version', default='')
    parser.add_argument('--cargo-version', default='')
    parser.add_argument('--output-path', required=True)
    args = parser.parse_args()

    describe_path = Path(args.describe_eif_path)
    describe = json.loads(describe_path.read_text())
    measurements = describe.get('Measurements') or describe.get('measurements') or {}

    def read_pcr(name: str) -> str | None:
        value = measurements.get(name.upper()) or describe.get(name) or (describe.get('eif_pcrs') or {}).get(name)
        return value.lower() if isinstance(value, str) else None

    pcr0 = read_pcr('pcr0')
    pcr1 = read_pcr('pcr1')
    pcr2 = read_pcr('pcr2')
    pcr8 = read_pcr('pcr8')

    if not (pcr0 and pcr1 and pcr2):
        raise SystemExit('Missing PCRs in describe-eif output')

    build_env = {}
    if args.docker_version:
        build_env['docker_version'] = args.docker_version
    if args.rust_version:
        build_env['rust_version'] = args.rust_version
    if args.cargo_version:
        build_env['cargo_version'] = args.cargo_version

    data = {
        'workload_id': args.workload_id,
        'repo_url': args.repo_url,
        'project_repo_url': args.project_repo_url,
        'release_tag': args.release_tag,
        'commit_sha': args.commit_sha,
        'oci_image_digest': args.oci_image_digest,
        'eif_sha256': sha256_file(Path(args.eif_path)),
        'describe_eif_sha256': sha256_file(describe_path),
        'nitro_cli_version': args.nitro_cli_version,
        'nitro_cli_source_repo': args.nitro_cli_source_repo,
        'nitro_cli_source_tag': args.nitro_cli_source_tag,
        'build_timestamp': dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
        'pcr0': pcr0,
        'pcr1': pcr1,
        'pcr2': pcr2,
        'pcr8': pcr8,
        'release_url': args.release_url,
    }
    if build_env:
        data['build_environment'] = build_env

    Path(args.output_path).write_text(json.dumps(data, indent=2) + '\n')


if __name__ == '__main__':
    main()
