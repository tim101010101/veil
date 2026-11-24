#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def cargo(*args):
    return subprocess.check_output(['cargo', '--color', 'never', *args], text=True)


def generate(package, target):
    metadata = json.loads(cargo('metadata', '--locked', '--format-version=1', '--filter-platform', target))
    tree = cargo('tree', '--locked', '--package', package, '--target', target,
                 '--edges', 'normal,build', '--prefix', 'none', '--format', '{p}')
    selected = {match.groups() for line in tree.splitlines()
                if (match := re.match(r'([A-Za-z0-9_-]+) v([^\s]+)', line))}
    root = next(p for p in metadata['packages'] if p['name'] == package and p['source'] is None)
    repository = root['repository']
    if not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Corresponding source must use a public GitHub repository')
    commit = os.environ.get('VEIL_BUILD_COMMIT', 'main')
    if commit != 'main' and not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('Source commit must be a full Git commit ID')
    output = [
        'Veil third-party notices',
        'Veil is AGPL-3.0-only. See LICENSE for its terms and warranty disclaimer.',
        f'Veil corresponding source and build instructions: {repository}/tree/{commit}',
        'Cargo.lock pins the dependency sources. Run cargo vendor --locked to download them.',
        'Exact source archives are listed below. Build-time dependencies are included.',
        'Third-party components retain their own licenses and copyright notices.',
        '',
    ]
    licenses = {}
    project = Path(__file__).resolve().parent.parent
    packages = sorted((p for p in metadata['packages']
                       if p['source'] and (p['name'], p['version']) in selected),
                      key=lambda p: (p['name'], p['version']))
    if not packages:
        raise ValueError('No third-party dependencies were resolved')
    for dependency in packages:
        if dependency['source'] != 'registry+https://github.com/rust-lang/crates.io-index':
            raise ValueError('Review non-crates.io dependency source before distribution')
        directory = Path(dependency['manifest_path']).resolve().parent
        files = {p for p in directory.iterdir() if p.is_file() and re.match(
            r'^(licen[cs]e|copying|copyright|notice)(?:$|[._-])', p.name, re.I)}
        if dependency.get('license_file'):
            files.add(directory / dependency['license_file'])
        declared = dependency['license'] or ''
        choice = declared
        if dependency['name'].startswith('bitwarden-') and 'GPL-3.0-only' in declared:
            files.add(project / 'licenses/bitwarden-gpl.txt')
            choice = 'GPL-3.0-only'
        elif dependency['repository'] == 'https://github.com/madsmtm/objc2' and 'MIT' in declared:
            files.add(project / 'licenses/objc2-mit.txt')
            choice = 'MIT'
        if not declared or not files:
            raise ValueError(f'Missing license evidence for {dependency["name"]} {dependency["version"]}')
        ids = []
        for path in sorted(files):
            resolved = path.resolve()
            if not (resolved.is_relative_to(directory) or resolved.is_relative_to(project / 'licenses')):
                raise ValueError('License file escapes its source directory')
            text = path.read_text()
            digest = hashlib.sha256(text.encode()).hexdigest()
            licenses[digest] = text
            ids.append(digest)
        output.extend([
            f'{dependency["name"]} {dependency["version"]}',
            f'Declared license: {declared}',
            f'Distribution license option: {choice}',
            'Authors: ' + '; '.join(dependency['authors']),
            f'Source: https://crates.io/api/v1/crates/{dependency["name"]}/{dependency["version"]}/download',
            'License text SHA256: ' + ', '.join(ids),
            '',
        ])
    for digest, text in sorted(licenses.items()):
        output.extend([f'===== License text {digest} =====', text, ''])
    return '\n'.join(output)


def main():
    parser = argparse.ArgumentParser(description='Bundle notices for locked public CLI dependencies')
    parser.add_argument('--package', default='veil-cli')
    parser.add_argument('--target', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(generate(args.package, args.target))


if __name__ == '__main__':
    main()
