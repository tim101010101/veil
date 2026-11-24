#!/usr/bin/env python3
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import tomllib

PROJECT = Path(__file__).resolve().parent.parent
TARGETS = {
    'aarch64-apple-darwin': ('Mach-O 64-bit', False),
    'x86_64-apple-darwin': ('Mach-O 64-bit', False),
    'x86_64-unknown-linux-musl': ('ELF 64-bit LSB', True),
    'aarch64-unknown-linux-musl': ('ELF 64-bit LSB', True),
}
MEMBERS = {'veil', 'LICENSE', 'BUILD-INFO.json', 'THIRD-PARTY-NOTICES.txt'}
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_UNPACKED = 160 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def version():
    return tomllib.loads((PROJECT / 'Cargo.toml').read_text())['workspace']['package']['version']


def check_tag(tag):
    require(re.fullmatch(r'v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', tag),
            'Release tags must use stable vX.Y.Z versions')
    require(tag == 'v' + version(), 'Release tag does not match the workspace version')
    require((PROJECT / 'docs/releases' / (version() + '.md')).is_file(), 'Reviewed release notes are missing')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check_binary(data, target):
    require(target in TARGETS, 'Unsupported release target')
    for name in ('GITHUB_WORKSPACE', 'HOME'):
        value = os.environ.get(name, '')
        if len(value) > 1:
            require(value.encode() not in data, 'Binary embeds a build-machine path')
    require(b'/Users/' not in data and b'/home/runner/' not in data, 'Binary embeds an unnormalized home path')
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'veil'
        path.write_bytes(data)
        description = subprocess.check_output(['file', '--brief', str(path)], text=True)
        prefix, linux = TARGETS[target]
        require(prefix in description, 'Binary format does not match the release target')
        if not linux:
            architecture = 'arm64' if target.startswith('aarch64-') else 'x86_64'
            require(architecture in description and 'executable' in description,
                    'Binary format does not match the release target')
        if linux:
            architecture = 'x86-64' if target.startswith('x86_64-') else 'ARM aarch64'
            require(architecture in description, 'Linux binary architecture does not match its target')
            headers = subprocess.check_output(['readelf', '--program-headers', str(path)], text=True)
            dynamic = subprocess.check_output(['readelf', '--dynamic', str(path)], text=True)
            require('INTERP' not in headers and '(NEEDED)' not in dynamic, 'Linux release binary is not static')


def write_archive(path, payloads, epoch):
    require(not path.exists(), 'Refusing to overwrite an existing release archive')
    with path.open('xb') as stream:
        with gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=epoch) as compressed:
            with tarfile.open(mode='w', fileobj=compressed, format=tarfile.USTAR_FORMAT) as archive:
                for name in sorted(payloads):
                    data = payloads[name]
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    member.mode = 0o755 if name == 'veil' else 0o644
                    member.uid = member.gid = 0
                    member.uname = member.gname = 'root'
                    member.mtime = epoch
                    archive.addfile(member, io.BytesIO(data))
    path.with_name(path.name + '.sha256').write_text(f'{digest(path.read_bytes())}  {path.name}\n')


def verify_archive(path, target, expected_version, commit):
    require(path.name == f'veil-{expected_version}-{target}.tar.gz', 'Unexpected release archive filename')
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_ARCHIVE,
            'Invalid or oversized release archive')
    checksum = path.with_name(path.name + '.sha256')
    require(not checksum.is_symlink(), 'Release checksums must be regular files')
    require(checksum.read_text() == f'{digest(path.read_bytes())}  {path.name}\n', 'Release checksum mismatch')
    with gzip.open(path, 'rb') as stream:
        data = stream.read(MAX_UNPACKED + 1)
    require(len(data) <= MAX_UNPACKED, 'Unpacked release exceeds the size limit')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        members = []
        for member in archive:
            members.append(member)
            require(len(members) <= len(MEMBERS), 'Unexpected release archive member')
        require(len(members) == len(MEMBERS) and {m.name for m in members} == MEMBERS,
                'Release archive must contain exactly the documented files')
        for member in members:
            require(member.isfile() and member.uid == 0 and member.gid == 0
                    and member.uname == 'root' and member.gname == 'root', 'Unsafe release archive metadata')
            require(member.mode == (0o755 if member.name == 'veil' else 0o644), 'Unexpected release file mode')
        require(len({m.mtime for m in members}) == 1, 'Inconsistent release timestamps')
        payloads = {member.name: archive.extractfile(member).read() for member in members}
    info = json.loads(payloads['BUILD-INFO.json'])
    require(isinstance(info, dict) and info.get('name') == 'veil' and info.get('version') == expected_version
            and info.get('commit') == commit and info.get('target') == target,
            'Release build metadata does not match the intended source and target')
    require(info.get('binary_sha256') == digest(payloads['veil']), 'Binary does not match its build metadata')
    require(payloads['LICENSE'] == (PROJECT / 'LICENSE').read_bytes(), 'Release license does not match the source')
    repository = tomllib.loads((PROJECT / 'Cargo.toml').read_text())['workspace']['package']['repository']
    require(f'{repository}/tree/{commit}'.encode() in payloads['THIRD-PARTY-NOTICES.txt'],
            'Dependency notices do not identify the corresponding source')
    check_binary(payloads['veil'], target)
    return info


def package(target, notices, output):
    require(target in TARGETS, 'Unsupported release target')
    commit = os.environ['VEIL_BUILD_COMMIT']
    require(re.fullmatch(r'[0-9a-f]{40}', commit), 'A full source commit ID is required')
    binary = PROJECT / 'target' / target / 'release/veil'
    subprocess.run([str(binary), '--help'], check=True, stdout=subprocess.DEVNULL)
    info = json.loads(subprocess.check_output([str(binary), '--json', 'version'], text=True))
    require(info.get('name') == 'veil' and info.get('version') == version() and info.get('commit') == commit,
            'CLI smoke test returned unexpected build metadata')
    data = binary.read_bytes()
    info.update(target=target, ref=os.environ['GITHUB_REF'], binary_sha256=digest(data))
    payloads = {
        'veil': data,
        'LICENSE': (PROJECT / 'LICENSE').read_bytes(),
        'BUILD-INFO.json': (json.dumps(info, indent=2) + '\n').encode(),
        'THIRD-PARTY-NOTICES.txt': notices.read_bytes(),
    }
    output.mkdir(parents=True, exist_ok=True)
    path = output / f'veil-{version()}-{target}.tar.gz'
    write_archive(path, payloads, int(os.environ['SOURCE_DATE_EPOCH']))
    verify_archive(path, target, version(), commit)
    print(f'Verified {path.name}')


def verify_directory(directory, commit):
    require(re.fullmatch(r'[0-9a-f]{40}', commit), 'A full source commit ID is required')
    expected = {f'veil-{version()}-{target}.tar.gz{suffix}' for target in TARGETS for suffix in ('', '.sha256')}
    actual = {p.name for p in directory.iterdir()}
    require(actual in (expected, expected | {'SHA256SUMS'}), 'The release must contain all four targets and no extra assets')
    lines = []
    for target in sorted(TARGETS):
        path = directory / f'veil-{version()}-{target}.tar.gz'
        verify_archive(path, target, version(), commit)
        lines.append(f'{digest(path.read_bytes())}  {path.name}\n')
    checksums = directory / 'SHA256SUMS'
    text = ''.join(lines)
    if checksums.exists():
        require(not checksums.is_symlink() and checksums.read_text() == text, 'Aggregate checksums do not match the archives')
    checksums.write_text(text)
    print('Verified all four release archives and wrote SHA256SUMS')


def main():
    parser = argparse.ArgumentParser(description='Package and verify Veil CLI releases')
    commands = parser.add_subparsers(dest='command', required=True)
    tag = commands.add_parser('check-tag')
    tag.add_argument('tag')
    pack = commands.add_parser('package')
    pack.add_argument('--target', choices=TARGETS, required=True)
    pack.add_argument('--notices', type=Path, required=True)
    pack.add_argument('--output', type=Path, required=True)
    verify = commands.add_parser('verify')
    verify.add_argument('--directory', type=Path, required=True)
    verify.add_argument('--commit', required=True)
    args = parser.parse_args()
    if args.command == 'check-tag':
        check_tag(args.tag)
    elif args.command == 'package':
        package(args.target, args.notices, args.output)
    else:
        verify_directory(args.directory, args.commit)


if __name__ == '__main__':
    main()
