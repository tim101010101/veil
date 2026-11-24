#!/usr/bin/env python3
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('release', Path(__file__).with_name('release.py'))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
COMMIT = 'a' * 40


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.target = 'aarch64-apple-darwin'
        self.version = release.version()

    def archive(self, target=None, **changes):
        target = target or self.target
        binary = ('synthetic test executable: ' + target).encode()
        info = dict(name='veil', version=self.version, target=target, commit=COMMIT,
                    binary_sha256=release.digest(binary))
        info.update(changes)
        repository = release.tomllib.loads((release.PROJECT / 'Cargo.toml').read_text())['workspace']['package']['repository']
        payloads = {'veil': binary, 'LICENSE': (release.PROJECT / 'LICENSE').read_bytes(),
                    'BUILD-INFO.json': json.dumps(info).encode(),
                    'THIRD-PARTY-NOTICES.txt': f'Corresponding source: {repository}/tree/{COMMIT}'.encode()}
        path = self.root / f'veil-{self.version}-{target}.tar.gz'
        release.write_archive(path, payloads, 1700000000)
        return path

    def tool_output(self, args, **kwargs):
        if args[0] == 'file':
            data = Path(args[-1]).read_bytes()
            if b'aarch64-apple-darwin' in data:
                return 'Mach-O 64-bit executable arm64'
            if b'x86_64-apple-darwin' in data:
                return 'Mach-O 64-bit executable x86_64'
            if b'aarch64-unknown-linux-musl' in data:
                return 'ELF 64-bit LSB executable, ARM aarch64, statically linked'
            return 'ELF 64-bit LSB executable, x86-64, statically linked'
        return 'No dynamic section or program interpreter'

    def verify(self, path, **kwargs):
        with mock.patch.object(release.subprocess, 'check_output', side_effect=self.tool_output):
            return release.verify_archive(path, self.target, self.version, kwargs.get('commit', COMMIT))

    def test_only_matching_stable_tags_are_accepted(self):
        release.check_tag('v' + self.version)
        for tag in ['0.4.2', 'v00.4.2', 'v0.4.2-rc.1', 'v99.0.0', '../v0.4.2']:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.check_tag(tag)

    def test_normalized_archive_round_trip(self):
        path = self.archive()
        self.assertEqual(self.verify(path)['commit'], COMMIT)
        with tarfile.open(path) as archive:
            self.assertEqual({m.name for m in archive}, release.MEMBERS)

    def test_archives_are_deterministic_and_not_overwritten(self):
        path = self.archive()
        contents = path.read_bytes()
        with tarfile.open(path) as archive:
            payloads = {m.name: archive.extractfile(m).read() for m in archive}
        second = self.root / 'second.tar.gz'
        release.write_archive(second, payloads, 1700000000)
        self.assertEqual(contents, second.read_bytes())
        with self.assertRaisesRegex(ValueError, 'overwrite'):
            release.write_archive(path, payloads, 1700000000)

    def test_all_four_targets_are_required_and_checksums_are_repeatable(self):
        for target in release.TARGETS:
            self.archive(target)
        with mock.patch.object(release.subprocess, 'check_output', side_effect=self.tool_output):
            release.verify_directory(self.root, COMMIT)
            first = (self.root / 'SHA256SUMS').read_text()
            release.verify_directory(self.root, COMMIT)
        self.assertEqual(first, (self.root / 'SHA256SUMS').read_text())
        self.assertEqual(len(first.splitlines()), 4)

    def test_incomplete_or_extra_assets_refuse_publication(self):
        self.archive()
        with self.assertRaisesRegex(ValueError, 'all four'):
            release.verify_directory(self.root, COMMIT)
        for target in release.TARGETS:
            if target != self.target:
                self.archive(target)
        (self.root / 'unexpected.txt').write_text('not a release asset')
        with self.assertRaisesRegex(ValueError, 'extra assets'):
            release.verify_directory(self.root, COMMIT)
        self.assertFalse((self.root / 'SHA256SUMS').exists())

    def test_corrupted_checksum_is_rejected(self):
        path = self.archive()
        path.with_name(path.name + '.sha256').write_text('incorrect checksum')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            self.verify(path)

    def test_wrong_commit_or_target_is_rejected(self):
        path = self.archive(commit='b' * 40)
        with self.assertRaisesRegex(ValueError, 'metadata'):
            self.verify(path)

    def test_wrong_binary_digest_is_rejected(self):
        path = self.archive(binary_sha256='0' * 64)
        with self.assertRaisesRegex(ValueError, 'Binary does not match'):
            self.verify(path)

    def test_symlink_and_path_traversal_members_are_rejected(self):
        path = self.archive()
        for name in ['veil', '../escape']:
            with self.subTest(name=name):
                with gzip.open(path, 'wb') as compressed:
                    with tarfile.open(fileobj=compressed, mode='w') as archive:
                        for entry in sorted(release.MEMBERS):
                            member = tarfile.TarInfo(name if entry == 'veil' else entry)
                            member.uid = member.gid = 0
                            member.uname = member.gname = 'root'
                            member.mode = 0o755 if entry == 'veil' else 0o644
                            if entry == 'veil':
                                member.type = tarfile.SYMTYPE
                                member.linkname = '/outside'
                            archive.addfile(member, io.BytesIO())
                path.with_name(path.name + '.sha256').write_text(f'{release.digest(path.read_bytes())}  {path.name}\n')
                with self.assertRaises(ValueError):
                    self.verify(path)

    def test_duplicate_archive_members_are_rejected(self):
        path = self.archive()
        with gzip.open(path, 'wb') as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as archive:
                for _ in range(5):
                    archive.addfile(tarfile.TarInfo('veil'), io.BytesIO())
        path.with_name(path.name + '.sha256').write_text(f'{release.digest(path.read_bytes())}  {path.name}\n')
        with self.assertRaisesRegex(ValueError, 'Unexpected release archive member'):
            self.verify(path)

    def test_build_machine_paths_are_rejected(self):
        with mock.patch.dict(os.environ, HOME='/home/synthetic-builder'):
            with self.assertRaisesRegex(ValueError, 'build-machine path'):
                release.check_binary(b'binary /home/synthetic-builder/secret', self.target)

    def test_wrong_architecture_is_rejected(self):
        with mock.patch.object(release.subprocess, 'check_output', return_value='Mach-O 64-bit executable x86_64'):
            with self.assertRaisesRegex(ValueError, 'format'):
                release.check_binary(b'synthetic binary', self.target)

    def test_linux_dynamic_dependencies_are_rejected(self):
        def output(args, **kwargs):
            if args[0] == 'file':
                return 'ELF 64-bit LSB executable, x86-64'
            return 'INTERP' if '--program-headers' in args else '(NEEDED) libc.so.6'
        with mock.patch.object(release.subprocess, 'check_output', side_effect=output):
            with self.assertRaisesRegex(ValueError, 'not static'):
                release.check_binary(b'synthetic binary', 'x86_64-unknown-linux-musl')


if __name__ == '__main__':
    unittest.main()
