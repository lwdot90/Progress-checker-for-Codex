#!/usr/bin/env python3
"""Pure fixture/mocked-process packaging regressions; no native executable launched."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import stat
import subprocess
from types import SimpleNamespace
import tarfile
import tempfile
import unittest
from unittest.mock import patch, Mock

SCRIPTS = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), SCRIPTS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MAC = load('package-macos')
WIN = load('package-windows')
RELEASE = load('check-release-candidate')


class NativeImageTests(unittest.TestCase):
    def test_macho_architecture_and_wrong_format(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'binary'
            for cpu, architecture in ((0x01000007, 'x86_64'), (0x0100000c, 'aarch64')):
                path.write_bytes(b'\xcf\xfa\xed\xfe' + struct.pack('<I', cpu))
                self.assertEqual(MAC.macho_arch(path), architecture)
            for header in (b'\x7fELF0000', b'\xcf\xfa\xed\xfe' + struct.pack('<I', 1), b'MZ'):
                path.write_bytes(header)
                with self.assertRaises(ValueError):
                    MAC.macho_arch(path)

    def test_image_symlinks_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'target'
            target.write_bytes(b'MZ')
            alias = Path(directory) / 'alias'
            alias.symlink_to(target)
            for inspect in (MAC.macho_arch, WIN.windows_image):
                with self.assertRaises(ValueError):
                    inspect(alias)

    def test_pe_requires_x86_64_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'binary.exe'
            header = bytearray(64)
            header[:2] = b'MZ'
            struct.pack_into('<I', header, 60, 64)
            path.write_bytes(header + b'PE\x00\x00\x64\x86')
            WIN.windows_image(path)
            for signature in (b'PE\x00\x00\x4c\x01', b'ELFxxx', b''):
                path.write_bytes(header + signature)
                with self.assertRaises(ValueError):
                    WIN.windows_image(path)

    def test_mac_versions_mocked_without_launch(self):
        child = Mock(pid=12345)
        child.wait.return_value = 0
        child.stdout.fileno.return_value = 99
        responses = [b'progress-checker 0.5.0-dev\n', b'', b'progress-checker-mcp 0.5.0-dev\n', b'']
        with patch.object(MAC.subprocess, 'Popen', return_value=child) as launch, patch.object(MAC.select, 'select', return_value=([child.stdout], [], [])), patch.object(MAC.os, 'read', side_effect=responses), patch.object(MAC.os, 'killpg'):
            MAC.native_versions(Path('/fixture'), '0.5.0-dev')
            self.assertEqual(launch.call_count, 2)
            self.assertTrue(all(call.kwargs['start_new_session'] for call in launch.call_args_list))
        for payload in (b'wrong-version\n', b'x' * 513):
            with patch.object(MAC.subprocess, 'Popen', return_value=child), patch.object(MAC.select, 'select', return_value=([child.stdout], [], [])), patch.object(MAC.os, 'read', side_effect=[payload, b'']), patch.object(MAC.os, 'killpg'):
                with self.assertRaises(ValueError):
                    MAC.native_versions(Path('/fixture'), '0.5.0-dev')

    def test_mac_version_timeout_propagates(self):
        child = Mock(pid=12345)
        child.wait.return_value = 0
        with patch.object(MAC.subprocess, 'Popen', return_value=child), patch.object(MAC.select, 'select', return_value=([], [], [])), patch.object(MAC.os, 'killpg') as terminate:
            with self.assertRaises(subprocess.TimeoutExpired):
                MAC.native_versions(Path('/fixture'), '0.5.0-dev')
            terminate.assert_called_once()

    def test_mac_runtime_identity_rejects_untrusted_and_oversized_files(self):
        valid = dict(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_size=3,
                     st_dev=1, st_ino=2, st_mtime_ns=3, st_ctime_ns=4)
        for changes in ({'st_uid': 1000}, {'st_mode': stat.S_IFREG | 0o664},
                        {'st_size': 256 * 1024 * 1024 + 1}, {'st_mode': stat.S_IFDIR | 0o755}):
            path = unittest.mock.Mock()
            path.stat.return_value = SimpleNamespace(**(valid | changes))
            path.is_symlink.return_value = False
            with self.assertRaises(ValueError):
                MAC.runtime_identity(path)
            path.open.assert_not_called()
        path = unittest.mock.Mock()
        path.stat.side_effect = FileNotFoundError('missing dyld')
        with self.assertRaises(FileNotFoundError):
            MAC.runtime_identity(path)

    def test_mac_runtime_read_growth_and_replacement_are_refused(self):
        valid = dict(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_size=3,
                     st_dev=1, st_ino=2, st_mtime_ns=3, st_ctime_ns=4)
        for data, after, message in ((b'1234', valid, 'grew'),
                                      (b'123', valid | {'st_ino': 99}, 'changed')):
            path = unittest.mock.Mock()
            path.stat.side_effect = [SimpleNamespace(**valid), SimpleNamespace(**after)]
            path.is_symlink.return_value = False
            path.open.return_value = io.BytesIO(data)
            with self.assertRaisesRegex(ValueError, message):
                MAC.runtime_identity(path)

    def test_native_packagers_refuse_wrong_host_before_launch(self):
        with patch('sys.argv', ['package-macos', '--target', 'x86_64-apple-darwin', '--binary-dir', '/fixture']), patch.object(MAC.platform, 'system', return_value='Linux'), patch.object(MAC.subprocess, 'run') as launch:
            with self.assertRaises(SystemExit):
                MAC.main()
            launch.assert_not_called()
        with patch('sys.argv', ['package-windows', '--bin-dir', '/fixture']), patch.object(WIN.os, 'name', 'posix'), patch.object(WIN.subprocess, 'run') as launch:
            with self.assertRaises(SystemExit):
                WIN.main()
            launch.assert_not_called()


class ReleaseArchiveTests(unittest.TestCase):
    def archive(self, directory, entries):
        archive = Path(directory) / 'candidate.tar.gz'
        with tarfile.open(archive, 'w:gz') as bundle:
            for name, payload, kind in entries:
                member = tarfile.TarInfo(name)
                if kind == 'link':
                    member.type = tarfile.SYMTYPE
                    member.linkname = '/outside'
                    bundle.addfile(member)
                else:
                    member.size = len(payload)
                    bundle.addfile(member, io.BytesIO(payload))
        return archive

    def inspect(self, archive, sha=None):
        return RELEASE.inspect_archive(archive, sha or hashlib.sha256(archive.read_bytes()).hexdigest(), '0.5.0-dev')

    def test_wrong_identity_traversal_symlinks_and_duplicates_refused(self):
        prefix = 'progress-checker-0.5.0-dev-linux-x86_64/'
        with tempfile.TemporaryDirectory() as directory:
            archive = self.archive(directory, [(prefix + 'README.md', b'a', 'file')])
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                self.inspect(archive, '0' * 64)
            for entries, message in (([('../escape', b'', 'file')], 'Unsafe'), ([(prefix + '../escape', b'', 'file')], 'Unsafe'), ([(prefix + 'alias', b'', 'link')], 'Links'), ([(prefix + 'a', b'a', 'file'), (prefix + 'a', b'b', 'file')], 'Duplicate')):
                with self.assertRaisesRegex(ValueError, message):
                    self.inspect(self.archive(directory, entries))

    def test_oversized_member_refused_without_allocating_payload(self):
        member = tarfile.TarInfo('progress-checker-0.5.0-dev-linux-x86_64/big')
        member.size = 256 * 1024 * 1024 + 1
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'placeholder'
            archive.write_bytes(b'fixture')
            with patch.object(RELEASE.tarfile, 'open') as opening:
                opening.return_value.__enter__.return_value = [member]
                with self.assertRaisesRegex(ValueError, 'size cap'):
                    self.inspect(archive)

    def test_compressed_aggregate_bomb_refused_without_large_allocations(self):
        members = []
        for index in range(3):
            member = tarfile.TarInfo('progress-checker-0.5.0-dev-linux-x86_64/file' + str(index))
            member.size = 256 * 1024 * 1024
            members.append(member)
        class SizedPayload:
            def __len__(self):
                return 256 * 1024 * 1024
        bundle = Mock()
        bundle.__iter__ = Mock(return_value=iter(members))
        stream = Mock()
        stream.read.return_value = SizedPayload()
        context = Mock()
        context.__enter__ = Mock(return_value=stream)
        context.__exit__ = Mock(return_value=False)
        bundle.extractfile.return_value = context
        with patch.object(RELEASE, 'bounded_archive_hash', return_value='a' * 64), patch.object(RELEASE.tarfile, 'open') as opening:
            opening.return_value.__enter__.return_value = bundle
            with self.assertRaisesRegex(ValueError, 'aggregate size cap'):
                RELEASE.inspect_archive(Path('/fixture'), 'a' * 64, '0.5.0-dev')

    def test_archive_growth_and_metadata_mutation_refused(self):
        before = dict(st_size=3, st_dev=1, st_ino=2, st_mtime_ns=3, st_ctime_ns=4)
        for data, after, message in ((b'abcd', before, 'grew'), (b'abc', before | {'st_ino': 99}, 'changed')):
            path = Mock()
            path.stat.side_effect = [SimpleNamespace(**before), SimpleNamespace(**after)]
            path.is_symlink.return_value = False
            path.is_file.return_value = True
            path.open.return_value = io.BytesIO(data)
            with self.assertRaisesRegex(ValueError, message):
                RELEASE.bounded_archive_hash(path)

    def test_malformed_checksum_schema_refused(self):
        files = {name: b'fixture' for name in RELEASE.REQUIRED}
        files['checksums.json'] = b'[]'
        prefix = 'progress-checker-0.5.0-dev-linux-x86_64/'
        with tempfile.TemporaryDirectory() as directory:
            archive = self.archive(directory, [(prefix + name, data, 'file') for name, data in files.items()])
            with self.assertRaisesRegex(ValueError, 'Checksum inventory'):
                self.inspect(archive)

    def test_version_mismatch_after_valid_checksums_refused(self):
        files = {name: b'fixture' for name in RELEASE.REQUIRED}
        files['plugin/plugin.json'] = json.dumps({'name': 'progress-checker', 'version': '0.4.0-dev'}).encode()
        files['checksums.json'] = json.dumps({name: hashlib.sha256(data).hexdigest() for name, data in files.items()}).encode()
        prefix = 'progress-checker-0.5.0-dev-linux-x86_64/'
        with tempfile.TemporaryDirectory() as directory:
            archive = self.archive(directory, [(prefix + name, data, 'file') for name, data in files.items()])
            with self.assertRaisesRegex(ValueError, 'identity/version'):
                self.inspect(archive)


if __name__ == '__main__':
    unittest.main()
