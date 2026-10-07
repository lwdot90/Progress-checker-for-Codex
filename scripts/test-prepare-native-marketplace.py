#!/usr/bin/env python3
"""Synthetic preparation tests: no installer, package executable, Git or network."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

SOURCE = Path(__file__).with_name('prepare-native-marketplace.py')
SPEC = importlib.util.spec_from_file_location('prepare_native_marketplace', SOURCE)
PREPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE)


class Preparation(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='pc-native-prepare-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.package = self.root / 'package'
        self.plugin = self.package / 'plugin'
        self.plugin.mkdir(parents=True)
        for name in ('LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md'):
            self.write(name, 'public legal material\n')
        for name in PREPARE.EXECUTABLES:
            text = 'import argparse\nparser = argparse.ArgumentParser()\nparser.add_argument("--state-dir", type=str)\n' if name == 'checker-global' else 'public executable fixture\n'
            self.write('bin/' + name, text, mode=0o755)
        self.write('plugin.json', json.dumps({
            '$schema': PREPARE.SCHEMA + '/plugin.schema.json',
            'name': 'progress-checker', 'version': '0.4.0-dev',
        }))
        self.write('skills/progress-checker/SKILL.md', 'Public workflow instructions\n')
        license_data = b'preserved dependency license\n'
        self.write('third-party/crates/example/LICENSE', license_data)
        self.write('third-party/rust/LICENSE', license_data)
        digest = hashlib.sha256(license_data).hexdigest()
        self.write('third-party/inventory.json', json.dumps({
            'packages': [{'files_sha256': {'crates/example/LICENSE': digest}}],
            'rust_standard_library': {'files_sha256': {'rust/LICENSE': digest}},
        }))
        (self.package / 'install.py').write_text('raise RuntimeError("must never execute")\n')
        self.checksums()

    def write(self, name, data, mode=0o644):
        path = self.plugin / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode())
        path.chmod(mode)

    def checksums(self):
        paths = sorted(self.package.rglob('*'))
        value = {path.relative_to(self.package).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in paths if path.is_file() and path != self.package / 'checksums.json'}
        (self.package / 'checksums.json').write_text(json.dumps(value))

    def refused(self, text):
        output = self.root / 'refused'
        with self.assertRaisesRegex(ValueError, text):
            PREPARE.prepare_payload(self.package, output)
        self.assertFalse(output.exists())

    def test_payload_is_portable_reproducible_and_preserves_legal_bytes(self):
        self.write('mcp.json', '{"old": "/explicit/custom/state"}')
        self.checksums()
        first = PREPARE.prepare_payload(self.package, self.root / 'first')
        second = PREPARE.prepare_payload(self.package, self.root / 'second')
        self.assertEqual(first, second)
        target = self.root / 'first' / PREPARE.PLUGIN_PATH
        mcp = PREPARE.read_json(target / 'mcp.json')['mcpServers']['progress_checker']
        self.assertEqual(mcp, {'type': 'stdio', 'command': './bin/checker-global', 'args': []})
        self.assertEqual((target / 'third-party/crates/example/LICENSE').read_bytes(),
                         (self.plugin / 'third-party/crates/example/LICENSE').read_bytes())
        self.assertEqual((target / 'bin/checker-global').stat().st_mode & 0o777, 0o755)
        self.assertFalse((self.root / 'first/install.py').exists())
        self.assertNotIn(str(self.root), json.dumps(first))
        self.assertEqual(PREPARE.read_json(self.root / 'first/NATIVE_PAYLOAD.json'), first)

    def test_tampered_and_unlisted_package_files_refuse(self):
        self.write('LICENSE', 'changed')
        self.refused('checksum mismatch')
        self.checksums()
        self.write('extra.txt', 'not inventoried')
        self.refused('cover every payload file')

    def test_symlink_and_special_file_refuse_without_reading_target(self):
        outside = self.root / 'outside'
        outside.write_text('must not copy')
        (self.plugin / 'link').symlink_to(outside)
        self.refused('symlink or special file')
        (self.plugin / 'link').unlink()
        os.mkfifo(self.plugin / 'pipe')
        self.refused('symlink or special file')

    def test_private_directory_refuses(self):
        (self.plugin / '.codex').mkdir()
        self.refused('Excluded package path')

    def test_missing_binary_and_lost_executable_mode_refuse(self):
        binary = self.plugin / 'bin/progress-checker-mcp'
        binary.unlink()
        self.checksums()
        self.refused('missing required native files')
        self.write('bin/progress-checker-mcp', 'public fixture', mode=0o644)
        self.checksums()
        self.refused('Native executable must have mode 0755')

    def test_older_required_state_gateway_refuses(self):
        self.write('bin/checker-global', 'import argparse\nparser=argparse.ArgumentParser()\nparser.add_argument("--state-dir",required=True)\n', mode=0o755)
        self.checksums()
        self.refused('must support omitted --state-dir')

    def test_missing_inventory_license_refuses(self):
        (self.plugin / 'third-party/crates/example/LICENSE').unlink()
        self.checksums()
        self.refused('Dependency license inventory mismatch')

    def test_existing_output_is_preserved(self):
        output = self.root / 'existing'
        output.mkdir()
        sentinel = output / 'sentinel'
        sentinel.write_text('preserve')
        with self.assertRaisesRegex(ValueError, 'must not already exist'):
            PREPARE.prepare_payload(self.package, output)
        self.assertEqual(sentinel.read_text(), 'preserve')

    def test_output_inside_package_refuses_before_mutation(self):
        with self.assertRaisesRegex(ValueError, 'outside the input package'):
            PREPARE.prepare_payload(self.package, self.package / 'nested')
        self.assertFalse((self.package / 'nested').exists())

    def test_duplicate_checksums_refuse(self):
        (self.package / 'checksums.json').write_text('{"x":"a","x":"b"}')
        self.refused('Duplicate JSON key')

    def test_catalog_pins_exact_artifact_without_local_binding(self):
        sha = 'ABCDEF0123456789ABCDEF0123456789ABCDEF01'
        output = self.root / 'catalog'
        catalog = PREPARE.prepare_catalog(sha, PREPARE.SOURCE_URL, output)
        source = catalog['plugins'][0]['source']
        self.assertEqual(source, {'source': 'git-subdir', 'url': PREPARE.SOURCE_URL,
                                 'path': './' + PREPARE.PLUGIN_PATH, 'sha': sha.lower()})
        self.assertEqual(PREPARE.read_json(output / '.agents/plugins/marketplace.json'), catalog)
        self.assertFalse((output / PREPARE.PLUGIN_PATH).exists())

    def test_invalid_catalog_selectors_refuse_without_output(self):
        for sha, url in [('a' * 39, PREPARE.SOURCE_URL), ('z' * 40, PREPARE.SOURCE_URL),
                         ('a' * 40, 'https://user:secret@example.com/repo.git'),
                         ('a' * 40, 'https://example.com/repo.git#main'),
                         ('a' * 40, 'file:///tmp/repo'),
                         ('a' * 40, 'https://example.com/repo.git?token=value')]:
            with self.subTest(sha=sha, url=url):
                output = self.root / 'bad-catalog'
                with self.assertRaises(ValueError):
                    PREPARE.prepare_catalog(sha, url, output)
                self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
