#!/usr/bin/env python3
"""Behavioral version/package guard tests; invoked by approved engineering check."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from package_version import source_version, binary_versions

ROOT = Path(__file__).resolve().parent.parent


class VersionTests(unittest.TestCase):
    def test_actual_source_and_compiled_versions_match(self):
        version = source_version(ROOT)
        binary_versions(ROOT / '.local/checker-target/debug', version)
        inventory = json.loads((ROOT / 'plugins/progress-checker/third-party/inventory.json').read_text())
        self.assertEqual(inventory['workspace_version'], version)

    def test_mismatched_manifest_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'plugins/progress-checker').mkdir(parents=True)
            (root / 'Cargo.toml').write_text('[workspace.package]\nversion="1.0.0"\n')
            (root / 'plugins/progress-checker/plugin.json').write_text('{"version":"2.0.0"}')
            with self.assertRaisesRegex(ValueError, 'must match'):
                source_version(root)

    def test_wrong_compiled_binary_is_refused_before_packaging(self):
        with self.assertRaisesRegex(ValueError, 'rebuild before packaging'):
            binary_versions(ROOT / '.local/checker-target/debug', '99.0.0')

    def test_gateway_reports_manifest_version_without_tracking(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'bin').mkdir()
            shutil.copyfile(ROOT / 'plugins/progress-checker/bin/checker-global', root / 'bin/checker-global')
            shutil.copyfile(ROOT / 'plugins/progress-checker/plugin.json', root / 'plugin.json')
            (root / 'bin/progress-checker-mcp').symlink_to(ROOT / '.local/checker-target/debug/progress-checker-mcp')
            frame = {'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'version-test','version':'1'}}}
            answer = subprocess.run(['/usr/bin/python3', str(root / 'bin/checker-global')], input=json.dumps(frame)+'\n', capture_output=True, text=True, check=True, timeout=15)
            result = json.loads(answer.stdout)['result']
            self.assertEqual(result['serverInfo']['version'], source_version(ROOT))
            self.assertFalse((root / '.progress-checker').exists())


if __name__ == '__main__':
    unittest.main()
