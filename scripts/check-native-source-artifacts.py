#!/usr/bin/env python3
"""Static source/package-contract regressions; never qualifies target execution."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('release_integrity', ROOT / 'scripts/check-release-candidate.py')
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)


class SourceArtifactTests(unittest.TestCase):
    def test_source_version_and_dependency_notices_are_bound(self):
        cargo = tomllib.loads((ROOT / 'Cargo.toml').read_text())
        version = cargo['workspace']['package']['version']
        self.assertEqual(version, '0.5.0-dev')
        manifest = json.loads((ROOT / 'plugins/progress-checker/plugin.json').read_text())
        self.assertEqual(manifest['version'], version)
        base = ROOT / 'plugins/progress-checker/third-party'
        inventory = json.loads((base / 'inventory.json').read_text())
        self.assertEqual(inventory['workspace_version'], version)
        self.assertEqual(inventory['cargo_lock_sha256'], hashlib.sha256((ROOT / 'Cargo.lock').read_bytes()).hexdigest())
        for package in inventory['packages'] + [inventory['rust_standard_library']]:
            for relative, expected in package['files_sha256'].items():
                path = base / relative
                self.assertFalse(path.is_symlink(), relative)
                self.assertTrue(path.resolve().is_relative_to(base.resolve()), relative)
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected, relative)

    def test_frozen_archive_identities_remain_exact(self):
        plan = json.loads((ROOT / '.progress-checker/plugin-plan.json').read_text())
        for key in ('acceptance_archive', 'acceptance_old_archive', 'global_archive', 'native_onboarding_release'):
            entry = plan[key]
            relative = entry.get('path', entry.get('archive_path'))
            self.assertEqual(RELEASE.bounded_archive_hash(ROOT / relative), entry['sha256'], relative)

    def test_full_workspace_compile_gate_includes_native_gateway(self):
        workspace = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['members']
        for name in ('checker-core', 'checker-cli', 'checker-service', 'checker-mcp', 'checker-global'):
            self.assertIn(name, workspace)
        workflow = (ROOT / '.github/workflows/platform-build.yml').read_text()
        self.assertIn('cargo check --workspace --all-targets --locked', workflow)
        self.assertNotIn('--exclude', workflow)
        for runner in ('fedora:44', 'ubuntu-24.04', 'aarch64-apple-darwin', 'x86_64-pc-windows-msvc', 'x86_64-unknown-linux-gnu'):
            self.assertIn(runner, workflow)
        self.assertNotIn('continue-on-error: true', workflow)
        self.assertIn('actual_host', workflow)
        self.assertIn('expected_host', workflow)
        self.assertIn('rust-toolchain.toml', workflow)

    def test_platform_primitives_are_declared_and_limitations_remain_explicit(self):
        modules = (ROOT / 'checker-core/src/platform/mod.rs').read_text()
        for name in ('macos_inventory', 'macos_process', 'macos_sandbox',
                     'windows_inventory', 'windows_process', 'windows_sandbox'):
            self.assertIn('pub mod ' + name + ';', modules)
            self.assertTrue((ROOT / ('checker-core/src/platform/' + name + '.rs')).is_file())
        schema = json.loads((ROOT / 'schemas/platform-qualification.schema.json').read_text())
        self.assertEqual(schema['properties']['trust_status']['const'], 'untrusted-until-collector-validated')
        self.assertIn('not trusted evidence', schema['description'])


if __name__ == '__main__':
    unittest.main()
