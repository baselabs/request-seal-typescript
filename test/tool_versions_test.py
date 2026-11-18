import importlib.util
import json
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('tool_versions', Path(__file__).resolve().parents[1] / 'scripts/tool-versions.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SOURCE = Path(__file__).resolve().parents[1].joinpath('.tool-versions').read_text()


class ToolVersionsTest(unittest.TestCase):
    def test_complete_exact_inventory(self):
        actual = module.read_versions(SOURCE + '\n# comment\n')
        self.assertEqual(actual['nodes'], ['22.12.0', '22.23.1', '24.21.0', '26.11.1'])
        self.assertEqual(actual['nodejs'], '24.21.0')
        self.assertEqual(actual['native'], [{'runtime': 'deno', 'version': '2.5.6'}, {'runtime': 'bun', 'version': '1.3.14'}])
        self.assertEqual(actual['deno-os-trust'], '2.9.7')
        self.assertEqual(actual['npm'], '11.19.0')
        self.assertEqual(actual['elixir'], '1.20.3-otp-29')
        self.assertEqual(actual['erlang'], '29.0.3')

    def test_rejects_inexact_duplicate_missing_unknown_and_incompatible_tools(self):
        for mutation in (
            SOURCE.replace('24.21.0', '24'), SOURCE.replace('24.21.0', 'latest'),
            SOURCE.replace('24.21.0', '24.21.0 26.11.1'),
            SOURCE + '\nnodejs 24.21.0', SOURCE + '\nunknown 1.2.3',
            SOURCE.replace('bun 1.3.14', ''), SOURCE.replace('bun 1.3.14', 'bun'),
            SOURCE.replace('nodejs-compat ', 'nodejs-compat 24.21.0 '),
            SOURCE.replace('1.20.3-otp-29', '1.20.3-otp-28'),
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                module.read_versions(mutation)

    def test_every_repository_manifest_declares_the_selected_manager(self):
        root = Path(__file__).resolve().parents[1]
        expected = 'npm@' + module.read_versions(SOURCE)['npm']
        for relative in ('package.json', 'interop/package.json', 'interop/adapters/package.json', 'interop/browser/package.json', 'interop/migration/package.json', 'interop/reciprocal/package.json'):
            with self.subTest(manifest=relative):
                self.assertEqual(json.loads((root / relative).read_text())['packageManager'], expected)
