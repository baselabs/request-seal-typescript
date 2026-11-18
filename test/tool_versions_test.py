import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tool_versions', ROOT / 'scripts/tool-versions.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SOURCE = ROOT.joinpath('.tool-versions').read_text()
MANIFEST = ROOT.joinpath('package.json').read_text()
KNOWN_TOOLS = {'nodejs', 'deno', 'bun', 'elixir', 'erlang'}


class ToolVersionsTest(unittest.TestCase):
    def test_complete_exact_inventory(self):
        actual = module.read_versions(SOURCE + '\n# comment\n', MANIFEST)
        self.assertEqual(actual['nodes'], ['22.12.0', '22.23.1', '24.21.0', '26.11.1'])
        self.assertEqual(actual['nodejs'], '24.21.0')
        self.assertEqual(actual['native'], [{'runtime': 'deno', 'version': '2.5.6'}, {'runtime': 'bun', 'version': '1.3.14'}])
        self.assertEqual(actual['deno_os_trust'], ['2.9.7'])
        self.assertEqual(actual['npm'], '11.19.0')
        self.assertEqual(actual['elixir'], '1.20.3-otp-29')
        self.assertEqual(actual['erlang'], '29.0.3')

    def test_declares_only_tools_that_version_managers_install(self):
        names = {line.split()[0] for line in SOURCE.splitlines() if line.split()}
        self.assertEqual(names, KNOWN_TOOLS)

    def test_rejects_inexact_duplicate_missing_unknown_and_incompatible_tools(self):
        for mutation in (
            SOURCE.replace('24.21.0', '24'), SOURCE.replace('24.21.0', 'latest'),
            SOURCE.replace('nodejs 24.21.0', 'nodejs 24.21.0 24.21.0'),
            SOURCE + '\nnodejs 24.21.0', SOURCE + '\nunknown 1.2.3', SOURCE + '\nnpm 11.19.0',
            SOURCE.replace('bun 1.3.14', ''), SOURCE.replace('bun 1.3.14', 'bun'),
            SOURCE.replace('bun 1.3.14', 'bun 1.3.14 1.4.3'),
            SOURCE.replace('erlang 29.0.3', 'erlang 29.0.3 29.1.1'),
            SOURCE.replace('deno 2.5.6 2.9.7', 'deno 2.5.6'),
            SOURCE.replace('deno 2.5.6 2.9.7', 'deno 2.9.7 2.5.6'),
            SOURCE.replace('deno 2.5.6 2.9.7', 'deno 2.5.6 2.5.6'),
            SOURCE.replace('1.20.3-otp-29', '1.20.3-otp-28'),
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                module.read_versions(mutation, MANIFEST)

    def test_requires_an_exact_npm_package_manager(self):
        for manager in (None, 'npm@11', 'npm@latest', 'pnpm@10.0.0', 'npm@11.19.0+sha512.abc'):
            manifest = json.loads(MANIFEST)
            if manager is None:
                manifest.pop('packageManager')
            else:
                manifest['packageManager'] = manager
            with self.subTest(manager=manager), self.assertRaises(ValueError):
                module.read_versions(SOURCE, json.dumps(manifest))

    def test_every_repository_manifest_declares_the_selected_manager(self):
        expected = 'npm@' + module.read_versions(SOURCE, MANIFEST)['npm']
        for relative in ('interop/package.json', 'interop/adapters/package.json', 'interop/browser/package.json', 'interop/migration/package.json', 'interop/reciprocal/package.json'):
            with self.subTest(manifest=relative):
                self.assertEqual(json.loads((ROOT / relative).read_text())['packageManager'], expected)
