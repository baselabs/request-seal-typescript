import hashlib
import importlib.util
import json
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('package_manager', ROOT / 'scripts/package-manager.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
MANIFEST = ROOT.joinpath('package.json').read_text()
WORKFLOWS = {name: (ROOT / '.github/workflows' / name).read_text()
             for name in ('ci.yml', 'pages.yml', 'publish.yml')}


def read_outputs(source):
    return dict(line.split('=', 1) for line in source.splitlines())


def shared_outputs():
    child = subprocess.run(['scripts/toolchain.sh'], cwd=ROOT, text=True,
                           capture_output=True, check=True, timeout=10)
    return read_outputs(child.stdout)


class ToolchainTest(unittest.TestCase):
    def test_shared_reader_identity_and_executable_mode(self):
        reader = ROOT / 'scripts/toolchain.sh'
        self.assertEqual(hashlib.sha256(reader.read_bytes()).hexdigest(),
                         'b29bfeb6ec4ec8f5b7e3ac3c963f04b6d3c73483172e5bd59ea40f20b102f1eb')
        self.assertEqual(stat.S_IMODE(reader.stat().st_mode), 0o755)

    def test_complete_exact_inventory_through_shared_outputs(self):
        actual = shared_outputs()
        tools = {'nodejs', 'deno', 'bun', 'elixir', 'erlang'}
        self.assertEqual(set(actual), tools | {name + '_lanes' for name in tools} | {'otp', 'beam_lanes'})
        self.assertEqual([actual['nodejs'], *json.loads(actual['nodejs_lanes'])],
                         ['24.21.0', '22.12.0', '22.23.1', '26.11.1'])
        self.assertEqual(actual['deno'], '2.5.6')
        self.assertEqual(json.loads(actual['deno_lanes']), ['2.9.7'])
        self.assertEqual(actual['bun'], '1.3.14')
        self.assertEqual(actual['elixir'], '1.20.3-otp-29')
        self.assertEqual(actual['otp'], actual['erlang'])
        self.assertEqual(actual['otp'], '29.0.3')
        for tool in tools:
            values = [actual[tool], *json.loads(actual[tool + '_lanes'])]
            pattern = r'\d+\.\d+\.\d+-otp-\d+' if tool == 'elixir' else r'\d+\.\d+\.\d+'
            self.assertEqual(len(set(values)), len(values), tool)
            for value in values:
                self.assertRegex(value, '^' + pattern + '$')
        for tool in ('bun', 'elixir', 'erlang'):
            self.assertEqual(json.loads(actual[tool + '_lanes']), [], tool)
        self.assertEqual(json.loads(actual['beam_lanes']), [])
        for probe in json.loads(actual['deno_lanes']):
            self.assertGreater(tuple(map(int, probe.split('.'))), tuple(map(int, actual['deno'].split('.'))))

    def test_matrices_use_every_shared_lane_without_rereading_declarations(self):
        job = WORKFLOWS['ci.yml'].split('      - name: Compose runtime matrices from shared outputs\n')[1].split('\n  node:')[0]
        self.assertIn('id: matrix', job)
        bindings = {'NODEJS': 'nodejs', 'NODEJS_LANES': 'nodejs_lanes',
                    'DENO': 'deno', 'DENO_LANES': 'deno_lanes', 'BUN': 'bun'}
        for name, output in bindings.items():
            self.assertIn(f'{name}: ${{{{ steps.versions.outputs.{output} }}}}', job)
        script = textwrap.dedent(job.split("<<'PYTHON'\n")[1].split('          PYTHON')[0])
        versions = shared_outputs()
        # A changed default and extra lanes must flow through the actual workflow body.
        variants = [versions, {**versions, 'nodejs': '30.1.2', 'nodejs_lanes': '["28.1.0","26.2.3"]',
                               'deno': '3.1.0', 'deno_lanes': '["3.2.0","3.3.0"]', 'bun': '2.1.0'}]
        for variant in variants:
            with self.subTest(nodejs=variant['nodejs']):
                child = subprocess.run([sys.executable, '-I', '-B', '-c', script], cwd=ROOT,
                                       env={name: variant[output] for name, output in bindings.items()},
                                       text=True, capture_output=True, check=True, timeout=10)
                actual = {name: json.loads(value) for name, value in read_outputs(child.stdout).items()}
                self.assertEqual(actual, {
                    'nodes': [variant['nodejs'], *json.loads(variant['nodejs_lanes'])],
                    'native': [{'runtime': 'deno', 'version': variant['deno']},
                               {'runtime': 'bun', 'version': variant['bun']}],
                    'deno_os_trust': json.loads(variant['deno_lanes']),
                })

    def test_workflows_select_and_refuse_runtimes_only_through_shared_outputs(self):
        for name, workflow in WORKFLOWS.items():
            with self.subTest(workflow=name):
                self.assertNotIn('version-file:', workflow)
                self.assertNotIn('actions/setup-python', workflow)
                self.assertNotIn('.tool-versions', workflow)
                self.assertNotRegex(workflow, r'\b(?:sh|bash)\s+scripts/toolchain\.sh')
                self.assertNotRegex(workflow, r'(?:node|deno|bun|elixir|otp)-version:\s*[\'"\d]')
                self.assertIn('run: scripts/toolchain.sh >> "$GITHUB_OUTPUT"', workflow)
                self.assertIn('run: python3 -I -B scripts/package-manager.py >> "$GITHUB_OUTPUT"', workflow)
                self.assertNotIn('steps.versions.outputs.npm', workflow)
                self.assertEqual(workflow.count('uses: actions/setup-node@'),
                                 workflow.count('run: scripts/toolchain.sh --installed "nodejs=$EXPECTED_NODE"'))
        ci = WORKFLOWS['ci.yml']
        for output in ('elixir', 'otp'):
            self.assertIn(f'{output}: ${{{{ steps.versions.outputs.{output} }}}}', ci)
            self.assertEqual(ci.count(f'{output}-version: ${{{{ needs.toolchains.outputs.{output} }}}}'), 3)
        self.assertEqual(ci.count('version-type: strict'), 3)
        self.assertEqual(ci.count('run: scripts/toolchain.sh --installed "elixir=$EXPECTED_ELIXIR" "erlang=$EXPECTED_OTP"'), 3)
        self.assertIn('actual="$("$EXPECTED_RUNTIME" --version | awk', ci)
        self.assertIn('test "$actual" = "$EXPECTED_VERSION"', ci)
        self.assertIn('actual="$(deno --version | awk', ci)
        self.assertIn('test "$actual" = "$EXPECTED_DENO"', ci)

    def test_no_repository_owned_runtime_declaration_reader_remains(self):
        self.assertFalse((ROOT / 'scripts/tool-versions.py').exists())
        for script in (ROOT / 'scripts').iterdir():
            if script.is_file() and script.name != 'toolchain.sh':
                self.assertNotIn('.tool-versions', script.read_text(), str(script.relative_to(ROOT)))
        for name in ('runtime-matrix.test.ts', 'foundation-fixes.test.ts', 'reciprocal.test.ts'):
            source = (ROOT / 'test' / name).read_text()
            self.assertIn('readToolchain(', source)
            self.assertNotRegex(source, r'(?:read|readFileSync)\([^\n]*\.tool-versions')
        helper = (ROOT / 'test/support/toolchain.ts').read_text()
        self.assertIn("spawnSync('scripts/toolchain.sh'", helper)
        self.assertNotIn('readFileSync', helper)

    def test_requires_an_exact_npm_package_manager(self):
        self.assertEqual(module.read_npm(MANIFEST), '11.19.0')
        for manager in (None, 11, 'npm@11', 'npm@latest', 'pnpm@10.0.0', 'npm@11.19.0+sha512.abc'):
            manifest = json.loads(MANIFEST)
            manifest['packageManager'] = manager
            with self.subTest(manager=manager), self.assertRaises(ValueError):
                module.read_npm(json.dumps(manifest))
        with self.assertRaises(ValueError):
            module.read_npm('{}')

    def test_every_repository_manifest_declares_the_selected_manager(self):
        self.assertEqual(module.check_managers(ROOT), module.read_npm(MANIFEST))
        with tempfile.TemporaryDirectory(prefix='request-seal-managers-') as directory:
            root = Path(directory)
            manifests = ['package.json', *[str(path.relative_to(ROOT)) for path in (ROOT / 'interop').rglob('package.json')
                                          if 'node_modules' not in path.parts]]
            for relative in manifests:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(MANIFEST)
            self.assertEqual(module.check_managers(root), module.read_npm(MANIFEST))
            target = root / 'interop/adapters/package.json'
            target.write_text(json.dumps({'packageManager': 'npm@99.0.0'}))
            with self.assertRaisesRegex(ValueError, 'interop/adapters/package.json must declare'):
                module.check_managers(root)
