import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {selectRuntimeLimits} from '../tools/conformance/runtime-limits.ts';
import {FETCH_VERIFICATION_RUNTIMES} from '../src/adapters/fetch/index.ts';
const read = (file: string) => readFileSync(new URL('../' + file, import.meta.url), 'utf8');

test('documented runtime lanes equal the exact CI lanes and the package floor', () => {
  const ci = read('.github/workflows/ci.yml');
  const tokens = /node: \[([^\]]+)\]/.exec(ci)?.[1]?.split(',').map(s => s.trim().replace(/^'|'$/g, ''));
  assert.ok(tokens);
  for (const token of tokens) assert.match(token, /^\d+\.\d+\.\d+$/, 'every Node lane must pin an exact version');
  assert.deepEqual(tokens, ['22.12.0', '22.23.1', '24.21.0', '26.11.1']);
  assert.match(ci, /name: Node \$\{\{ matrix\.node == '26\.11\.1' && '26' \|\| matrix\.node \}\}/);
  assert.match(ci, /if \(actual!==expected\) process\.exit\(1\)/);
  const denos = [...ci.matchAll(/deno-version: '([^']+)'/g)].map(m => m[1]!);
  const buns = [...ci.matchAll(/bun-version: '([^']+)'/g)].map(m => m[1]!);
  for (const version of [...denos, ...buns]) assert.match(version, /^\d+\.\d+\.\d+$/);
  const browsers = /playwright install --with-deps ([a-z ]+)/.exec(ci)?.[1]?.trim().split(/ +/) ?? [];
  assert.deepEqual(browsers, ['chromium', 'firefox', 'webkit']);

  const policy = JSON.parse(read('tools/conformance/runtime-limits.json'));
  type Limit = {id: string; observed: string; items: number[]; platforms?: string[]};
  const limitationBoundary = (entries: Limit[]) => entries.map(entry =>
    `\`${entry.id}\` ${entry.items.length === 1 ? 'item' : 'items'} ${entry.items.join(', ')}${entry.platforms ? ' on ' + entry.platforms.join(', ') : ''}: \`${entry.observed}\`.`).join(' ');
  // Runtime facts without a repository source; Fetch verification derives from the allowlist.
  const noSystemStore = 'No `tls.getCACertificates`, so `cacerts: "os"` returns `discovery/transport_unavailable`.';
  const nativeFacts: Record<string, string> = {
    'node:22.12.0': noSystemStore + ' Empty-query Fetch signing returns `adapter/invalid_request`.',
    'node:22.23.1': 'Empty-query Fetch signing returns `adapter/invalid_request`.',
    'deno:2.5.6': noSystemStore,
  };
  const nativeBoundary = (runtime: string, limits: Limit[] = []) => [
    nativeFacts[runtime],
    limitationBoundary(limits),
    (FETCH_VERIFICATION_RUNTIMES as readonly string[]).includes(runtime)
      ? undefined : 'Fetch verification returns `adapter/invalid_request` outside the measured allowlist.',
  ].filter(Boolean).join(' ');
  const expected: string[][] = tokens.map(version => [`Node ${version}`, version, nativeBoundary(`node:${version}`)]);
  for (const version of denos) expected.push([`Deno ${version}`, version, version === '2.9.7'
    ? 'Denied OS roots check only; without `--allow-sys=ca`, source creation and fetch return `discovery/transport_unavailable`. Full-suite support is not asserted.'
    : nativeBoundary(`deno:${version}`, policy.deno[version])]);
  for (const version of buns) expected.push([`Bun ${version}`, version, nativeBoundary(`bun:${version}`, policy.bun[version])]);
  for (const engine of browsers) {
    const name = engine === 'webkit' ? 'WebKit' : engine[0]!.toUpperCase() + engine.slice(1);
    const versions = Object.keys(policy[engine]);
    assert.equal(versions.length, 1, 'One exact browser release per CI engine');
    const version = versions[0]!;
    const limits = limitationBoundary(policy[engine][version]);
    expected.push([name, version, (limits ? limits + ' ' : '') + 'Browser Fetch verification returns `adapter/invalid_request`.']);
  }
  const table = read('docs/reference/runtime-matrix.md').split('## Tested runtime lanes\n')[1]!.split('## Node floor and engines')[0]!.split('\n').filter(line => line.startsWith('|')).join('\n');
  const rows = table.split('\n').slice(2).map(line => {
    assert.match(line, /^\|.*\|$/);
    const cells = line.slice(1, -1).split('|').map(cell => cell.trim());
    assert.equal(cells.length, 3, 'Every compatibility row has exactly three cells');
    return cells;
  });
  assert.deepEqual(rows, expected, 'Reference runtime, version, and boundary must equal CI and declared limitations');
  const pkg = JSON.parse(read('package.json'));
  assert.equal(pkg.engines.node, '>=' + tokens[0]);
  const browser = JSON.parse(read('interop/browser/package.json'));
  assert.match(browser.devDependencies.playwright, /^\d+\.\d+\.\d+$/);
  assert.equal(pkg.devDependencies.playwright, undefined);
  assert.deepEqual(Object.keys(browser.devDependencies), ['playwright']);
  assert.match(read('.github/workflows/release.yml'), /uses: \.\/\.github\/workflows\/ci.yml/);
  assert.match(ci, /^  browsers:\n    runs-on: ubuntu-24\.04/m);
});

test('browser policy validates the whole table and rejects unknown fields', () => {
  const table = JSON.parse(read('tools/conformance/runtime-limits.json'));
  assert.doesNotThrow(() => selectRuntimeLimits(table, process.versions));
  const invalid = structuredClone(table); invalid.webkit['27.2'][0].unknown = true;
  assert.throws(() => selectRuntimeLimits(invalid, process.versions), /invalid_runtime_limits/);
  const browser = read('interop/browser/run.ts');
  assert.match(browser, /Every declared limitation must execute with its exact reason/);
  assert.match(browser, /selectRuntimeLimits\(table, process\.versions\)/);
  assert.match(read('.gitignore'), /interop\/browser\/\.generated\//);
});

test('Firefox signing is supported and its body allocation bound is documented', () => {
  const table = JSON.parse(read('tools/conformance/runtime-limits.json'));
  assert.deepEqual(table.firefox['157.0'], []);
  const docs = read('docs/reference/runtime-matrix.md');
  assert.match(docs, /clone\(\)\.arrayBuffer\(\)/);
  assert.match(docs, /maxBytes bounds accepted bytes, not the peak allocation/);
  assert.doesNotMatch(read('README.md'), /fetch\/request_body|fetch\/empty_query/);
});

test('CI exercises denied OS roots on an exact newer Deno without sys permission', () => {
  const ci = read('.github/workflows/ci.yml');
  assert.match(ci, /deno-version: '2\.9\.7'/);
  assert.match(ci, /REQUEST_SEAL_EXPECT_DENIED_ROOTS: .1.\n\s+run: deno test --no-check --allow-read --allow-env=REQUEST_SEAL_EXPECT_DENIED_ROOTS test\/discovery-os-trust\.test\.ts/);
});

test('the WebKit probe includes published RFC 8032 test 1', () => {
  const probe = read('interop/browser/cases.ts');
  assert.match(probe, /d75a980182b10ab7d54bfed3c964073a/);
  assert.match(probe, /e5564300c360ac729086e2cc806e828a/);
  assert.match(probe, /RFC 8032 test 1/);
});

test('browser dependency maintenance covers audit, bounded runtime, and the local cache', () => {
  assert.match(read('.github/dependabot.yml'), /"\/interop\/browser"/);
  const job = read('.github/workflows/ci.yml').split('  browsers:\n')[1]!;
  assert.match(job, /timeout-minutes: 15/);
  assert.match(job, /npm audit --prefix interop\/browser --audit-level=high/);
  assert.match(read('.gitignore'), /# Local runtime cache\.\n\.tools\//);
});
