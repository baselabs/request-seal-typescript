import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, mkdtempSync, writeFileSync, mkdirSync, rmSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
const read = (p: string) => readFileSync(p, 'utf8');
test('CI reextracts pinned Elixir errors with the reference repository', () => {
  const source = read('.github/workflows/ci.yml');
  assert.match(source, /fetch --depth 1 https:\/\/github.com\/baselabs\/request_seal\.git 511fed142044ccea28bdcbb317c091cb2c8a515d/);
  assert.match(source, /checkout --detach FETCH_HEAD/);
  assert.match(source, /REQUEST_SEAL_REPO:.*runner\.temp/);
  assert.match(source, /--test test\/extract-elixir-reasons\.ts/);
  assert.match(source, /511fed142044ccea28bdcbb317c091cb2c8a515d/);
});

test('parity table regeneration preserves helpers after the entries terminator', () => {
  const root = mkdtempSync(join(tmpdir(), 'request-seal-parity-splice-'));
  try {
    mkdirSync(join(root, 'src/errors'), {recursive: true});
    const source = read('src/errors/parity.ts').replace('] as const;', '] as const;\nconst plantedHelper = 42;');
    writeFileSync(join(root, 'src/errors/parity.ts'), source);
    const prefix = Object.hasOwn(process.versions, 'deno') ? ['run', '--allow-read', '--allow-write'] : Object.hasOwn(process.versions, 'bun') ? ['run'] : ['--experimental-strip-types', '--no-warnings'];
    const child = spawnSync(process.execPath, [...prefix, resolve('scripts/render-parity.ts'), '--update-table', resolve('test/fixtures/elixir-reasons-511fed1.json')], {cwd: root, encoding: 'utf8'});
    assert.equal(child.status, 0, child.stdout + child.stderr);
    assert.ok(read(join(root, 'src/errors/parity.ts')).includes('const plantedHelper = 42;'));
    const first = read(join(root, 'src/errors/parity.ts'));
    const again = spawnSync(process.execPath, [...prefix, resolve('scripts/render-parity.ts'), '--update-table', resolve('test/fixtures/elixir-reasons-511fed1.json')], {cwd: root, encoding: 'utf8'});
    assert.equal(again.status, 0, again.stdout + again.stderr);
    assert.equal(read(join(root, 'src/errors/parity.ts')), first, 'second regeneration must preserve identical bytes');
  } finally {rmSync(root, {recursive: true, force: true});}
});
test('retryability extraction reads its own complete struct, excluding adjacent structs', async () => {
  const {extractCallSites} = await import('../scripts/extract-elixir-reasons.ts');
  const sources = {'lib/request_seal/discovery/transport.ex': `defmodule RequestSeal.Discovery.Transport do
  alias RequestSeal.Discovery.Error
  def check(status) do
    first = %Error{reason: :connect_failed, retryable: false}
    second = %Error{reason: :unexpected_status,
      retryable: status in 500..599}
    {first, second}
  end
end`};
  const sites = extractCallSites(sources).sites.get('discovery')!;
  const first = sites.find(s => s.rule_id === 'discovery/connect_failed')!;
  const second = sites.find(s => s.rule_id === 'discovery/unexpected_status')!;
  assert.doesNotMatch(first.expression, /500\.\.599/);
  assert.match(second.expression, /500\.\.599/);
});

test('retryable prose separates each section with the reference document separator', async () => {
  const {renderParity} = await import('../scripts/render-parity.ts');
  assert.match(renderParity(), /\(status-derived\) · jose:/);
});
test('CI test steps keep repository credentials out of their environment', () => {
  const source = read('.github/workflows/ci.yml');
  assert.doesNotMatch(source, /GH_TOKEN:/);
});

test('CI PostgreSQL service images use immutable Linux image digests', () => {
  const images = [...read('.github/workflows/ci.yml').matchAll(/image: (postgres:\S+)/g)].map(m => m[1]);
  assert.equal(images.length, 3, 'Node, native, and reciprocal jobs each have one PostgreSQL service');
  for (const image of images) assert.match(image!, /^postgres:18@sha256:[a-f0-9]{64}$/);
});

test('publication checks the existing name and tag before build, then plans from the inspected archive', () => {
  const source = read('.github/workflows/publish.yml');
  const order = ['scripts/registry-check.ts existing', 'Refuse an already-tagged version', 'Build the library and documentation', 'Inspect the exact package archive', 'scripts/registry-check.ts plan', 'npm stage publish', 'scripts/registry-check.ts read-back'];
  const positions = order.map(text => source.indexOf(text));
  assert.ok(positions.every(position => position >= 0));
  assert.deepEqual(positions, [...positions].sort((a, b) => a - b));
  assert.match(source, /git.*ls-remote.*--tags.*refs\/tags\/v\$\{version\}/);
  assert.match(source, /assert\.equal\(tags\.trim\(\), '', `v\$\{version\} is already tagged`\)/);
  assert.match(source, /if: steps\.registry\.outputs\.action == 'stage'/);
  assert.match(source, /npm stage publish \.\/artifacts\/package\.tgz --provenance --ignore-scripts/);
  assert.match(source, /if: always\(\) && steps\.inspect\.outcome == 'success'/);
  assert.match(source, /name: release-assets\n\s+path: artifacts\//);
  assert.doesNotMatch(source, /NODE_AUTH_TOKEN|NPM_TOKEN|secrets\.|gh release|tags:/);
});

test('published installs depend on upload, use the same actor gate, and have no environment or key', () => {
  const source = read('.github/workflows/publish.yml');
  const upload = source.split('  publish:\n')[1]!.split('  published-package:\n')[0]!;
  const consumer = source.split('  published-package:\n')[1]!;
  const gate = (job: string) => /^    if: (.+)$/m.exec(job)![1];
  assert.equal(gate(upload), gate(consumer));
  assert.match(consumer, /needs: publish/);
  assert.doesNotMatch(consumer, /environment:|secrets\.|id-token: write/);
  assert.match(consumer, /PUBLISHED: \$\{\{ needs\.publish\.outputs\.published \}\}/);
  assert.match(consumer, /test "\$PUBLISHED" = true/);
  assert.match(consumer, /npm install --ignore-scripts --registry=https:\/\/registry\.npmjs\.org\/ "\$package_name@\$package_version"/);
  assert.match(consumer, /npm audit signatures/);
  assert.match(consumer, /trap 'rm -rf "\$consumer"' EXIT/);
});

test('qualification has one verdict and no setup action writes or restores an application cache', () => {
  const source = read('.github/workflows/ci.yml');
  const verdict = source.split('  qualified:\n')[1]!;
  assert.match(verdict, /^    if: always\(\)/);
  assert.doesNotMatch(verdict, /^    name:/m);
  assert.match(verdict, /needs: \[toolchains, node, native, os-trust-denied, browsers, reciprocal\]/);
  assert.doesNotMatch(source, /actions\/cache@|actions\/cache\/save@|^\s+cache: true|no-cache: false|package-manager-cache: true/m);
  assert.match(source, /bun-version: \$\{\{ matrix\.version \}\}\n\s+no-cache: true/);
  for (const file of ['ci.yml', 'publish.yml', 'pages.yml']) {
    const workflow = read('.github/workflows/' + file);
    const actions = [...workflow.matchAll(/uses: (\S+)@([^\s]+)([^\n]*)/g)];
    assert.ok(actions.length);
    for (const [, name, pin, comment] of actions) {
      assert.match(pin!, /^[a-f0-9]{40}$/);
      if (!name!.startsWith('baselabs/')) assert.match(comment!, /^ # v\d+\.\d+\.\d+$/);
    }
    assert.equal((workflow.match(/uses: actions\/checkout@/g) ?? []).length, (workflow.match(/persist-credentials: false/g) ?? []).length);
  }
});
test('every workflow step fails on a failure anywhere in a pipe', () => {
  // A run: with no shell is bash -e without pipefail; shell: bash adds -o pipefail.
  for (const name of ['ci.yml', 'publish.yml', 'pages.yml']) {
    const source = read(`.github/workflows/${name}`);
    assert.match(source, /^defaults:\n  run:\n    shell: bash\n/m, name);
    // A job-level defaults.run replaces the workflow's, so none may omit the shell.
    assert.doesNotMatch(source, /^    defaults:/m, name);
    assert.doesNotMatch(source, /^\s+shell: (?!bash$)/m, name);
    assert.doesNotMatch(source, /(^|[\s;&|])sh scripts\//m, name);
  }
  const ci = read('.github/workflows/ci.yml');
  assert.equal((ci.match(/bash scripts\/red-proof\.sh /g) ?? []).length, 4);
  const script = read('scripts/red-proof.sh');
  assert.match(script, /^#!\/usr\/bin\/env bash\n(?:#[^\n]*\n)*set -euo pipefail\n/);
});
