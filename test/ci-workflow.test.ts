import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, mkdtempSync, writeFileSync, mkdirSync, rmSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
const read = (p: string) => readFileSync(p, 'utf8');
test('native CI test lanes glob the same root test files as npm', () => {
  // Full native lanes keep the root glob; targeted permission probes have their own job.
  const source = read('.github/workflows/ci.yml').split('  native:\n')[1]!.split('  os-trust-denied:\n')[0]!;
  for (const lane of [/deno test[^\n]+test\/\*\.test\.ts/, /bun test(?: --isolate)?(?: --timeout 30000)? test\/\*\.test\.ts/]) assert.match(source, lane);
  assert.equal(JSON.parse(read('package.json')).scripts.test.endsWith('test/*.test.ts'), true);
  assert.doesNotMatch(source, /(?:deno test|bun test)[^\n]*test\/[a-z_-]+\.test\.ts/);
});
test('CI reextracts pinned Elixir errors with the reference repository', () => {
  const source = read('.github/workflows/ci.yml');
  assert.match(source, /git clone --depth 1 --branch v0\.5\.2 https:\/\/github.com\/baselabs\/request_seal/);
  assert.match(source, /REQUEST_SEAL_REPO:.*runner\.temp/);
  assert.match(source, /--test test\/extract-elixir-reasons\.ts/);
  assert.match(source, /53b6690ccd5036d58b280d08cf0cacc6427262fe/);
});

test('parity table regeneration preserves helpers after the entries terminator', () => {
  const root = mkdtempSync(join(tmpdir(), 'request-seal-parity-splice-'));
  try {
    mkdirSync(join(root, 'src/errors'), {recursive: true});
    const source = read('src/errors/parity.ts').replace('] as const;', '] as const;\nconst plantedHelper = 42;');
    writeFileSync(join(root, 'src/errors/parity.ts'), source);
    const prefix = Object.hasOwn(process.versions, 'deno') ? ['run', '--allow-read', '--allow-write'] : Object.hasOwn(process.versions, 'bun') ? ['run'] : ['--experimental-strip-types', '--no-warnings'];
    const child = spawnSync(process.execPath, [...prefix, resolve('scripts/render-parity.ts'), '--update-table', resolve('test/fixtures/elixir-reasons-53b6690.json')], {cwd: root, encoding: 'utf8'});
    assert.equal(child.status, 0, child.stdout + child.stderr);
    assert.ok(read(join(root, 'src/errors/parity.ts')).includes('const plantedHelper = 42;'));
    const first = read(join(root, 'src/errors/parity.ts'));
    const again = spawnSync(process.execPath, [...prefix, resolve('scripts/render-parity.ts'), '--update-table', resolve('test/fixtures/elixir-reasons-53b6690.json')], {cwd: root, encoding: 'utf8'});
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
