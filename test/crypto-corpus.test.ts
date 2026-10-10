import test from 'node:test';
import assert from 'node:assert/strict';
import {surfaceRegistry} from '../tools/conformance/loader.ts';
test('conformance registers crypto.verify and key.import', () => {
  const registry = surfaceRegistry();
  assert.equal(registry.has('smoke'), true);
  assert.equal(
    registry.has('crypto.verify'),
    true,
    'crypto.verify must be registered',
  );
  assert.equal(
    registry.has('key.import'),
    true,
    'key.import must be registered',
  );
});
import {
  readFile,
  writeFile,
  mkdir,
  mkdtemp,
  rm,
  cp,
} from 'node:fs/promises';
import {join, resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {canonicalJson, runCorpus, selectRuntimeLimits, classifyRuntimeResult} from '../tools/conformance/loader.ts';
const sha = (bytes: Uint8Array | string) =>
  createHash('sha256').update(bytes).digest('hex');
async function corpus(
  format: string,
  name: string,
  overrides: Record<string, Record<string, string>> = {},
) {
  const parent = 'test';
  const root = await mkdtemp(join(parent, '.tmp-corpus-'));
  try {
    await mkdir(join(root, 'sources'));
    await mkdir(join(root, 'cases/crypto'), {recursive: true});
    const source = await readFile('test/fixtures/wycheproof/' + name);
    await writeFile(join(root, 'sources/vector.json'), source);
    const total = JSON.parse(source.toString()).numberOfTests;
    const notApplicable = Object.values(overrides).filter(
      (v) => v.outcome === 'not_applicable',
    ).length;
    const m = {
      format: 'request-seal-conformance-batch/1',
      id: 'crypto/' + name.replace(/\.json$/, ''), surface: 'crypto.verify', class: 'mixed',
      evidence_class: 'published_vector',
      source: {document: 'Wycheproof', section: format, url: 'https://github.com/C2SP/wycheproof/tree/12fd3aa'},
      batch: {file: 'sources/vector.json', item_format: format, count: {int: String(total)}, not_applicable: {int: String(notApplicable)}},
      overrides,
    };
    const positive = await readFile('conformance/cases/crypto/rfc8032-1.json', 'utf8');
    await writeFile(join(root, 'cases/crypto/positive.json'), positive);
    const manifest = canonicalJson(m);
    await writeFile(join(root, 'cases/crypto/wycheproof.json'), manifest);
    const index = {
      format: 'request-seal-conformance-corpus-index/1',
      elixir_release: 'v0.4.0',
      known_positive: 'crypto/rfc8032-1',
      files: [
        {path: 'cases/crypto/positive.json', sha256: sha(positive)},
        {path: 'cases/crypto/wycheproof.json', sha256: sha(manifest)},
        {path: 'sources/vector.json', sha256: sha(source)},
      ],
      cases: [
        {id: 'crypto/rfc8032-1', manifest: 'cases/crypto/positive.json', surface: 'crypto.verify', class: 'byte_exact'},
        {
          id: m.id,
          manifest: 'cases/crypto/wycheproof.json',
          surface: m.surface,
          class: m.class,
          count: m.batch.count, not_applicable: m.batch.not_applicable,
        },
      ],
    };
    await writeFile(join(root, 'index.json'), canonicalJson(index));
    return {
      report: await runCorpus(root, {unpinned: true}),
      total,
      notApplicable,
    };
  } finally {
    await rm(root, {recursive: true, force: true});
  }
}
test('complete pinned Wycheproof Ed25519 and P1363 batches assert every item', async (t) => {
  for (const [format, name, total] of [
    ['wycheproof-ed25519/1', 'ed25519_test.json', 151],
    ['wycheproof-ecdsa/1', 'ecdsa_secp256r1_sha256_p1363_test.json', 262],
  ] as const) {
    const c = await corpus(format, name);
    assert.equal(c.report.ok, true, JSON.stringify(c.report));
    assert.equal(c.total, total);
    assert.equal(c.notApplicable, 0);
    assert.equal(c.report.executed + c.report.runtime_limited, total + 1);
    assert.equal(c.report.listed, c.report.executed + c.report.not_applicable + c.report.runtime_limited);
    t.diagnostic(
      `${format}: executed=${total - c.notApplicable - c.report.runtime_limited} not_applicable=${c.notApplicable} runtime_limited=${c.report.runtime_limited}`,
    );
  }
});
test('Wycheproof overrides enforce selected verdicts and unsupported formats reject', async () => {
  const skipped = await corpus('wycheproof-ed25519/1', 'ed25519_test.json', {
    '1': {outcome: 'not_applicable', reason: 'Explicit selected item exclusion'},
  });
  assert.equal(skipped.report.ok, true);
  assert.equal(skipped.notApplicable, 1);
  const wrong = await corpus('wycheproof-ed25519/1', 'ed25519_test.json', {
    '1': {outcome: 'reject', rule_id: 'crypto/invalid_signature', clause: 'RFC 8032 Section 5.1.7'},
  });
  assert.equal(wrong.report.ok, false);
  assert.equal(wrong.report.failures[0]?.reason, 'outcome_mismatch');
  const unsupported = await corpus('rfc8032/1', 'ed25519_test.json', {'1': {outcome: 'reject', rule_id: 'crypto/invalid_signature', clause: 'RFC 8032 Section 5.1.7'}});
  assert.equal(unsupported.report.ok, false);
  assert.equal(unsupported.report.failures[0]?.reason, 'unsupported_overrides');
  const ecdsa = await corpus('wycheproof-ecdsa/1', 'ecdsa_secp256r1_sha256_p1363_test.json', {'1': {outcome: 'reject', rule_id: 'crypto/invalid_signature', clause: 'RFC 6979 Section 2.4'}});
  assert.equal(ecdsa.report.ok, false);
  assert.equal(ecdsa.report.failures[0]?.reason, 'outcome_mismatch');
  const unknown = await corpus('wycheproof-ed25519/1', 'ed25519_test.json', {
    '999999': {outcome: 'not_applicable', reason: 'Unknown item'},
  });
  assert.equal(unknown.report.ok, false);
  assert.equal(unknown.report.failures[0]?.reason, 'invalid_overrides');
});

test('published extreme-s signatures use the shared consumer runtime policy', async (t) => {
  const {cryptoBatchItem} = await import('../tools/conformance/crypto-surfaces.ts');
  const table = JSON.parse(await readFile('tools/conformance/runtime-limits.json', 'utf8'));
  const limits = selectRuntimeLimits(table, process.versions);
  const source = JSON.parse(await readFile('test/fixtures/wycheproof/ecdsa_secp256r1_sha256_p1363_test.json', 'utf8'));
  const parent = source.testGroups.at(-1);
  for (const value of parent.tests) {
    assert.equal(value.result, 'valid');
    const result = await cryptoBatchItem({id: String(value.tcId), value, parent, position: 0, notApplicable: false}, {batch: {item_format: 'wycheproof-ecdsa/1'}});
    const status = classifyRuntimeResult(limits, 'crypto/ecdsa_secp256r1_sha256_p1363_test', String(value.tcId), result);
    assert.ok(status === 'executed' || status === 'runtime_limited', JSON.stringify(result));
    t.diagnostic(`ECDSA ${value.tcId}: ${status}; published valid`);
  }
});

test('public-only corpus import projects private JWK examples without changing the source', {timeout: 30_000}, async () => {
  const ids = ['rfc7517-0','rfc7517-1','rfc8037-ed25519'];
  const before = new Map<string, Uint8Array>();
  for (const id of ids) {
    const m = JSON.parse(await readFile(`conformance/cases/key/${id}.json`, 'utf8'));
    const path = 'conformance/' + m.inputs.material.ref.file;
    const source = new Uint8Array(await readFile(path));
    assert.ok(JSON.parse(new TextDecoder().decode(source)).keys?.some((k: {d?: string}) => k.d) || JSON.parse(new TextDecoder().decode(source)).d);
    before.set(path, source);
  }
  const report = await runCorpus('conformance', {pendingOk: true});
  assert.deepEqual(report.failures.filter(f => ids.some(id => f.id === 'key/' + id)), []);
  for (const [path, source] of before) assert.deepEqual(new Uint8Array(await readFile(path)), source);
});

// Policy inputs exercise exact version matching; verdicts come from published
// signatures and actual WebCrypto, never a replacement crypto implementation.
test('runtime limitations select only the exact named version', async () => {
  const limits = await import('../tools/conformance/loader.ts');
  const table = JSON.parse(await readFile('tools/conformance/runtime-limits.json', 'utf8'));
  assert.equal(limits.selectRuntimeLimits(table, {bun: '1.3.14'}).length, 3);
  assert.equal(limits.selectRuntimeLimits(table, {deno: '2.5.6'}).length, 2);
  for (const versions of [{bun: '1.3.13'}, {bun: '1.3.15'}, {node: '24.21.0'}, {deno: '2.5.7'}])
    assert.deepEqual(limits.selectRuntimeLimits(table, versions), []);
  assert.deepEqual(limits.selectRuntimeLimits(table, {bun: '1.3.14-canary', node: '24.21.0'}), []);
  assert.equal(limits.selectRuntimeLimits(table, {bun: '1.3.14', node: '24.21.0'}).length, 3);
});
test('a stale runtime limitation fails the real corpus CLI', {timeout: 30_000}, async () => {
  const root = await mkdtemp(join(tmpdir(), 'request-seal-runtime-policy-'));
  try {
    await cp('src', join(root, 'src'), {recursive: true});
    await cp('test/fixtures/upstream/httpwg-structured-fields/PINNED.ts', join(root, 'test/fixtures/upstream/httpwg-structured-fields/PINNED.ts'));
    await cp('tools/conformance', join(root, 'tools/conformance'), {recursive: true});
    await writeFile(join(root, 'package.json'), '{"type":"module"}');
    const table = JSON.parse(await readFile('tools/conformance/runtime-limits.json', 'utf8'));
    const runtime = process.versions.bun ? 'bun' : process.versions.deno ? 'deno' : 'node';
    const version = process.versions[runtime]!;
    table[runtime] ??= {};
    table[runtime][version] ??= [];
    table[runtime][version].push({id: 'crypto/ed25519_test', items: [1], observed: 'crypto/invalid_signature', reason: 'Published valid Ed25519 item proves stale policy fails.'});
    await writeFile(join(root, 'tools/conformance/runtime-limits.json'), JSON.stringify(table));
    const prefix = runtime === 'deno' ? ['run', '--allow-read'] : runtime === 'bun' ? ['run'] : ['--experimental-strip-types', '--no-warnings'];
    const child = spawnSync(process.execPath, [...prefix, join(root, 'tools/conformance/cli.ts'), '--corpus', resolve('conformance'), '--pending-ok'], {encoding: 'utf8', timeout: 25_000});
    assert.equal(child.status, 1, child.stderr || child.stdout);
    assert.ok(child.stdout.trim(), child.stderr);
    const report = JSON.parse(child.stdout);
    assert.equal(report.ok, false);
    assert.ok(report.failures.some((f: {id: string; reason: string}) => f.id === 'crypto/ed25519_test/0:1' && f.reason === 'stale_runtime_limitation'));
  } finally {await rm(root, {recursive: true, force: true});}
});
test('an unlisted real divergence fails despite a runtime limitation', async () => {
  const limits = await import('../tools/conformance/loader.ts');
  const {cryptoBatchItem} = await import('../tools/conformance/crypto-surfaces.ts');
  const source = JSON.parse(await readFile('test/fixtures/wycheproof/ed25519_test.json', 'utf8'));
  const parent = source.testGroups[0], value = parent.tests[0];
  const result = await cryptoBatchItem({id: String(value.tcId), value, parent, position: 0, notApplicable: false}, {batch: {item_format: 'wycheproof-ed25519/1'}, overrides: {[value.tcId]: {outcome: 'reject', rule_id: 'crypto/invalid_signature'}}});
  assert.equal(result.ok, false);
  const policy = [{id: 'crypto/ed25519_test', items: [value.tcId + 1], observed: 'crypto/invalid_signature', reason: 'Another item cannot cover this divergence.'}];
  assert.equal(limits.classifyRuntimeResult(policy, 'crypto/ed25519_test', String(value.tcId), result), 'outcome_mismatch');
  const c = await corpus('wycheproof-ed25519/1', 'ed25519_test.json', {'1': {outcome: 'reject', rule_id: 'crypto/invalid_signature', clause: 'RFC 8032 Section 5.1.7'}});
  assert.equal(c.report.ok, false);
  assert.equal(c.report.failures[0]?.reason, 'outcome_mismatch');
  assert.equal(c.report.runtime_limited, 0);
});
