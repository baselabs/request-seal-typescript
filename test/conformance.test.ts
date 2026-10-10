import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { cp, mkdtemp, readFile, writeFile, rm, unlink, mkdir } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
const cliPrefix = Object.hasOwn(process.versions, 'deno') ? ['run', '--allow-read'] : Object.hasOwn(process.versions, 'bun') ? ['run'] : ['--experimental-strip-types', '--no-warnings'];
const fixture = resolve('test/fixtures/corpus-smoke');
async function rewrite(root: string, target: string, change: (value: any) => void) {
  const file = resolve(root, target); const value = JSON.parse(await readFile(file, 'utf8')); change(value);
  const {canonicalJson} = await import('../tools/conformance/loader.ts');
  const contents = canonicalJson(value); await writeFile(file, contents);
  if (target !== 'index.json') {
    const index = JSON.parse(await readFile(resolve(root, 'index.json'), 'utf8'));
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(contents));
    index.files.find((f: {path: string}) => f.path === target).sha256 = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
    await writeFile(resolve(root, 'index.json'), canonicalJson(index));
  }
}
const mutations: [string, string, (root: string) => Promise<void>][] = [
  ['expected byte', 'outcome_mismatch', root => rewrite(root, 'cases/smoke/bytes.json', c => {c.expected.bytes.b64 = 'YWJk';})],
  ['rule_id', 'outcome_mismatch', root => rewrite(root, 'cases/smoke/rejection.json', c => {c.expected.rule_id = 'core/input.invalid_options';})],
  ['digest', 'file_digest_mismatch', root => rewrite(root, 'index.json', i => {i.files[0].sha256 = '0'.repeat(64);})],
  ['missing listed file', 'missing_file', root => unlink(resolve(root, 'cases/smoke/bytes.json'))],
  ['unlisted file', 'unlisted_or_missing_file', root => writeFile(resolve(root, 'cases/smoke/unlisted.json'), '{}')],
  ['known_positive', 'invalid_index', root => rewrite(root, 'index.json', i => {delete i.known_positive;})],
  ['unknown surface', 'invalid_manifest', root => rewrite(root, 'index.json', i => {i.cases[0].surface = 'not.registered';})],
  ['unregistered surface with matching index', 'pending_surface', async root => {
    await rewrite(root, 'cases/smoke/bytes.json', c => {c.surface = 'not.registered';});
    await rewrite(root, 'index.json', i => {i.cases[0].surface = 'not.registered';});
  }],
  ['duplicate case', 'invalid_or_duplicate_case', root => rewrite(root, 'index.json', i => {i.cases.push(i.cases[0]);})],
  ['truncated cases', 'unconsumed_manifest', root => rewrite(root, 'index.json', i => {i.cases.pop();})],
  ['known positive is rejection', 'invalid_known_positive', root => rewrite(root, 'index.json', i => {i.known_positive = 'smoke/rejection';})],
  ['path escape', 'invalid_file_inventory', root => rewrite(root, 'index.json', i => {i.files[0].path = '../outside';})],
];
test('corpus consumption ties out inventory, index pin and known-positive execution', async () => {
  assert.ok(existsSync(new URL('../tools/conformance/loader.ts', import.meta.url)), 'corpus verifier requires an implementation');
  const {runCorpus} = await import('../tools/conformance/loader.ts');
  const report = await runCorpus(fixture, {smoke: true});
  assert.equal(report.ok, true, JSON.stringify(report)); assert.equal(report.listed, 19); assert.equal(report.executed, 19); assert.equal(report.known_positive_executed, true);
  assert.equal((await runCorpus(fixture)).ok, false, 'release pin refuses the separate smoke corpus');
});
for (const [name, reason, mutation] of mutations) test(`conformance tamper: ${name}`, async () => {
  assert.ok(existsSync(new URL('../tools/conformance/loader.ts', import.meta.url)), 'corpus tamper defenses require an implementation');
  const {runCorpus} = await import('../tools/conformance/loader.ts');
  // Every temporary corpus is removed at its creation scope.
  const root = await mkdtemp(join(tmpdir(), 'request-seal-corpus-mutant-'));
  try {
    await cp(fixture, root, {recursive: true}); await mutation(root);
    const report = await runCorpus(root, {unpinned: true});
    assert.equal(report.ok, false, `${name} was accepted`);
    assert.equal(report.failures[0]!.reason, reason);
    const child = spawnSync(process.execPath, [...cliPrefix, 'tools/conformance/cli.ts', '--corpus', root, '--unpinned'], {encoding: 'utf8'});
    assert.equal(child.status, 1, child.stdout + child.stderr);
    assert.equal(JSON.parse(child.stdout).ok, false);
  } finally { await rm(root, {recursive: true, force: true}); }
});
test('listed source references resolve RFC 6901 pointers without losing numeric text', async () => {
  const {resolvePointer} = await import('../tools/conformance/loader.ts');
  assert.equal(typeof resolvePointer, 'function', 'source-reference support requires an implementation');
  const {decodeJson} = await import('../src/json.ts');
  const parsed = decodeJson(new TextEncoder().encode('{"a/b":{"~key":[9007199254740993]}}'));
  assert.ok(parsed.ok);
  const node = resolvePointer(parsed.value.node, '/a~1b/~0key/0');
  assert.deepEqual(node, {kind: 'number', lexeme: '9007199254740993'});
  assert.throws(() => resolvePointer(parsed.value.node, '/a~2b'));
  assert.throws(() => resolvePointer(parsed.value.node, '/a~1b/~0key/00'));
});
test('a real listed source reference executes, while an invalid pointer fails', async () => {
  const {runCorpus, canonicalJson} = await import('../tools/conformance/loader.ts');
  const root = await mkdtemp(join(tmpdir(), 'request-seal-corpus-reference-'));
  try {
    await cp(fixture, root, {recursive: true}); await mkdir(resolve(root, 'sources'), {recursive: true});
    const source = canonicalJson({'a/b': {'~key': 'YWJj'}});
    await writeFile(resolve(root, 'sources/value.json'), source);
    const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(source))), b => b.toString(16).padStart(2, '0')).join('');
    await rewrite(root, 'index.json', index => {index.files.push({path: 'sources/value.json', sha256: digest}); index.files.sort((a: {path:string}, b: {path:string}) => a.path < b.path ? -1 : 1);});
    await rewrite(root, 'cases/smoke/bytes.json', manifest => {manifest.inputs.value = {ref: {file: 'sources/value.json', pointer: '/a~1b/~0key'}};});
    const positive = await runCorpus(root, {unpinned: true}); assert.equal(positive.ok, true, canonicalJson(positive));
    await rewrite(root, 'cases/smoke/bytes.json', manifest => {manifest.inputs.value.ref.pointer = '/absent';});
    const rejected = await runCorpus(root, {unpinned: true}); assert.equal(rejected.ok, false);
    assert.ok(rejected.failures.some(f => f.reason === 'invalid_source_reference'));
  } finally { await rm(root, {recursive: true, force: true}); }
});

for (const operation of ['base64url.decode', 'json.decode', 'not.an.operation']) {
  for (const value of [undefined, {}, {b64: 1}, {b64: 'AA', extra: true}]) {
    test(`malformed ${operation} input fails at loader with case ID ${JSON.stringify(value)}`, async () => {
      const {runCorpus} = await import('../tools/conformance/loader.ts');
      const {tmpdir} = await import('node:os'); const {join} = await import('node:path');
      const root = await mkdtemp(join(tmpdir(), 'request-seal-shape-'));
      try {
        await cp(fixture, root, {recursive: true});
        await rewrite(root, 'cases/smoke/rejection.json', c => {c.inputs = {operation}; if(value !== undefined) c.inputs.value = value;});
        const report = await runCorpus(root, {unpinned: true});
        assert.deepEqual(report.failures[0], {id: 'smoke/rejection', reason: 'invalid_manifest'});
      } finally {await rm(root, {recursive: true, force: true});}
    });
  }
}
test('malformed manifest JSON fails per case and inventory rejects case-insensitive collisions', async () => {
  const {runCorpus, canonicalJson} = await import('../tools/conformance/loader.ts');
  const {tmpdir} = await import('node:os'); const {join} = await import('node:path');
  const root = await mkdtemp(join(tmpdir(), 'request-seal-manifest-'));
  try {
    await cp(fixture, root, {recursive: true});
    const raw = '{'; await writeFile(resolve(root, 'cases/smoke/rejection.json'), raw);
    const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw))), b => b.toString(16).padStart(2, '0')).join('');
    await rewrite(root, 'index.json', i => {i.files.find((f: {path: string}) => f.path === 'cases/smoke/rejection.json').sha256 = digest;});
    assert.deepEqual((await runCorpus(root, {unpinned: true})).failures[0], {id: 'smoke/rejection', reason: 'invalid_manifest'});
    await cp(fixture, root, {recursive: true});
    await rewrite(root, 'index.json', i => {i.files.push({...i.files[0], path: 'cases/smoke/BYTES.json'}); i.files.sort((a: {path:string},b: {path:string}) => a.path < b.path ? -1 : 1);});
    assert.equal((await runCorpus(root, {unpinned: true})).failures[0]?.reason, 'invalid_file_inventory');
  } finally {await rm(root, {recursive: true, force: true});}
});

test('conformance tamper: smoke pin detects index mutation', async () => {
  const {runCorpus} = await import('../tools/conformance/loader.ts');
  const root = await mkdtemp(join(tmpdir(), 'request-seal-smoke-pin-'));
  try {
    await cp(fixture, root, {recursive: true});
    await rewrite(root, 'index.json', i => {i.known_positive = 'smoke/rejection';});
    const report = await runCorpus(root, {smoke: true});
    assert.equal(report.failures[0]!.reason, 'index_pin_mismatch');
  } finally {await rm(root, {recursive: true, force: true});}
});
test('manifest paths that collide case-insensitively reject before execution', async () => {
  const {runCorpus} = await import('../tools/conformance/loader.ts');
  const root = await mkdtemp(join(tmpdir(), 'request-seal-folded-manifest-'));
  try {
    await cp(fixture, root, {recursive: true});
    await rewrite(root, 'index.json', i => {i.cases[1].manifest = 'cases/smoke/BYTES.json';});
    const report = await runCorpus(root, {unpinned: true});
    assert.equal(report.failures[0]?.reason, 'invalid_or_duplicate_case');
  } finally {await rm(root, {recursive: true, force: true});}
});
for (const expected of [{bytes: {}}, {bytes: {b64: 1}}, {bytes: {b64: 'Zh'}}, {bytes: {b64: 'YWJj', extra: true}}]) {
  test(`malformed expected bytes fail at loader with case ID ${JSON.stringify(expected)}`, async () => {
    const {runCorpus} = await import('../tools/conformance/loader.ts');
    const root = await mkdtemp(join(tmpdir(), 'request-seal-expected-shape-'));
    try {
      await cp(fixture, root, {recursive: true});
      await rewrite(root, 'cases/smoke/bytes.json', c => {c.expected = expected;});
      assert.deepEqual((await runCorpus(root, {unpinned: true})).failures[0], {id: 'smoke/bytes', reason: 'invalid_manifest'});
    } finally {await rm(root, {recursive: true, force: true});}
  });
}

test('a caller registry supplies rejection kinds for its custom surface', async () => {
  const {runCorpus, surfaceRegistry} = await import('../tools/conformance/loader.ts');
  const root = await mkdtemp(join(tmpdir(), 'request-seal-custom-registry-'));
  try {
    await cp(fixture, root, {recursive: true});
    await rewrite(root, 'cases/smoke/rejection.json', c => {c.surface = 'caller.smoke';});
    await rewrite(root, 'index.json', i => {i.cases.find((c: any) => c.id === 'smoke/rejection').surface = 'caller.smoke';});
    const registry = new Map(surfaceRegistry());
    const real = registry.get('smoke')!;
    // The existing real decoder still executes; the caller names its surface.
    registry.set('caller.smoke', Object.assign((...args: Parameters<typeof real>) => real(...args), {errorKinds: real.errorKinds ?? []}));
    const report = await runCorpus(root, {unpinned: true, registry});
    assert.equal(report.ok, true, JSON.stringify(report));
    const listed = JSON.parse(await readFile(join(root, 'index.json'), 'utf8')).cases.length;
    assert.equal(report.executed, listed); assert.equal(report.known_positive_executed, true);
  } finally {await rm(root, {recursive: true, force: true});}
});
