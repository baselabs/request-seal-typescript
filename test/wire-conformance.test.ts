import {PINNED} from './fixtures/upstream/httpwg-structured-fields/PINNED.ts';
import test from 'node:test';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
import {
  surfaceRegistry,
  type CorpusCase,
  type CorpusResources,
} from '../tools/conformance/loader.ts';
import { decodeJson } from '../src/json.ts';
import { read, json } from './support/upstream.ts';
import { ok } from '../src/result.ts';
// Fixture reads and the owned decoder supply source trees to focused registry tests.
const resources: CorpusResources = {
  read(path) {
    return ok(read(path.split('/')[1]!, path.split('/').slice(2).join('/')));
  },
  reference(value) {
    const v = value as { ref: { file: string; pointer: string } };
    const r = this.read(v.ref.file);
    assert.ok(r.ok);
    const parsed = decodeJson(r.value, {
      maxBytes: 16777216,
      maxDepth: 64,
      maxMembers: 100000,
      maxArrayLength: 100000,
      maxStringBytes: 1048576,
    });
    assert.ok(parsed.ok);
    assert.equal(v.ref.pointer, '');
    return ok(parsed.value.node);
  },
};
function manifest(surface: string, inputs: Record<string, unknown>): CorpusCase {
  return {
    format: 'request-seal-conformance-case/1',
    id: 'wire/conformance',
    surface,
    class: 'verify_only',
    evidence_class: 'published_vector',
    source: {
      document: 'RFC 9421',
      section: '2',
      url: 'https://www.rfc-editor.org/rfc/rfc9421.html',
    },
    inputs,
    expected: { valid: true },
  };
}
test('surface registry executes all four wire entry points', async () => {
  const registry = surfaceRegistry();
  for (const name of [
    'structured_fields.parse',
    'structured_fields.serialize',
    'message.validate',
    'signature_base.build',
  ])
    assert.equal(typeof registry.get(name), 'function', name);
  const m = {
    kind: 'request',
    method: 'GET',
    raw_target: '/',
    target_form: 'origin',
    fields: [],
    trailers: 'unavailable',
    body: 'unavailable',
  };
  for (const [surface, inputs] of [
    [
      'structured_fields.parse',
      { field_type: 'item', raw: { b64: 'NDI' }, schema: 'rfc8941', mode: 'rfc' },
    ],
    [
      'structured_fields.serialize',
      {
        value: { kind: 'item', value: { kind: 'integer', value: { int: '42' } }, parameters: [] },
        schema: 'rfc8941',
      },
    ],
    ['message.validate', { message: m }],
    ['signature_base.build', { message: m, parameters: '("@method")' }],
  ] as const) {
    const r = await registry.get(surface)!(manifest(surface, inputs), resources);
    assert.ok(r.ok, JSON.stringify(r));
  }
});
test('batch item formats consume published vectors and detect changed expectations', async () => {
  const registry = surfaceRegistry();
  for (const [surface, format, origin, file] of [
    [
      'structured_fields.parse',
      'httpwg-structured-fields/1',
      'httpwg-structured-fields',
      'examples.json',
    ],
    ['signature_base.build', 'rfc9421-signature-bases/1', 'rfc9421', 'rfc9421.json'],
  ]) {
    const result = await registry.get(surface!)!(
      manifest(surface!, {
        format,
        cases: { ref: { file: `sources/${origin}/${file}`, pointer: '' } },
      }),
      resources,
    );
    assert.ok(result.ok, JSON.stringify(result));
    const cases = json(origin!, file!);
    if (format === 'httpwg-structured-fields/1') cases[0].canonical = ['wrong'];
    else cases[0].base = 'wrong';
    const rejected = await registry.get(surface!)!(
      manifest(surface!, { format, cases }),
      resources,
    );
    assert.equal(rejected.ok, false);
  }
});
test('complete vector batches execute through the real corpus loader', async () => {
  const { mkdtemp, mkdir, writeFile, rm } = await import('node:fs/promises');
  const { createHash } = await import('node:crypto');
  const { runCorpus, canonicalJson } = await import('../tools/conformance/loader.ts');
  const { files } = await import('./support/upstream.ts');
  const root = pathToFileURL(await mkdtemp(join(tmpdir(), 'request-seal-corpus-')) + '/');
  await mkdir(new URL('sources/', root), { recursive: true });
  await mkdir(new URL('cases/', root), { recursive: true });
  try {
    const inventory: { path: string; sha256: string }[] = [],
      cases: { id: string; manifest: string; surface: string; class: string }[] = [];
    const write = async (path: string, bytes: Uint8Array) => {
      await mkdir(new URL('.', new URL(path, root)), { recursive: true });
      await writeFile(new URL(path, root), bytes);
      inventory.push({ path, sha256: createHash('sha256').update(bytes).digest('hex') });
    };
    for (const [origin, file, format, surface] of [
      ...files('httpwg-structured-fields')
        .filter((f) => f.endsWith('.json'))
        .map((f) => [
          'httpwg-structured-fields',
          f,
          'httpwg-structured-fields/1',
          'structured_fields.parse',
        ]),
      ['rfc9421', 'rfc9421.json', 'rfc9421-signature-bases/1', 'signature_base.build'],
    ]) {
      const id = 'wire/' + origin + '-' + file!.replace(/[^a-z0-9]/g, '-'),
        source = `sources/${origin}/${file}`,
        path = 'cases/' + id.split('/')[1] + '.json';
      await write(source, read(origin!, file!));
      const vectors = format === 'httpwg-structured-fields/1' ? json(origin!, file!) : [];
      const optional = vectors.filter((v: any) => v.can_fail);
      const m = manifest(surface!, {format, cases: optional.length ? vectors.filter((v: any) => !v.can_fail) : {ref: {file: source, pointer: ''}}});
      const c = {...m, id};
      await write(path, new TextEncoder().encode(canonicalJson(c)));
      cases.push({id, manifest: path, surface: surface!, class: 'verify_only'});
      for (const [index, vector] of optional.entries()) {
        const decision = PINNED.find(p => p.file === file && p.name === vector.name); assert.ok(decision);
        const itemId = id + '-optional-' + index, itemPath = path.replace('.json', '-optional-' + index + '.json');
        await write(itemPath, new TextEncoder().encode(canonicalJson({...manifest(surface!, {format, cases: [vector]}), id: itemId, pin: decision.outcome})));
        cases.push({id: itemId, manifest: itemPath, surface: surface!, class: 'verify_only'});
      }
    }
    inventory.sort((a, b) => (a.path < b.path ? -1 : 1));
    await writeFile(
      new URL('index.json', root),
      canonicalJson({
        format: 'request-seal-conformance-corpus-index/1',
        elixir_release: 'v0.2.0',
        files: inventory,
        cases,
        known_positive: cases.find((c) => c.id.includes('examples'))!.id,
      }),
    );
    const report = await runCorpus(root.pathname, { unpinned: true });
    assert.equal(report.ok, true, canonicalJson(report));
    assert.equal(report.executed, cases.length);
    assert.equal(report.listed, cases.length);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test('corpus rejection rules use the selected surface error kind', async () => {
  const registry = surfaceRegistry();
  for (const [surface, kind] of [
    ['message.validate', 'message'],
    ['signature_base.build', 'signature_base'],
  ]) {
    const result = await registry.get(surface!)!(
      manifest(surface!, {
        message: {
          kind: 'request',
          method: 'bad method',
          raw_target: '/',
          target_form: 'origin',
          fields: [],
          body: 'unavailable',
        },
        ...(surface === 'signature_base.build' ? { parameters: '()' } : {}),
      }),
      resources,
    );
    assert.ok(!result.ok && 'error' in result);
    assert.equal(result.error.kind, kind);
    assert.equal(result.error.reason, 'invalid_message');
  }
});

test('corpus message keys reject camelCase', async () => {
  const registry = surfaceRegistry();
  const message = { kind: 'request', method: 'GET', raw_target: '/', target_form: 'origin', fields: [], body: 'unavailable', rawTarget: '/' };
  const rejected = await registry.get('message.validate')!(manifest('message.validate', { message }), resources);
  assert.equal(rejected.ok, false);
  const accepted = await registry.get('message.validate')!(manifest('message.validate', { message: { kind: 'request', method: 'GET', raw_target: '/', target_form: 'origin', fields: [], body: 'unavailable' } }), resources);
  assert.ok(accepted.ok);
});
test('decimal oracle distinguishes scaled values that collide as floating point', async () => {
  const cases = [{ name: 'exact decimal', header_type: 'item', raw: ['800000000000.015'], expected: [{ kind: 'number', lexeme: '800000000000.0149' }, []], canonical: ['800000000000.015'] }];
  const r = await surfaceRegistry().get('structured_fields.parse')!(manifest('structured_fields.parse', { format: 'httpwg-structured-fields/1', cases }), resources);
  assert.equal(r.ok, false);
});

test('single HTTPWG corpus decisions use manifest pins instead of fixture pins', async () => {
  const cases = [{name: 'non-zero pad bits', header_type: 'item', raw: [':Zh==:'], can_fail: true}];
  const base = manifest('structured_fields.parse', {format: 'httpwg-structured-fields/1', cases});
  const surface = surfaceRegistry().get('structured_fields.parse')!;
  assert.equal((await surface({...base, pin: 'reject'}, resources)).ok, true);
  assert.equal((await surface({...base, pin: 'accept'}, resources)).ok, false);
});

test('HTTPWG optional verdicts require an explicit accept or reject pin', async () => {
  // Published optional-failure vector that our parser accepts: acceptance cannot
  // hide a missing decision as an incidental parser failure.
  const vectors = json('httpwg-structured-fields', 'binary.json') as any[];
  const vector = vectors.find(v => v.name === 'unpadded' && v.can_fail);
  assert.ok(vector);
  const surface = surfaceRegistry().get('structured_fields.parse')!;
  const m = manifest('structured_fields.parse', {format: 'httpwg-structured-fields/1', cases: [vector]});
  assert.equal((await surface({...m, pin: 'accept'}, resources)).ok, true);
  assert.deepEqual(await surface(m, resources), {ok: false, loaderReason: 'invalid_manifest'});
  assert.deepEqual(await surface({...m, pin: 'unknown'}, resources), {ok: false, loaderReason: 'invalid_manifest'});
});
