import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import fc from 'fast-check';
const bytes = (s: string) => new TextEncoder().encode(s);
test('bounded I-JSON preserves pairs, duplicates and number lexemes', async () => {
  assert.ok(existsSync(new URL('../src/json.ts', import.meta.url)), 'owned bounded I-JSON requires an implementation');
  const {decodeJson, encodeJson} = await import('../src/json.ts');
  const decoded = decodeJson(bytes('{"__proto__":1,"constructor":2,"x":9007199254740993,"x":1e2}'));
  assert.ok(decoded.ok);
  assert.deepEqual(decoded.value, {node: {kind: 'object', pairs: [['__proto__', {kind: 'number', lexeme: '1'}], ['constructor', {kind: 'number', lexeme: '2'}], ['x', {kind: 'number', lexeme: '9007199254740993'}], ['x', {kind: 'number', lexeme: '1e2'}]]}, duplicates: ['x']});
  for (const invalid of ['\ufeff{}', '"\\ud800"', '"\\udfff"', '"\\ufdd0"', '"\\uffff"', '"\\udbff\\udfff"', '"\u0001"', '{}x', '{}\u00a0', '01', '+1', '1.', '[1,]', '{"a":1,}', '{"a" 1}', '{a:1}', '[true false]', '', 'NaN']) {
    const result = decodeJson(bytes(invalid)); assert.equal(result.ok, false, JSON.stringify(invalid));
    if (!result.ok) assert.equal('bytes' in result.error, false);
  }
  assert.equal(decodeJson(new Uint8Array([0xff])).ok, false);
  assert.equal(decodeJson(bytes('[[[[[]]]]]')).ok, false);
  assert.equal(decodeJson(bytes('{"a":1,"b":2}'), {maxMembers: 1}).ok, false);
  assert.equal(decodeJson(bytes('[1,2]'), {maxArrayLength: 1}).ok, false);
  assert.equal(decodeJson(bytes('"é"'), {maxStringBytes: 1}).ok, false);
  assert.equal(decodeJson(bytes('null'), {maxBytes: 3}).ok, false);
  assert.equal(decodeJson(bytes('null'), {maxDepth: 0}).ok, false);
  assert.ok(decodeJson(bytes('"\\ud83d\\ude00"')).ok);
  assert.ok(decodeJson(bytes('"\\u0000"')).ok);
  assert.ok(decodeJson(bytes('{} \t\n\r')).ok);
  const edges = JSON.parse(readFileSync(new URL('./fixtures/otp-json-edges.json', import.meta.url), 'utf8'));
  for (const edge of edges.edges) assert.equal(decodeJson(bytes(edge.literal)).ok, edge.accepted, edge.literal);
  // JSON.stringify supplies independent canonical input; never used by the decoder.
  const leaf = fc.oneof(fc.boolean(), fc.constant(null), fc.string({unit: fc.integer({min: 0, max: 127}).map(n => String.fromCharCode(n))}), fc.integer());
  const tree = fc.oneof(leaf, fc.array(leaf, {maxLength: 8}), fc.dictionary(fc.string({unit: fc.integer({min: 0, max: 127}).map(n => String.fromCharCode(n)), maxLength: 12}), leaf, {maxKeys: 8}));
  fc.assert(fc.property(tree, value => {
    const input = JSON.stringify(value); const result = decodeJson(bytes(input)); assert.ok(result.ok);
    const encoded = encodeJson(result.value.node); assert.ok(encoded.ok);
    const next = decodeJson(encoded.value); assert.ok(next.ok); assert.deepEqual(next.value, result.value);
  }), {numRuns: 300});
  const deep = '['.repeat(1500) + '0' + ']'.repeat(1500);
  assert.ok(decodeJson(bytes(deep), {maxDepth: 1500}).ok, 'explicit stack handles permitted deep input');
});
import { spawnSync } from 'node:child_process';
test('JSON encoding bounds a cyclic caller graph and rejects malformed numeric text', async () => {
  const url = new URL('../src/json.ts', import.meta.url).href;
  const code = `import(${JSON.stringify(url)}).then(({encodeJson}) => { const node = {kind:"array",items:[]}; node.items.push(node); const started = performance.now(); const result = encodeJson(node); console.log(JSON.stringify({ok: result.ok, elapsedMs: performance.now() - started})); })`;
  const prefix = Object.hasOwn(process.versions, 'deno') ? ['eval', '--no-check'] : Object.hasOwn(process.versions, 'bun') ? ['-e'] : ['--experimental-strip-types', '--no-warnings', '--input-type=module', '-e'];
  const child = spawnSync(process.execPath, [...prefix, code], {encoding: 'utf8', timeout: 5000});
  // Startup and module loading have a separate watchdog; the encoder retains its bound.
  assert.equal(child.status, 0, 'cyclic encoding child must terminate within its watchdog');
  const result = JSON.parse(child.stdout);
  assert.equal(result.ok, false);
  assert.ok(result.elapsedMs >= 0 && result.elapsedMs < 500, 'cyclic encoding must terminate within the bound');
  const {encodeJson} = await import('../src/json.ts');
  assert.equal(encodeJson({kind: 'number', lexeme: '1}'}).ok, false);
  assert.equal(encodeJson('\ud800').ok, false);
});
