import test from 'node:test';
import assert from 'node:assert/strict';
import { runInNewContext } from 'node:vm';
import * as SF from '../src/structured-fields/index.ts';
import { Message, Body, TransportFacts, FieldOccurrence } from '../src/message/index.ts';
import { build } from '../src/signature-base/index.ts';
import { BODY_MAX_BYTES } from '../src/constants.ts';
import type { Result } from '../src/result.ts';
const text = (b: Uint8Array) => new TextDecoder().decode(b);
function value<T>(r: Result<T>): T { assert.ok(r.ok, JSON.stringify(r)); return r.value; }
function reason(r: Result<unknown>, expected: string) { assert.ok(!r.ok); assert.equal(r.error.reason, expected); }
const schema = (type: SF.FieldType = 'list') => value(SF.createSchema({ revision: 'rfc9651', type, itemTypes: ['integer', 'decimal', 'date', 'string', 'token', 'bytes', 'boolean', 'display_string'], innerLists: true }));
const item = (s: string): SF.Item => ({ kind: 'item', value: { kind: 'string', value: s }, parameters: [] });
const request = async () => value(await Message.request('GET', 'https://a.example/', [], null));

test('strict IP-literal authority grammar', async () => {
  for (const host of ['[1.2.3.4]', '[127.1]', '[2130706433]', '[0x7f.1]', '[fe80::1%25en0]', '[fe80::1%en0]']) {
    reason(await Message.request('GET', `https://${host}/`, [], null), 'invalid_message');
    const m = await request();
    reason(Message.create({ ...m, method: 'CONNECT', rawTarget: `${host}:443`, targetForm: 'authority', authority: `${host}:443` }), 'invalid_message');
  }
  for (const host of ['[::1]', '[2001:db8::1]', '[::ffff:192.0.2.1]', '[v1.a:b]', '[V1.a:b]', '[vF.host-._~!$&\'()*+,;=:]'])
    {
      value(await Message.request('GET', `https://${host}/`, [], null));
      value(Message.create({ ...await request(), authority: host }));
    }
});
test('URL precedes invalid header', async () => reason(await Message.request('GET', 'broken', [['bad name', 'x']], null), 'invalid_message'));
test('invalid authority follows oversized body', async () => reason(await Message.request('GET', 'https://[127.1]/', [], new Uint8Array(BODY_MAX_BYTES + 1)), 'invalid_body'));
test('changing caller getter keeps lines and signature params consistent', async () => {
  for (const threshold of [3, 4]) {
    let calls = 0;
    const p = { kind: 'inner_list', get value() { return ++calls <= threshold ? [item('@method')] : [item('@authority')]; }, parameters: [] };
    const b = text(value(build(await request(), p)));
    const component = b.slice(0, b.indexOf(':'));
    assert.equal(b.split('\n')[1], `"@signature-params": (${component})`);
  }
});
test('property order cannot conceal duplicate identity', async () => {
  const m = value(await Message.request('GET', 'https://a.example/', [['d', 'a=1']], null));
  const p = { kind: 'inner_list', value: [
    { ...item('d'), parameters: [['key', { kind: 'string', value: 'a' }]] },
    { ...item('d'), parameters: [['key', { value: 'a', kind: 'string' }]] },
  ], parameters: [] };
  reason(build(m, p, { fieldSchemas: { d: schema('dictionary') } }), 'duplicate_component');
});
test('parsed bytes copy on every read including parameters and inner items', () => {
  for (const raw of [':AAEC:', '1;p=:AAEC:', '(:AAEC:);p=:AAEC:']) {
    const type = raw.startsWith('(') ? 'list' : 'item';
    const p = value(SF.parse(type, raw, { schema: schema(type) }));
    const mutate = (v: SF.Value) => {
      if (v.kind === 'item' && v.value.kind === 'bytes') v.value.value[0] = 255;
      if (v.kind === 'item' || v.kind === 'inner_list') for (const [, b] of v.parameters) if (b.kind === 'bytes') b.value[0] = 255;
      if (v.kind === 'list' || v.kind === 'inner_list') v.value.forEach(mutate);
    };
    mutate(p);
    assert.equal(text(value(SF.serialize(p))), raw);
  }
});
test('explicit schema and opt-in inner lists', () => {
  reason(SF.parse('item', '1'), 'invalid_schema');
  for (const revision of ['rfc8941', 'rfc9651']) reason(SF.parse('list', '(1)', { schema: revision }), 'schema_type');
  value(SF.parse('list', '(1)', { schema: schema() }));
});
test('selective dictionary and parameter uniqueness', () => {
  reason(SF.parse('dictionary', 'sha-256=:AA==:, sha-256=:AQ==:', { schema: schema('dictionary'), uniqueKeys: ['sha-256', 'sha-512'] }), 'duplicate_key');
  const p = value(SF.parse('dictionary', 'x=1,x=2', { schema: schema('dictionary'), uniqueKeys: ['sha-256'] }));
  assert.equal(text(value(SF.serialize(p))), 'x=2');
  for (const raw of ['(1;p;p)', '(1);p;p', '1;p;p']) reason(SF.parse('list', raw, { schema: schema(), uniqueParameters: true }), 'duplicate_parameter');
  value(SF.parse('item', '1;p;p', { schema: 'rfc8941', uniqueKeys: 'all' }));
  for (const uniqueKeys of ['wrong', ['Bad'], ['a'.repeat(257)], [1]]) reason(SF.parse('item', '1', { schema: 'rfc8941', uniqueKeys }), 'invalid_limits');
});
test('parseField combines digest occurrences before selective uniqueness', async () => {
  assert.equal(typeof SF.StructuredFields.parseField, 'function');
  const parseField = SF.StructuredFields.parseField;
  const m = value(await Message.request('GET', 'https://a.example/', [['Content-Digest', 'sha-256=:AA==:'], ['content-digest', 'sha-512=:AQ==:']], null));
  const s = schema('dictionary');
  assert.equal(text(value(SF.serialize(value(parseField(m, 'CONTENT-DIGEST', s, 'headers', { uniqueKeys: ['sha-256', 'sha-512'] }))))), 'sha-256=:AA==:, sha-512=:AQ==:');
  const dup = value(await Message.request('GET', 'https://a.example/', [['content-digest', 'sha-256=:AA==:'], ['content-digest', 'sha-256=:AQ==:']], null));
  reason(parseField(dup, 'content-digest', s, 'headers', { uniqueKeys: ['sha-256'] }), 'duplicate_key');
  reason(parseField(m, 'missing', s), 'missing_field');
  reason(parseField(m, 'content-digest', s, 'trailers'), 'unavailable_section');
  reason(parseField({}, 'content-digest', s), 'invalid_message');
  reason(parseField(m, 'bad name', s), 'invalid_field');
});
test('display parse limit precedes malformed escape', () => reason(SF.parse('item', '%"a%zz"', { schema: 'rfc9651', limits: { maxValueBytes: 1 } }), 'limit'));
test('display serialization limit precedes malformed Unicode', () => reason(SF.serialize({ kind: 'item', value: { kind: 'display_string', value: 'aa\ud800' }, parameters: [] }, { schema: 'rfc9651', limits: { maxValueBytes: 1 } }), 'limit'));
test('invalid first parameter precedes parameter ceiling', () => reason(SF.serialize({ ...item('x'), parameters: [['Bad', { kind: 'boolean', value: true }], ['a', { kind: 'boolean', value: true }]] }, { schema: 'rfc8941', limits: { maxParameters: 1 } }), 'invalid_value'));
test('invalid first member precedes member ceiling', () => reason(SF.serialize({ kind: 'dictionary', value: [['Bad', item('x')], ['a', item('x')]] }, { schema: schema('dictionary'), limits: { maxMembers: 1 } }), 'invalid_value'));
test('invalid first inner item precedes inner ceiling', () => reason(SF.serialize({ kind: 'list', value: [{ kind: 'inner_list', value: [null, item('x')], parameters: [] }] }, { schema: schema(), limits: { maxInnerItems: 1 } }), 'invalid_value'));
test('inner list root rejects schema type', () => reason(SF.serialize({ kind: 'inner_list', value: [item('x')], parameters: [] }, { schema: schema() }), 'schema_type'));
test('integer and decimal negative zero normalize', () => {
  for (const [kind, v, expected] of [['integer', -0, '0'], ['decimal', { scaled: -0, scale: 3 }, '0.0']] as const)
    assert.equal(text(value(SF.serialize({ kind: 'item', value: { kind, value: v }, parameters: [] }, { schema: 'rfc9651' }))), expected);
});
test('exact decimal coefficient and RFC decimal ceiling', () => {
  const serialize = (scaled: number | bigint, scale: number) => SF.serialize({ kind: 'item', value: { kind: 'decimal', value: { scaled, scale } }, parameters: [] }, { schema: 'rfc9651' });
  assert.equal(text(value(serialize(999999999999999n * 10n ** 15n, 18))), '999999999999.999');
  reason(serialize(10n ** 30n, 18), 'invalid_value');
  for (const sign of [1n, -1n]) {
    assert.equal(text(value(serialize(sign * 999999999999999n, 3))), `${sign < 0 ? '-' : ''}999999999999.999`);
    reason(serialize(sign * 1000000000000000n, 3), 'invalid_value');
  }
});
test('bases and related requests require branded messages', async () => {
  const m = await request();
  reason(build({ ...m }, '("@method")'), 'invalid_message');
  reason(await Message.response(200, [], null, { request: { ...m } }), 'invalid_message');
  value(await Message.response(200, [], null, { request: m }));
});
test('cross-realm streams stay caller owned and unread', () => {
  const stream = runInNewContext('new ReadableStream()', { ReadableStream });
  Object.setPrototypeOf(stream, { getReader: ReadableStream.prototype.getReader });
  const b = value(Body.create({ state: 'streaming', source: stream }));
  assert.equal(b.source, stream);
  reason(Body.create({ state: 'streaming', source: {} }), 'invalid_body');
});

test('per-entry ceilings cannot skip sparse members or inner items', () => {
  for (const tree of [
    { kind: 'list', value: new Array(1) },
    { kind: 'list', value: [{ kind: 'inner_list', value: new Array(1), parameters: [] }] },
  ]) reason(SF.serialize(tree, { schema: schema() }), 'invalid_value');
});

test('malformed member shape precedes node ceiling', () => {
  reason(SF.serialize({ kind: 'list', value: [{}] }, { schema: schema(), limits: { maxNodes: 1 } }), 'invalid_value');
  reason(SF.serialize({ kind: 'list', value: [{ kind: 'inner_list', value: [{}], parameters: [] }] }, { schema: schema(), limits: { maxNodes: 2 } }), 'invalid_value');
});


test('caller accessors are read once when serializing and constructing a base', async () => {
  const m = await request();
  for (const operation of ['serialize', 'build'] as const) {
    const counts = new Map<string, number>();
    const counted = (name: string, source: Record<string, unknown>) => {
      const target = Object.create(null);
      for (const [key, original] of Object.entries(source))
        Object.defineProperty(target, key, { enumerable: true, get() {
          const label = `${name}.${key}`;
          counts.set(label, (counts.get(label) ?? 0) + 1);
          return original;
        } });
      return target;
    };
    const bare = counted('bare', { kind: 'string', value: '@method' });
    const component = counted('item', { kind: 'item', value: bare, parameters: [] });
    const created = counted('created', { kind: 'integer', value: 1 });
    const flag = counted('flag', { kind: 'boolean', value: true });
    const inner = counted('inner', { kind: 'inner_list', value: [component], parameters: [['created', created], ['extension', flag]] });
    const list = counted('list', { kind: 'list', value: [inner] });
    const result = operation === 'serialize' ? SF.serialize(list, { schema: schema() }) : build(m, inner);
    value(result);
    assert.equal(counts.size, operation === 'serialize' ? 14 : 12);
    for (const [key, count] of counts) assert.equal(count, 1, `${operation}: ${key}`);
  }
});

test('changing bare getters cannot inject additional signature members', async () => {
  const m = await request();
  // Exercise the token, integer, and inner-item attacks from the getter probe.
  for (const threshold of [1, 2, 3, 4, 5]) {
    for (const kind of ['token', 'integer'] as const) {
      let calls = 0;
      const original = kind === 'token' ? 'x' : 1;
      const bare = { kind, get value() { return ++calls <= threshold ? original : `${original}, ("@authority")`; } };
      const p = { kind: 'inner_list', value: [item('@method')], parameters: [[kind === 'token' ? 'extension' : 'created', bare]] };
      const b = text(value(build(m, p)));
      assert.equal(b, `"@method": GET\n"@signature-params": ("@method");${kind === 'token' ? 'extension=x' : 'created=1'}`);
      assert.equal(calls, 1);
    }
    let calls = 0;
    const tok = { kind: 'token', get value() { return ++calls <= threshold ? 'x' : 'x "@authority"'; } };
    const nested = { kind: 'inner_list', value: [{ ...item('@method'), parameters: [['t', tok]] }], parameters: [] };
    reason(build(m, nested), 'invalid_component_parameters');
    assert.equal(calls, 1);
  }
});

test('authority and target grammar follow header and body validation', async () => {
  for (const url of ['https://[127.1]/', 'https://a.example/%zz']) {
    reason(await Message.request('GET', url, [['bad name', 'x']], null), 'invalid_field');
    reason(await Message.request('GET', url, [], new Uint8Array(BODY_MAX_BYTES + 1)), 'invalid_body');
    reason(await Message.request('GET', url, [], null), 'invalid_message');
  }
  reason(await Message.request('GET', 'broken', [], new Uint8Array(BODY_MAX_BYTES + 1)), 'invalid_message');
});

test('listed duplicate keys reject before value syntax and later limits', () => {
  const options = { schema: schema('dictionary'), uniqueKeys: ['sha-256'] };
  for (const raw of ['sha-256=:AA==:, sha-256=:AQ==:, BAD', 'sha-256=:AA==:, sha-256=:invalid:'])
    reason(SF.parse('dictionary', raw, options), 'duplicate_key');
  reason(SF.parse('dictionary', 'a=:AA==:, a=:AQ==:, b=:AA==:', { schema: schema('dictionary'), uniqueKeys: ['a'], limits: { maxMembers: 2 } }), 'duplicate_key');
  reason(SF.parse('dictionary', 'sha-256=:AA==:, sha-256=:AQ==:, BAD', { ...options, uniqueKeys: 'all' }), 'syntax');
  reason(SF.parse('dictionary', 'a=:AA==:, a=:AQ==:, b=:AA==:', { schema: schema('dictionary'), uniqueKeys: 'all', limits: { maxMembers: 2 } }), 'limit');
});

test('serialization validates options before rejecting an inner-list root', () => {
  const root = { kind: 'inner_list', value: [item('x')], parameters: [] };
  reason(SF.serialize(root, { schema: schema(), extra: true }), 'invalid_limits');
  reason(SF.serialize(root, { schema: schema(), limits: { maxBytes: 0 } }), 'invalid_limits');
  reason(SF.serialize(root, { schema: 'wrong' }), 'invalid_schema');
  reason(SF.serialize(root, { schema: schema() }), 'schema_type');
});

test('serialization snapshots preserve own-property shape requirements', () => {
  const tree = { kind: 'item', value: { kind: 'integer', value: 1 }, parameters: [] };
  const input = new Proxy({}, {
    ownKeys() { return Reflect.ownKeys(tree); },
    get(_target, key) { return Reflect.get(tree, key); },
  });
  reason(SF.serialize(input, { schema: 'rfc8941' }), 'invalid_value');
});
