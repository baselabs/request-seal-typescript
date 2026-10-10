import test from 'node:test';
import assert from 'node:assert/strict';
import * as api from '../src/index.ts';
import {dataBytes} from '../src/crypto/primitive.ts';
import {parseField, parse, serialize} from '../src/structured-fields/index.ts';
const value = <T>(r: api.Result<T>): T => {assert.ok(r.ok); return r.value;};
test('cryptographic strings use ByteString octets and reject non-octet code units', () => {
  const latin = '\xff'.repeat(api.SIGNATURE_BASE_MAX_BYTES);
  assert.ok(new TextEncoder().encode(latin).length > api.SIGNATURE_BASE_MAX_BYTES);
  assert.equal(value(dataBytes(latin)).length, api.SIGNATURE_BASE_MAX_BYTES);
  assert.equal(dataBytes(latin + '\xff').ok, false);
  assert.equal(dataBytes('\u0100'.repeat(api.SIGNATURE_BASE_MAX_BYTES / 2)).ok, false);
});
test('parseField checks Message branding before malformed schema and options', () => {
  const r = parseField({}, 'x', {} as never, 'headers', {unknown: true});
  assert.equal(r.ok, false);
  if (!r.ok) {assert.equal(r.error.kind, 'message'); assert.equal(r.error.reason, 'invalid_message');}
});
test('Display String serialization enforces the emitted byte ceiling', () => {
  const parsed = value(parse('item', '%"%c3%a9"', {schema: 'rfc9651'}));
  const bytes = value(serialize(parsed));
  assert.equal(bytes.length, 9);
  assert.equal(serialize(parsed, {limits: {maxBytes: 8}}).ok, false);
  assert.deepEqual(value(serialize(parsed, {limits: {maxBytes: 9}})), bytes);
});

test('query coverage eagerly decodes keys and only selected values', async () => {
  const m = value(await api.Message.request('GET', 'https://example.com/?%FF=x&q=1', [], null));
  for (const name of ['q', 'absent']) {
    const r = api.SignatureBase.build(m, `("@query-param";name="${name}")`);
    assert.equal(!r.ok && r.error.reason, 'invalid_query_encoding');
  }
  const message = value(await api.Message.request('GET', 'https://example.com/?other=%FF&q=1&a+b=2&%E2%82%AC=3', [], null));
  const r = api.SignatureBase.build(message, '("@query-param";name="q" "@query-param";name="a%20b" "@query-param";name="%E2%82%AC")');
  assert.ok(r.ok);
  assert.match(new TextDecoder().decode(r.value), /: 1\n/);
  assert.match(new TextDecoder().decode(r.value), /: 2\n/);
  assert.match(new TextDecoder().decode(r.value), /: 3\n/);
  const bad = api.SignatureBase.build(message, '("@query-param";name="other")');
  assert.equal(!bad.ok && bad.error.reason, 'invalid_query_encoding');
});
