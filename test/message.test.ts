import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import fc from 'fast-check';
import { read } from './support/upstream.ts';
import {
  BODY_MAX_BYTES,
  MESSAGE_MAX_FIELD_BYTES,
  MESSAGE_MAX_TARGET_BYTES,
  MESSAGE_MAX_FIELDS_BYTES,
} from '../src/constants.ts';
const model = async () => {
  assert.ok(
    existsSync(new URL('../src/message/index.ts', import.meta.url)),
    'Message implementation required',
  );
  return import('../src/message/index.ts');
};
const text = (b: Uint8Array) => Array.from(b, (n) => String.fromCharCode(n)).join('');
async function attrs() {
  const { Body, TransportFacts } = await model();
  const b = Body.create({ state: 'unavailable' }),
    t = TransportFacts.create({});
  assert.ok(b.ok && t.ok);
  return {
    kind: 'request',
    method: 'GET',
    rawTarget: '/',
    targetForm: 'origin',
    fields: [],
    trailers: 'unavailable',
    body: b.value,
    transport: t.value,
  };
}
async function request(extra: Record<string, unknown> = {}) {
  const { Message } = await model();
  const r = Message.create({ ...(await attrs()), ...extra });
  assert.ok(r.ok, JSON.stringify(r));
  return r.value;
}
test('captured real HTTP heads preserve every byte and occurrence', async () => {
  const { Message, FieldOccurrence } = await model();
  const head = (bytes: Uint8Array) => {
    const [h, tail] = text(bytes).split('\r\n\r\n');
    assert.equal(tail, '');
    const [line, ...lines] = h!.split('\r\n');
    return {
      line: line!,
      fields: lines.map((l) => {
        const i = l.indexOf(':');
        const f = FieldOccurrence.create({
          name: l.slice(0, i),
          value: l.slice(i + 1),
          section: 'headers',
          provenance: 'http1',
        });
        assert.ok(f.ok);
        return f.value;
      }),
    };
  };
  const q = head(read('http', 'request.http')),
    s = head(read('http', 'response.http'));
  const [method, rawTarget] = q.line.split(' ');
  const req = await request({ method, rawTarget, fields: q.fields });
  assert.equal(req.fields.filter((f) => f.name === 'Accept').length, 2);
  const res = Message.create({
    ...(await attrs()),
    kind: 'response',
    method: null,
    rawTarget: null,
    targetForm: null,
    status: Number(s.line.split(' ')[1]),
    fields: s.fields,
    relatedRequest: req,
  });
  assert.ok(res.ok);
  for (const [h, m, file] of [
    [q, req, 'request.http'],
    [s, res.value, 'response.http'],
  ] as const)
    assert.equal(
      h.line +
        '\r\n' +
        m.fields.map((f) => f.name + ':' + text(f.value) + '\r\n').join('') +
        '\r\n',
      text(read('http', file)),
    );
});
test('all message errors and symmetric constructor/validator rejection paths', async () => {
  const { Message, FieldOccurrence, Body, TransportFacts } = await model();
  const a = await attrs();
  for (const mutation of [
    { method: '' },
    { method: 'GET\r\n' },
    { method: 'G'.repeat(257) },
    { status: 200 },
    { relatedRequest: await request() },
    { rawTarget: '/%GG' },
    { rawTarget: '/a b' },
    { rawTarget: '/#f' },
    { rawTarget: '/a[b]' },
    { rawTarget: '' },
    { rawTarget: '/' + 'a'.repeat(MESSAGE_MAX_TARGET_BYTES) },
    { targetForm: 'absolute' },
    { targetForm: 'asterisk' },
    { method: 'CONNECT' },
    { scheme: 'https' },
    { scheme: 'https', authority: 'user@host' },
    { scheme: 'https', authority: '[abc' },
    { method: 'CONNECT', targetForm: 'authority', rawTarget: 'host:65536' },
    {
      rawTarget: 'https://example.com/',
      targetForm: 'absolute',
      scheme: 'http',
      authority: 'example.com',
    },
    { trailers: 'pending' },
    { unexpected: true },
  ])
    for (const fn of [Message.create, Message.validate]) {
      const r = fn({ ...a, ...mutation });
      assert.ok(!r.ok, JSON.stringify(mutation));
      assert.equal(r.error.reason, 'invalid_message');
    }
  for (const key of ['fields', 'trailers'])
    for (const value of ['bad\r\n', '\0', '\x7f', 'a'.repeat(MESSAGE_MAX_FIELD_BYTES + 1)]) {
      const r = Message.create({
        ...a,
        [key]: [
          {
            name: 'x',
            value,
            section: key === 'fields' ? 'headers' : 'trailers',
            provenance: 'caller',
          },
        ],
      });
      assert.ok(!r.ok);
      assert.equal(r.error.reason, 'invalid_field');
    }
  for (const body of [
    { state: 'retained', bytes: 'x'.repeat(BODY_MAX_BYTES + 1) },
    { state: 'streaming' },
    { state: 'unavailable', bytes: '' },
    { state: 'retained', bytes: '', ownership: 'library' },
  ]) {
    assert.equal(Body.create(body).ok, false);
    const r = Message.create({ ...a, body });
    assert.ok(!r.ok);
    assert.equal(r.error.reason, 'invalid_body');
  }
  for (const transport of [
    { evidence: 'observed' },
    { tls: true },
    { httpVersion: 'guess' },
    { peer: 'x' },
  ]) {
    assert.equal(TransportFacts.create(transport).ok, false);
    const r = Message.create({ ...a, transport });
    assert.ok(!r.ok);
    assert.equal(r.error.reason, 'invalid_transport');
  }
  for (const field of [
    { name: 'bad name', value: '', section: 'headers' },
    { name: 'x', value: '', section: 'other' },
  ])
    assert.equal(FieldOccurrence.create(field).ok, false);
  for (const status of [99, 600, '200', null])
    assert.equal(
      Message.create({
        ...a,
        kind: 'response',
        method: null,
        rawTarget: null,
        targetForm: null,
        status,
      }).ok,
      false,
    );
});
test('all target forms, explicit origins, transport and unread real stream', async () => {
  const { Body, Message } = await model();
  for (const [method, targetForm, rawTarget] of [
    ['GET', 'origin', '/a%2fb?'],
    ['GET', 'absolute', 'https://www.example.com'],
    ['CONNECT', 'authority', '[::1]:443'],
    ['OPTIONS', 'asterisk', '*'],
  ]) {
    const r = await request({ method, targetForm, rawTarget });
    assert.equal(r.rawTarget, rawTarget);
    assert.equal(r.scheme, null);
    assert.equal(r.transport.evidence, 'declared');
  }
  const stream = new Blob([new Uint8Array(read('http', 'response.http'))]).stream();
  const body = Body.create({ state: 'streaming', source: stream });
  assert.ok(body.ok);
  const r = Message.create({ ...(await attrs()), body: body.value, trailers: 'pending' });
  assert.ok(r.ok);
  assert.equal(stream.locked, false);
  assert.equal(text((await stream.getReader().read()).value!).slice(0, 8), 'HTTP/1.1');
});
test('builders preserve target octets, origin normalization, duplicate fields and actual digest bytes', async () => {
  const { Message } = await model();
  const bytes = new Uint8Array([0, 255, 1]);
  const m = await Message.request(
    'post',
    'HTTPS://EXAMPLE.COM:443/a%2Fb?',
    [
      ['X', ' one'],
      ['X', 'two'],
    ],
    bytes,
    { digest: ['sha-256', 'sha-512'] },
  );
  assert.ok(m.ok);
  assert.equal(m.value.rawTarget, '/a%2Fb?');
  assert.equal(m.value.authority, 'example.com');
  bytes[0] = 9;
  assert.equal(m.value.body.bytes![0], 0);
  const digest = m.value.fields.at(-1)!;
  const { encodeBase64 } = await import('../src/bytes.ts');
  const sha256 = encodeBase64(
    new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array([0, 255, 1]))),
  );
  assert.ok(text(digest.value).startsWith(`sha-256=:${sha256}:`));
  assert.equal(
    (
      await Message.request('GET', 'https://example.com/', [['Content-Digest', 'x']], null, {
        digest: ['sha-256'],
      })
    ).ok,
    false,
  );
  const response = await Message.response(204, [], null, { request: m.value });
  assert.ok(response.ok);
  assert.equal(response.value.relatedRequest?.rawTarget, m.value.rawTarget);
});
test('field boundary generation and repeats retain order with aggregate ceilings', async () => {
  const { Message, FieldOccurrence } = await model();
  const a = await attrs();
  fc.assert(
    fc.property(
      fc.stringMatching(/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,32}$/),
      fc.array(fc.integer({ min: 0, max: 255 }), { maxLength: 50 }),
      (name, bytes) => {
        const f = FieldOccurrence.create({
          name,
          value: new Uint8Array(bytes),
          section: 'headers',
        });
        const accepted = bytes.every(n => n === 9 || (n >= 32 && n <= 126) || n >= 128);
        assert.equal(f.ok, accepted);
        if (!f.ok) { assert.equal(f.error.reason, 'invalid_field'); return; }
        const r = Message.create({ ...a, fields: [f.value, f.value] });
        assert.ok(r.ok);
        assert.deepEqual(
          r.value.fields.map((x) => [x.name, Array.from(x.value)]),
          [
            [name, bytes],
            [name, bytes],
          ],
        );
      },
    ),
    { seed: 9421, numRuns: 300 },
  );
  const f = FieldOccurrence.create({
    name: 'x',
    value: 'x'.repeat(MESSAGE_MAX_FIELD_BYTES),
    section: 'headers',
  });
  assert.ok(f.ok);
  assert.equal(Message.create({ ...a, fields: Array(17).fill(f.value) }).ok, false);
  assert.ok(MESSAGE_MAX_FIELDS_BYTES < 17 * (MESSAGE_MAX_FIELD_BYTES + 1));
  const tiny = FieldOccurrence.create({ name: 'x', value: '', section: 'headers' });
  assert.ok(tiny.ok);
  assert.ok(Message.create({ ...a, fields: Array(1024).fill(tiny.value) }).ok);
  assert.equal(Message.create({ ...a, fields: Array(1025).fill(tiny.value) }).ok, false);
});
test('aggregate byte boundary, output byte isolation and option keys read once', async () => {
  const { Message, FieldOccurrence } = await model();
  const a = await attrs();
  const big = FieldOccurrence.create({
      name: 'x',
      value: 'a'.repeat(MESSAGE_MAX_FIELD_BYTES),
      section: 'headers',
    }),
    last = FieldOccurrence.create({
      name: 'x',
      value: 'a'.repeat(MESSAGE_MAX_FIELD_BYTES - 16),
      section: 'headers',
    });
  assert.ok(big.ok && last.ok);
  const accepted = Message.create({ ...a, fields: [...Array(15).fill(big.value), last.value] });
  assert.ok(accepted.ok);
  const final = FieldOccurrence.create({
    name: 'x',
    value: 'a'.repeat(MESSAGE_MAX_FIELD_BYTES - 15),
    section: 'headers',
  });
  assert.ok(final.ok);
  const rejected = Message.create({ ...a, fields: [...Array(15).fill(big.value), final.value] });
  assert.ok(!rejected.ok);
  assert.equal(rejected.error.reason, 'invalid_field');
  const bytes = accepted.value.fields[0]!.value;
  bytes[0] = 0;
  assert.equal(accepted.value.fields[0]!.value[0], 97);
  assert.ok(Message.validate(accepted.value).ok);
  let calls = 0;
  const built = await Message.request('GET', 'https://example.com/', [], null, {
    get digest() {
      calls++;
      return ['sha-256'];
    },
  });
  assert.ok(built.ok);
  assert.equal(calls, 1);
  const opts = Object.create({ digest: ['not-an-algorithm'] });
  assert.ok((await Message.request('GET', 'https://example.com/', [], null, opts)).ok);
});
test('target, field-name and combined occurrence counts accept exact ceilings', async () => {
  const { Message, FieldOccurrence } = await model();
  const a = await attrs();
  assert.ok(Message.create({ ...a, rawTarget: '/' + 'a'.repeat(MESSAGE_MAX_TARGET_BYTES - 1) }).ok);
  const f = FieldOccurrence.create({ name: 'x'.repeat(256), value: '', section: 'headers' });
  assert.ok(f.ok);
  assert.equal(
    FieldOccurrence.create({ name: 'x'.repeat(257), value: '', section: 'headers' }).ok,
    false,
  );
  const trailer = FieldOccurrence.create({ name: 'x', value: '', section: 'trailers' });
  assert.ok(trailer.ok);
  assert.ok(
    Message.create({ ...a, fields: [f.value], trailers: Array(1023).fill(trailer.value) }).ok,
  );
  assert.equal(
    Message.create({ ...a, fields: [f.value], trailers: Array(1024).fill(trailer.value) }).ok,
    false,
  );
});

test('every field octet has an explicit accept or reject boundary', async () => {
  const { FieldOccurrence } = await model();
  for (let n = 0; n <= 255; n++) {
    const r = FieldOccurrence.create({ name: 'x', value: new Uint8Array([n]), section: 'headers' });
    assert.equal(r.ok, n === 9 || (n >= 32 && n <= 126) || n >= 128, String(n));
    if (!r.ok) assert.equal(r.error.reason, 'invalid_field');
  }
});
