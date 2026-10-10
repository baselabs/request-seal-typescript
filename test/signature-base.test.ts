import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import fc from 'fast-check';
import { json } from './support/upstream.ts';
import { Message, Body, TransportFacts, FieldOccurrence } from '../src/message/index.ts';
import { parse, createSchema } from '../src/structured-fields/index.ts';
const engine = async () => {
  assert.ok(
    existsSync(new URL('../src/signature-base/index.ts', import.meta.url)),
    'Signature base implementation required',
  );
  return import('../src/signature-base/index.ts');
};
const text = (b: Uint8Array) => new TextDecoder().decode(b);
function request(extra: Record<string, unknown> = {}) {
  const b = Body.create({ state: 'unavailable' }),
    t = TransportFacts.create({});
  assert.ok(b.ok && t.ok);
  const r = Message.create({
    kind: 'request',
    method: 'POST',
    rawTarget: '/path?param=value',
    targetForm: 'origin',
    scheme: 'https',
    authority: 'www.example.com',
    fields: [],
    trailers: 'unavailable',
    body: b.value,
    transport: t.value,
    ...extra,
  });
  assert.ok(r.ok, JSON.stringify(r));
  return r.value;
}
function fields(pairs: readonly (readonly [string, string | Uint8Array])[], section = 'headers') {
  return pairs.map(([name, value]) => {
    const r = FieldOccurrence.create({ name, value, section });
    assert.ok(r.ok);
    return r.value;
  });
}
function response(relatedRequest: unknown = null, extra: Record<string, unknown> = {}) {
  return requestResponse({ relatedRequest, ...extra });
}
function requestResponse(extra: Record<string, unknown>) {
  const b = Body.create({ state: 'unavailable' }),
    t = TransportFacts.create({});
  assert.ok(b.ok && t.ok);
  const r = Message.create({
    kind: 'response',
    status: 200,
    fields: [],
    trailers: 'unavailable',
    body: b.value,
    transport: t.value,
    ...extra,
  });
  assert.ok(r.ok);
  return r.value;
}
function published(v: any): Message {
  return v.kind === 'request'
    ? request({
        method: v.method,
        rawTarget: v.raw_target,
        scheme: v.scheme,
        authority: v.authority,
        fields: fields(v.fields),
      })
    : response(v.related_request ? published(v.related_request) : null, {
        status: Number(v.status.lexeme),
        fields: fields(v.fields),
      });
}
test('all RFC 9421 complete bases and Appendix B.4 transformations', async (t) => {
  const { build } = await engine();
  const vectors = json('rfc9421', 'rfc9421.json');
  assert.equal(vectors.length, 12);
  assert.equal(vectors[0].section, '2.4');
  let transforms = 0;
  for (const v of vectors) {
    const m = published(v.message),
      b = build(m, v.parameters);
    assert.ok(b.ok, JSON.stringify(b));
    assert.equal(text(b.value), v.base, v.section);
    const p = parse('list', v.parameters, { schema: { revision: 'rfc8941', type: 'list', itemTypes: ['string'], innerLists: true } });
    assert.ok(p.ok && p.value.kind === 'list');
    const direct = build(m, p.value.value[0]);
    assert.ok(direct.ok);
    assert.equal(text(direct.value), v.base);
    for (const transformation of v.transformations ?? []) {
      transforms++;
      const b = build(published(transformation.message), v.parameters);
      assert.ok(b.ok);
      assert.equal(text(b.value) === v.base, transformation.same_base);
    }
  }
  t.diagnostic(`RFC 9421 bases=${vectors.length} B.4 transformations=${transforms}`);
});
test('all signature-base reasons have exact rejection checks', async () => {
  const { build } = await engine();
  const m = request(),
    r = response(m),
    dictionary = createSchema({
      revision: 'rfc8941',
      type: 'dictionary',
      itemTypes: ['integer', 'string', 'boolean'],
      innerLists: true,
    });
  assert.ok(dictionary.ok);
  const opts = { fieldSchemas: { x: dictionary.value } };
  const x = request({ fields: fields([['x', 'a=1']]) });
  const cases: [unknown, unknown, string, unknown?][] = [
    [null, '()', 'invalid_message'],
    [m, '()', 'invalid_options', { unknown: true }],
    [m, '42', 'invalid_signature_parameters'],
    [m, '("@method" "@method")', 'duplicate_component'],
    [m, '("Host")', 'invalid_component'],
    [m, '("@unknown")', 'unknown_component'],
    [m, '("x";unknown)', 'invalid_component_parameters'],
    [m, '("x";bs;sf)', 'incompatible_parameters'],
    [m, '("@status")', 'wrong_message_kind'],
    [response(), '("@method";req)', 'missing_request_context'],
    [request({ scheme: null, authority: null }), '("@authority")', 'unavailable_origin'],
    [m, '("x";tr)', 'unavailable_trailers'],
    [m, '("x")', 'missing_field'],
    [request({ fields: fields([['x', new Uint8Array([255])]]) }), '("x")', 'non_ascii'],
    [x, '("x";sf)', 'unknown_field_schema'],
    [x, '("x";key="z")', 'missing_dictionary_key', opts],
    [
      request({ fields: fields([['x', 'invalid,!!']]) }),
      '("x";sf)',
      'invalid_structured_field',
      opts,
    ],
    [
      x,
      '("x";key="a")',
      'invalid_field_schema',
      { fieldSchemas: { x: { ...dictionary.value, type: 'item' } } },
    ],
    [m, '("@query-param";name="%70aram")', 'noncanonical_query_name'],
    [m, '("@query-param";name="%FF")', 'invalid_query_encoding'],
    [m, '("@query-param";name="absent")', 'missing_query_parameter'],
    [
      request({ rawTarget: '/?a=1&%61=2' }),
      '("@query-param";name="a")',
      'ambiguous_query_parameter',
    ],
    [m, '("@method")', 'limit', { maxBytes: 8 }],
  ];
  for (const [message, p, reason, options] of cases) {
    const b = build(message, p, options);
    assert.ok(!b.ok, reason);
    assert.equal(b.error.kind, 'signature_base', reason);
    assert.equal(b.error.reason, reason);
    assert.equal(Object.keys(b.error).sort().join(','), 'kind,reason');
  }
});
test('field transformations, schema selection, related trailers and exact query encoding', async () => {
  const { build } = await engine();
  const schema = createSchema({
    revision: 'rfc8941',
    type: 'dictionary',
    itemTypes: ['integer', 'boolean'],
    innerLists: true,
  });
  assert.ok(schema.ok);
  const req = request({
    rawTarget: '/a%2Fb?q=with+spaces&empty=&unused=%FF',
    fields: fields([
      ['X', ' a=1'],
      ['x', ' b=2;p'],
    ]),
    trailers: fields([['x', 'c=3']], 'trailers'),
  });
  const b = build(
    response(req),
    '("x";req;sf "x";req;tr;key="c" "x";req;bs "@query-param";req;name="q" "@query-param";req;name="empty")',
    { fieldSchemas: { x: schema.value } },
  );
  assert.ok(b.ok);
  assert.ok(text(b.value).includes('"x";req;sf: a=1, b=2;p\n'));
  assert.ok(text(b.value).includes('"x";req;tr;key="c": 3\n'));
  assert.ok(text(b.value).includes('"x";req;bs: :YT0x:, :Yj0yO3A=:\n'));
  assert.ok(text(b.value).includes('name="q": with%20spaces\n'));
  assert.ok(text(b.value).includes('name="empty": \n'));
  for (const p of [
    '("@method");created="1"',
    '("@method");expires=1.5',
    '("@method");keyid=42',
    '("x";sf=?0)',
    '("@method";tr)',
  ])
    assert.equal(build(req, p).ok, false);
  assert.equal(
    build(response(req), '("x";req;tr;key="c" "x";tr;req;key="c")', {
      fieldSchemas: { x: schema.value },
    }).ok,
    false,
  );
  const raw = build(req, '("@path")'),
    changed = build(request({ ...req, rawTarget: '/a%2fb?q=with+spaces' }), '("@path")');
  assert.ok(raw.ok && changed.ok);
  assert.notEqual(text(raw.value), text(changed.value));
  const bs = build(request({ fields: fields([['x', new Uint8Array([32, 255, 9])]]) }), '("x";bs)');
  assert.ok(bs.ok);
  assert.ok(text(bs.value).startsWith('"x";bs: :/w==:'));
});
test('uncovered headers never change bases and covered order follows parameters', async () => {
  const { build } = await engine();
  fc.assert(
    fc.property(fc.stringMatching(/^[a-z0-9]{1,40}$/), fc.boolean(), fc.uniqueArray(fc.stringMatching(/^[a-z][a-z0-9!#$%&'*+.^_`|~-]{0,30}$/), { minLength: 3, maxLength: 3 }), (value, reverse, generatedNames) => {
      const [x, y, z] = generatedNames as [string, string, string];
      const m = request({
          fields: fields([
            [x, value],
            [y, 'two'],
          ]),
        }),
        names = reverse ? [y, x] : [x, y];
      const p = '(' + names.map((n) => JSON.stringify(n)).join(' ') + ')';
      const a = build(m, p),
        b = build(
          request({
            ...m,
            fields: fields([
              [y, 'two'],
              [x, value],
              [z.toUpperCase(), 'uncovered'],
            ]),
          }),
          p,
        );
      assert.ok(a.ok && b.ok);
      assert.deepEqual(a.value, b.value);
      assert.equal(
        text(a.value).split('\n')[0],
        JSON.stringify(names[0]) + ': ' + (reverse ? 'two' : value),
      );
      const dup = build(m, '(' + JSON.stringify(x) + ' ' + JSON.stringify(x) + ')');
      assert.ok(!dup.ok);
      assert.equal(dup.error.reason, 'duplicate_component');
    }),
    { seed: 9421, numRuns: 300 },
  );
});
test('component, final byte and query-name work ceilings', async () => {
  const { build } = await engine();
  const m = request();
  const good = build(m, '("@method")');
  assert.ok(good.ok);
  assert.ok(build(m, '("@method")', { maxBytes: good.value.length }).ok);
  const bad = build(m, '("@method")', { maxBytes: good.value.length - 1 });
  assert.ok(!bad.ok);
  assert.equal(bad.error.reason, 'limit');
  const p =
    '(' + Array.from({ length: 256 }, (_, n) => `"@query-param";name="k${n}"`).join(' ') + ')';
  const q = request({
    rawTarget: '/?' + Array.from({ length: 900 }, (_, n) => `k${n}=v${n}`).join('&'),
  });
  assert.ok(build(q, p).ok);
  const limited = build(q, p, { maxComponents: 255 });
  assert.ok(!limited.ok);
  assert.equal(limited.error.reason, 'limit');
  for (const opts of [
    { maxComponents: 257 },
    { maxBytes: 1048577 },
    { maxBytes: 0 },
    { fieldSchemas: { X: {} } },
  ])
    assert.equal(build(m, '()', opts).ok, false);
});
test('the default base byte ceiling accepts exactly one MiB and rejects one more', async () => {
  const { build } = await engine();
  const { SIGNATURE_BASE_MAX_BYTES, MESSAGE_MAX_FIELD_BYTES } = await import('../src/constants.ts');
  const names = Array.from({ length: 16 }, (_, i) => `x${i}`),
    p = '(' + names.map((n) => JSON.stringify(n)).join(' ') + ')';
  const overhead =
    names.map((n) => JSON.stringify(n) + ': \n').join('').length +
    ('"@signature-params": ' + p).length;
  const last = SIGNATURE_BASE_MAX_BYTES - overhead - 15 * MESSAGE_MAX_FIELD_BYTES;
  const input = (more: number) =>
    request({
      fields: fields(
        names.map(
          (n, i) => [n, 'a'.repeat(i === 15 ? last + more : MESSAGE_MAX_FIELD_BYTES)] as const,
        ),
      ),
    });
  const accepted = build(input(0), p);
  assert.ok(accepted.ok);
  assert.equal(accepted.value.length, SIGNATURE_BASE_MAX_BYTES);
  const rejected = build(input(1), p);
  assert.ok(!rejected.ok);
  assert.equal(rejected.error.reason, 'limit');
});
test('all nine derived components, target forms and empty paths have exact output', async () => {
  const { build } = await engine();
  const m = request({
    method: 'post',
    rawTarget: '/a%2Fb?q=a+b',
    scheme: 'HTTPS',
    authority: 'WWW.EXAMPLE.COM:443',
  });
  const p =
    '("@method" "@request-target" "@target-uri" "@authority" "@scheme" "@path" "@query" "@query-param";name="q")';
  const b = build(m, p);
  assert.ok(b.ok);
  assert.equal(
    text(b.value),
    [
      '"@method": post',
      '"@request-target": /a%2Fb?q=a+b',
      '"@target-uri": HTTPS://WWW.EXAMPLE.COM:443/a%2Fb?q=a+b',
      '"@authority": www.example.com',
      '"@scheme": https',
      '"@path": /a%2Fb',
      '"@query": ?q=a+b',
      '"@query-param";name="q": a%20b',
      '"@signature-params": ' + p,
    ].join('\n'),
  );
  const status = build(response(), '("@status")');
  assert.ok(status.ok);
  assert.equal(text(status.value), '"@status": 200\n"@signature-params": ("@status")');
  for (const [method, targetForm, rawTarget, scheme, authority, uri] of [
    ['GET', 'absolute', 'https://www.example.com', null, null, 'https://www.example.com'],
    [
      'CONNECT',
      'authority',
      'www.example.com:80',
      'http',
      'www.example.com:80',
      'http://www.example.com:80',
    ],
    ['OPTIONS', 'asterisk', '*', 'http', 'www.example.com', 'http://www.example.com'],
  ]) {
    const m = request({ method, targetForm, rawTarget, scheme, authority });
    const p = '("@request-target" "@path" "@query" "@target-uri")';
    const b = build(m, p);
    assert.ok(b.ok);
    assert.equal(
      text(b.value),
      `"@request-target": ${rawTarget}\n"@path": /\n"@query": ?\n"@target-uri": ${uri}\n"@signature-params": ${p}`,
    );
  }
});
test('covered duplicates change bases; pending trailers reject without reading the stream', async () => {
  const { build } = await engine();
  const a = build(request({ fields: fields([['x', 'one']]) }), '("x")'),
    b = build(
      request({
        fields: fields([
          ['x', 'one'],
          ['x', 'two'],
        ]),
      }),
      '("x")',
    );
  assert.ok(a.ok && b.ok);
  assert.notDeepEqual(a.value, b.value);
  const stream = new Blob([new Uint8Array([1, 2])]).stream(),
    body = Body.create({ state: 'streaming', source: stream });
  assert.ok(body.ok);
  const m = request({ body: body.value, trailers: 'pending' });
  const rejected = build(m, '("x";tr)');
  assert.ok(!rejected.ok);
  assert.equal(rejected.error.reason, 'unavailable_trailers');
  assert.equal(stream.locked, false);
});

test('RFC 9421 Sections 2.1 and 2.2 transcribed component fixtures', async (t) => {
  const { build } = await engine();
  const { readFileSync } = await import('node:fs');
  const { createHash } = await import('node:crypto');
  const raw = readFileSync(new URL('./fixtures/rfc9421-components/components.json', import.meta.url));
  const checksum = readFileSync(new URL('./fixtures/rfc9421-components/SHA256SUMS', import.meta.url), 'utf8').split(' ')[0];
  assert.equal(createHash('sha256').update(raw).digest('hex'), checksum);
  const vectors = JSON.parse(raw.toString());
  const dictionary = createSchema({ revision: 'rfc8941', type: 'dictionary', itemTypes: ['integer', 'token', 'boolean'], innerLists: true });
  assert.ok(dictionary.ok);
  for (const v of vectors) {
    const attrs = v.message;
    const fs = fields(attrs.fields);
    const m = attrs.kind === 'request'
      ? request({ method: attrs.method, rawTarget: attrs.raw_target, targetForm: attrs.target_form, scheme: attrs.scheme, authority: attrs.authority, fields: fs })
      : response(null, { status: attrs.status, fields: fs, trailers: fields(attrs.trailers ?? [], 'trailers') });
    const p = '(' + v.identifier + ')';
    const bytes = valueBase(build(m, p, { fieldSchemas: { 'example-dict': dictionary.value } }));
    assert.equal(text(bytes), v.example_bytes + '\n"@signature-params": ' + p, v.section + ' ' + v.identifier);
  }
  t.diagnostic(`RFC 9421 component examples=${vectors.length}`);
});
function valueBase(r: ReturnType<typeof import('../src/signature-base/index.ts').build>): Uint8Array { assert.ok(r.ok); return r.value; }

test('multi_signature published single-label bases run where derivable', async (t) => {
  const { build } = await engine();
  const corpus = json('multi_signature', 'rfc9421.json');
  const bases = json('rfc9421', 'rfc9421.json');
  let count = 0;
  const execute = (m: Message, signatureInput: string) => {
    const p = parse('dictionary', signatureInput, { schema: { revision: 'rfc8941', type: 'dictionary', itemTypes: ['string'], innerLists: true }, mode: 'unique' });
    assert.ok(p.ok && p.value.kind === 'dictionary');
    for (const [label, member] of p.value.value) {
      assert.equal(member.kind, 'inner_list');
      const result = build(m, member);
      assert.ok(result.ok);
      const rendered = text(result.value);
      const params = rendered.split('\n').at(-1)!.slice('"@signature-params": '.length);
      const vector = bases.find((v: any) => v.parameters === params && v.base === rendered);
      if (vector) assert.equal(rendered, vector.base);
      else {
        // Section 4.3 preserves sig1 after proxy mutation. Its six component lines
        // are the published proxy base prefix; only the signature metadata differs.
        assert.equal(label, 'sig1');
        const proxyBase = bases.find((v: any) => v.section === '4.3').base;
        const fixtureParams = signatureInput.split(', proxy_sig=')[0]!.slice('sig1='.length);
        let lines: string[];
        if (m.authority === 'origin.host.internal.example') lines = proxyBase.split('\n').slice(0, 6);
        else {
          // Section 2.4's signed request uses the request lines of its published
          // response base, in its own explicitly listed order, without req flags.
          const linkedBase = bases.find((v: any) => v.section === '2.4' && v.parameters.includes('"@query";req')).base;
          const sourceLines: string[] = linkedBase.split('\n').filter((line: string) => line.includes(';req:')).map((line: string) => line.replace(';req:', ':'));
          const names = ['@method', '@authority', '@path', '@query', 'content-digest', 'content-type', 'content-length'];
          lines = names.map(name => sourceLines.find(line => line.startsWith('"' + name + '":'))!);
        }
        assert.equal(rendered, lines.join('\n') + '\n"@signature-params": ' + fixtureParams);
      }
      count++;
    }
  };
  for (const signature of corpus.signatures) execute(published(corpus.b2), signature.signature_input);
  for (const source of [corpus.proxy, ...corpus.linkage, ...corpus.linkage.map((m: any) => m.related_request)])
    for (const [name, raw] of source.fields) if (name.toLowerCase() === 'signature-input') execute(published(source), raw);
  t.diagnostic(`multi_signature single-label bases=${count}`);
  assert.equal(count, 10);
});
