import test from 'node:test';
import { pinnedRejects } from './fixtures/upstream/httpwg-structured-fields/PINNED.ts';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import fc from 'fast-check';
import { json, files } from './support/upstream.ts';
import { decodeBase64 } from '../src/bytes.ts';
import { STRUCTURED_FIELDS_LIMITS as ceilings } from '../src/constants.ts';
const fullSchema = (type: string, revision = 'rfc9651') => ({ revision, type, itemTypes: revision === 'rfc8941' ? ['integer', 'decimal', 'string', 'token', 'bytes', 'boolean'] : ['integer', 'decimal', 'string', 'token', 'bytes', 'boolean', 'date', 'display_string'], innerLists: true });
const text = (b: Uint8Array) => new TextDecoder().decode(b);
const sf = async () => {
  assert.ok(
    existsSync(new URL('../src/structured-fields/index.ts', import.meta.url)),
    'Structured Fields implementation required',
  );
  return import('../src/structured-fields/index.ts');
};
function bare(x: any): any {
  if (x?.kind === 'number') {
    if (!/[.eE]/.test(x.lexeme)) return { kind: 'integer', value: Number(x.lexeme) };
    const [mantissa, exp = '0'] = x.lexeme.toLowerCase().split('e');
    const fraction = (mantissa.split('.')[1] ?? '').length;
    return {
      kind: 'decimal',
      value: { scaled: Number(mantissa.replace('.', '')), scale: fraction - Number(exp) },
    };
  }
  if (x && typeof x === 'object') {
    if (x.__type === 'binary') {
      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      let bits = 0,
        acc = 0;
      const out: number[] = [];
      for (const c of x.value.replace(/=+$/, '')) {
        acc = (acc << 5) | alphabet.indexOf(c);
        bits += 5;
        if (bits >= 8) {
          bits -= 8;
          out.push((acc >>> bits) & 255);
          acc &= (1 << bits) - 1;
        }
      }
      return { kind: 'bytes', value: new Uint8Array(out) };
    }
    if (x.__type === 'date') return { kind: 'date', value: Number(x.value.lexeme) };
    return { kind: x.__type === 'displaystring' ? 'display_string' : x.__type, value: x.value };
  }
  return { kind: typeof x === 'boolean' ? 'boolean' : 'string', value: x };
}
export function expected(x: any, type: string): any {
  if (type === 'dictionary')
    return {
      kind: 'dictionary',
      value: x.map(([k, v]: any) => [k, expected(v, Array.isArray(v[0]) ? 'inner_list' : 'item')]),
    };
  if (type === 'list')
    return {
      kind: 'list',
      value: x.map((v: any) => expected(v, Array.isArray(v[0]) ? 'inner_list' : 'item')),
    };
  return {
    kind: type,
    value: type === 'item' ? bare(x[0]) : x[0].map((v: any) => expected(v, 'item')),
    parameters: x[1].map(([k, v]: any) => [k, bare(v)]),
  };
}
test('all HTTPWG published parsing and serialization cases', async (t) => {
  const { parse, serialize } = await sf();
  let total = 0,
    must = 0,
    can = 0;
  for (const file of files('httpwg-structured-fields').filter((f) => f.endsWith('.json')))
    for (const v of json('httpwg-structured-fields', file)) {
      total++;
      if (v.must_fail) must++;
      if (v.can_fail) can++;
      const label = `${file}: ${v.name}`;
      if (v.raw) {
        const p = parse(v.header_type, v.raw.join(', '), { schema: fullSchema(v.header_type) });
        if (
          v.must_fail ||
          (v.can_fail &&
            pinnedRejects(file, v.name))
        )
          assert.equal(p.ok, false, label);
        else {
          assert.ok(p.ok, label + JSON.stringify(p));
          const want = expected(v.expected, v.header_type);
          const normalize = (x: any): any =>
            x?.kind === 'decimal'
              ? {
                  kind: 'decimal',
                  value: { scaled: x.value.scaled * 10 ** (3 - x.value.scale), scale: 3 },
                }
              : Array.isArray(x)
                ? x.map(normalize)
                : x && typeof x === 'object' && !(x instanceof Uint8Array)
                  ? Object.fromEntries(Object.entries(x).map(([k, v]) => [k, normalize(v)]))
                  : x;
          assert.deepEqual(p.value, normalize(want), label);
          const s = serialize(p.value);
          assert.ok(s.ok, label);
          assert.equal(text(s.value), (v.canonical ?? v.raw).join(', '), label);
        }
      }
      if (v.expected) {
        const s = serialize(expected(v.expected, v.header_type), { schema: fullSchema(v.header_type) });
        if (v.must_fail) assert.equal(s.ok, false, label);
        else {
          assert.ok(s.ok, label + JSON.stringify(s));
          assert.equal(text(s.value), (v.canonical ?? v.raw ?? []).join(', '), label);
        }
      }
    }
  assert.equal(total, 2137);
  t.diagnostic(`httpwg total=${total} must_fail=${must} can_fail_pinned=${can}`);
});
test('generated canonical values and strings round-trip; planted duplicates reject', async () => {
  const { parse, serialize } = await sf();
  fc.assert(
    fc.property(
      fc.integer({ min: -999999999999999, max: 999999999999999 }),
      fc.stringMatching(/^[a-z*][a-z0-9*_\-.]{0,24}$/),
      (n, k) => {
        for (const value of [
          expected([{ kind: 'number', lexeme: String(n) }, []], 'item'),
          { kind: 'list', value: [expected([{ kind: 'number', lexeme: String(n) }, []], 'item')] },
          {
            kind: 'dictionary',
            value: [[k, expected([{ kind: 'number', lexeme: String(n) }, []], 'item')]],
          },
        ]) {
          const s = serialize(value, { schema: fullSchema(value.kind) });
          assert.ok(s.ok);
          const p = parse(value.kind, text(s.value), { schema: 'rfc8941' });
          assert.ok(p.ok);
          assert.deepEqual(p.value, value);
          const again = serialize(p.value);
          assert.ok(again.ok);
          assert.equal(text(again.value), text(s.value));
        }
        for (const [type, raw, reason] of [
          ['dictionary', `${k}=1,${k}=${n}`, 'duplicate_key'],
          ['item', `1;${k}=1;${k}=${n}`, 'duplicate_parameter'],
        ]) {
          const p = parse(type, raw, { schema: 'rfc8941', mode: 'unique' });
          assert.ok(!p.ok);
          assert.equal(p.error.reason, reason);
        }
      },
    ),
    { seed: 9651, numRuns: 300 },
  );
});
test('all lowered ceilings and defaults accept boundary and reject one more', async () => {
  const { parse, serialize } = await sf();
  const samples = (n: number): [keyof typeof ceilings, string, string, string][] => [
    ['maxBytes', 'list', 'a' + ' '.repeat(n - 1), 'a' + ' '.repeat(n)],
    [
      'maxMembers',
      'list',
      Array(n).fill('a').join(','),
      Array(n + 1)
        .fill('a')
        .join(','),
    ],
    [
      'maxInnerItems',
      'list',
      '(' + Array(n).fill('a').join(' ') + ')',
      '(' +
        Array(n + 1)
          .fill('a')
          .join(' ') +
        ')',
    ],
    ['maxParameters', 'item', 'a' + ';p'.repeat(n), 'a' + ';p'.repeat(n + 1)],
    [
      'maxNodes',
      'list',
      Array(n - 1)
        .fill('a')
        .join(','),
      Array(n).fill('a').join(','),
    ],
    ['maxKeyBytes', 'dictionary', 'a'.repeat(n), 'a'.repeat(n + 1)],
    ['maxValueBytes', 'item', 'a'.repeat(n), 'a'.repeat(n + 1)],
  ];
  fc.assert(
    fc.property(fc.integer({ min: 2, max: 30 }), (n) => {
      for (const [key, type, a, b] of samples(n)) {
        const opts = { schema: fullSchema(type!, 'rfc8941'), limits: { [key]: n } };
        const p = parse(type, a, opts);
        assert.ok(p.ok, key);
        assert.ok(serialize(p.value, opts).ok, key);
        const bad = parse(type, b, opts);
        assert.ok(!bad.ok, key);
        assert.equal(bad.error.reason, 'limit', key);
      }
    }),
    { seed: 9651, numRuns: 100 },
  );
  for (const [key, n] of Object.entries(ceilings)) {
    const sample = samples(n).find((s) => s[0] === key)!;
    if (key === 'maxNodes') continue;
    assert.ok(parse(sample[1], sample[2], { schema: fullSchema(sample[1], 'rfc8941') }).ok, key);
    const b = parse(sample[1], sample[3], { schema: fullSchema(sample[1], 'rfc8941') });
    assert.ok(!b.ok, key);
    assert.equal(b.error.reason, 'limit', key);
  }
  for (const [key, type, a, b] of [
    ['maxBytes', 'item', 'aa', 'aaa'],
    ['maxMembers', 'list', 'a,a', 'a,a,a'],
    ['maxInnerItems', 'list', '(a a)', '(a a a)'],
    ['maxParameters', 'item', 'a;p;q', 'a;p;q;r'],
    ['maxNodes', 'list', 'a', 'a,a'],
    ['maxKeyBytes', 'dictionary', 'aa', 'aaa'],
    ['maxValueBytes', 'item', 'aa', 'aaa'],
  ]) {
    const p = parse(type, a, { schema: fullSchema(type!, 'rfc8941') }),
      q = parse(type, b, { schema: fullSchema(type!, 'rfc8941') });
    assert.ok(p.ok && q.ok);
    assert.ok(serialize(p.value, { limits: { [key!]: 2 } }).ok);
    const bad = serialize(q.value, { limits: { [key!]: 2 } });
    assert.ok(!bad.ok);
    assert.equal(bad.error.reason, 'limit');
  }
});
test('revision, shape, fixed depth, numeric syntax, UTF-8 and option guards', async () => {
  const { parse, serialize } = await sf();
  for (const raw of ['@1', '%"hello"', '?1;p=@1', '?1;p=%"x"']) {
    const p = parse('item', raw, { schema: 'rfc8941' });
    assert.ok(!p.ok);
    assert.equal(p.error.reason, 'revision_type');
  }
  for (const raw of ['((1))', '1234567890123456', '1.2345', '%"%FF"', '%"%ff"', '"\r"'])
    assert.equal(parse('list', raw, { schema: 'rfc9651' }).ok, false);
  assert.equal(
    serialize(
      { kind: 'item', value: { kind: 'display_string', value: '\ud800' }, parameters: [] },
      { schema: 'rfc9651' },
    ).ok,
    false,
  );
  for (const opts of [
    { unknown: true },
    { limits: { maxBytes: 65537 } },
    { limits: { maxNodes: 0 } },
    { schema: 'unknown' },
    { mode: 'unknown' },
  ])
    assert.equal(parse('item', '1', opts).ok, false);
  const unique = parse('dictionary', 'a=1,a=2', { schema: 'rfc8941', mode: 'unique', limits: { maxMembers: 1 } });
  assert.ok(!unique.ok);
  assert.equal(unique.error.reason, 'limit');
  const p = parse('dictionary', 'a=1,b=2,a=3', { schema: 'rfc8941' });
  assert.ok(p.ok);
  const s = serialize(p.value);
  assert.ok(s.ok);
  assert.equal(text(s.value), 'a=3, b=2');
  assert.ok(Object.isFrozen(p.value));
});
test('every bare type, ordered parameters and inner lists obey the canonical laws', async () => {
  const { parse, serialize } = await sf();
  const key = fc.stringMatching(/^[a-z*][a-z0-9*_\-.]{0,24}$/);
  const bare = fc.oneof(
    fc.integer({ min: -999999999999999, max: 999999999999999 }).map((value) => ({ kind: 'integer', value })),
    fc
      .integer({ min: -999999999999999, max: 999999999999999 })
      .map((scaled) => ({ kind: 'decimal', value: { scaled, scale: 3 } })),
    fc.integer({ min: -999999999999999, max: 999999999999999 }).map((value) => ({ kind: 'date', value })),
    fc.boolean().map((value) => ({ kind: 'boolean', value })),
    fc
      .array(fc.integer({ min: 32, max: 126 }), { maxLength: 20 })
      .map((bytes) => ({ kind: 'string', value: String.fromCharCode(...bytes) })),
    fc
      .stringMatching(/^[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]{0,80}$/)
      .map((value) => ({ kind: 'token', value })),
    fc.uint8Array({ maxLength: 256 }).map((value) => ({ kind: 'bytes', value })),
    fc
      .array(fc.constantFrom('a', '\0', '%', '"', 'é', '😀', '\ufeff'), { maxLength: 20 })
      .map((chars) => ({ kind: 'display_string', value: chars.join('') })),
  );
  const params = fc.uniqueArray(fc.tuple(key, bare), { maxLength: 4, selector: (x) => x[0] });
  const item = fc
    .tuple(bare, params)
    .map(([value, parameters]) => ({ kind: 'item', value, parameters }));
  const member = fc.oneof(
    item,
    fc
      .tuple(fc.array(item, { maxLength: 4 }), params)
      .map(([value, parameters]) => ({ kind: 'inner_list', value, parameters })),
  );
  const values = fc.oneof(
    item,
    fc.array(member, { maxLength: 4 }).map((value) => ({ kind: 'list', value })),
    fc
      .uniqueArray(fc.tuple(key, member), { maxLength: 4, selector: (x) => x[0] })
      .map((value) => ({ kind: 'dictionary', value })),
  );
  fc.assert(
    fc.property(values, (value) => {
      const s = serialize(value, { schema: fullSchema(value.kind) });
      assert.ok(s.ok, JSON.stringify(s));
      const p = parse(value.kind, text(s.value), { schema: fullSchema(value.kind) });
      assert.ok(p.ok);
      assert.deepEqual(p.value, value);
      const s2 = serialize(p.value);
      assert.ok(s2.ok);
      assert.deepEqual(s2.value, s.value);
    }),
    { seed: 89419651, numRuns: 300 },
  );
});
test('the default node ceiling counts every encounter before deduplication', async () => {
  const { parse } = await sf();
  const good = Array(1023).fill('a;p;q;r').concat('a;p;q').join(','),
    bad = Array(1024).fill('a;p;q;r').join(',');
  assert.ok(parse('list', good, { schema: 'rfc8941' }).ok);
  const rejected = parse('list', bad, { schema: 'rfc8941' });
  assert.ok(!rejected.ok);
  assert.equal(rejected.error.reason, 'limit');
});
test('schema restrictions, nested retention and own option snapshots apply symmetrically', async () => {
  const { parse, serialize, createSchema } = await sf();
  const restrictions = [
    { itemTypes: ['integer'] },
    { parameterTypes: ['boolean'] },
    { innerLists: false },
  ];
  const base = {
    revision: 'rfc9651',
    type: 'list',
    itemTypes: ['integer', 'string', 'boolean'],
    parameterTypes: ['integer', 'string', 'boolean'],
    innerLists: true,
  };
  const value = parse('list', '("x");p=1', { schema: base });
  assert.ok(value.ok);
  for (const extra of restrictions) {
    const schema = createSchema({ ...base, ...extra });
    assert.ok(schema.ok);
    const a = parse('list', '("x");p=1', { schema: schema.value }),
      b = serialize(value.value, { schema: schema.value });
    assert.ok(!a.ok && !b.ok);
    assert.equal(a.error.reason, 'schema_type');
    assert.equal(b.error.reason, 'schema_type');
  }
  let schemaReads = 0,
    modeReads = 0,
    limitReads = 0,
    byteReads = 0;
  const p = parse('list', '(@1)', {
    get schema() {
      schemaReads++;
      return fullSchema('list');
    },
    get mode() {
      modeReads++;
      return 'unique';
    },
    get limits() {
      limitReads++;
      return {
        get maxBytes() {
          byteReads++;
          return 20;
        },
      };
    },
  });
  assert.ok(p.ok && p.value.kind === 'list');
  assert.deepEqual([schemaReads, modeReads, limitReads, byteReads], [1, 1, 1, 1]);
  const inner = p.value.value[0];
  assert.ok(inner?.kind === 'inner_list');
  const child = serialize(inner.value[0]);
  assert.ok(child.ok);
  assert.equal(text(child.value), '@1');
  const inherited = Object.create({ schema: 'rfc9651' });
  const rejected = parse('item', '@1', inherited);
  assert.ok(!rejected.ok);
  assert.equal(rejected.error.reason, 'invalid_schema');
});
test('malformed serializer roots reject as invalid values',async()=>{
 const {serialize}=await sf();for(const value of [{},{kind:'unknown',value:[]},{kind:'item',parameters:[]}]){const result=serialize(value, { schema: 'rfc8941' });assert.ok(!result.ok);assert.equal(result.error.reason,'invalid_value');}
});

test('shared canonical padding rulings reject all three byte sequences', async () => {
  const { PINNED } = await import('./fixtures/upstream/httpwg-structured-fields/PINNED.ts');
  const { parse } = await sf();
  for (const decision of PINNED) if ('raw' in decision && decision.reason === 'canonical padding') {
    const p = parse('item', decision.raw, { schema: 'rfc8941' });
    assert.ok(!p.ok);
    assert.equal(p.error.reason, 'syntax');
  }
});

test('independently generated canonical strings span the full grammar', async () => {
  const { parse, serialize } = await sf();
  const key = fc.stringMatching(/^[a-z*][a-z0-9*_\-.]{0,40}$/);
  const integer = fc.integer({ min: -999999999999999, max: 999999999999999 }).map(n => n === 0 ? 0 : n);
  const bare = fc.oneof(
    integer.map(value => ({ kind: 'integer', value })),
    integer.map(value => ({ kind: 'date', value })),
    integer.map(scaled => ({ kind: 'decimal', value: { scaled, scale: 3 } })),
    fc.boolean().map(value => ({ kind: 'boolean', value })),
    fc.array(fc.integer({ min: 32, max: 126 }), { maxLength: 128 }).map(chars => ({ kind: 'string', value: String.fromCharCode(...chars) })),
    fc.stringMatching(/^[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]{0,128}$/).map(value => ({ kind: 'token', value })),
    fc.uint8Array({ maxLength: 512 }).map(value => ({ kind: 'bytes', value })),
    fc.array(fc.integer({ min: 0, max: 0x10ffff }).map(n => n >= 0xd800 && n <= 0xdfff ? 'x' : String.fromCodePoint(n)), { maxLength: 40 }).map(chars => ({ kind: 'display_string', value: chars.join('') })),
  );
  const parameters = fc.uniqueArray(fc.tuple(key, bare), { selector: p => p[0], maxLength: 8 });
  const item = fc.tuple(bare, parameters).map(([value, parameters]) => ({ kind: 'item', value, parameters }));
  const member = fc.oneof(item, fc.tuple(fc.array(item, { maxLength: 8 }), parameters).map(([value, parameters]) => ({ kind: 'inner_list', value, parameters })));
  const tree = fc.oneof(item, fc.array(member, { maxLength: 8 }).map(value => ({ kind: 'list', value })), fc.uniqueArray(fc.tuple(key, member), { selector: p => p[0], maxLength: 8 }).map(value => ({ kind: 'dictionary', value })));
  // Independent test encoder: decimal digit placement and native base64, no product serializer.
  const quote = (s: string) => '"' + Array.from(s, c => c === '"' || c === '\\' ? '\\' + c : c).join('') + '"';
  function encodeBare(b: any): string {
    switch (b.kind) {
      case 'integer': return String(b.value);
      case 'date': return '@' + b.value;
      case 'decimal': {
        const digits = String(Math.abs(b.value.scaled)).padStart(4, '0');
        const fraction = digits.slice(-3).replace(/0+$/, '') || '0';
        return (b.value.scaled < 0 ? '-' : '') + digits.slice(0, -3) + '.' + fraction;
      }
      case 'boolean': return b.value ? '?1' : '?0';
      case 'token': return b.value;
      case 'bytes': return ':' + Buffer.from(b.value).toString('base64') + ':';
      case 'string': return quote(b.value);
      case 'display_string': return '%"' + Array.from(Buffer.from(b.value, 'utf8'), n => n >= 32 && n <= 126 && n !== 34 && n !== 37 ? String.fromCharCode(n) : '%' + n.toString(16).padStart(2, '0')).join('') + '"';
      default: throw new Error('Unexpected generated kind');
    }
  }
  const params = (p: any[]) => p.map(([k, b]) => ';' + k + (b.kind === 'boolean' && b.value ? '' : '=' + encodeBare(b))).join('');
  function encode(v: any): string {
    if (v.kind === 'item') return encodeBare(v.value) + params(v.parameters);
    if (v.kind === 'inner_list') return '(' + v.value.map(encode).join(' ') + ')' + params(v.parameters);
    if (v.kind === 'list') return v.value.map(encode).join(', ');
    return v.value.map(([k, m]: any) => k + (m.kind === 'item' && m.value.kind === 'boolean' && m.value.value ? params(m.parameters) : '=' + encode(m))).join(', ');
  }
  fc.assert(fc.property(tree, v => {
    const canonical = encode(v);
    const parsed = parse(v.kind, canonical, { schema: fullSchema(v.kind) });
    assert.ok(parsed.ok, canonical);
    assert.deepEqual(parsed.value, v);
    const bytes = serialize(parsed.value);
    assert.ok(bytes.ok);
    assert.equal(text(bytes.value), canonical);
  }), { seed: 94219651, numRuns: 500 });
  fc.assert(fc.property(key, k => {
    for (const [type, raw, reason] of [
      ['dictionary', `${k}=1,${k}=2`, 'duplicate_key'],
      ['item', `1;${k};${k}`, 'duplicate_parameter'],
      ['list', `(1;${k};${k})`, 'duplicate_parameter'],
      ['list', `(1);${k};${k}`, 'duplicate_parameter'],
      ['dictionary', `${k}=(1;${k};${k})`, 'duplicate_parameter'],
      ['dictionary', `${k}=(1);${k};${k}`, 'duplicate_parameter'],
    ]) {
      const p = parse(type, raw, { schema: fullSchema(type!), mode: 'unique' });
      assert.ok(!p.ok);
      assert.equal(p.error.reason, reason);
    }
  }), { seed: 96519421, numRuns: 300 });
});


test('optional-failure pins are scoped to their source file', () => {
  assert.equal(pinnedRejects('binary.json', 'non-zero pad bits'), true);
  assert.equal(pinnedRejects('string.json', 'non-zero pad bits'), false);
  assert.equal(pinnedRejects('binary.json', 'unpadded'), false);
});
