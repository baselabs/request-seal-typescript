import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import * as API from '../src/index.ts';
import {JWS, JWE, Nested, KeyManagement, Custody, ok, err, withDeadline, encodeBase64Url, decodeBase64Url, type Result, type Context, type JoseProtectedHeader} from '../src/index.ts';
import {JoseHeader} from '../src/jose/header.ts';
import {joseError} from '../src/errors/types.ts';
import {value} from './support/jose-oaep.ts';
const b = (s: string) => new TextEncoder().encode(s);
function reason(r: Result<unknown>, expected: string) {
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.error.reason, expected);
}
const rsa = async () => JSON.parse(await readFile('conformance/sources/rfc7516/rfc7516.json', 'utf8')).key;
const unknownPolicy = {algorithms: ['HS256'], timeout: 5000, key_resolver: () => err(joseError('unknown_key', 'key'))};

test('key-management rejects mislabeled RSA and GCM wrapping algorithms', async () => {
  for (const [alg, label] of [['RSA-OAEP', 'RSA-OAEP-256'], ['RSA-OAEP-256', 'RSA-OAEP'], ['A128GCMKW', 'A256GCMKW'], ['A256GCMKW', 'A128GCMKW']] as const) {
    const owner = value(await KeyManagement.local(alg, alg.startsWith('RSA') ? await rsa() : crypto.getRandomValues(new Uint8Array(alg === 'A128GCMKW' ? 16 : 32))));
    const recipient = alg.startsWith('RSA') ? value(await Custody.local({jwe: alg}, await rsa())) : owner;
    const cek = crypto.getRandomValues(new Uint8Array(16));
    try {
      let wrapped;
      if (alg.startsWith('RSA')) {
        const token = value(await JWE.encrypt([['alg', alg], ['enc', 'A128GCM']], b('secret'), recipient));
        const parts = token.split('.');
        wrapped = {encrypted_key: value(decodeBase64Url(parts[1])), header: value(JoseHeader.parse(parts[0]))};
      } else wrapped = value(await owner.wrap(alg, cek));
      const header: JoseProtectedHeader = [['alg', label], ['enc', 'A128GCM'], ...wrapped.header.filter(p => p[0] !== 'alg' && p[0] !== 'enc')];
      reason(await owner.decrypt(wrapped.encrypted_key, header), 'decryption_failed');
      reason(await owner.unwrap(wrapped.encrypted_key, header), 'decryption_failed');
    } finally {cek.fill(0); await owner.release(); await recipient.release();}
  }
});
test('key-management unwrap confines content keys and matches boundary failure sequences', (t) => {
  const deno = 'deno' in process.versions, bun = 'bun' in process.versions;
  const prefix = deno ? ['run', '--allow-read'] : bun ? ['run'] : ['--experimental-strip-types', '--no-warnings'];
  const r = spawnSync(process.execPath, [...prefix, 'test/support/jose-subtle-trace.ts'], {encoding: 'utf8', timeout: 30000});
  assert.equal(r.error, undefined, String(r.error));
  t.diagnostic(r.stdout.trim());
  assert.equal(r.status, 0, r.stdout + r.stderr);
});
test('duplicate attachment precedes later malformed syntax and member limits', () => {
  for (const raw of ['{"alg":"HS256","a":1,"a":2,,}', '{"alg":"HS256","a":1,"a":2,' + Array.from({length: 70}, (_, i) => '"k' + i + '":0').join(',') + '}']) reason(JoseHeader.json(b(raw)), 'duplicate_member');
});
test('header depth pre-scan precedes malformed syntax and ignores quoted brackets', () => {
  reason(JoseHeader.json(b('{"alg":"HS256",,"x":[[[[1]]]]}')), 'limit');
  assert.equal(JoseHeader.json(b('{"alg":"HS256","x":"[[[[[\\\""}')).ok, true);
});
test('small header maps validate in reference map order', () => {
  reason(JoseHeader.json(b('{"b":1.5,"a":1000000000000000}')), 'limit');
  reason(JoseHeader.json(b('{"alg":"HS256","x":{"b":1.5,"a":1000000000000000}}')), 'limit');
});
test('compact JSON prefix uses reference leading whitespace', () => {
  for (const ws of ['\v', '\f', '\u00a0', '\u0085', '\u2003']) reason(JoseHeader.compact(b(ws + '{}.x.y'), 3), 'unsupported_serialization');
  reason(JoseHeader.parse(value(JoseHeader.compact(b('\ufeff{}.x.y'), 3))[0]), 'invalid_base64');
});
test('compact non-Latin-1 segments report invalid base64', async () => {
  reason(await JWS.verify('eyJhbGciOiJIUzI1NiJ9.eA.\u0100', unknownPolicy), 'invalid_base64');
  reason(await JWS.verify('\u2003{}.x.y', unknownPolicy), 'invalid_base64');
});
test('signing validates payload and input size before header and binding', async () => {
  reason(await JWS.sign(null, b(''), null), 'detached_payload');
  reason(await JWS.sign(null, null, null), 'invalid_serialization');
  reason(await JWS.signProtected(b('bad'), b(''), null), 'detached_payload');
  const h = value(await Custody.local({jws: 'RS256'}, await rsa()));
  try {reason(await JWS.sign([['alg', 'PS256']], new Uint8Array(786432), h), 'limit');}
  finally {await h.release();}
});
test('caller pair limits and unsafe integers match header reasons', () => {
  reason(JoseHeader.serialize({alg: 'HS256'}), 'limit');
  reason(JoseHeader.serialize([['alg', 'HS256'], ['x', Number.MAX_SAFE_INTEGER + 1]]), 'limit');
});
test('unknown keys resolve before oversized signatures fail verification', async () => {
  reason(await JWS.verify('eyJhbGciOiJIUzI1NiJ9.eA.' + encodeBase64Url(new Uint8Array(1025)), unknownPolicy), 'unknown_key');
});
test('nested JSON-looking inner text reaches JWS serialization rejection', async () => {
  let content: Uint8Array = new Uint8Array();
  const token = value(await JWE.encrypt([['alg', 'dir'], ['enc', 'A128GCM'], ['cty', 'JWT']], b('{"a":1}.x.y'), (_alg: string, cek: Uint8Array) => {content = new Uint8Array(cek); return ok({encrypted_key: new Uint8Array(), header: []});}));
  const jwe = {algorithms: ['dir'], encryption: ['A128GCM'], max_plaintext: 1024, timeout: 5000, key_resolver: () => ok({algorithm: 'dir', unwrap: () => ok(content)})};
  try {reason(await Nested.decrypt(token, {jwe, jws: unknownPolicy}, {content_types: ['JWT']}), 'unsupported_serialization');}
  finally {content.fill(0);}
});
test('nested validates options before policies', async () => {
  reason(await Nested.decrypt(null, null, null), 'invalid_options');
  reason(await Nested.decrypt(null, null, {content_types: []}), 'invalid_options');
});
test('wrapper additions reject injecting nodes and snapshot strings once', async () => {
  const owner = value(await KeyManagement.local('A128GCMKW', crypto.getRandomValues(new Uint8Array(16))));
  try {
    const result = await JWE.encrypt([['alg', 'A128GCMKW'], ['enc', 'A128GCM']], b('payload'), async (alg: string, cek: Uint8Array) => {
      const w = value(await owner.wrap(alg, cek));
      return ok({encrypted_key: w.encrypted_key, header: w.header.map(p => p[0] === 'tag' ? ['tag', {kind: 'number', lexeme: '"' + p[1] + '","kid":"injected","cty":"x"'}] : p)});
    });
    reason(result, 'unsupported_header');
    for (const header of [[['kid', 'injected']], [['iv', 1]]]) reason(await JWE.encrypt([['alg', 'A128GCMKW'], ['enc', 'A128GCM']], b('payload'), () => ok({encrypted_key: new Uint8Array(16), header})), 'unsupported_header');
    let reads = 0;
    const wire = value(await JWE.encrypt([['alg', 'A128GCMKW'], ['enc', 'A128GCM']], b('payload'), async (alg: string, cek: Uint8Array) => {
      const w = value(await owner.wrap(alg, cek));
      return ok({encrypted_key: w.encrypted_key, header: w.header.map(p => [p[0], {get value() {return p[1];}}]).map(p => {
        const pair = [p[0], '']; Object.defineProperty(pair, '1', {get() {reads++; return (p[1] as {value: unknown}).value;}}); return pair;
      })});
    }));
    assert.equal(reads, 2); assert.equal(wire.split('.').length, 5);
  } finally {await owner.release();}
});
test('wrapper failures use branded entropy errors and otherwise signer failure', async () => {
  const pairs = [['alg', 'A128GCMKW'], ['enc', 'A128GCM']];
  reason(await JWE.encrypt(pairs, b('payload'), () => ({ok: false, error: {reason: 'entropy_failure'}})), 'signer_failed');
  reason(await JWE.encrypt(pairs, b('payload'), () => err(joseError('entropy_failure', 'crypto'))), 'entropy_failure');
  const owner = value(await KeyManagement.local('A256GCMKW', crypto.getRandomValues(new Uint8Array(32))));
  try {
    reason(await JWE.encrypt(pairs, b('payload'), (alg: string, cek: Uint8Array) => owner.wrap(alg, cek)), 'signer_failed');
    const failed = await owner.wrap('A128GCMKW', crypto.getRandomValues(new Uint8Array(16)));
    assert.equal(failed.ok, false);
    if (failed.ok) throw Error('Expected a real binding failure');
    reason(await JWE.encrypt(pairs, b('payload'), () => {throw failed.error;}), 'signer_failed');
  }
  finally {await owner.release();}
});
test('callback content capabilities remain caller owned across decrypt calls', async () => {
  const v = JSON.parse(await readFile('conformance/sources/rfc7520/5_6.direct_encryption_using_aes-gcm.json', 'utf8'));
  const owner = value(await KeyManagement.local('dir', value(decodeBase64Url(v.input.key.k))));
  const content = value(await owner.unwrap(new Uint8Array(), [['alg', 'dir']], value(withDeadline())));
  const p = {algorithms: ['dir'], encryption: ['A128GCM'], max_plaintext: 1048576, timeout: 5000, key_resolver: () => ok({algorithm: 'dir', unwrap: () => ok(content)})};
  try {
    for (let i = 0; i < 2; i++) assert.equal((await JWE.decrypt(v.output.compact, p)).ok, true);
    await content.release(); reason(await JWE.decrypt(v.output.compact, p), 'decryption_failed');
  } finally {await content.release(); await owner.release();}
});
test('OAEP measurement declares significance and every corruption pair', async () => {
  const source = await readFile('bench/ceilings.ts', 'utf8');
  assert.match(source, /ks_threshold/); assert.match(source, /pairwise/);
  const doc = await readFile('docs/design/threat-model.md', 'utf8');
  assert.match(doc, /0\.0608/); assert.match(doc, /Run 3/);
});
test('JOSE headers accept Unicode noncharacters as the reference does', () => {
  for (const cp of [0xfdd0, 0xfffe, 0xffff, 0x10ffff]) assert.equal(JoseHeader.json(b('{"alg":"HS256","x":"' + String.fromCodePoint(cp) + '"}')).ok, true);
});
test('nested header objects emit reference small-map order', () => {
  const r = value(JoseHeader.serialize([['alg', 'HS256'], ['x', {b: 1, a: 2}]]));
  assert.equal(new TextDecoder().decode(value(decodeBase64Url(r.protected))), '{"alg":"HS256","x":{"a":2,"b":1}}');
});
test('header implementation is internal to the package', () => {
  assert.equal(Object.hasOwn(API, 'JoseHeader'), false);
  assert.equal(Object.hasOwn(API, 'JWS'), true);
});
test('temporary test key directories are ignored', async () => {
  assert.ok((await readFile('.gitignore', 'utf8')).split('\n').includes('test/.tmp-*/'));
});
test('arity-two function signers sign exact bytes with bounded failures', async () => {
  const v = JSON.parse(await readFile('conformance/sources/rfc7515/rfc7515.json', 'utf8'))['A.1'];
  const owner = value(await Custody.local({jws: 'HS256'}, v.key));
  const parts = v.compact.split('.');
  let calls = 0;
  try {
    const signer = async (selector: unknown, input: Uint8Array) => {calls++; assert.deepEqual(selector, {jws: 'HS256'}); assert.deepEqual(input, b(parts[0] + '.' + parts[1])); return owner.sign(selector, input, value(withDeadline()));};
    assert.equal(value(await JWS.signProtected(value(decodeBase64Url(parts[0])), value(decodeBase64Url(parts[1])), signer)), v.compact);
    const token = value(await JWS.sign([['alg', 'HS256']], b('payload'), async (s: unknown, input: Uint8Array) => owner.sign(s, input, value(withDeadline()))));
    assert.equal((await JWS.verify(token, {algorithms: ['HS256'], timeout: 5000, key_resolver: () => ok({algorithm: 'HS256', key: owner})})).ok, true);
    assert.equal(calls, 1);
    reason(await JWS.sign([['alg', 'HS256']], b('payload'), (_s: unknown, _b: Uint8Array) => {throw Error('private-canary');}), 'signer_failed');
    reason(await JWS.sign([['alg', 'HS256']], b('payload'), (_s: unknown, _b: Uint8Array) => ({ok: true, value: 'not bytes'})), 'signer_failed');
    reason(await JWS.sign([['alg', 'HS256']], b('payload'), async (_s: unknown, _b: Uint8Array) => {await new Promise(r => setTimeout(r, 25)); return ok(new Uint8Array(32));}, {timeout: 2}), 'deadline_exceeded');
  } finally {await owner.release();}
});

test('container duplicate attaches after its value has decoded', () => {
  reason(JoseHeader.json(b('{"alg":"HS256","a":{},"a":{,}}')), 'invalid_header');
  reason(JoseHeader.json(b('{"alg":"HS256","a":{},"a":{}}')), 'duplicate_member');
});

for (const length of [0, 20000]) test('function signer rejects signature length ' + length, async () => {
  const r = await JWS.sign([['alg', 'HS256']], b('payload'), (_s: unknown, _input: Uint8Array) => ok(new Uint8Array(length)));
  reason(r, 'signer_failed');
  if (!r.ok) {assert.equal(r.error.kind, 'jose'); if (r.error.kind === 'jose') assert.equal(r.error.layer, 'crypto');}
});
test('compact octet strings use the same byte limits as byte arrays', () => {
  for (const input of ['\xff'.repeat(600000), new Uint8Array(600000).fill(255)]) reason(JoseHeader.compact(input, 3), 'invalid_serialization');
});
test('protected segment size is measured in bytes', () => {
  reason(JoseHeader.parse('\u0100'.repeat(11000)), 'limit');
  reason(JoseHeader.parse('\xff'.repeat(11000)), 'invalid_base64');
});
test('oversized compact strings reject before encoding or scanning', () => {
  const Original = Uint8Array, originalTest = RegExp.prototype.test, originalIndexOf = String.prototype.indexOf;
  let allocations = 0, scans = 0;
  class Counting extends Original {
    constructor(input: number | ArrayLike<number> | ArrayBuffer = 0) {allocations++; super(input as ArrayBuffer);}
  }
  globalThis.Uint8Array = Counting as Uint8ArrayConstructor;
  RegExp.prototype.test = function(input) {scans++; return originalTest.call(this, input);};
  String.prototype.indexOf = function(...args) {scans++; return originalIndexOf.apply(this, args);};
  try {
    for (const input of ['x'.repeat(1048577), '\u0100'.repeat(1048577)]) {
      allocations = 0; scans = 0;
      const result = JoseHeader.compact(input, 3);
      assert.equal(allocations, 0, 'limit rejects before byte allocation');
      assert.equal(scans, 0, 'limit rejects before scanning any string');
      reason(result, 'limit');
    }
  } finally {globalThis.Uint8Array = Original; RegExp.prototype.test = originalTest; String.prototype.indexOf = originalIndexOf;}
});

for (const [name, input, expected] of [
  ['map-ordered ranges', [['b', 1.5], ['a', 1000000000000000]], 'limit'],
  ['duplicates before types', [['a', 1.5], ['a', 1]], 'duplicate_member'],
  ['depth before types', [['a', 1.5], ['b', [[[[1]]]]]], 'limit'],
  ['nested map-ordered ranges', [['alg', 'HS256'], ['x', {b: 1.5, a: 1000000000000000}]], 'limit'],
] as const) test('caller pairs validate ' + name, () => reason(JoseHeader.serialize(input), expected));
test('timing documentation states the measured runtime split', async () => {
  const doc = await readFile('docs/design/threat-model.md', 'utf8');
  assert.match(doc, /every exceedance involves the masked.data.block population/);
  assert.match(doc, /highest p50 in 11 of 12 Node/);
  assert.match(doc, /none of the six Deno.*none of the six Bun/s);
  assert.match(doc, /No constant-time claim is made/);
});
test('reference differences document wrapper types and signer deadlines', async () => {
  const doc = await readFile('docs/reference/jose.md', 'utf8');
  assert.match(doc, /non-string wrapper addition value.*unsupported_header/s);
  assert.match(doc, /reference.*invalid_base64/s);
  assert.match(doc, /function signer.*branded error/s);
  assert.match(doc, /through a callback.*caller owned/s);
});

test('GCMKW member failures match the pinned decode and width reasons on both paths', async () => {
  const kek = value(await KeyManagement.local('A128GCMKW', crypto.getRandomValues(new Uint8Array(16))));
  const wrap = (algorithm: string, cek: Uint8Array) => kek.wrap('A128GCMKW', cek, value(withDeadline()));
  const compact = value(await JWE.encrypt([['alg','A128GCMKW'],['enc','A128GCM']], b('payload'), wrap));
  const policy = {algorithms: ['A128GCMKW'], encryption: ['A128GCM'], max_plaintext: 1048576, timeout: 5000, key_resolver: () => ok({algorithm: 'A128GCMKW', unwrap: (ek: Uint8Array, h: JoseProtectedHeader, c: Context) => kek.unwrap(ek, h, c)})};
  try {
    for (const member of ['iv','tag']) for (const content of [undefined, '!', encodeBase64Url(new Uint8Array(1))]) {
      const expected = content === undefined || content === '!' ? 'invalid_base64' : member === 'iv' ? 'invalid_iv' : 'invalid_tag';
      const callback = async (_algorithm: string, cek: Uint8Array) => {
        const actual = value(await wrap('A128GCMKW', cek));
        return ok({...actual, header: actual.header.filter(p => p[0] !== member).concat(content === undefined ? [] : [[member, content]])});
      };
      reason(await JWE.encrypt([['alg','A128GCMKW'],['enc','A128GCM']], b('payload'), callback), expected);
      const parts = compact.split('.'); const h = JSON.parse(new TextDecoder().decode(value(decodeBase64Url(parts[0]))));
      if (content === undefined) delete h[member]; else h[member] = content;
      parts[0] = encodeBase64Url(b(JSON.stringify(h))); reason(await JWE.decrypt(parts.join('.'), policy), expected);
    }
  } finally {await kek.release();}
});
test('wrong-width wrapped keys use the pinned encrypt-path reason', async () => {
  const owner = value(await KeyManagement.local('A128GCMKW', crypto.getRandomValues(new Uint8Array(16))));
  try {
    const callback = async (_algorithm: string, cek: Uint8Array) => {
      const real = value(await owner.wrap('A128GCMKW', cek, value(withDeadline())));
      return ok({...real, encrypted_key: real.encrypted_key.subarray(0, -1)});
    };
    reason(await JWE.encrypt([['alg','A128GCMKW'],['enc','A128GCM']], b('payload'), callback), 'decryption_failed');
  } finally {await owner.release();}
});
