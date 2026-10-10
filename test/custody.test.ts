import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile, readdir} from 'node:fs/promises';
import {createHash, KeyObject} from 'node:crypto';
import {inspect} from 'node:util';
import * as api from '../src/index.ts';
function value<T>(r: api.Result<T>): T {
  assert.equal(r.ok, true, r.ok ? '' : api.ruleId(r.error));
  if (!r.ok) throw new Error('Rejected');
  return r.value;
}
const bytes = (s: string) => new TextEncoder().encode(s);
test('fixtures known-positive then exact SHA256SUMS inventories', async (t) => {
  for (const dir of [
    'upstream/crypto',
    'upstream/custody',
    'wycheproof',
    'rfc9421-source',
  ]) {
    const root = 'test/fixtures/' + dir + '/';
    const lines = (await readFile(root + 'SHA256SUMS', 'utf8'))
      .trim()
      .split('\n');
    const entries = lines.map((line) => line.split('  ') as [string, string]);
    const check = async ([hash, name]: [string, string]) =>
      assert.equal(
        createHash('sha256')
          .update(await readFile(root + name))
          .digest('hex'),
        hash,
        name,
      );
    await check(entries[0]!);
    t.diagnostic('KNOWN-POSITIVE: ' + entries[0]![1]);
    for (const entry of entries) {
      await check(entry);
      t.diagnostic(entry[1] + ': OK');
    }
    assert.deepEqual(
      entries.map((e) => e[1]).sort(),
      (await readdir(root))
        .filter((n) => !['SHA256SUMS', 'PROVENANCE.md'].includes(n))
        .sort(),
    );
  }
});
test('custody exports a confined handle and local importer', () => {
  assert.equal(
    Object.hasOwn(api, 'Custody'),
    true,
    'Custody importer must be exported',
  );
});
test('private JWK imports metadata agreement and RSA CRT rejection', async () => {
  const {Custody} = api as any;
  assert.ok(Custody);
  const jwks = JSON.parse(
    await readFile('test/fixtures/upstream/custody/rfc7517.json', 'utf8'),
  );
  const ed = JSON.parse(
    await readFile('test/fixtures/upstream/custody/rfc8037.json', 'utf8'),
  );
  const [ec, rsa] = jwks.keys;
  const signingEc = {...ec};
  delete signingEc.use;
  assert.equal(
    (await Custody.local('ecdsa-p256-sha256', ec)).error?.reason,
    'key_mismatch',
  );
  for (const [a, k] of [
    ['ecdsa-p256-sha256', signingEc],
    [{jws: 'RS256'}, rsa],
    ['ed25519', ed],
  ]) {
    const h: any = value(await Custody.local(a, k));
    const c = value(api.withDeadline());
    const sig = value(await h.sign(a, bytes('sample'), c));
    assert.equal((await h.verify(a, sig, bytes('sample'), c)).ok, true);
    for (const [field, bad, reason] of [
      ['d', 'AA', 'invalid_key'],
      ['alg', 'HS256', 'key_mismatch'],
      ['key_ops', ['verify'], 'key_mismatch'],
      ['key_ops', null, 'invalid_key'],
    ])
      assert.equal(
        (await Custody.local(a, {...k, [field as string]: bad})).error?.reason,
        reason,
      );
    value(await h.release());
  }
  for (const field of ['d', 'p', 'q', 'dp', 'dq', 'qi'])
    assert.equal(
      (await Custody.local({jws: 'RS256'}, {...rsa, [field]: 'AQ'})).error
        ?.reason,
      'invalid_key',
    );
  assert.equal(
    (
      await Custody.local('ed25519', {
        ...ed,
        x: api.encodeBase64Url(new Uint8Array(32)),
      })
    ).error?.reason,
    'invalid_key',
  );
  const oneAsymmetric = await readFile('test/fixtures/upstream/crypto/rfc8410_10_3_oneasymmetrickey.pem', 'utf8');
  // Published armor has six END dashes; OTP accepts it before the v2 container check.
  assert.equal((await Custody.local('ed25519', oneAsymmetric)).error?.reason, 'unsupported_format');
  assert.equal((await Custody.local('ed25519', oneAsymmetric.replace('-----END PRIVATE KEY------', '-----END PRIVATE KEY-----'))).error?.reason, 'unsupported_format');
  assert.equal(
    (
      await Custody.local(
        'ed25519',
        '-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----',
      )
    ).error?.reason,
    'unsupported_format',
  );
  assert.equal(
    (
      await Custody.local(
        'rsa-v1_5-sha256',
        await readFile(
          'test/fixtures/upstream/crypto/rsa_pss_private.pem',
          'utf8',
        ),
      )
    ).error?.reason,
    'key_mismatch',
  );
});
test('caller-owned identities unknown never equals itself release rejects all operations', async () => {
  const {Custody, KeyIdentity} = api as any;
  assert.ok(Custody);
  const handles: any[] = [];
  for (const identity of [
    bytes('trusted-alias'),
    'trusted-alias',
    'different',
    undefined,
  ])
    handles.push(
      value(
        await Custody.local('hmac-sha256', {
          hmac: bytes('custody-secret-canary-32-byte-string'),
          ...(identity === undefined ? {} : {identity}),
        }),
      ),
    );
  const identities = await Promise.all(
    handles.map(async (h) => value(await h.identity())),
  );
  assert.equal(value(KeyIdentity.same(identities[0], identities[1])), true);
  assert.equal(value(KeyIdentity.same(identities[0], identities[2])), false);
  assert.equal(value(KeyIdentity.same(identities[3], identities[3])), false);
  assert.equal(inspect(identities[0]).includes('trusted-alias'), false);
  const h = handles[0];
  value(await h.release());
  const c = value(api.withDeadline());
  for (const r of [
    await h.sign('hmac-sha256', bytes('data'), c),
    await h.verify('hmac-sha256', new Uint8Array(32), bytes('data'), c),
    await h.publicKey(),
    await h.identity(),
    await h.unwrap({jwe: 'RSA-OAEP'}, new Uint8Array(256), c),
  ])
    assert.equal(r.error?.reason, 'key_not_found');
  for (const item of handles) value(await item.release());
});
test('canary traversal observes positive controls then every fault result and handle', async (t) => {
  const {Custody} = api as any;
  assert.ok(Custody);
  const sentinel = 'custody-private-sentinel-32-byte-secret';
  const realKey = await crypto.subtle.importKey(
    'raw',
    bytes(sentinel),
    {name: 'HMAC', hash: 'SHA-256'},
    false,
    ['sign', 'verify'],
  );
  function found(input: unknown, visited = new Set<object>()): boolean {
    if (typeof input === 'string') return input.includes(sentinel);
    if (!input || (typeof input !== 'object' && typeof input !== 'function') || visited.has(input)) return false;
    visited.add(input);
    if (input instanceof CryptoKey) return true;
    if (input instanceof Uint8Array)
      return new TextDecoder().decode(input).includes(sentinel);
    for (const k of Reflect.ownKeys(input)) {
      const d = Object.getOwnPropertyDescriptor(input, k);
      if (d && 'value' in d && found(d.value, visited)) return true;
      if (d?.get) {
        try {if (found(d.get.call(input), visited)) return true;}
        catch (e) {if (found(e, visited)) return true;}
      }
    }
    return found(Object.getPrototypeOf(input), visited);
  }
  assert.equal(found({nested: [realKey]}), true);
  assert.equal(found({get inheritedKey() {return realKey;}}), true);
  assert.equal(found(Object.create({nested: [bytes(sentinel)]})), true);
  if (process.versions.deno !== '2.5.6')
    assert.ok(KeyObject.from(realKey).export().includes(Buffer.from(sentinel)));
  else assert.throws(() => KeyObject.from(realKey), TypeError);
  assert.throws(() => KeyObject.from({} as CryptoKey));
  assert.equal(found({nested: [bytes(sentinel)]}), true);
  const asymmetric = [
    ['rsa-v1_5-sha256', 'rsa_private.pem', '6FC966E4967685476E2E7ABE38028248E0DE590ED4AACEDE7ADD9BA9EB800F4F'],
    ['ecdsa-p256-sha256', 'p256_private.pem', '529B85F3597E90EC5B8DFED3E26352BF4AF9B4DEBB1A29BBAE77FA105A5C603B'],
  ] as const;
  const needles = await Promise.all(asymmetric.map(async ([, file, prefix], index) => {
    const {readPem, readDer} = await import('../src/custody/der.ts');
    const pem = value(readPem(await readFile('test/fixtures/upstream/crypto/' + file, 'utf8')));
    const node = value(readDer(pem.der));
    const raw = node.children[index === 0 ? 3 : 1]!.bytes;
    const secret = new Uint8Array(raw[0] === 0 && index === 0 ? raw.subarray(1) : raw);
    assert.equal(Buffer.from(secret.subarray(0, 32)).toString('hex').toUpperCase(), prefix);
    function erase(n: typeof node): void {n.bytes.fill(0); for (const child of n.children) erase(child);}
    erase(node); pem.der.fill(0);
    return secret;
  }));
  const encodedNeedles = needles.flatMap(n => [Buffer.from(n).toString('hex'), api.encodeBase64Url(n)]);
  function asymmetricFound(input: unknown, visited = new Set<object>()): boolean {
    if (typeof input === 'string') return encodedNeedles.some(n => input.toLowerCase().includes(n.toLowerCase()));
    if (!input || (typeof input !== 'object' && typeof input !== 'function') || visited.has(input)) return false;
    visited.add(input);
    if (input instanceof CryptoKey) return true;
    if (input instanceof Uint8Array) return needles.some(n => Buffer.from(input).includes(Buffer.from(n)));
    for (const k of Reflect.ownKeys(input)) {
      const d = Object.getOwnPropertyDescriptor(input, k);
      if (d && 'value' in d && asymmetricFound(d.value, visited)) return true;
      if (d?.get) {try {if (asymmetricFound(d.get.call(input), visited)) return true;} catch (e) {if (asymmetricFound(e, visited)) return true;}}
    }
    return asymmetricFound(Object.getPrototypeOf(input), visited);
  }
  for (const n of needles) {
    assert.equal(asymmetricFound({get secret() {return n;}}), true);
    assert.equal(asymmetricFound(Object.create({secret: api.encodeBase64Url(n)})), true);
  }
  const asymmetricPaths: unknown[] = [];
  for (const [algorithm, file] of asymmetric) {
    const pem = await readFile('test/fixtures/upstream/crypto/' + file, 'utf8');
    const {readPem} = await import('../src/custody/der.ts');
    const der = value(readPem(pem)).der;
    for (const material of [der.slice(0, -1), new Uint8Array([...der, 0]), pem.replace('-----END', 'AAAA\n-----END')]) {
      const r = await Custody.local(algorithm, material);
      assert.equal(r.ok, false);
      asymmetricPaths.push(r);
    }
    const handle: api.KeyHandle = value(await api.Custody.local(algorithm, pem));
    asymmetricPaths.push(handle, await handle.sign('ed25519', bytes('data'), value(api.withDeadline())));
    value(await handle.release());
    asymmetricPaths.push(await handle.sign(algorithm, bytes('data'), value(api.withDeadline())));
    der.fill(0);
  }
  for (const item of asymmetricPaths) {
    assert.equal(asymmetricFound(item), false);
    assert.equal(asymmetricFound(JSON.stringify(item)), false);
    assert.equal(asymmetricFound(inspect(item, {showHidden: true, depth: null})), false);
    try {assert.equal(asymmetricFound(structuredClone(item)), false);} catch (e) {assert.equal(asymmetricFound(e), false);}
  }
  const h: any = value(
    await Custody.local('hmac-sha256', {hmac: bytes(sentinel)}),
  );
  const controller = new AbortController();
  controller.abort(sentinel);
  const c = value(api.withDeadline({signal: controller.signal}));
  const paths = [
    await Custody.local('ed25519', sentinel),
    await h.sign('ed25519', bytes('data'), value(api.withDeadline())),
    await h.sign('hmac-sha256', bytes('data'), c),
    await api.run(value(api.withDeadline()), () => {
      throw new Error(sentinel);
    }),
  ];
  value(await h.release());
  paths.push(
    await h.sign('hmac-sha256', bytes('data'), value(api.withDeadline())),
  );
  for (const item of [h, ...paths]) {
    assert.equal(found(item), false);
    if (item === h) assert.throws(() => KeyObject.from(h));
    assert.equal(found(JSON.stringify(item)), false);
    assert.equal(found(inspect(item)), false);
    try {
      assert.equal(found(structuredClone(item)), false);
    } catch (e) {
      assert.equal(found(e), false);
    }
  }
  t.diagnostic(
    'CANARIES: HMAC, RSA d and P-256 scalar; getters/prototypes, DER truncation/trailing/bad armor, wrong algorithm, deadline/abort, custodian throw, released handle; positive controls found; fault sentinel/CryptoKey search: 0',
  );
});
