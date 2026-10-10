import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import {readFile} from 'node:fs/promises';
import {
  readDer,
  encodeDer,
  readPem,
  writePem,
  decodeKey,
  publicSpki,
  sequence,
  integer,
  oid,
  tlv,
  concat,
  OIDS,
} from '../src/custody/der.ts';
import {
  Custody,
  PublicKey,
  withDeadline,
  encodeBase64Url,
  isKeyHandle,
  isPublicKey,
  isKeyIdentity,
  KEY_MAX_BYTES,
  DER_MAX_DEPTH,
  type Result,
  type KeyHandle,
} from '../src/index.ts';
const value = <T>(r: Result<T>): T => {
  assert.equal(r.ok, true, r.ok ? '' : r.error.reason);
  if (!r.ok) throw new Error('Rejected');
  return r.value;
};
const read = (name: string) =>
  readFile('test/fixtures/upstream/crypto/' + name, 'utf8');
test('DER rejects indefinite nonminimal truncated negative trailing and excessive trees', () => {
  for (const b of [
    [],
    [48, 128, 0, 0],
    [48, 129, 1, 0],
    [2, 2, 0, 1],
    [3, 2, 8, 0],
    [6, 1, 128],
    [48, 0, 0],
    [48, 2, 2, 2],
    [2, 0],
  ])
    assert.equal(readDer(new Uint8Array(b)).ok, false);
  assert.equal(readDer(new Uint8Array(KEY_MAX_BYTES + 1)).ok, false);
  let nested = integer(0n);
  for (let i = 0; i < DER_MAX_DEPTH + 2; i++) nested = sequence(nested);
  assert.equal(readDer(nested).ok, false);
});
test('DER property codec round trips real WebCrypto-generated PKCS8/SPKI structures', async () => {
  const specs = [
    {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-512',
    },
    {name: 'ECDSA', namedCurve: 'P-256'},
    {name: 'ECDSA', namedCurve: 'P-384'},
    {name: 'Ed25519'},
  ];
  const keys: Uint8Array[] = [];
  for (const spec of specs) {
    const pair = (await crypto.subtle.generateKey(spec, true, [
      'sign',
      'verify',
    ])) as {privateKey: CryptoKey; publicKey: CryptoKey};
    keys.push(
      new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey)),
      new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)),
    );
  }
  // Fixed real-key regression set: each generated structure is exercised once.
  for (const der of keys) assert.deepEqual(value(encodeDer(value(readDer(der)))), der);
  for (const der of keys) der.fill(0);
});
test('nested key mutations reach RSA values OIDs EC points and PSS parameters within a bound', async (t) => {
  const names = ['rsa_private.pem', 'rsa_pss_private.pem', 'p256_private.pem', 'ed25519_private.pem', 'rsa_public.pem', 'rsa_pss_public.pem', 'p256_public.pem', 'ed25519_public.pem'];
  const materials = await Promise.all(names.map(async name => value(readPem(await read(name)))));
  const seeds = materials.map(m => m.der);
  // Add a real RSA container with present PSS parameters to reach their children.
  const rsa = value(decodeKey(await read('rsa_private.pem'), 'pem'));
  const rawRsa = value(readDer(rsa.der)).children[2]!.bytes;
  const pss = sequence(integer(0n), sequence(oid(OIDS.pss), sequence(tlv(160, sequence(oid('608648016503040203'), tlv(5, new Uint8Array()))), tlv(162, integer(64n)))), tlv(4, rawRsa));
  seeds.push(pss); materials.push({label: 'PRIVATE KEY', der: pss}); names.push('rsa_pss_private.pem');
  type Shape = {tag: number; bytes: Uint8Array; children: Shape[]; embedded: Shape | undefined; prefix: Uint8Array; depth: number};
  function shape(n: import('../src/custody/der.ts').DerNode, depth = 0): Shape {
    const out: Shape = {tag: n.tag, bytes: new Uint8Array(n.bytes), children: n.children.map(c => shape(c, depth + 1)), embedded: undefined, prefix: new Uint8Array(), depth};
    const prefix = n.tag === 3 && n.bytes[0] === 0 ? 1 : 0;
    if ((n.tag === 4 || prefix) && depth < DER_MAX_DEPTH) {
      const inner = readDer(n.bytes.subarray(prefix));
      if (inner.ok) {out.embedded = shape(inner.value, depth + 1); out.prefix = n.bytes.slice(0, prefix);}
    }
    return out;
  }
  function encode(n: Shape): Uint8Array<ArrayBuffer> {
    return tlv(n.tag, n.embedded ? concat(n.prefix, encode(n.embedded)) : n.children.length ? concat(...n.children.map(encode)) : n.bytes);
  }
  function flatten(n: Shape): Shape[] {return [n, ...n.children.flatMap(flatten), ...(n.embedded ? flatten(n.embedded) : [])];}
  const kinds = ['length', 'tag', 'integer', 'swap', 'order', 'truncate', 'extra', 'oid', 'point'] as const;
  const exercised = new Set<string>(), depths = new Set<number>();
  let rsaValueChecks = 0, oidChanges = 0, pointChanges = 0, pssParameterChanges = 0;
  function mutate(index: number, kind: typeof kinds[number], position: number, choice: number): Uint8Array {
    exercised.add(kind);
    const seed = seeds[index]!;
    if (kind === 'truncate') return seed.slice(0, position % seed.length);
    const root = shape(value(readDer(seed))), nodes = flatten(root);
    const candidates = nodes.filter(n => kind === 'integer' ? n.tag === 2 : kind === 'oid' ? n.tag === 6 : kind === 'point' ? n.tag === 3 && !n.embedded : kind === 'swap' || kind === 'order' || kind === 'extra' ? n.children.length >= 2 : true);
    const selected = (candidates.length ? candidates : nodes)[position % (candidates.length || nodes.length)]!;
    depths.add(selected.depth);
    if (index === 8 && selected.depth >= 3) pssParameterChanges++;
    if (kind === 'integer' && selected.tag === 2) {
      const old = selected.bytes.reduce((v, b) => (v << 8n) | BigInt(b), 0n);
      const next = choice % 2 && old > 0n ? old - 1n : old + 1n;
      selected.bytes = value(readDer(integer(next))).bytes;
    } else if (kind === 'oid' && selected.tag === 6) {selected.bytes[position % selected.bytes.length]! ^= 1; oidChanges++;}
    else if (kind === 'point' && selected.tag === 3) {selected.bytes[1 + position % (selected.bytes.length - 1)]! ^= 1; pointChanges++;}
    else if (kind === 'swap' && selected.children.length >= 2) {
      const at = choice % selected.children.length, other = (at + 1) % selected.children.length;
      [selected.children[at], selected.children[other]] = [selected.children[other]!, selected.children[at]!];
    } else if (kind === 'order') selected.children.reverse();
    else if (kind === 'extra') selected.children.push(shape(value(readDer(tlv(5, new Uint8Array()))), selected.depth + 1));
    else if (kind === 'tag') selected.tag = 31;
    else if (kind === 'length') {selected.bytes = selected.bytes.slice(1); if (selected.children.length) selected.children.pop();}
    const mutated = encode(root);
    // These preconditions are exactly rsaJwk's path to validateRsaValues:
    // canonical parsed INTEGERs, version zero, and the complete component list.
    const parsed = readDer(mutated);
    if (materials[index]!.label === 'RSA PRIVATE KEY' && parsed.ok) {
      let inner = parsed.value;
      if (inner.tag === 48 && inner.children.length === 9 && inner.children.every(n => n.tag === 2 && n.bytes[0]! < 128) && inner.children[0]!.bytes.length === 1 && inner.children[0]!.bytes[0] === 0) rsaValueChecks++;
    }
    return mutated;
  }
  async function check(data: Uint8Array, index: number) {
    const start = performance.now(), label = materials[index]!.label;
    const pem = '-----BEGIN ' + label + '-----\n' + Buffer.from(data).toString('base64') + '\n-----END ' + label + '-----';
    const algorithm = names[index]!.startsWith('rsa') ? 'rsa-pss-sha512' : names[index]!.startsWith('p256') ? 'ecdsa-p256-sha256' : 'ed25519';
    const results = [decodeKey(data, 'pkcs8'), decodeKey(data, 'spki'), decodeKey(pem, 'pem'), await Custody.local(algorithm, pem), await PublicKey.import(pem, 'pem')];
    for (const r of results) {
      assert.equal(typeof r.ok, 'boolean');
      if (r.ok) {
        if (isKeyHandle(r.value)) value(await r.value.release());
        else if ('der' in r.value) r.value.der.fill(0);
      } else assert.ok(['custody', 'crypto'].includes(r.error.kind));
    }
    assert.ok(performance.now() - start < 1000, 'each input traversal stays below 1000 ms');
  }
  for (const [i, seed] of seeds.entries()) {
    if (i === 8) continue;
    const r = decodeKey(value(writePem(materials[i]!.label, seed)), 'pem');
    assert.ok(r.ok); r.value.der.fill(0);
  }
  // Fixed mutation regression table, alongside randomized depth and value changes.
  for (const [index, kind, at, choice] of [[0, 'integer', 1, 0], [1, 'integer', 1, 1], [2, 'point', 0, 0], [8, 'oid', 2, 0], ...kinds.map(k => [0, k, 0, 0])] as [number, typeof kinds[number], number, number][]) await check(mutate(index, kind, at, choice), index);
  await fc.assert(fc.asyncProperty(fc.integer({min: 0, max: seeds.length - 1}), fc.constantFrom(...kinds), fc.nat(), fc.nat(), async (index, kind, position, choice) => {await check(mutate(index, kind, position, choice), index);}), {numRuns: 1000, seed: 42});
  assert.deepEqual([...exercised].sort(), [...kinds].sort());
  assert.ok(rsaValueChecks > 0, 'some inputs reach RSA value checks');
  assert.ok(depths.has(0) && [...depths].some(d => d >= 4), 'root and nested nodes mutated');
  assert.ok(oidChanges > 0 && pointChanges > 0 && pssParameterChanges > 0);
  for (const seed of seeds) seed.fill(0); rsa.der.fill(0);
  t.diagnostic(`STRUCTURED FUZZ: 1000 mutations; RSA value checks=${rsaValueChecks}; OIDs=${oidChanges}; points=${pointChanges}; PSS children=${pssParameterChanges}; depths=${[...depths].sort().join(',')}`);
});
test('PKCS1 SEC1 PKCS8 and PSS restrictions are preserved', async () => {
  const rsa = value(decodeKey(await read('rsa_private.pem'), 'pem'));
  const original = value(readDer(rsa.der));
  const privateOctets = original.children[2]!.bytes;
  for (const label of ['RSA PRIVATE KEY', 'PRIVATE KEY']) {
    const h = value(
      await Custody.local(
        'rsa-v1_5-sha256',
        value(
          writePem(
            label,
            label === 'RSA PRIVATE KEY' ? privateOctets : rsa.der,
          ),
        ),
      ),
    );
    assert.equal(isKeyHandle(h), true);
    value(await h.release());
  }
  const rawPublic = value(publicSpki(rsa.jwk));
  const pubNode = value(readDer(rawPublic));
  const pkcs1 = pubNode.children[1]!.bytes.slice(1);
  assert.equal(
    (await PublicKey.import(value(writePem('RSA PUBLIC KEY', pkcs1)), 'pem'))
      .ok,
    true,
  );
  for (const params of [
    undefined,
    sequence(),
    sequence(
      tlv(160, sequence(oid('608648016503040203'), tlv(5, new Uint8Array()))),
    ),
    sequence(
      tlv(
        161,
        sequence(
          oid('2a864886f70d010108'),
          sequence(oid('608648016503040203'), tlv(5, new Uint8Array())),
        ),
      ),
    ),
    sequence(tlv(162, integer(64n))),
    sequence(tlv(163, integer(1n))),
  ]) {
    const alg = params
      ? sequence(oid(OIDS.pss), params)
      : sequence(oid(OIDS.pss));
    const der = sequence(integer(0n), alg, tlv(4, privateOctets));
    const imported = await Custody.local('rsa-pss-sha512', der);
    const publicDer = sequence(alg, value(encodeDer(pubNode.children[1]!)));
    const publicImported = await PublicKey.import(publicDer, 'spki');
    if (params) assert.equal(!publicImported.ok && publicImported.error.reason, 'invalid_key');
    else assert.ok(publicImported.ok);
    // OpenSSL pkey -text reports empty PSS parameters as SHA-1, MGF1 SHA-1, salt 20 defaults.
    if (params)
      assert.equal(!imported.ok && imported.error.reason, 'unsupported_format');
    else {
      const h = value(imported);
      assert.equal((await Custody.local('rsa-v1_5-sha256', der)).ok, false);
      value(await h.release());
    }
  }
  const ed = value(readPem(await read('ed25519_private.pem')));
  const node = value(readDer(ed.der));
  const v2 = sequence(
    integer(1n),
    ...node.children.slice(1).map((n) => value(encodeDer(n))),
  );
  const rejectedV2 = await Custody.local('ed25519', v2);
  assert.equal(!rejectedV2.ok && rejectedV2.error.reason, 'unsupported_format');
  const ec = value(readPem(await read('p256_private.pem')));
  assert.equal(ec.label, 'EC PRIVATE KEY');
  const ecNode = value(readDer(ec.der));
  const noPoint = sequence(
    ...ecNode.children
      .filter((n) => n.tag !== 161)
      .map((n) => value(encodeDer(n))),
  );
  const h = value(
    await Custody.local(
      'ecdsa-p256-sha256',
      value(writePem('EC PRIVATE KEY', noPoint)),
    ),
  );
  assert.equal((await h.publicKey()).ok, true);
  value(await h.release());
  const conflicting = sequence(
    integer(0n),
    sequence(oid(OIDS.ec), oid(OIDS.p384)),
    tlv(4, ec.der),
  );
  assert.equal(
    (await Custody.local('ecdsa-p384-sha384', conflicting)).ok,
    false,
  );
  rsa.der.fill(0);
  ed.der.fill(0);
  ec.der.fill(0);
});
test('public brands restricted exports thumbprints and small-order Ed25519 rejection', async () => {
  const j = JSON.parse(
    await readFile('test/fixtures/upstream/custody/rfc8037.json', 'utf8'),
  );
  delete j.d;
  const key = value(await PublicKey.import(j, 'jwk'));
  assert.equal(isPublicKey(key), true);
  assert.equal(
    value(await key.thumbprint()),
    'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k',
  );
  const h = value(
    await Custody.local('ed25519', await read('ed25519_private.pem')),
  );
  assert.equal(isKeyIdentity(value(await h.identity())), true);
  assert.equal(isKeyHandle({...h}), false);
  assert.equal(isPublicKey({...key}), false);
  assert.equal(isKeyIdentity({kind: 'unknown'}), false);
  const restricted = value(
    await PublicKey.import(
      {...j, alg: 'EdDSA', use: 'sig', key_ops: ['verify']},
      'jwk',
    ),
  );
  assert.equal(restricted.spki().ok, false);
  assert.equal(restricted.pem().ok, false);
  assert.equal(value(restricted.jwk()).alg, 'EdDSA');
  const bad = [
    '00'.repeat(32),
    '01' + '00'.repeat(31),
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
    'ec' + 'ff'.repeat(30) + '7f',
    'ed' + 'ff'.repeat(30) + '7f',
  ];
  for (const point of bad) {
    const x = new Uint8Array(Buffer.from(point, 'hex'));
    const raw = sequence(
      sequence(oid(OIDS.ed)),
      tlv(3, concat(new Uint8Array([0]), x)),
    );
    for (const [format, input] of [
      ['jwk', {...j, x: encodeBase64Url(x)}],
      ['spki', raw],
      ['pem', value(writePem('PUBLIC KEY', raw))],
    ] as const)
      assert.equal((await PublicKey.import(input, format)).ok, false);
  }
  value(await h.release());
});

test('PEM interior MIME junk is ignored exactly as OTP pem_decode', async () => {
  const {readFile} = await import('node:fs/promises');
  const pem = await readFile('test/fixtures/upstream/crypto/ed25519_public.pem', 'utf8');
  const original = readPem(pem); assert.ok(original.ok);
  for (const junk of ['!', '-', '_', ' ', '\t', '\v', '\f', '\x00']) {
    const altered = readPem(pem.replace(/(-----BEGIN PUBLIC KEY-----\n.)/, '$1' + junk));
    assert.ok(altered.ok, JSON.stringify(junk)); assert.deepEqual(altered.value.der, original.value.der);
  }
});
