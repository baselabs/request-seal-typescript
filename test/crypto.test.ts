import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import fc from 'fast-check';
import * as api from '../src/index.ts';

const root = 'test/fixtures/upstream/crypto/';
const text = (name: string) => readFile(root + name, 'utf8');
const hex = (s: string) => new Uint8Array(Buffer.from(s, 'hex'));
const bytes = (s: string) => new TextEncoder().encode(s);
function value<T>(r: api.Result<T>): T {
  assert.equal(r.ok, true, r.ok ? '' : api.ruleId(r.error));
  if (!r.ok) throw new Error('Rejected');
  return r.value;
}
// This assertion executes before accessing new exports, so the initial red names the absent behavior.
test('crypto exports a real signature boundary', () => {
  assert.equal(
    Object.hasOwn(api, 'Crypto'),
    true,
    'Crypto boundary must be exported',
  );
});
test('published RFC 9421, RFC 6979, and RFC 8032 primitive vectors', async (t) => {
  const {Crypto, Custody, PublicKey} = api as any;
  assert.ok(Crypto, 'Crypto boundary must be exported');
  const vectors = JSON.parse(await text('rfc9421.json'));
  assert.equal(vectors.length, 7);
  for (const v of vectors) {
    const material =
      v.key === 'hmac'
        ? {
            hmac: new Uint8Array(
              Buffer.from((await text('hmac.txt')).trim(), 'base64'),
            ),
          }
        : await text(v.key + '_private.pem');
    const handle: any = value(await Custody.local(v.algorithm, material));
    const key =
      v.key === 'hmac'
        ? handle
        : value(
            await PublicKey.import(await text(v.key + '_public.pem'), 'pem'),
          );
    const signature = new Uint8Array(Buffer.from(v.signature, 'base64'));
    assert.equal(
      (await Crypto.verify(v.algorithm, key, signature, bytes(v.base))).ok,
      true,
      v.section,
    );
    assert.equal(
      (await Crypto.verify(v.algorithm, key, signature, bytes(v.base + '\n')))
        .ok,
      false,
    );
    const bad = new Uint8Array(signature);
    bad[0]! ^= 1;
    assert.equal(
      (await Crypto.verify(v.algorithm, key, bad, bytes(v.base))).ok,
      false,
    );
    const signed: Uint8Array = value(
      await Crypto.sign(v.algorithm, handle, bytes(v.base)),
    );
    if (['rsa', 'hmac', 'ed25519'].includes(v.key))
      assert.deepEqual(signed, signature);
    assert.equal(
      (await Crypto.verify(v.algorithm, key, signed, bytes(v.base))).ok,
      true,
    );
    value(await handle.release());
    t.diagnostic('Appendix/vector: ' + v.section);
  }
  const p = JSON.parse(await text('rfc6979.json'));
  const pkey = value(
    await PublicKey.import(
      {
        kty: 'EC',
        crv: 'P-384',
        x: api.encodeBase64Url(hex(p.Ux)),
        y: api.encodeBase64Url(hex(p.Uy)),
      },
      'jwk',
    ),
  );
  assert.equal(
    (
      await Crypto.verify(
        'ecdsa-p384-sha384',
        pkey,
        hex(p.r + p.s),
        bytes('sample'),
      )
    ).ok,
    true,
  );
  for (const v of JSON.parse(await text('rfc8032.json'))) {
    const handle: any = value(
      await Custody.local('ed25519', {
        kty: 'OKP',
        crv: 'Ed25519',
        x: api.encodeBase64Url(hex(v['PUBLIC KEY:'])),
        d: api.encodeBase64Url(hex(v['SECRET KEY:'])),
      }),
    );
    assert.deepEqual(
      value(
        await handle.sign('ed25519', hex(v.MESSAGE), value(api.withDeadline())),
      ),
      hex(v['SIGNATURE:']),
    );
    value(await handle.release());
  }
});
test('algorithm registries stay separate; key binding and signature widths reject', async () => {
  const {Crypto, Custody, PublicKey} = api as any;
  assert.ok(Crypto);
  const key = value(
    await PublicKey.import(await text('p256_public.pem'), 'pem'),
  );
  for (const alg of [
    'ES256',
    'ECDSA-P256-SHA256',
    {jws: 'ecdsa-p256-sha256'},
    {jws: 'es256'},
    {jws: 'none'},
  ]) {
    const r = await Crypto.verify(
      alg,
      key,
      new Uint8Array(64),
      bytes('sample'),
    );
    assert.equal(r.error?.reason, 'unsupported_algorithm');
  }
  for (const alg of ['ed25519', 'ecdsa-p384-sha384', 'rsa-pss-sha512'])
    assert.equal(
      (await Crypto.verify(alg, key, new Uint8Array(64), bytes('sample'))).error
        ?.reason,
      'key_mismatch',
    );
  for (const sig of [
    new Uint8Array(63),
    new Uint8Array(65),
    new Uint8Array(1025),
    new Uint8Array(64),
  ])
    assert.equal(
      (await Crypto.verify('ecdsa-p256-sha256', key, sig, bytes('sample')))
        .error?.reason,
      'invalid_signature',
    );
  const handle: any = value(
    await Custody.local('ed25519', await text('ed25519_private.pem')),
  );
  assert.equal(
    (
      await handle.sign(
        {jws: 'EdDSA'},
        bytes('sample'),
        value(api.withDeadline()),
      )
    ).error?.reason,
    'key_mismatch',
  );
  assert.equal(
    (
      await Crypto.sign(
        'ed25519',
        handle,
        new Uint8Array(api.SIGNATURE_BASE_MAX_BYTES + 1),
      )
    ).error?.reason,
    'invalid_data',
  );
  value(await handle.release());
});
test('fast-check signing laws and sampled single-bit corruption for every selector', async () => {
  const {Crypto, Custody} = api as any;
  assert.ok(Crypto);
  const p = JSON.parse(await text('rfc6979.json'));
  const p384 = {
    kty: 'EC',
    crv: 'P-384',
    d: api.encodeBase64Url(hex(p.x)),
    x: api.encodeBase64Url(hex(p.Ux)),
    y: api.encodeBase64Url(hex(p.Uy)),
  };
  const hmac = {
    hmac: new Uint8Array(
      Buffer.from((await text('hmac.txt')).trim(), 'base64'),
    ),
  };
  const cases: [unknown, unknown][] = [
    ['rsa-pss-sha512', await text('rsa_private.pem')],
    ['rsa-v1_5-sha256', await text('rsa_private.pem')],
    ['hmac-sha256', hmac],
    ['ecdsa-p256-sha256', await text('p256_private.pem')],
    ['ecdsa-p384-sha384', p384],
    ['ed25519', await text('ed25519_private.pem')],
    ...[
      'RS256',
      'PS256',
      'PS384',
      'PS512',
      'HS256',
      'ES256',
      'ES384',
      'EdDSA',
    ].map(
      (n) =>
        [
          {jws: n},
          n === 'HS256'
            ? hmac
            : n === 'ES256'
              ? undefined
              : n === 'ES384'
                ? p384
                : undefined,
        ] as [unknown, unknown],
    ),
  ];
  for (const [a, m] of cases) {
    const n = (a as {jws?: string}).jws;
    const material =
      m ??
      (await text(
        n === 'ES256'
          ? 'p256_private.pem'
          : n === 'EdDSA'
            ? 'ed25519_private.pem'
            : 'rsa_private.pem',
      ));
    const h: any = value(await Custody.local(a, material));
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({minLength: 1, maxLength: 128}),
        fc.nat(),
        async (message, pick) => {
          const sig: Uint8Array = value(await Crypto.sign(a, h, message));
          assert.equal((await Crypto.verify(a, h, sig, message)).ok, true);
          const altered = new Uint8Array(sig);
          altered[pick % altered.length]! ^= 1 << pick % 8;
          assert.equal((await Crypto.verify(a, h, altered, message)).ok, false);
          const changed = new Uint8Array(message);
          changed[pick % changed.length]! ^= 1 << pick % 8;
          assert.equal((await Crypto.verify(a, h, sig, changed)).ok, false);
        },
      ),
      {numRuns: 12},
    );
    value(await h.release());
  }
});
test('RFC 9421 Appendix B.3 TLS proxy published signature from checksummed RFC text', async (t) => {
  const {Crypto, PublicKey} = api as any;
  const source = await readFile(
    'test/fixtures/rfc9421-source/rfc9421.txt',
    'utf8',
  );
  const section = source.slice(
    source.lastIndexOf('B.3.  TLS-Terminating Proxies'),
    source.lastIndexOf('B.4.  HTTP Message Transformations'),
  );
  const baseStart = section.indexOf('   "@path": /foo');
  assert.ok(baseStart > 0);
  const block = section.slice(
    baseStart,
    section.indexOf(
      '\n\n   This results in the following signature:',
      baseStart,
    ),
  );
  const base = block
    .replace(/\\\n +/g, '')
    .split('\n')
    .map((line) => line.slice(3))
    .join('\n');
  const match = /\n   (xVM[\s\S]*?)\n\n/.exec(section);
  assert.ok(match);
  const signature = new Uint8Array(
    Buffer.from(match[1]!.replace(/[\\\s]/g, ''), 'base64'),
  );
  const key = value(
    await PublicKey.import(await text('p256_public.pem'), 'pem'),
  );
  assert.equal(
    (await Crypto.verify('ecdsa-p256-sha256', key, signature, bytes(base))).ok,
    true,
  );
  assert.equal(
    (
      await Crypto.verify(
        'ecdsa-p256-sha256',
        key,
        signature,
        bytes(base + '\n'),
      )
    ).ok,
    false,
  );
  t.diagnostic(
    'Appendix/vector: B.3 (ttrp, response B.2.4 separately verified)',
  );
});
test('primitive signature ceiling rejects symmetrically for public keys and handles', async () => {
  const {Crypto, Custody} = api as any;
  const handle: any = value(
    await Custody.local('ed25519', await text('ed25519_private.pem')),
  );
  const publicKey = value(await handle.publicKey());
  for (const key of [handle, publicKey]) {
    const result = await Crypto.verify(
      'ed25519',
      key,
      new Uint8Array(api.SIGNATURE_MAX_BYTES + 1),
      bytes('data'),
    );
    assert.equal(
      !result.ok && result.error.reason,
      'invalid_signature',
      'Oversized signature must reject consistently',
    );
  }
  value(await handle.release());
});
