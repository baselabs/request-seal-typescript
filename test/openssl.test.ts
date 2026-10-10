import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFile, writeFile, mkdtemp, rm} from 'node:fs/promises';
import {join} from 'node:path';
import {
  Crypto,
  Custody,
  withDeadline,
  encodeBase64Url,
  type Result,
  type SigningAlgorithm,
} from '../src/index.ts';
import {
  sequence,
  integer,
  readDer,
  writePem,
  oid,
  tlv,
  concat,
  OIDS,
} from '../src/custody/der.ts';
import {unsigned} from '../src/crypto/primitive.ts';
import {CURVE_ORDERS, ED25519_ORDER} from '../src/crypto/algorithm.ts';
const value = <T>(r: Result<T>): T => {
  assert.equal(r.ok, true, r.ok ? '' : r.error.reason);
  if (!r.ok) throw new Error('Rejected');
  return r.value;
};
function der(signature: Uint8Array): Uint8Array {
  const width = signature.length / 2;
  return sequence(
    integer(unsigned(signature.slice(0, width))),
    integer(unsigned(signature.slice(width))),
  );
}
function raw(signature: Uint8Array, width: number): Uint8Array {
  const node = value(readDer(signature));
  assert.equal(node.children.length, 2);
  const out = new Uint8Array(width * 2);
  for (let i = 0; i < 2; i++) {
    let bytes = node.children[i]!.bytes;
    if (bytes[0] === 0) bytes = bytes.slice(1);
    assert.ok(bytes.length <= width);
    out.set(bytes, (i + 1) * width - bytes.length);
  }
  return out;
}
test('OpenSSL reciprocal peer every HTTP/JWS algorithm and PSS/ECDSA/Ed25519 negatives', async (t) => {
  const root = await mkdtemp('test/.tmp-openssl-');
  const fixture = 'test/fixtures/upstream/crypto/';
  const command = (args: string[]) => {
    const r = spawnSync('openssl', args, {maxBuffer: 1024 * 1024});
    t.diagnostic('COMMAND: openssl ' + args.join(' '));
    t.diagnostic(
      'RESULT: exit=' +
        r.status +
        ' ' +
        (args.includes('-binary')
          ? 'binary output'
          : r.stdout.toString().trim()) +
        ' ' +
        r.stderr.toString().trim(),
    );
    assert.equal(r.status, 0, r.stderr.toString());
    return new Uint8Array(r.stdout);
  };
  try {
    command(['version']);
    const p = JSON.parse(await readFile(fixture + 'rfc6979.json', 'utf8'));
    const ph = (s: string) => new Uint8Array(Buffer.from(s, 'hex'));
    const p384 = {
      kty: 'EC',
      crv: 'P-384',
      d: encodeBase64Url(ph(p.x)),
      x: encodeBase64Url(ph(p.Ux)),
      y: encodeBase64Url(ph(p.Uy)),
    };
    const p384Der = sequence(
      integer(1n),
      tlv(4, ph(p.x)),
      tlv(160, oid(OIDS.p384)),
      tlv(161, tlv(3, concat(new Uint8Array([0, 4]), ph(p.Ux), ph(p.Uy)))),
    );
    await writeFile(
      join(root, 'p384_private.pem'),
      value(writePem('EC PRIVATE KEY', p384Der)),
    );
    const cases: [SigningAlgorithm, string, string, number][] = [
      ['rsa-pss-sha512', 'rsa_pss', 'sha512', 64],
      ['rsa-v1_5-sha256', 'rsa', 'sha256', 0],
      ['hmac-sha256', 'hmac', 'sha256', 0],
      ['ecdsa-p256-sha256', 'p256', 'sha256', 32],
      ['ecdsa-p384-sha384', 'p384', 'sha384', 48],
      ['ed25519', 'ed25519', 'none', 0],
      ...(
        [
          'RS256',
          'PS256',
          'PS384',
          'PS512',
          'HS256',
          'ES256',
          'ES384',
          'EdDSA',
        ] as const
      ).map(
        (n) =>
          [
            {jws: n},
            n === 'HS256'
              ? 'hmac'
              : n === 'ES256'
                ? 'p256'
                : n === 'ES384'
                  ? 'p384'
                  : n === 'EdDSA'
                    ? 'ed25519'
                    : n === 'RS256'
                      ? 'rsa'
                      : 'rsa_pss',
            n === 'PS512'
              ? 'sha512'
              : n === 'PS384' || n === 'ES384'
                ? 'sha384'
                : n === 'EdDSA'
                  ? 'none'
                  : 'sha256',
            n === 'PS256'
              ? 32
              : n === 'PS384'
                ? 48
                : n === 'PS512'
                  ? 64
                  : n === 'ES256'
                    ? 32
                    : n === 'ES384'
                      ? 48
                      : 0,
          ] as [SigningAlgorithm, string, string, number],
      ),
    ];
    for (const [algorithm, id, hash, width] of cases) {
      const secret =
        id === 'hmac'
          ? new Uint8Array(
              Buffer.from(
                (await readFile(fixture + 'hmac.txt', 'utf8')).trim(),
                'base64',
              ),
            )
          : undefined;
      const material = secret
        ? {hmac: secret}
        : id === 'p384'
          ? p384
          : await readFile(fixture + id + '_private.pem', 'utf8');
      const h = value(await Custody.local(algorithm, material));
      try {
        const message = new TextEncoder().encode(
          'OpenSSL reciprocal primitive message',
        );
        const input = join(root, 'message'),
          output = join(root, 'signature'),
          publicFile = join(root, 'public.pem');
        await writeFile(input, message);
        const sig = value(await Crypto.sign(algorithm, h, message));
        if (secret) {
          const peer = command([
            'dgst',
            '-sha256',
            '-mac',
            'HMAC',
            '-macopt',
            'hexkey:' + Buffer.from(secret).toString('hex'),
            '-binary',
            input,
          ]);
          assert.deepEqual(peer, sig);
          assert.equal(
            (await Crypto.verify(algorithm, h, peer, message)).ok,
            true,
          );
        } else {
          const publicKey = value(await h.publicKey());
          await writeFile(publicFile, value(publicKey.pem()));
          const ec = id.startsWith('p');
          await writeFile(output, ec ? der(sig) : sig);
          const pss =
            id === 'rsa_pss'
              ? [
                  '-sigopt',
                  'rsa_padding_mode:pss',
                  '-sigopt',
                  'rsa_pss_saltlen:' + width,
                  '-sigopt',
                  'rsa_mgf1_md:' + hash,
                ]
              : [];
          const verify =
            id === 'ed25519'
              ? [
                  'pkeyutl',
                  '-verify',
                  '-pubin',
                  '-inkey',
                  publicFile,
                  '-rawin',
                  '-in',
                  input,
                  '-sigfile',
                  output,
                ]
              : [
                  'dgst',
                  '-' + hash,
                  '-verify',
                  publicFile,
                  '-signature',
                  output,
                  ...pss,
                  input,
                ];
          command(verify);
          const privateFile =
            id === 'p384'
              ? join(root, 'p384_private.pem')
              : fixture + id + '_private.pem';
          const sign =
            id === 'ed25519'
              ? [
                  'pkeyutl',
                  '-sign',
                  '-inkey',
                  privateFile,
                  '-rawin',
                  '-in',
                  input,
                  '-out',
                  output,
                ]
              : [
                  'dgst',
                  '-' + hash,
                  '-sign',
                  privateFile,
                  '-out',
                  output,
                  ...pss,
                  input,
                ];
          command(sign);
          const peer = await readFile(output);
          assert.equal(
            (
              await Crypto.verify(
                algorithm,
                publicKey,
                ec ? raw(peer, width) : peer,
                message,
              )
            ).ok,
            true,
          );
          assert.equal(
            (await Crypto.verify(algorithm, publicKey, sig.slice(1), message))
              .ok,
            false,
          );
          if (ec) {
            assert.equal(
              (await Crypto.verify(algorithm, publicKey, der(sig), message)).ok,
              false,
            );
            const order = CURVE_ORDERS[id === 'p256' ? 'P-256' : 'P-384']!,
              s = unsigned(sig.subarray(width)),
              high = s > order / 2n ? s : order - s;
            const highBytes = Buffer.from(
              high.toString(16).padStart(width * 2, '0'),
              'hex',
            );
            const highSig = new Uint8Array(sig);
            highSig.set(highBytes, width);
            assert.equal(
              (await Crypto.verify(algorithm, publicKey, highSig, message)).ok,
              true,
            );
            await writeFile(output, der(highSig));
            command(verify);
          }
          if (id === 'ed25519') {
            const noncanonical = new Uint8Array(sig);
            let s = ED25519_ORDER;
            for (let i = 32; i < 64; i++) {
              noncanonical[i] = Number(s & 255n);
              s >>= 8n;
            }
            assert.equal(
              (await Crypto.verify(algorithm, publicKey, noncanonical, message))
                .ok,
              false,
            );
          }
        }
        t.diagnostic(
          'RECIPROCAL PASS: ' +
            JSON.stringify(algorithm) +
            ' TS -> OpenSSL; OpenSSL -> TS',
        );
      } finally {
        value(await h.release());
      }
    }
    const h = value(
      await Custody.local(
        'rsa-pss-sha512',
        await readFile(fixture + 'rsa_pss_private.pem', 'utf8'),
      ),
    );
    const key = value(await h.publicKey());
    const input = join(root, 'message'),
      output = join(root, 'signature');
    for (const [salt, mgf] of [
      [32, 'sha512'],
      [64, 'sha256'],
    ] as const) {
      command([
        'dgst',
        '-sha512',
        '-sign',
        fixture + 'rsa_pss_private.pem',
        '-out',
        output,
        '-sigopt',
        'rsa_padding_mode:pss',
        '-sigopt',
        'rsa_pss_saltlen:' + salt,
        '-sigopt',
        'rsa_mgf1_md:' + mgf,
        input,
      ]);
      const r = await Crypto.verify(
        'rsa-pss-sha512',
        key,
        await readFile(output),
        await readFile(input),
      );
      assert.equal(!r.ok && r.error.reason, 'invalid_signature');
      t.diagnostic('REJECTED: PSS salt=' + salt + ' MGF1=' + mgf);
    }
    value(await h.release());
  } finally {
    await rm(root, {recursive: true, force: true});
  }
});
