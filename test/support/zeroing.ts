import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import process from 'node:process';
import {readFileSync} from 'node:fs';
const Original = Uint8Array;
const made: Uint8Array[] = [];
class Tracked extends Original {
  constructor(input: number | ArrayLike<number> | ArrayBuffer = 0, byteOffset?: number, length?: number) { super(input as ArrayBuffer, byteOffset, length); made.push(this); }
}
function count(needle: Uint8Array): number {
  return made.filter(a => {
    outer: for (let i = 0; i + needle.length <= a.length; i++) {
      for (let j = 0; j < needle.length; j++) if (a[i + j] !== needle[j]) continue outer;
      return true;
    }
    return false;
  }).length;
}
async function main() {
  globalThis.Uint8Array = Tracked as Uint8ArrayConstructor;
  try {
    const {Custody} = await import('../../src/index.ts');
    const {decodeKey, readDer, writePem} = await import('../../src/custody/der.ts');
    const value = <T>(r: import('../../src/result.ts').Result<T>): T => {assert.ok(r.ok); return r.value;};
    function publicOnly(jwk: object) {
      for (const field of ['d', 'p', 'q', 'dp', 'dq', 'qi'])
        assert.equal(Object.hasOwn(jwk, field), false, 'decoder must not emit private string member ' + field);
    }
    for (const [algorithm, file, secret] of [
      ['rsa-v1_5-sha256', 'rsa_private.pem', '6FC966E4967685476E2E7ABE38028248E0DE590ED4AACEDE7ADD9BA9EB800F4F'],
      ['ecdsa-p256-sha256', 'p256_private.pem', '529B85F3597E90EC5B8DFED3E26352BF4AF9B4DEBB1A29BBAE77FA105A5C603B'],
      ['ed25519', 'ed25519_private.pem', ''],
    ]) {
      const pem = readFileSync('test/fixtures/upstream/crypto/' + file, 'utf8');
      const label = /-----BEGIN ([A-Z ]+)-----/.exec(pem)![1]!;
      const raw = new Original(Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''), 'base64'));
      const normalized = value(decodeKey(pem, 'pem'));
      publicOnly(normalized.jwk);
      const pkcs8 = new Tracked(normalized.der); normalized.der.fill(0);
      const edSeed = algorithm === 'ed25519' ? value(readDer(new Tracked(raw))).children[2]!.bytes.subarray(2) : undefined;
      const needle = new Original(edSeed ?? Buffer.from(secret!, 'hex'));
      edSeed?.fill(0);
      made.length = 0; const positive = new Tracked(needle);
      assert.equal(count(needle), 1, 'tracker positive control'); positive.fill(0); made.length = 0;
      const cases: [string, string | Uint8Array, 'pem' | 'pkcs8'][] = [
        [label, pem, 'pem'],
        ['pkcs8 PEM', value(writePem('PRIVATE KEY', pkcs8)), 'pem'],
        ['pkcs8 DER', pkcs8, 'pkcs8'],
      ];
      for (const [name, material, format] of cases) {
        made.length = 0;
        const decoded = value(decodeKey(material, format));
        publicOnly(decoded.jwk); decoded.der.fill(0);
        assert.equal(count(needle), 0, 'decodeKey owned buffers erased after caller clears returned DER');
        const der = typeof material === 'string' ? rawFor(material) : material;
        const trailing = new Original(der.length + 1); trailing.set(der);
        const badComponent = new Original(der);
        // Keep the sentinel intact while invalidating the exponent, point, or seed length.
        if (algorithm!.startsWith('rsa')) {
          const at = Buffer.from(der).indexOf(Buffer.from([2, 3, 1, 0, 1]));
          assert.ok(at >= 0); badComponent[at + 4] = 2;
        } else if (algorithm === 'ed25519') {
          const at = Buffer.from(der).indexOf(Buffer.from([4, 34, 4, 32]));
          assert.ok(at >= 0); badComponent[at + 3] = 31;
        } else badComponent[badComponent.length - 1] = badComponent.at(-1)! ^ 1;
        const asMaterial = (data: Uint8Array) => {
          if (format === 'pkcs8') return new Tracked(data);
          const armorLabel = /-----BEGIN ([A-Z ]+)-----/.exec(material as string)![1]!;
          return '-----BEGIN ' + armorLabel + '-----\n' + Buffer.from(data).toString('base64') + '\n-----END ' + armorLabel + '-----';
        };
        for (const [input, expected] of [[material, true], [asMaterial(trailing), false], [asMaterial(badComponent), false]] as const) {
          made.length = 0;
          const r = await Custody.local(algorithm, input);
          assert.equal(r.ok, expected, file + ' ' + name);
          if (r.ok) { publicOnly(value(value(await r.value.publicKey()).jwk())); await r.value.release(); }
          console.log(file + ' ' + name + ': import=' + r.ok + ' private-byte buffers=' + count(needle));
          assert.equal(count(needle), 0, 'owned private buffers erased on success and failure');
        }
      }
      // JWK is imported by custody rather than the DER decoder. Check its actual
      // public projection as well as the owned byte copies of private members.
      const params = algorithm!.startsWith('rsa') ? {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'} : algorithm === 'ed25519' ? {name: 'Ed25519'} : {name: 'ECDSA', namedCurve: 'P-256'};
      const runtimeKey = await crypto.subtle.importKey('pkcs8', pkcs8, params, true, ['sign']);
      const jwk = await crypto.subtle.exportKey('jwk', runtimeKey);
      // Node 24 exports the fully specified Ed25519 JOSE label. RequestSeal's
      // selected registry uses EdDSA; prove the metadata rejection, then declare
      // the selected label for this private-material projection check.
      if (algorithm === 'ed25519' && jwk.alg === 'Ed25519') {
        const mismatched = await Custody.local(algorithm, jwk);
        assert.equal(mismatched.ok, false);
        assert.equal(!mismatched.ok && mismatched.error.reason, 'key_mismatch');
        jwk.alg = 'EdDSA';
      }
      for (const [input, expected] of [[jwk, true], [{...jwk, d: '!'}, false]] as const) {
        made.length = 0;
        const r = await Custody.local(algorithm, input);
        assert.equal(r.ok, expected);
        if (r.ok) {publicOnly(value(value(await r.value.publicKey()).jwk())); await r.value.release();}
        assert.equal(count(needle), 0, 'JWK private owned buffers erased');
        console.log(file + ' jwk: import=' + r.ok + ' private-byte buffers=' + count(needle));
      }
      pkcs8.fill(0); raw.fill(0); needle.fill(0);
    }
  } finally {globalThis.Uint8Array = Original;}
}
function rawFor(pem: string): Uint8Array<ArrayBuffer> {
  return new Original(Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''), 'base64'));
}
main().catch(e => {console.error(e); process.exitCode = 1;});
