// Trace library entry into the real boundary before capture. Every call forwards.
// Some runtimes implement unwrapKey via other public methods; exclude those
// internal calls from the library sequence. This says nothing about runtime timing.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const calls: string[] = [];
const recovered: CryptoKey[] = [];
const native = crypto.subtle;
let nativeDepth = 0;
for (const name of ['generateKey', 'importKey', 'unwrapKey', 'decrypt'] as const) {
  const original = native[name].bind(native) as (...args: unknown[]) => Promise<unknown>;
  Object.defineProperty(native, name, {configurable: true, value: async (...args: unknown[]) => {
    if (nativeDepth === 0) calls.push(name);
    if (name === 'generateKey' && nativeDepth === 0) {
      assert.equal(args[1], false);
      assert.deepEqual(args[2], ['decrypt']);
    }
    if (name === 'unwrapKey') {
      assert.equal(args[5], false);
      assert.deepEqual(args[6], ['decrypt']);
      assert.ok((args[2] as CryptoKey).usages.includes('unwrapKey'));
    }
    nativeDepth++;
    try {
      const result = await original(...args);
      if (name === 'unwrapKey') recovered.push(result as CryptoKey);
      return result;
    } finally {nativeDepth--; }
  }});
}
async function main() {
  const {JWE, KeyManagement, Custody, ok, encodeBase64Url, decodeBase64Url} = await import('../../src/index.ts');
  const {JoseHeader} = await import('../../src/jose/header.ts');
  const {value} = await import('./jose-oaep.ts');
  const rsa = JSON.parse(await readFile('conformance/sources/rfc7516/rfc7516.json', 'utf8')).key;
  for (const alg of ['RSA-OAEP', 'RSA-OAEP-256', 'A128GCMKW', 'A256GCMKW']) {
    const owner = value(await KeyManagement.local(alg, alg.startsWith('RSA') ? rsa : crypto.getRandomValues(new Uint8Array(alg === 'A128GCMKW' ? 16 : 32))));
    const recipient = alg.startsWith('RSA') ? value(await Custody.local({jwe: alg}, rsa)) : undefined;
    try {
      const token = value(await JWE.encrypt([['alg', alg], ['enc', 'A128GCM']], new TextEncoder().encode('payload'), recipient ?? ((a: string, cek: Uint8Array) => owner.wrap(a, cek))));
      const policy = {algorithms: [alg], encryption: ['A128GCM'], timeout: 5000, max_plaintext: 1024, key_resolver: () => ok({algorithm: alg, unwrap: (ek: unknown, h: import('../../src/jose/header.ts').Header, c: import('../../src/context.ts').Context) => owner.unwrap(ek, h, c)})};
      calls.length = 0; recovered.length = 0;
      assert.equal((await JWE.decrypt(token, policy)).ok, true);
      assert.equal(recovered.length, 1, 'unwrap must return a native key');
      assert.equal(recovered[0]!.extractable, false);
      const traces: string[][] = [];
      for (const failure of ['tag', 'unwrap']) {
        const parts = token.split('.');
        if (failure === 'unwrap' && alg.endsWith('GCMKW')) {
          const h = value(JoseHeader.parse(parts[0]));
          const pairs = h.map(p => {
            if (p[0] !== 'tag') return p;
            const tag = value(decodeBase64Url(p[1])); tag[0]! ^= 1;
            return [p[0], encodeBase64Url(tag)] as const;
          });
          const {encodeJson} = await import('../../src/json.ts');
          parts[0] = encodeBase64Url(value(encodeJson({kind: 'object', pairs})));
        } else {
          const index = failure === 'tag' ? 4 : 1;
          const data = value(decodeBase64Url(parts[index])); data[0]! ^= 1;
          parts[index] = encodeBase64Url(data);
        }
        calls.length = 0;
        const result = await JWE.decrypt(parts.join('.'), policy);
        assert.equal(result.ok, false);
        if (!result.ok) assert.equal(result.error.reason, 'decryption_failed');
        traces.push([...calls]);
      }
      assert.deepEqual(traces[0], ['generateKey', 'unwrapKey', 'decrypt']);
      assert.deepEqual(traces[1], traces[0]);
      console.log(alg + ' ' + JSON.stringify(traces));
    } finally {await owner.release(); await recipient?.release();}
  }
}
main().catch(e => {console.error(e); process.exitCode = 1;});
