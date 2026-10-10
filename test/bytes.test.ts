import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import fc from 'fast-check';
test('ByteString copies bytes and strict base64 codecs preserve canonical forms', async () => {
  assert.ok(existsSync(new URL('../src/bytes.ts', import.meta.url)), 'ByteString and strict codecs require an implementation');
  const b = await import('../src/bytes.ts');
  const input = new Uint8Array([0, 255]); const copy = b.byteString(input);
  assert.ok(copy.ok); input[0] = 1; assert.deepEqual(copy.value, new Uint8Array([0, 255]));
  assert.deepEqual(b.byteString('\u0000\u00ff'), {ok: true, value: new Uint8Array([0, 255])});
  for (const bad of ['\u0100', '\ud800', 1, null, {}, ['a']]) assert.equal(b.byteString(bad).ok, false);
  const vectors = [['', ''], ['f', 'Zg=='], ['fo', 'Zm8='], ['foo', 'Zm9v'], ['foob', 'Zm9vYg=='], ['fooba', 'Zm9vYmE='], ['foobar', 'Zm9vYmFy']];
  for (const [plain, encoded] of vectors) assert.equal(b.encodeBase64(new TextEncoder().encode(plain)), encoded);
  fc.assert(fc.property(fc.uint8Array(), bytes => {
    for (const [encode, decode] of [[b.encodeBase64, b.decodeBase64], [b.encodeBase64Url, b.decodeBase64Url]] as const) {
      const canonical = encode(bytes); const result = decode(canonical);
      assert.ok(result.ok); assert.deepEqual(result.value, bytes); assert.equal(encode(result.value), canonical);
    }
  }), {numRuns: 300});
  for (const bad of ['Zg', 'Zg=', 'Zg===', 'Zh==', 'Zm9=', 'Zg==\n', ' Zg==', '=Zg=', 'Zg==Zg==', '-_==', 'a', 'é', '\u0000']) assert.equal(b.decodeBase64(bad).ok, false, bad);
  for (const bad of ['Zg=', 'Zg==', 'Zh', 'Zm9', 'Zg\n', ' Zg', '+w', '/w', 'a', 'é', '\u0000']) assert.equal(b.decodeBase64Url(bad).ok, false, bad);
});
