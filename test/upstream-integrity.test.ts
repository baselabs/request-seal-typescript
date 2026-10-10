import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { read, files } from './support/upstream.ts';
const hash = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
test('upstream known-positive, every copied byte and all SHA256SUMS inventories', (t) => {
  const inventory = JSON.parse(
    readFileSync(new URL('./fixtures/upstream-inventory.json', import.meta.url), 'utf8'),
  ) as Record<string, string>;
  assert.ok(Object.hasOwn(inventory, 'httpwg-structured-fields/examples.json'));
  assert.equal(
    hash(read('httpwg-structured-fields', 'examples.json')),
    inventory['httpwg-structured-fields/examples.json'],
  );
  t.diagnostic('KNOWN-POSITIVE httpwg-structured-fields/examples.json OK');
  const origins = ['httpwg-structured-fields', 'rfc9421', 'multi_signature', 'http'];
  for (const [path, digest] of Object.entries(inventory)) {
    const at = path.indexOf('/');
    assert.equal(hash(read(path.slice(0, at), path.slice(at + 1))), digest, path);
    t.diagnostic(`SHA256 ${path} OK`);
  }
  for (const origin of origins.filter((x) => x !== 'http')) {
    const lines = new TextDecoder().decode(read(origin, 'SHA256SUMS')).trim().split('\n');
    const listed: string[] = [];
    for (const line of lines) {
      const [digest, path] = line.split('  ');
      assert.ok(digest && path);
      listed.push(path);
      assert.equal(hash(read(origin, path)), digest, `${origin}/${path}`);
      t.diagnostic(`SHA256SUMS ${origin}/${path} OK`);
    }
    assert.deepEqual(
      listed.sort(),
      files(origin)
        .filter((f) => f.endsWith('.json') || f === 'LICENSE')
        .sort(),
    );
  }
  const capture = JSON.parse(new TextDecoder().decode(read('http', 'capture.json')));
  for (const [file, digest] of Object.entries(capture.sha256)) {
    assert.equal(hash(read('http', file)), digest);
    t.diagnostic(`CAPTURE SHA256 ${file} OK`);
  }
});
