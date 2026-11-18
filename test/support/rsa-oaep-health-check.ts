import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {Custody, KeyManagement, type Result} from '../../src/index.ts';
import {decodeKey} from '../../src/custody/der.ts';

const Original = Uint8Array;
const allocated = new Set<Uint8Array>();
const erased: {buffer: Uint8Array; before: Uint8Array}[] = [];
// Observe byte erasure, leaving every WebCrypto operation and entropy source native.
class Tracked extends Original {
  constructor(input: number | ArrayLike<number> | ArrayBuffer = 0, byteOffset?: number, length?: number) {
    super(input as ArrayBuffer, byteOffset, length);
    if (input === 32) allocated.add(this);
  }
  override fill(value: number, start?: number, end?: number): this {
    if (allocated.has(this) && value === 0 && start === undefined && end === undefined)
      erased.push({buffer: this, before: new Original(this)});
    return super.fill(value, start, end);
  }
}
function value<T>(result: Result<T>): T {assert.ok(result.ok, 'fixture key decodes'); return result.value;}
function clear(): void {
  for (const entry of erased) entry.before.fill(0);
  erased.length = 0; allocated.clear();
}
async function main(): Promise<void> {
  const decoded = value(decodeKey(readFileSync('test/fixtures/upstream/crypto/rsa_private.pem', 'utf8'), 'pem'));
  const material = new Tracked(decoded.der); decoded.der.fill(0);
  globalThis.Uint8Array = Tracked as Uint8ArrayConstructor;
  try {
    const control = new Tracked(32).fill(7); control.fill(0);
    assert.equal(erased.length, 1, 'byte tracker observes an actual pre-erasure buffer');
    assert.ok(erased[0]!.before.every(byte => byte === 7), 'byte tracker copies contents before erasure');
    assert.ok(control.every(byte => byte === 0), 'byte tracker leaves erasure native');
    clear();
    for (const algorithm of ['RSA-OAEP', 'RSA-OAEP-256'] as const) {
      for (const construct of [
        () => Custody.local({jwe: algorithm}, material, {format: 'pkcs8'}),
        () => KeyManagement.local(algorithm, material),
      ]) {
        const result = await construct(); assert.ok(result.ok, algorithm + ' custody construction succeeds');
        const owner = result.value;
        try {
          assert.equal(erased.length, 1, 'each constructor executes the real custody CEK health check once');
          const entry = erased[0]!;
          assert.equal(entry.before.length, 32, 'health-check CEK is 32 octets');
          assert.equal(entry.before[0], 1, 'health-check CEK has a fixed nonzero first octet');
          assert.ok(entry.buffer.every(byte => byte === 0), 'the health-check CEK is erased after native import');
        } finally {await owner.release(); clear();}
      }
    }
    console.log('PASS real RSA-OAEP health-check CEKs observed and erased');
  } finally {globalThis.Uint8Array = Original; material.fill(0); clear();}
}
// Every assertion above carries a fixed message, so reporting it exposes no key or CEK octets.
main().catch((error: unknown) => {console.error('RSA-OAEP health-check observation failed: ' + (error instanceof Error ? error.message : 'non-Error rejection')); process.exitCode = 1;});
