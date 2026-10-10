import assert from 'node:assert/strict';
import {confineContentKey} from '../../src/custody/content_key.ts';
import {withDeadline, releaseContext} from '../../src/context.ts';
const dog = setTimeout(() => {console.log('held');process.exit(3);}, 2000);
if (typeof dog === 'object') dog.unref();
else (globalThis as unknown as {Deno: {unrefTimer(id: number): void}}).Deno.unrefTimer(dog);
const key = await crypto.subtle.generateKey({name: 'AES-GCM', length: 128}, false, ['encrypt', 'decrypt']);
const nonce = new Uint8Array(12), plaintext = new TextEncoder().encode('late cancellation plaintext');
const ciphertext = new Uint8Array(await crypto.subtle.encrypt({name: 'AES-GCM', iv: nonce}, key, plaintext));
const controller = new AbortController();
const context = withDeadline({signal: controller.signal, timeoutMs: 5000}); assert.ok(context.ok);
const confined = confineContentKey(key), Original = Uint8Array;
let produced: Uint8Array | undefined;
class Tracked extends Original {
  constructor(input: number | ArrayLike<number> | ArrayBuffer = 0, byteOffset?: number, length?: number) {
    super(input as ArrayBuffer, byteOffset, length);
    if (input instanceof ArrayBuffer && this.length === plaintext.length && this.every((byte, index) => byte === plaintext[index])) {
      produced = this;
      // Real caller cancellation in the microtask after plaintext production:
      // the worker's freshness check passes, but the outer race must reject.
      queueMicrotask(() => controller.abort());
    }
  }
}
globalThis.Uint8Array = Tracked as Uint8ArrayConstructor;
try {
  const result = await confined.decrypt(new Uint8Array(ciphertext), {iv: new Uint8Array(nonce)}, context.value);
  assert.ok(produced, 'tracker observes the actual successful AES-GCM output');
  assert.equal(!result.ok && result.error.reason, 'deadline_exceeded');
  assert.ok(produced.every(byte => byte === 0), 'plaintext discarded by the outer race must be erased');
  console.log('PASS actual AES-GCM plaintext erased when cancellation wins after production');
} finally {globalThis.Uint8Array = Original; releaseContext(context.value); await confined.release();}
