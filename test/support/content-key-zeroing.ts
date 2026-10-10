import assert from 'node:assert/strict';
const runtime = crypto.subtle;
const decrypt = runtime.decrypt.bind(runtime);
const descriptor = Object.getOwnPropertyDescriptor(runtime, 'decrypt');
let unblock: (() => void) | undefined;
let discarded: ArrayBuffer | undefined;
let observed!: () => void;
const decrypted = new Promise<void>(resolve => {observed = resolve;});
Object.defineProperty(runtime, 'decrypt', {configurable: true, value: async (...args: Parameters<typeof decrypt>) => {
  const plaintext = await decrypt(...args);
  discarded = plaintext;
  await new Promise<void>(resolve => {unblock = resolve; observed();});
  return plaintext;
}});
try {
  const {confineContentKey} = await import('../../src/custody/content_key.ts');
  const {withDeadline} = await import('../../src/context.ts');
  const dog = setTimeout(() => {console.log('held');process.exit(3);}, 2000);
  if (typeof dog === 'object') dog.unref();
  else (globalThis as unknown as {Deno: {unrefTimer(id: number): void}}).Deno.unrefTimer(dog);
  const key = await runtime.generateKey({name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
  const iv = new Uint8Array(12), plaintext = new TextEncoder().encode('secret buffer tracker');
  const ciphertext = new Uint8Array(await runtime.encrypt({name: 'AES-GCM', iv}, key, plaintext));
  const confined = confineContentKey(key);
  const caller = new AbortController();
  const c = withDeadline({timeoutMs: 5000, signal: caller.signal}); assert.ok(c.ok);
  const running = confined.decrypt(ciphertext, {iv}, c.value);
  await decrypted;
  assert.equal(c.value.signal.aborted, false, 'real decrypt output is observed before cancellation');
  caller.abort();
  const result = await running;
  assert.equal(result.ok, false);
  assert.equal(!result.ok && result.error.reason, 'deadline_exceeded');
  assert.ok(discarded); assert.deepEqual(new Uint8Array(discarded), plaintext, 'tracker sees real decrypted bytes before release');
  assert.ok(unblock); unblock();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.ok(new Uint8Array(discarded).every(b => b === 0), 'discarded plaintext must be zeroed');
  await confined.release();
  console.log('PASS real delayed AES-GCM plaintext tracked and erased after cancellation');
} finally {
  if (descriptor) Object.defineProperty(runtime, 'decrypt', descriptor);
  else Reflect.deleteProperty(runtime, 'decrypt');
}
