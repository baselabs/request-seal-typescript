import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {
  Custody,
  createKeyHandle,
  withDeadline,
  run,
  remainingMs,
  isUnwrappedKey,
  type KeyHandle,
  type Custodian,
  type Context,
  type Result,
  type PublicKey,
  type KeyIdentity,
  type UnwrappedKey,
} from '../src/index.ts';
const value = <T>(r: Result<T>): T => {
  assert.equal(r.ok, true, r.ok ? '' : r.error.reason);
  if (!r.ok) throw new Error('Rejected');
  return r.value;
};
const bytes = (s: string) => new TextEncoder().encode(s);
const delay = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));
// A real custodian: every operation reaches the actual local handle and performs cryptography.
class SlowCustodian implements Custodian {
  #local: KeyHandle;
  #delay: number;
  constructor(local: KeyHandle, wait: number) {
    this.#local = local;
    this.#delay = wait;
  }
  async #wait(context?: Context): Promise<void> {
    const remaining = context ? remainingMs(context) : 0;
    // Short-deadline cases wait past the absolute cutoff; normal contexts use
    // the configured delay for explicit abort and release tests.
    await delay(Math.max(this.#delay, remaining < 1000 ? remaining + 10 : 0));
  }
  async sign(
    algorithm: unknown,
    data: unknown,
    context: Context,
  ): Promise<Result<Uint8Array<ArrayBuffer>>> {
    const result = await this.#local.sign(algorithm, data, context);
    await this.#wait(context);
    return result;
  }
  async verify(
    algorithm: unknown,
    signature: unknown,
    data: unknown,
    context: Context,
  ): Promise<Result<true>> {
    const result = await this.#local.verify(
      algorithm,
      signature,
      data,
      context,
    );
    await this.#wait(context);
    return result;
  }
  async publicKey(context?: Context): Promise<Result<PublicKey>> {
    const result = await this.#local.publicKey(context);
    await this.#wait(context);
    return result;
  }
  async identity(context?: Context): Promise<Result<KeyIdentity>> {
    const result = await this.#local.identity(context);
    await this.#wait(context);
    return result;
  }
  async unwrap(
    algorithm: unknown,
    wrapped: unknown,
    context: Context,
    options?: unknown,
  ): Promise<Result<UnwrappedKey>> {
    const result = await this.#local.unwrap(
      algorithm,
      wrapped,
      context,
      options,
    );
    await this.#wait(context);
    return result;
  }
  async release(): Promise<Result<true>> {
    return this.#local.release();
  }
}
test('slow real custodian deadlines discard late signatures metadata and verification', async () => {
  const underlying = value(
    await Custody.local(
      'ed25519',
      await readFile(
        'test/fixtures/upstream/crypto/ed25519_private.pem',
        'utf8',
      ),
    ),
  );
  const c = value(withDeadline());
  const sig = value(await underlying.sign('ed25519', bytes('data'), c));
  const slow = value(
    createKeyHandle('ed25519', new SlowCustodian(underlying, 80)),
  );
  for (const operation of [
    (c: Context) => slow.sign('ed25519', bytes('data'), c),
    (c: Context) => slow.verify('ed25519', sig, bytes('data'), c),
    (c: Context) => slow.publicKey(c),
    (c: Context) => slow.identity(c),
  ]) {
    const r = await operation(value(withDeadline({timeoutMs: 30})));
    assert.equal(!r.ok && r.error.reason, 'deadline_exceeded');
    assert.equal(!r.ok && 'retryable' in r.error && r.error.retryable, true);
  }
  const controller = new AbortController();
  const inFlight = slow.sign(
    'ed25519',
    bytes('data'),
    value(withDeadline({signal: controller.signal})),
  );
  await delay(5);
  controller.abort();
  const aborted = await inFlight;
  assert.equal(!aborted.ok && aborted.error.reason, 'deadline_exceeded');
  const pending = slow.sign('ed25519', bytes('data'), value(withDeadline()));
  await delay(5);
  value(await slow.release());
  const released = await pending;
  assert.equal(!released.ok && released.error.reason, 'key_not_found');
  await delay(100);
});
test('RSA-OAEP unwrap yields a confined AES capability for 128 and 256 bits', async () => {
  const pem = await readFile(
    'test/fixtures/upstream/crypto/rsa_private.pem',
    'utf8',
  );
  for (const name of ['RSA-OAEP', 'RSA-OAEP-256'] as const) {
    const alg = {jwe: name} as const;
    const h = value(await Custody.local(alg, pem));
    const publicKey = value(await h.publicKey());
    const jwk = value(publicKey.jwk());
    const wrapping = await crypto.subtle.importKey(
      'jwk',
      jwk,
      {name: 'RSA-OAEP', hash: name === 'RSA-OAEP' ? 'SHA-1' : 'SHA-256'},
      false,
      ['wrapKey', 'encrypt'],
    );
    for (const length of [128, 256]) {
      const key = await crypto.subtle.generateKey(
        {name: 'AES-GCM', length},
        true,
        ['encrypt', 'decrypt'],
      );
      const wrapped = new Uint8Array(
        await crypto.subtle.wrapKey('raw', key, wrapping, {name: 'RSA-OAEP'}),
      );
      const iv = new Uint8Array(12),
        plain = bytes('Authenticated content');
      const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt({name: 'AES-GCM', iv}, key, plain),
      );
      const sealed = value(
        await h.unwrap(alg, wrapped, value(withDeadline()), {length}),
      );
      assert.equal(isUnwrappedKey(sealed), true);
      assert.deepEqual(
        value(await sealed.decrypt(ciphertext, {iv}, value(withDeadline()))),
        plain,
      );
      const clone = structuredClone(sealed);
      assert.deepEqual(Reflect.ownKeys(clone), []);
      assert.equal(isUnwrappedKey(clone), false);
      const tampered = new Uint8Array(ciphertext);
      tampered[0]! ^= 1;
      const result = await sealed.decrypt(
        tampered,
        {iv},
        value(withDeadline()),
      );
      assert.equal(!result.ok && result.error.reason, 'decryption_failed');
      value(await sealed.release());
      const released = await sealed.decrypt(
        ciphertext,
        {iv},
        value(withDeadline()),
      );
      assert.equal(!released.ok && released.error.reason, 'key_not_found');
    }
    const sign = await h.sign(alg, bytes('data'), value(withDeadline()));
    assert.equal(!sign.ok && sign.error.reason, 'unsupported_operation');
    for (const wrapped of [new Uint8Array(255), new Uint8Array(256)]) {
      const r = await h.unwrap(alg, wrapped, value(withDeadline()));
      assert.equal(!r.ok && r.error.reason, 'decryption_failed');
    }
    const slow = value(createKeyHandle(alg, new SlowCustodian(h, 80)));
    const aes = await crypto.subtle.generateKey(
      {name: 'AES-GCM', length: 256},
      true,
      ['encrypt'],
    );
    const wrapped = new Uint8Array(
      await crypto.subtle.wrapKey('raw', aes, wrapping, {name: 'RSA-OAEP'}),
    );
    const r = await slow.unwrap(
      alg,
      wrapped,
      value(withDeadline({timeoutMs: 25})),
    );
    assert.equal(!r.ok && r.error.reason, 'deadline_exceeded');
    value(await slow.release());
    await delay(90);
  }
});
test('own options getters read once unknown keys and inherited identities reject', async () => {
  const pem = await readFile(
    'test/fixtures/upstream/crypto/ed25519_private.pem',
    'utf8',
  );
  let reads = 0;
  const r = await Custody.local('ed25519', pem, {
    get format() {
      reads++;
      return 'pem';
    },
  });
  const h = value(r);
  assert.equal(reads, 1);
  value(await h.release());
  const extra = await Custody.local('ed25519', pem, {
    format: 'pem',
    secret: 'option-canary',
  });
  assert.equal(!extra.ok && extra.error.reason, 'invalid_options');
  const short = await Custody.local('hmac-sha256', {hmac: new Uint8Array(31)});
  assert.equal(!short.ok && short.error.reason, 'invalid_key');
  const nonsecret = bytes('known caller secret has at least thirty-two bytes');
  const material = {hmac: nonsecret, identity: 'one'};
  const first = value(await Custody.local('hmac-sha256', material));
  nonsecret.fill(0);
  const second = value(
    await Custody.local('hmac-sha256', {hmac: nonsecret, identity: 'one'}),
  );
  const sig = value(
    await first.sign('hmac-sha256', bytes('data'), value(withDeadline())),
  );
  assert.equal(
    (
      await second.verify(
        'hmac-sha256',
        sig,
        bytes('data'),
        value(withDeadline()),
      )
    ).ok,
    false,
  );
  value(await first.release());
  value(await second.release());
});

test('discarded content plaintext is erased after a delayed real decrypt', async () => {
  const {spawnSync} = await import('node:child_process');
  const prefix = Object.hasOwn(process.versions, 'deno') ? ['run', '--no-check', '--allow-read'] : Object.hasOwn(process.versions, 'bun') ? ['run'] : ['--experimental-strip-types', '--no-warnings'];
  const child = spawnSync(process.execPath, [...prefix, 'test/support/content-key-zeroing.ts'], {encoding: 'utf8', timeout: 10000});
  assert.equal(child.status, 0, child.stdout + child.stderr);
});

test('content keys erase plaintext when cancellation wins after its production', {timeout: 10000}, async () => {
  const {spawnSync} = await import('node:child_process');
  const prefix = Object.hasOwn(process.versions, 'deno') ? ['run', '--allow-read'] : Object.hasOwn(process.versions, 'bun') ? ['run'] : ['--experimental-strip-types', '--no-warnings'];
  const child = spawnSync(process.execPath, [...prefix, 'test/support/content-key-race-zeroing.ts'], {encoding: 'utf8', timeout: 5000});
  assert.equal(child.status, 0, child.stdout + child.stderr);
  assert.match(child.stdout, /PASS actual AES-GCM plaintext erased/);
});
