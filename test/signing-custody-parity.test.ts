import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {Custody, Message, sign, withDeadline, ok, type Result, type KeyHandle, type Context} from '../src/index.ts';
import {createKeyHandle, type Custodian} from '../src/key_handle.ts';
import {coreError, custodyError, isRequestSealError} from '../src/errors/types.ts';
function value<T>(r: Result<T>): T {assert.equal(r.ok, true, JSON.stringify(r)); if (!r.ok) throw new Error('Rejected result'); return r.value;}
const explicit = {label: 'sig', algorithm: 'ed25519', signatureInput: '("@method" "@path");alg="ed25519"'};
const generated = {label: 'sig', algorithm: 'ed25519', components: '("@method" "@path")', expiresIn: 60};
async function setup() {
  const local = value(await Custody.local('ed25519', readFileSync('test/fixtures/upstream/crypto/ed25519_private.pem', 'utf8')));
  const message = value(await Message.request('GET', 'https://example.com/', [], null));
  return {local, message};
}
// Perform real signing, then alter its result at the caller-owned custody boundary.
// The remaining methods delegate to the same live local capability.
function transformed(local: KeyHandle, transform: (r: Result<Uint8Array<ArrayBuffer>>, c: Context) => unknown): KeyHandle {
  const port: Custodian = {
    async sign(a, b, c) {return transform(await local.sign(a, b, c), c) as Result<Uint8Array<ArrayBuffer>>;},
    verify: local.verify.bind(local), publicKey: local.publicKey.bind(local), identity: local.identity.bind(local),
    unwrap: local.unwrap.bind(local), release: local.release.bind(local),
  };
  return value(createKeyHandle('ed25519', port));
}
function failure(r: Result<unknown>, reason: string, source: string | null = null) {
  assert.equal(r.ok, false); if (r.ok) throw new Error('Expected rejection');
  assert.equal(r.error.kind, 'core');
  assert.equal(r.error.reason, reason);
  if (r.error.kind !== 'core') throw new Error('Expected core error');
  assert.equal(r.error.layer, reason === 'signer_algorithm_mismatch' ? 'input' : 'crypto');
  assert.equal(r.error.retryable, false);
  const e = r.error as any;
  assert.equal(e.source?.reason ?? null, source);
  assert.equal(e.message, reason === 'signer_algorithm_mismatch' ? 'signer algorithm does not match signature specification' : null);
  if (source) {assert.equal(e.source.kind, 'custody'); assert.ok(isRequestSealError(e.source)); assert.ok(Object.isFrozen(e.source));}
  return e;
}
test('explicit handle mismatch has its distinct reason and exact message before message validation', async () => {
  const other = value(await Custody.local('hmac-sha256', {hmac: crypto.getRandomValues(new Uint8Array(32))}));
  try {failure(await sign(null, explicit, other), 'signer_algorithm_mismatch');} finally {await other.release();}
});
test('explicit timeout accepts both bounds, rejects malformed values, and snapshots once', async () => {
  const {local, message} = await setup();
  try {
    value(await sign(message, explicit, local, {signingTimeout: 300000}));
    // A one-millisecond budget is valid, but real crypto may exhaust it.
    const lower = await sign(message, explicit, local, {signingTimeout: 1});
    if (!lower.ok) failure(lower, 'signing_failed', 'deadline_exceeded');
    value(await sign(message, explicit, (a: unknown, b: unknown, c: Context) => local.sign(a, b, c), {signingTimeout: 1}));
    for (const signingTimeout of [0, -1, 300001, 1.5, Infinity, NaN, null, undefined, '5000']) {
      const r = await sign(message, explicit, local, {signingTimeout}); assert.equal(!r.ok && r.error.reason, 'invalid_options');
    }
    let reads = 0;
    value(await sign(message, explicit, local, {get signingTimeout() {reads++; return 300000;}}));
    assert.equal(reads, 1);
    for (const options of [{signingTimeout: 5000, unknown: true}, {[Symbol('unknown')]: true}]) {
      const r = await sign(message, explicit, local, options); assert.equal(!r.ok && r.error.reason, 'invalid_options');
    }
  } finally {await local.release();}
});
test('explicit handle and callable preserve identical wire bytes and callable timeout behavior', async () => {
  const {local, message} = await setup();
  try {
    const expected = value(await sign(message, explicit, (a: unknown, b: unknown, c: Context) => local.sign(a, b, c)));
    assert.deepEqual(value(await sign(message, explicit, local)), expected);
    assert.deepEqual(value(await sign(message, explicit, async (a: unknown, b: unknown, c: Context) => {
      const r = await local.sign(a, b, c); await new Promise(resolve => setTimeout(resolve, 30)); return r;
    }, {signingTimeout: 1})), expected);
  } finally {await local.release();}
});
for (const [form, spec] of [['explicit', explicit], ['generated', generated]] as const) {
  test(`${form} released handle retains the bounded custody source`, async () => {
    const {local, message} = await setup(); await local.release();
    const e = failure(await sign(message, spec, local), 'signing_failed', 'key_not_found');
    assert.equal(e.source.retryable, false);
  });
  test(`${form} malformed custody signing output retains the signing-output source`, async () => {
    const {local, message} = await setup();
    try {
      for (const output of [new Uint8Array(), new Uint8Array(1025), new Uint8Array(16385), 'private-caller-bytes']) {
        const handle = transformed(local, r => {value(r); return {ok: true, value: output};});
        const e = failure(await sign(message, spec, handle), 'signing_failed', 'invalid_signing_output');
        assert.equal(e.source.retryable, false); assert.ok(!JSON.stringify(e).includes('private-caller-bytes'));
      }
    } finally {await local.release();}
  });
  test(`${form} malformed custody errors retain only custodian_failure`, async () => {
    const {local, message} = await setup();
    try {
      const handle = transformed(local, r => {value(r); return {ok: false, error: {reason: 'private-caller-bytes'}};});
      const e = failure(await sign(message, spec, handle), 'signing_failed', 'custodian_failure');
      assert.ok(!JSON.stringify(e).includes('private-caller-bytes'));
    } finally {await local.release();}
  });
  test(`${form} custody timeout keeps outer nonretryable and source retryable`, async () => {
    const {local, message} = await setup();
    try {
      const handle = transformed(local, async r => {value(r); await new Promise(resolve => setTimeout(resolve, 80)); return r;});
      const e = failure(await sign(message, spec, handle, {signingTimeout: 40}), 'signing_failed', 'deadline_exceeded');
      assert.equal(e.source.retryable, true);
      const longerParent = value(withDeadline({timeoutMs: 30000}));
      const capped = failure(await sign(message, spec, handle, {context: longerParent, signingTimeout: 40}), 'signing_failed', 'deadline_exceeded');
      assert.equal(capped.source.retryable, true);
      assert.equal(longerParent.signal.aborted, false);
      const parent = value(withDeadline({timeoutMs: 40}));
      failure(await sign(message, spec, handle, {context: parent, signingTimeout: 300000}), 'signing_failed', 'deadline_exceeded');
    } finally {await local.release();}
  });
  test(`${form} callable signing failures keep signer_failed and no custody source`, async () => {
    const {local, message} = await setup();
    try {
      for (const transform of [(r: unknown) => {value(r as Result<unknown>); return {ok: true, value: new Uint8Array()};}, (r: unknown) => {value(r as Result<unknown>); throw new Error('private-caller-bytes');}, (r: unknown) => {value(r as Result<unknown>); return {ok: false, error: custodyError('custodian_rejected')};}]) {
        failure(await sign(message, spec, async (a: unknown, b: unknown, c: Context) => transform(await local.sign(a, b, c))), 'signer_failed');
      }
    } finally {await local.release();}
  });
}
test('explicit custody default is five seconds and an explicit timeout sets the custody deadline', async () => {
  const {local, message} = await setup(); const observed: number[] = [];
  try {
    const handle = transformed(local, (r, c) => {observed.push(c.deadline); return r;});
    const beforeDefault = performance.now();
    value(await sign(message, explicit, handle));
    assert.ok(observed[0]! >= beforeDefault + 5000 && observed[0]! <= performance.now() + 5000);
    const beforeExplicit = performance.now();
    value(await sign(message, explicit, handle, {signingTimeout: 6500}));
    assert.ok(observed[1]! >= beforeExplicit + 6500 && observed[1]! <= performance.now() + 6500);
  } finally {await local.release();}
});
test('explicit handle custody deadline starts after the signature base is built', () => {
  const source = readFileSync('src/sign.ts', 'utf8');
  const base = source.indexOf('const base = build(');
  assert.ok(base > 0);
  assert.doesNotMatch(source.slice(0, base), /withDeadline\(\{timeoutMs: isKeyHandle\(signer\) \? explicitTimeout/);
  assert.match(source.slice(base), /if \(isKeyHandle\(signer\)\) \{/);
});
test('invalid explicit timeout wins over a mismatched handle', async () => {
  const other = value(await Custody.local('hmac-sha256', {hmac: crypto.getRandomValues(new Uint8Array(32))}));
  try {
    const rejected = await sign(null, explicit, other, {signingTimeout: 0});
    assert.equal(!rejected.ok && rejected.error.reason, 'invalid_options');
  } finally {await other.release();}
});
for (const [form, spec] of [['explicit', explicit], ['generated', generated]] as const) {
  test(`${form} rejects ArrayBuffer custody output and preserves exact subarray bytes and HTTP bounds`, async () => {
    const {local, message} = await setup();
    try {
      const buffer = transformed(local, r => ({ok: true, value: value(r).buffer}));
      failure(await sign(message, spec, buffer), 'signing_failed', 'invalid_signing_output');
      const direct = await buffer.sign('ed25519', new Uint8Array([1]), value(withDeadline()));
      assert.equal(!direct.ok && direct.error.reason, 'invalid_signing_output');
      for (const size of [1, 64, 1024]) {
        let expected = new Uint8Array();
        const subarray = transformed(local, r => {
          const actual = value(r), storage = new Uint8Array(size + 2).fill(255);
          for (let i = 0; i < size; i++) storage[i + 1] = actual[i % actual.length]!;
          expected = storage.slice(1, size + 1);
          return {ok: true, value: storage.subarray(1, size + 1)};
        });
        const signed = value(await sign(message, spec, subarray));
        const wire = signed.fields.find(f => f.name.toLowerCase() === 'signature')!.value;
        assert.equal(new TextDecoder().decode(wire), `sig=:${Buffer.from(expected).toString('base64')}:`);
      }
    } finally {await local.release();}
  });
}
test('core error message and custody source fields reject unbranded private data', () => {
  const plain = coreError('invalid_options', 'input') as any;
  assert.equal(plain.message, null); assert.equal(plain.source, null);
  assert.throws(() => coreError('signing_failed' as never, 'crypto', null, {kind: 'custody', reason: 'private-caller-bytes'} as never), TypeError);
});

for (const [form, spec] of [['explicit', explicit], ['generated', generated]] as const) {
  test(`${form} settled signing releases only its owned child Context listeners`, async () => {
    const {getEventListeners} = await import('node:events');
    const {local, message} = await setup();
    const parent = value(withDeadline({timeoutMs: 300000}));
    const callerListener = () => {};
    parent.signal.addEventListener('abort', callerListener);
    try {
      assert.equal(getEventListeners(parent.signal, 'abort').length, 1);
      value(await sign(message, spec, local, {context: parent, signingTimeout: 300000}));
      assert.equal(getEventListeners(parent.signal, 'abort').length, 1);
      assert.equal(parent.signal.aborted, false);
      await local.release();
      failure(await sign(message, spec, local, {context: parent, signingTimeout: 300000}), 'signing_failed', 'key_not_found');
      assert.equal(getEventListeners(parent.signal, 'abort').length, 1);
    } finally {parent.signal.removeEventListener('abort', callerListener); await local.release();}
  });
}
