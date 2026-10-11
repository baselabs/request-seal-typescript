import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile, mkdtemp, writeFile, rm} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import * as api from '../src/index.ts';
import {sequence, oid, OIDS, tlv, integer, readPem, readDer, encodeDer, decodeKey} from '../src/custody/der.ts';
const value = <T>(r: api.Result<T>): T => { assert.equal(r.ok, true, r.ok ? '' : r.error.reason); if (!r.ok) throw new Error('Rejected'); return r.value; };
const reason = (r: api.Result<unknown>) => r.ok ? 'success' : r.error.reason;
const read = (name: string) => readFile('test/fixtures/upstream/crypto/' + name, 'utf8');
const prefix = Object.hasOwn(process.versions, 'deno') ? ['run', '--no-check', '--allow-read'] : Object.hasOwn(process.versions, 'bun') ? ['run'] : ['--experimental-strip-types', '--no-warnings'];

test('non-byte-aligned RSA OpenSSL reciprocal signatures and OAEP', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'request-seal-rsa-'));
  const openssl = (args: string[]) => { const r = spawnSync('openssl', args, {encoding: 'utf8'}); t.diagnostic('COMMAND: openssl ' + args.join(' ')); t.diagnostic('RESULT: exit=' + r.status + ' ' + r.stdout.trim()); assert.equal(r.status, 0, r.stderr); };
  try {
    for (const bits of [2050, 3070]) {
      const keyFile = join(root, 'key.pem'), pubFile = join(root, 'public.pem'), messageFile = join(root, 'message'), sigFile = join(root, 'signature');
      openssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:' + bits, '-out', keyFile]);
      openssl(['pkey', '-in', keyFile, '-pubout', '-out', pubFile]);
      const pem = await readFile(keyFile, 'utf8');
      const message = new TextEncoder().encode('non-byte-aligned modulus');
      await writeFile(messageFile, message);
      const h = value(await api.Custody.local('rsa-v1_5-sha256', pem));
      try {
        const pub = value(await api.PublicKey.import(await readFile(pubFile, 'utf8'), 'pem'));
        const sig = value(await api.Crypto.sign('rsa-v1_5-sha256', h, message));
        assert.equal(sig.length, Math.ceil(bits / 8));
        await writeFile(sigFile, sig);
        openssl(['dgst', '-sha256', '-verify', pubFile, '-signature', sigFile, messageFile]);
        openssl(['dgst', '-sha256', '-sign', keyFile, '-out', sigFile, messageFile]);
        value(await api.Crypto.verify('rsa-v1_5-sha256', pub, new Uint8Array(await readFile(sigFile)), message));
      } finally { value(await h.release()); }
      const unwrap = value(await api.Custody.local({jwe: 'RSA-OAEP-256'}, pem));
      try {
        const cek = new Uint8Array(32); crypto.getRandomValues(cek); await writeFile(messageFile, cek);
        openssl(['pkeyutl', '-encrypt', '-pubin', '-inkey', pubFile, '-in', messageFile, '-out', sigFile, '-pkeyopt', 'rsa_padding_mode:oaep', '-pkeyopt', 'rsa_oaep_md:sha256', '-pkeyopt', 'rsa_mgf1_md:sha256']);
        const content = value(await unwrap.unwrap({jwe: 'RSA-OAEP-256'}, new Uint8Array(await readFile(sigFile)), value(api.withDeadline())));
        assert.equal(Object.isFrozen(Object.getPrototypeOf(content)), true);
        assert.equal(Object.isFrozen(Object.getPrototypeOf(content).constructor), true);
        const aes = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
        const iv = new Uint8Array(12); const ciphertext = new Uint8Array(await crypto.subtle.encrypt({name: 'AES-GCM', iv}, aes, message));
        assert.deepEqual(value(await content.decrypt(ciphertext, {iv}, value(api.withDeadline()))), message);
        value(await content.release()); cek.fill(0);
      } finally { value(await unwrap.release()); }
    }
  } finally { await rm(root, {recursive: true, force: true}); }
});

test('zeroing tracker finds positive control and no surviving private DER bytes', {timeout: 15_000}, (t) => {
  const child = spawnSync(process.execPath, [...prefix, 'test/support/zeroing.ts'], {encoding: 'utf8', timeout: 10000});
  assert.equal(child.status, 0, child.stdout + child.stderr);
  t.diagnostic(child.stdout.trim());
});

test('prototypes and constructors are frozen and cannot forge verification', async () => {
  const h = value(await api.Custody.local('ed25519', await read('ed25519_private.pem')));
  try {
    const pub = value(await h.publicKey());
    const id = value(await h.identity());
    for (const object of [pub, h, id]) {
      const prototype = Object.getPrototypeOf(object);
      const original = prototype.verify;
      const patched = Reflect.set(prototype, 'verify', async () => api.ok(true));
      try {
        assert.equal(patched, false);
        assert.equal(Object.isFrozen(prototype), true);
        assert.equal(Object.isFrozen(prototype.constructor), true);
        if (object !== id) assert.equal(reason(await api.Crypto.verify('ed25519', object, new Uint8Array(64), new Uint8Array())), 'invalid_signature');
      } finally { if (patched) { if (original) prototype.verify = original; else delete prototype.verify; } }
    }
    assert.equal(Object.isFrozen(api.PublicKey), true);
  } finally { value(await h.release()); }
});

test('CRLF and lenient END armor import like OTP', async () => {
  const pem = await read('ed25519_private.pem');
  const h = value(await api.Custody.local('ed25519', pem.replace(/\n/g, '\r\n'))); value(await h.release());
  for (const end of ['-----END PRIVATE KEY----', '-----END PRIVATE KEY------', '-----END another label']) {
    const imported = value(await api.Custody.local('ed25519', pem.replace('-----END PRIVATE KEY-----', end)));
    value(await imported.release());
  }
});

test('encrypted PEM markers reject before body parsing', async () => {
  for (const pem of ['-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00\n\nAA==\n-----END RSA PRIVATE KEY-----', '-----BEGIN ENCRYPTED PRIVATE KEY-----\n!\n-----END ENCRYPTED PRIVATE KEY-----'])
    assert.equal(reason(await api.Custody.local('ed25519', pem)), 'unsupported_format');
});

test('unknown and lowercase PEM labels return invalid_key', async () => {
  for (const label of ['UNKNOWN KEY', 'private key'])
    assert.equal(reason(await api.Custody.local('ed25519', `-----BEGIN ${label}-----\nAA==\n-----END ${label}-----`)), 'invalid_key');
});
test('unparseable PKCS8 garbage deep and excessive trees return unsupported_format', async () => {
  let deep = integer(0n); for (let i = 0; i < api.DER_MAX_DEPTH + 2; i++) deep = sequence(deep);
  const many = sequence(...Array.from({length: api.DER_MAX_NODES + 1}, () => tlv(5, new Uint8Array())));
  for (const der of [new Uint8Array([0, 1, 2]), sequence(integer(0n)), integer(0n), deep, many])
    assert.equal(reason(await api.Custody.local('ed25519', der)), 'unsupported_format');
});
test('PKCS8 version zero with publicKey returns unsupported_format', async () => {
  const ed = value(readPem(await read('ed25519_private.pem'))); const c = value(readDer(ed.der)).children;
  const v0Public = sequence(...c.map(n => value(encodeDer(n))), tlv(129, new Uint8Array([0, 1])));
  assert.equal(reason(await api.Custody.local('ed25519', v0Public)), 'unsupported_format');
});
test('public SPKI constrained PSS and unknown OID return invalid_key', async () => {
  const rsa = value(decodeKey(await read('rsa_public.pem'), 'pem')); const r = value(readDer(rsa.der));
  for (const alg of [sequence(oid(OIDS.pss), sequence()), sequence(oid('2a0304'))]) {
    const der = sequence(alg, value(encodeDer(r.children[1]!)));
    assert.equal(reason(await api.PublicKey.import(der, 'spki')), 'invalid_key');
  }
});

test('private JWK per-operation metadata rules', async () => {
  const ed = JSON.parse(await readFile('test/fixtures/upstream/custody/rfc8037.json', 'utf8'));
  for (const ops of [['sign', 'encrypt'], ['sign', 'deriveKey']]) assert.equal(reason(await api.Custody.local('ed25519', {...ed, key_ops: ops})), 'invalid_key');
  const rsa = JSON.parse(await readFile('test/fixtures/upstream/custody/rfc7517.json', 'utf8')).keys[1];
  delete rsa.alg;
  assert.equal(reason(await api.Custody.local({jwe: 'RSA-OAEP-256'}, {...rsa, key_ops: ['unwrapKey', 'sign']})), 'invalid_key');
  for (const extra of [{alg: 1}, {use: 'foo'}]) assert.equal(reason(await api.Custody.local('ed25519', {...ed, ...extra})), 'key_mismatch');
});

test('verification order capability-first checks and custody signature limits', async () => {
  const ed = JSON.parse(await readFile('test/fixtures/upstream/custody/rfc8037.json', 'utf8'));
  const h = value(await api.Custody.local('ed25519', {...ed, key_ops: ['sign']}));
  try {
    const pub = value(await h.publicKey()); const c = value(api.withDeadline());
    assert.equal(reason(await api.Crypto.verify('hmac-sha256', pub, 'bad', new Uint8Array())), 'key_mismatch');
    assert.equal(reason(await api.Crypto.verify('ed25519', pub, 'bad', new Uint8Array(api.SIGNATURE_BASE_MAX_BYTES + 1))), 'invalid_data');
    assert.equal(reason(await h.verify('ed25519', 'bad', {}, c)), 'unsupported_operation');
    assert.equal(reason(await h.unwrap('ed25519', {}, c)), 'unsupported_operation');
  } finally { value(await h.release()); }
  const full = value(await api.Custody.local('ed25519', await read('ed25519_private.pem')));
  try {
    const c = value(api.withDeadline());
    for (const size of [0, 1024, 1025, 16384]) assert.equal(reason(await full.verify('ed25519', new Uint8Array(size), new Uint8Array(), c)), 'invalid_signature');
    assert.equal(reason(await full.verify('ed25519', new Uint8Array(16385), new Uint8Array(), c)), 'limit');
    assert.equal(reason(await api.Crypto.verify('hmac-sha256', full, new Uint8Array(16385), new Uint8Array())), 'key_mismatch');
    const oaep = value(await api.Custody.local({jwe: 'RSA-OAEP'}, await read('rsa_private.pem')));
    try { assert.equal(reason(await oaep.sign({jwe: 'RSA-OAEP'}, {}, c)), 'unsupported_operation'); } finally { value(await oaep.release()); }
  } finally { value(await full.release()); }
});

test('capability Proxy is read once into owned snapshot', async () => {
  const local = value(await api.Custody.local('ed25519', await read('ed25519_private.pem')));
  let reads = 0;
  const caps = new Proxy(['sign'], {get(target, key, receiver) { if (key === Symbol.iterator) { reads++; const next = reads >= 2 ? ['sign', 'unwrap', 'unwrap'] : ['sign']; return next[Symbol.iterator].bind(next); } return Reflect.get(target, key, receiver); }});
  const h = value(api.createKeyHandle('ed25519', local, caps as api.KeyHandle['capabilities']));
  try { assert.deepEqual(h.capabilities, ['sign']); assert.ok(reads <= 1); } finally { value(await h.release()); }
});

test('custody error kind and retryability survive Crypto boundary', async () => {
  const h = value(await api.Custody.local('ed25519', await read('ed25519_private.pem')));
  value(await h.release());
  const r = await api.Crypto.sign('ed25519', h, new Uint8Array());
  assert.equal(reason(r), 'key_not_found'); assert.equal(!r.ok && r.error.kind, 'custody');
  for (const mode of ['deadline', 'throw'] as const) {
    const local = value(await api.Custody.local('ed25519', await read('ed25519_private.pem')));
    const port = Object.create(null) as api.Custodian;
    for (const name of ['verify', 'publicKey', 'identity', 'unwrap', 'release'] as const)
      Object.defineProperty(port, name, {value: local[name].bind(local)});
    Object.defineProperty(port, 'sign', {value: async (algorithm: unknown, data: unknown, context: api.Context) => {
      if (mode === 'deadline') {
        const expired = value(api.withDeadline({timeoutMs: 1}));
        await new Promise(resolve => setTimeout(resolve, 10));
        return local.sign(algorithm, data, expired);
      }
      const signed = await local.sign(algorithm, data, context);
      if (signed.ok) signed.value.fill(0);
      throw new Error('custodian diagnostic must stay private');
    }});
    const handle = value(api.createKeyHandle('ed25519', port));
    try {
      const result = await api.Crypto.sign('ed25519', handle, new Uint8Array());
      assert.equal(reason(result), mode === 'deadline' ? 'deadline_exceeded' : 'custodian_failure');
      assert.equal(!result.ok && result.error.kind, 'custody');
      assert.ok(!result.ok && result.error.kind === 'custody');
      assert.equal(result.error.retryable, mode === 'deadline');
      assert.equal(JSON.stringify(result).includes('diagnostic'), false);
    } finally {value(await handle.release());}
  }
});

test('CryptoKey clone behavior is version-pinned and documentation states confinement', async (t) => {
  const key = await crypto.subtle.importKey('raw', new Uint8Array(32), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
  const expected = new Uint8Array(await crypto.subtle.sign('HMAC', key, new Uint8Array()));
  async function check(copy: CryptoKey) {
    if (process.versions.deno === '2.5.6') {
      assert.equal(copy instanceof CryptoKey, false);
      await assert.rejects(crypto.subtle.sign('HMAC', copy, new Uint8Array()), TypeError);
    } else assert.deepEqual(new Uint8Array(await crypto.subtle.sign('HMAC', copy, new Uint8Array())), expected);
  }
  await check(structuredClone(key));
  const {port1, port2} = new MessageChannel();
  try {
    const copied = new Promise<CryptoKey>(resolve => {port2.onmessage = e => resolve(e.data as CryptoKey);}); port1.postMessage(key);
    await check(await copied);
  } finally {port1.close(); port2.close();}
  assert.match(await readFile('docs/design/threat-model.md', 'utf8'), /structuredClone.*postMessage.*CryptoKey.*usable copy/s);
  t.diagnostic('CLONES: ' + (process.versions.deno === '2.5.6' ? 'Deno 2.5.6 copies lose the CryptoKey brand; both operations reject TypeError' : 'structuredClone and postMessage yield usable cryptographic copies'));
});

test('runtime reference pins Bun extreme-s exception', async () => {
  assert.match(await readFile('docs/reference/runtime-matrix.md', 'utf8'), /Tested runtime lanes[\s\S]*Bun 1\.3\.14[\s\S]*261[\s\S]*262/);
});

test('changelog continuous list and corpus metadata first', async () => {
  const changelog = await readFile('CHANGELOG.md', 'utf8'); assert.doesNotMatch(changelog.split('## Unreleased')[1]!.trim(), /\n\n-/);
  assert.match(await readFile('docs/reference/corpus-format.md', 'utf8'), /^\*\*Status:\*\*/);
});

test('PKCS8 v2 reason is unsupported_format', async () => {
  const root = value(readDer(value(readPem(await read('ed25519_private.pem'))).der));
  assert.equal(reason(await api.Custody.local('ed25519', sequence(integer(1n), ...root.children.slice(1).map(n => value(encodeDer(n)))))), 'unsupported_format');
});


test('captured subtle.verify resists instance and prototype replacement after load', async () => {
  const h = value(await api.Custody.local('ed25519', await read('ed25519_private.pem')));
  const subtle = crypto.subtle;
  const prototype = Object.getPrototypeOf(subtle);
  const own = Object.getOwnPropertyDescriptor(subtle, 'verify');
  const inherited = Object.getOwnPropertyDescriptor(prototype, 'verify')!;
  try {
    Object.defineProperty(subtle, 'verify', {value: async () => true, configurable: true});
    assert.equal(reason(await api.Crypto.verify('ed25519', h, new Uint8Array(64), new Uint8Array())), 'invalid_signature');
    delete (subtle as unknown as Record<string, unknown>).verify;
    Object.defineProperty(prototype, 'verify', {value: async () => true, configurable: true});
    assert.equal(reason(await api.Crypto.verify('ed25519', h, new Uint8Array(64), new Uint8Array())), 'invalid_signature');
  } finally {
    Object.defineProperty(prototype, 'verify', inherited);
    if (own) Object.defineProperty(subtle, 'verify', own);
    else delete (subtle as unknown as Record<string, unknown>).verify;
    value(await h.release());
  }
});


test('successful custody signatures accept 1 and 16384 bytes and reject 0 and 16385', async () => {
  // Fault-inject sizes into actual signature bytes from a real local custodian;
  // this checks wrapper result validation, not external signature conformance.
  for (const size of [0, 1, 16384, 16385]) {
    const local = value(await api.Custody.local('ed25519', await read('ed25519_private.pem')));
    const port = Object.create(null) as api.Custodian;
    for (const name of ['verify', 'publicKey', 'identity', 'unwrap', 'release'] as const)
      Object.defineProperty(port, name, {value: local[name].bind(local)});
    Object.defineProperty(port, 'sign', {value: async (algorithm: unknown, data: unknown, context: api.Context) => {
      const signed = await local.sign(algorithm, data, context);
      if (!signed.ok) return signed;
      const resized = new Uint8Array(size);
      for (let i = 0; i < size; i++) resized[i] = signed.value[i % signed.value.length]!;
      signed.value.fill(0);
      return api.ok(resized);
    }});
    const h = value(api.createKeyHandle('ed25519', port));
    try {
      const r = await h.sign('ed25519', new Uint8Array(), value(api.withDeadline()));
      if (size === 1 || size === 16384) {assert.ok(r.ok); assert.equal(r.value.length, size); r.value.fill(0);}
      else assert.equal(reason(r), 'invalid_signing_output');
    } finally {value(await h.release());}
  }
});

test('Crypto handle failures retain operational kinds and normalize cryptographic reasons', async () => {
  const h = value(await api.Custody.local('ed25519', await read('ed25519_private.pem')));
  try {
    const pub = value(await h.publicKey());
    for (const key of [pub, h]) {
      const bad = await api.Crypto.verify('ed25519', key, new Uint8Array(64), new Uint8Array());
      assert.equal(reason(bad), 'invalid_signature');
      assert.equal(!bad.ok && bad.error.kind, 'crypto');
      const mismatch = await api.Crypto.verify('hmac-sha256', key, new Uint8Array(64), new Uint8Array());
      assert.equal(reason(mismatch), 'key_mismatch');
      assert.equal(!mismatch.ok && mismatch.error.kind, 'crypto');
    }
    for (const [algorithm, data, expected] of [['hmac-sha256', new Uint8Array(), 'key_mismatch'], ['ed25519', {}, 'invalid_data']] as const) {
      const r = await api.Crypto.sign(algorithm, h, data);
      assert.equal(reason(r), expected); assert.equal(!r.ok && r.error.kind, 'crypto');
    }
  } finally {value(await h.release());}
});

test('private JWK operation policy precedes malformed private material', async () => {
  const ed = JSON.parse(await readFile('test/fixtures/upstream/custody/rfc8037.json', 'utf8'));
  assert.equal(reason(await api.Custody.local('ed25519', {...ed, d: '!', key_ops: ['verify']})), 'key_mismatch');
  assert.equal(reason(await api.Custody.local('ed25519', {...ed, d: '!', key_ops: ['sign']})), 'invalid_key');
});

test('captured Promise methods and brands resist after-load verdict forgery', (t) => {
  const child = spawnSync(process.execPath, [...prefix, 'test/support/forge.ts'], {encoding: 'utf8', timeout: 10000});
  assert.equal(child.status, 0, child.stdout + child.stderr);
  t.diagnostic(child.stdout.trim());
});
