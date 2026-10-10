import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {getEventListeners} from 'node:events';
import {statSync} from 'node:fs';
import {delimiter, join} from 'node:path';
import * as api from '../src/index.ts';
import {createNodeHasher} from '../src/node_hasher.ts';
import {replayError} from '../src/errors/types.ts';
function value<T>(r: api.ReplayStoreResult<T>): T {if (!r.ok) throw r.error; return r.value;}
const context = () => value(api.withDeadline({timeoutMs: 10000}));
async function setup() {
  const handle = value(await api.Custody.local('ed25519', await readFile('test/fixtures/upstream/crypto/ed25519_private.pem', 'utf8')));
  const key = value(await api.PublicKey.import(await readFile('test/fixtures/upstream/crypto/ed25519_public.pem', 'utf8'), 'pem'));
  const message = value(await api.Message.request('GET', 'https://example.com/', [], 'abc', {digest: ['sha-256']}));
  const signed = value(await api.sign(message, {label: 's', signatureInput: '("@method" "content-digest");created=100;nonce="nonce"', algorithm: 'ed25519'}, (a: api.SigningAlgorithm,b: Uint8Array,c = context()) => handle.sign(a,b,c)));
  const memory = value(api.createMemoryStore({maxEntries: 100}));
  const attrs = {algorithms: ['ed25519'], components: '()', keyResolver: () => api.ok({algorithm: 'ed25519', key}), freshness: {clock: () => 100, maxAge: 60, skew: 0, requireExpires: false}, content: 'not_required', replay: {identifier: 'nonce', namespace: new Uint8Array([1]), commitment: (f: api.ReplayFacts) => api.ok(new TextEncoder().encode(f.identifier)), store: memory, timeoutMs: 5000}};
  return {handle, signed, memory, attrs};
}
test('caller store error vocabulary maps through claim, sweep, and required verification', async () => {
  const s = await setup();
  try {
    const c = value(api.Claim.create({namespace: new Uint8Array([1]), key: new Uint8Array([1]), retainUntil: 200}));
    const errors = [['unavailable', 'store_unavailable', 'store_unavailable'], ['timeout', 'store_timeout', 'store_timeout'], ['full', 'store_full', 'store_failed'], ['failure', 'store_failed', 'store_failed'], ['other', 'store_failed', 'store_failed']] as const;
    for (const [error, reason, verifyReason] of errors) {
      const store = {claim: async (claim: api.ReplayClaim, ctx: api.Context) => {await s.memory.claim(claim, ctx); return {ok: false as const, error};}, sweep: async (now: number, ctx: api.Context) => {await s.memory.sweep(now, ctx); return {ok: false as const, error};}};
      for (const result of [await api.Replay.claim(store, c, context()), await api.Replay.sweep(store, 200, context())]) {
        assert.equal(result.ok, false); if (!result.ok) assert.deepEqual(result.error, {kind: 'replay', reason, retryable: false});
      }
      const p = value(api.Policy.create({...s.attrs, replay: {...s.attrs.replay, store}}));
      const verified = await api.verify(s.signed, p, {label: 's'});
      assert.equal(verified.ok, false); if (!verified.ok) {assert.equal(verified.error.reason, verifyReason); assert.equal('retryable' in verified.error && verified.error.retryable, false);}
    }
    const own = {claim: () => api.err(replayError('store_full')), sweep: () => api.err(replayError('store_unavailable'))};
    assert.deepEqual((await api.Replay.claim(own, c, context())), api.err(replayError('store_full')));
    assert.deepEqual((await api.Replay.sweep(own, 200, context())), api.err(replayError('store_unavailable')));
  } finally {await s.handle.release();}
});
test('negative claim ends cover the signed bigint minimum and remain sweepable at zero', async () => {
  const min = -9223372036854775808n;
  for (const end of [min, min + 1n, BigInt(Number.MIN_SAFE_INTEGER) - 1n, Number.MIN_SAFE_INTEGER, -1, 0, 253402300799, 253402300799n]) {
    const c = api.Claim.create({namespace: new Uint8Array([1]), key: new Uint8Array([1]), retainUntil: end});
    assert.equal(c.ok, true, String(end));
    if (!c.ok) continue;
    assert.deepEqual(value(api.Replay.row(c.value)), ['01', '01', String(end)]);
    const store = value(api.createMemoryStore({maxEntries: 1}));
    assert.equal(value(await api.Replay.claim(store, c.value, context())), 'claimed');
    assert.equal(value(await api.Replay.sweep(store, 0, context())), end <= 0 ? 1 : 0);
  }
  for (const end of [min - 1n, 253402300800n, Number.MIN_SAFE_INTEGER - 1, -Infinity]) assert.equal(api.Claim.create({namespace: new Uint8Array([1]), key: new Uint8Array([1]), retainUntil: end}).ok, false);
  assert.equal(value(api.Replay.retainUntil({created: -100, expires: null, maxAge: 10, skew: 0})), -89);
  assert.equal(value(api.Replay.retainUntil({created: null, expires: -5, maxAge: null, skew: 0})), -5);
});
test('required replay releases child listeners after fifty verifies on a reused caller Context', async () => {
  const s = await setup();
  try {
    const callerSignal = new AbortController();
    const c = value(api.withDeadline({timeoutMs: 10000, signal: callerSignal.signal}));
    const before = getEventListeners(c.signal, 'abort').length;
    const p = value(api.Policy.create(s.attrs));
    for (let i = 0; i < 50; i++) {
      const r = await api.verify(s.signed, p, {label: 's', context: c});
      if (i === 0) assert.equal(r.ok, true); else {assert.equal(r.ok, false); if (!r.ok) assert.equal(r.error.reason, 'replayed');}
    }
    assert.equal(getEventListeners(c.signal, 'abort').length, before);
    assert.equal(c.signal.aborted, false);
  } finally {await s.handle.release();}
});
test('public receipts can only be obtained from a completed branded Verification', async () => {
  assert.equal(Object.hasOwn(api, 'Receipt'), false);
  assert.equal(Object.hasOwn(api, 'createReceipt'), false);
  assert.equal(api.isReplayReceipt({store: 'memory', retainUntil: 161}), false);
  const s = await setup();
  try {
    const v = value(await api.verify(s.signed, value(api.Policy.create(s.attrs)), {label: 's'}));
    assert.equal(api.isReplayReceipt(v.replay), true);
    assert.equal(api.isVerification({...v}), false);
    assert.equal(Object.isFrozen(v.replay), true);
  } finally {await s.handle.release();}
});
test('deadline during required content remains deadline_exceeded and never reaches replay', async () => {
  const s = await setup();
  try {
    const real = value(createNodeHasher());
    let checking = false, entered = false;
    const c = value(api.withDeadline({timeoutMs: 150}));
    const state = value(await api.DigestState.create('content', ['sha-256'], {create: async (algorithm: api.DigestAlgorithm) => {
      const session = await real.create(algorithm);
      return {update: session.update, finish: async () => {
        if (checking) {entered = true; await new Promise<void>(resolve => {if (c.signal.aborted) resolve(); else c.signal.addEventListener('abort', () => resolve(), {once: true});});}
        return session.finish();
      }};
    }}));
    value(await state.update(new TextEncoder().encode('abc')));
    checking = true;
    let commitments = 0, claims = 0;
    const store = {claim: (claim: api.ReplayClaim, ctx: api.Context) => {claims++; return s.memory.claim(claim, ctx);}, sweep: s.memory.sweep};
    const p = value(api.Policy.create({...s.attrs, content: {kind: 'content', algorithms: ['sha-256'], section: 'headers'}, replay: {...s.attrs.replay, store, commitment: (facts: api.ReplayFacts) => {commitments++; return s.attrs.replay.commitment(facts);}}}));
    const r = await api.verify(s.signed, p, {label: 's', context: c, digestState: state});
    assert.equal(entered, true);
    assert.equal(r.ok, false); if (!r.ok) assert.deepEqual(r.error, {kind: 'custody', reason: 'deadline_exceeded', retryable: true});
    assert.equal(commitments, 0); assert.equal(claims, 0);
    assert.equal(value(await s.memory.sweep(200, context())), 0);
  } finally {await s.handle.release();}
});

test('package Context functions preserve deadlines without exposing ownership release', () => {
  for (const name of ['withDeadline', 'run', 'remainingMs', 'isContext'] as const) assert.equal(typeof api[name], 'function');
  assert.equal(Object.hasOwn(api, 'releaseContext'), false);
});

test('caller deadline caps a longer replay timeout and prevents a late commitment from claiming', {timeout: 5000}, async () => {
  const s = await setup();
  try {
    let entered = false, settled!: () => void;
    const finished = new Promise<void>(resolve => {settled = resolve;});
    const caller = value(api.withDeadline({timeoutMs: 100}));
    const p = value(api.Policy.create({...s.attrs, replay: {...s.attrs.replay, timeoutMs: 2000, commitment: async (_facts: api.ReplayFacts, c: api.Context) => {
      entered = true;
      assert.equal(c.deadline, caller.deadline);
      await new Promise<void>(resolve => {if (c.signal.aborted) resolve(); else c.signal.addEventListener('abort', () => resolve(), {once: true});});
      settled(); return api.ok(new Uint8Array([1]));
    }}}));
    const r = await api.verify(s.signed, p, {label: 's', context: caller});
    await finished;
    assert.equal(entered, true);
    assert.equal(api.remainingMs(caller), 0);
    assert.equal(r.ok, false); if (!r.ok) {assert.equal(r.error.kind, 'core'); assert.equal(r.error.reason, 'store_timeout'); if (r.error.kind === 'core') {assert.equal(r.error.layer, 'replay'); assert.equal(r.error.retryable, false);}}
    assert.equal(value(await s.memory.sweep(200, context())), 0);
  } finally {await s.handle.release();}
});

const elixirOnPath = (process.env.PATH ?? '').split(delimiter).some(directory => {
  try {const file = statSync(join(directory, 'elixir')); return file.isFile() && (file.mode & 0o111) !== 0;} catch {return false;}
});
if (!elixirOnPath && process.env.CI === undefined) console.log('SKIP Elixir replay peer: Elixir is not on PATH');
test('Elixir replay peer bounds a database URL without userinfo before startup', {timeout: 30_000, skip: !elixirOnPath && process.env.CI === undefined ? 'Elixir is not on PATH' : false}, async () => {
  assert.ok(elixirOnPath, 'CI requires Elixir on PATH');
  const {spawnSync} = await import('node:child_process');
  const child = spawnSync('elixir', ['interop/replay/claim.exs'], {env: {...process.env, REQUESTSEAL_REPLAY_PG_URL: 'postgresql://localhost/db'}, encoding: 'utf8', timeout: 25_000});
  assert.equal(child.error, undefined, child.error?.message ?? 'Elixir subprocess must complete without a spawn error');
  assert.equal(child.status, 1, child.stdout + child.stderr);
  assert.equal(child.stderr.trim(), 'Invalid replay database URL: userinfo is required');
  assert.doesNotMatch(child.stderr, /MatchError|stack|password/);
});

test('missing Elixir executable skips locally and fails in CI', async () => {
  const {spawnSync} = await import('node:child_process');
  const {mkdtemp, rm} = await import('node:fs/promises');
  const {tmpdir} = await import('node:os'); const {join} = await import('node:path');
  const root = await mkdtemp(join(tmpdir(), 'request-seal-elixir-path-'));
  try {
    const args = process.versions.bun ? ['test', '--isolate', '--test-name-pattern=Elixir replay peer bounds', 'test/replay-fixes.test.ts'] : process.versions.deno ? ['test', '--no-check', '--allow-read', '--allow-env', '--allow-run=elixir', '--filter=Elixir replay peer bounds', 'test/replay-fixes.test.ts'] : ['--experimental-strip-types', '--no-warnings', '--test', '--test-name-pattern=Elixir replay peer bounds', 'test/replay-fixes.test.ts'];
    const env: NodeJS.ProcessEnv = {...process.env, PATH: root}; delete env.NODE_TEST_CONTEXT; delete env.CI;
    function execute(environment: NodeJS.ProcessEnv) {
      const native = (globalThis as unknown as {Deno?: {Command: new (command: string, options: {args: string[]; env: Record<string, string>; clearEnv: boolean; stdout: 'piped'; stderr: 'piped'}) => {outputSync: () => {code: number; stdout: Uint8Array; stderr: Uint8Array}}}}).Deno;
      if (native) {
        const r = new native.Command(process.execPath, {args, env: Object.fromEntries(Object.entries(environment).filter((pair): pair is [string, string] => typeof pair[1] === 'string')), clearEnv: true, stdout: 'piped', stderr: 'piped'}).outputSync();
        return {status: r.code, stdout: new TextDecoder().decode(r.stdout), stderr: new TextDecoder().decode(r.stderr)};
      }
      return spawnSync(process.execPath, args, {env: environment, encoding: 'utf8', timeout: 10000});
    }
    const local = execute(env);
    assert.equal(local.status, 0, local.stdout + local.stderr);
    assert.match(local.stdout + local.stderr, /Elixir is not on PATH/);
    if (process.versions.deno) assert.match(local.stdout + local.stderr, /0 passed \| 0 failed \| 1 ignored/);
    for (const flag of ['true', '']) {
      const ci = execute({...env, CI: flag});
      assert.equal(ci.status, 1, ci.stdout + ci.stderr); assert.match(ci.stdout + ci.stderr, /CI requires Elixir on PATH/);
    }
  } finally {await rm(root, {recursive: true, force: true});}
});
