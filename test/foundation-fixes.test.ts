import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import {spawnWithEnvSync as spawnSync} from './support/child-env.ts';
import * as api from '../src/index.ts';
import * as errors from '../src/errors/types.ts';
import { ERROR_PARITY, RULE_IDS } from '../src/errors/parity.ts';
import { deepFreeze } from '../src/brand.ts';
import { withDeadline, remainingMs, run } from '../src/context.ts';
import { ok, err } from '../src/result.ts';
import { structuredInteger } from '../src/numbers.ts';
import { decodeBase64, decodeBase64Url } from '../src/bytes.ts';
import { JOSE_MAX_PLAINTEXT_BYTES } from '../src/constants.ts';
const read = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8');
const prefix = Object.hasOwn(process.versions, 'deno') ? ['eval', '--no-check'] : Object.hasOwn(process.versions, 'bun') ? ['-e'] : ['--experimental-strip-types', '--no-warnings', '--input-type=module', '-e'];
test('scratch directories use OS temp', () => {
  for (const file of ['./conformance.test.ts', '../scripts/test-built.ts']) {
    const source = read(file);
    assert.match(source, /tmpdir\(\)/);
    assert.match(source, /request-seal-/);
    assert.match(source, /finally[\s\S]*rm\(/);
  }
});
test('constructed error pairs have registered rule IDs', () => {
  assert.ok(RULE_IDS.has('jose/key.algorithm_mismatch'));
  for (const layer of ['input', 'key', 'nesting']) assert.equal(RULE_IDS.has(`jose/${layer}.deadline_exceeded`), false);
  assert.ok(RULE_IDS.has('jose/crypto.deadline_exceeded'));
  for (const entry of ERROR_PARITY) {
    const constructors = {message: errors.messageError, structured_fields: errors.structuredFieldsError, signature_base: errors.signatureBaseError, digest: errors.digestError, crypto: errors.cryptoError, custody: errors.custodyError, discovery: errors.discoveryError, replay: errors.replayError};
    const e = entry.kind === 'core' ? errors.coreError(entry.reason, entry.layer) : entry.kind === 'jose' ? errors.joseError(entry.reason, entry.layer) : entry.kind === 'adapter' ? errors.adapterError(entry.reason, 'req', 'sign', 1) : (constructors[entry.kind] as (r: never) => errors.RequestSealError)(entry.reason as never);
    assert.ok(RULE_IDS.has(errors.ruleId(e)), errors.ruleId(e));
  }
  assert.throws(() => errors.joseError('invalid_signature', 'input'), TypeError);
});
test('public exports protect brands and freeze Results', async () => {
  for (const name of ['brand', 'isBranded', 'coreError', 'joseError', 'messageError', 'structuredFieldsError', 'signatureBaseError', 'digestError', 'cryptoError', 'custodyError', 'discoveryError', 'replayError', 'adapterError']) assert.equal(Object.hasOwn(api, name), false, name);
  assert.equal(typeof (api as Record<string, unknown>).isContext, 'function');
  const c = withDeadline({timeoutMs: 5000}); assert.ok(c.ok);
  assert.equal((api as any).isContext(c.value), true);
  assert.equal((api as any).isContext({...c.value}), false);
  assert.equal(errors.isRequestSealError({...errors.custodyError('invalid_options')}), false);
  assert.ok(Object.isFrozen(ok(1))); assert.ok(Object.isFrozen(err(errors.custodyError('invalid_options'))));
  await run(c.value, () => ok(1));
});
test('settled Context releases process and its run listener', {timeout: 15_000}, () => {
  const context = new URL('../src/context.ts', import.meta.url).href;
  const result = new URL('../src/result.ts', import.meta.url).href;
  const code = `const {withDeadline,run}=await import(${JSON.stringify(context)});const {ok}=await import(${JSON.stringify(result)});const dog=setTimeout(()=>{console.log('held');globalThis.Deno?Deno.exit(3):process.exit(3)},2000);globalThis.Deno?Deno.unrefTimer(dog):dog.unref();const caller=new AbortController();const c=withDeadline({timeoutMs:300000,signal:caller.signal});if(!c.ok)throw Error();await run(c.value,()=>ok(1));const {getEventListeners}=await import('node:events');console.log(getEventListeners(c.value.signal,'abort').length);caller.abort();if(!c.value.signal.aborted)throw Error('caller abort lost');`;
  const env = {...process.env}; delete env.NODE_TEST_CONTEXT;
  const child = spawnSync(process.execPath, [...prefix, code], {encoding: 'utf8', timeout: 10_000, env});
  assert.equal(child.status, 0, child.stderr || String(child.error));
  assert.equal(child.stdout.trim(), '0', 'settled run detached its abort listener');
});
test('child Context follows parent deadline and abort', async () => {
  const parent = withDeadline({timeoutMs: 5000}); assert.ok(parent.ok);
  const child = withDeadline({parent: parent.value, timeoutMs: 300000}); assert.ok(child.ok);
  assert.equal(child.value.deadline, parent.value.deadline);
  const parentRemaining = remainingMs(parent.value); const childRemaining = remainingMs(child.value);
  assert.ok(childRemaining <= parentRemaining);
  const caller = new AbortController(); const p = withDeadline({timeoutMs: 5000, signal: caller.signal}); assert.ok(p.ok);
  const c = withDeadline({parent: p.value}); assert.ok(c.ok); caller.abort(); assert.ok(c.value.signal.aborted);
  assert.equal(withDeadline({parent: {...parent.value}}).ok, false);
  await run(child.value, () => ok(1)); await run(parent.value, () => ok(1));
});
test('CI red proofs require marker and failure count', () => {
  const ci = read('../.github/workflows/ci.yml');
  assert.equal((ci.match(/scripts\/red-proof\.sh/g) ?? []).length, 3);
  const script = read('../scripts/red-proof.sh');
  assert.match(script, /Intentional red proof/); assert.match(script, /fail/); assert.match(script, /failed/);
});
test('core excludes extension-profile layers', () => {
  assert.doesNotMatch(read('../src/errors/types.ts'), /Layer<'core'> \| 'profile'/);
  assert.match(read('../docs/reference/error-parity.md'), /profile row/);
  assert.throws(() => errors.coreError('invalid_options', 'profile' as never), TypeError);
});
test('unknown error reasons and pairs throw TypeError', () => {
  const factories = [errors.messageError, errors.structuredFieldsError, errors.signatureBaseError, errors.digestError, errors.cryptoError, errors.custodyError, errors.discoveryError, errors.replayError];
  for (const factory of factories) assert.throws(() => factory('typo' as never), TypeError);
  assert.throws(() => errors.coreError('typo' as never, 'input'), TypeError);
  assert.throws(() => errors.coreError('invalid_signature', 'input'), TypeError);
  assert.throws(() => errors.joseError('typo' as never, 'input'), TypeError);
  assert.throws(() => errors.joseError('invalid_options', 'crypto'), TypeError);
  assert.throws(() => errors.adapterError('typo' as never, 'req', 'sign', 1), TypeError);
});
test('open reasons retain pinned call-site provenance', () => {
  const fixture = JSON.parse(read('./fixtures/elixir-reasons-b239287.json'));
  for (const id of ['structured_fields/revision_type', 'digest/invalid_state']) {
    assert.ok(fixture.entries.some((e: {rule_id: string}) => e.rule_id === id), id);
    assert.ok(fixture.modules.some((m: any) => m.call_sites?.some((s: any) => s.rule_id === id)), id);
  }
});
test('deepFreeze copies typed arrays and caller graphs', () => {
  const input = {nested: {bytes: new Uint8Array([1, 2])}};
  const frozen: any = deepFreeze(input); assert.equal(frozen.ok, true);
  assert.ok(Object.isFrozen(frozen.value)); assert.ok(Object.isFrozen(frozen.value.nested));
  assert.equal(Object.isFrozen(input), false); assert.equal(Object.isFrozen(input.nested), false);
  assert.notEqual(frozen.value.nested.bytes, input.nested.bytes); input.nested.bytes[0] = 9;
  assert.equal(frozen.value.nested.bytes[0], 1); assert.equal(Object.isFrozen(frozen.value.nested.bytes), false);
  assert.equal((deepFreeze(new Map()) as any).ok, false);
  const cycle: {self?: object} = {}; cycle.self = cycle;
  const copied: any = deepFreeze(cycle); assert.ok(copied.ok); assert.equal(copied.value.self, copied.value);
});
test('OTP JSON edge fixture drives expectations', async () => {
  const fixture = JSON.parse(read('./fixtures/otp-json-edges.json'));
  assert.match(fixture.otp_version, /^29/); assert.match(fixture.command, /json:decode/);
  const {decodeJson} = await import('../src/json.ts');
  for (const edge of fixture.edges) assert.equal(decodeJson(new TextEncoder().encode(edge.literal)).ok, edge.accepted, edge.literal);
});
test('native CI pins exact releases and required tests', () => {
  const ci = read('../.github/workflows/ci.yml');
  assert.match(ci, /deno-version: ['"]?v?\d+\.\d+\.\d+/); assert.match(ci, /bun-version: ['"]?\d+\.\d+\.\d+/);
  assert.doesNotMatch(ci, /setup-bun@[^\n]+# v2\s*\n/);
  assert.equal((ci.match(/test\/\*\.test\.ts/g) ?? []).length, 2);

  assert.doesNotMatch(ci + read('../package.json'), /--unpinned --smoke/);
});
test('numeric and codec bounds enforce strict rejections', () => {
  assert.equal(structuredInteger(-0).ok, false);
  for (const decode of [decodeBase64, decodeBase64Url]) {
    const huge = decode('A'.repeat(Math.ceil(JOSE_MAX_PLAINTEXT_BYTES / 3) * 4 + 4));
    assert.equal(huge.ok, false); if (!huge.ok) assert.equal(huge.error.reason, 'limit');
  }
  assert.match(JSON.parse(read('../package.json')).scripts.test, /--unhandled-rejections=strict/);
  assert.match(read('../docs/reference/error-parity.md'), /unexpected_status: 500–599 \(status-derived\)/);
  assert.doesNotMatch(read('../src/context.ts'), /cancelled/);
});
test('tamper tests assert exact failure reasons', () => {
  const source = read('./conformance.test.ts');
  assert.match(source, /failures\[0\][!?]?\.reason/);
  assert.match(source, /invalid_known_positive/); assert.match(source, /missing_file/); assert.match(source, /smoke pin/);
});
test('settled Context remains reusable by a subsequent run and child', async () => {
  const context = withDeadline({timeoutMs: 5000}); assert.ok(context.ok);
  assert.deepEqual(await run(context.value, () => ok(1)), ok(1));
  assert.ok(remainingMs(context.value) > 0); assert.equal(context.value.signal.aborted, false);
  const child = withDeadline({parent: context.value}); assert.ok(child.ok); assert.ok(remainingMs(child.value) > 0);
  assert.deepEqual(await run(context.value, () => ok(2)), ok(2));
  assert.deepEqual(await run(child.value, () => ok(3)), ok(3));
});
test('nested run preserves the outer run deadline timer and remaining time', async () => {
  const context = withDeadline({timeoutMs: 5000}); assert.ok(context.ok);
  const result = await run(context.value, async () => {
    assert.deepEqual(await run(context.value, () => ok('inner')), ok('inner'));
    assert.ok(remainingMs(context.value) > 0); assert.equal(context.value.signal.aborted, false);
    await new Promise(resolve => setTimeout(resolve, 20));
    return ok('outer');
  });
  assert.deepEqual(result, ok('outer'));
  const expiring = withDeadline({timeoutMs: 80}); assert.ok(expiring.ok);
  const expired = await run(expiring.value, async () => {
    await new Promise(resolve => setTimeout(resolve, 200));
    return ok('late');
  });
  assert.equal(expired.ok, false); if (!expired.ok) assert.equal(expired.error.reason, 'deadline_exceeded');
});
test('an active child ends at the idle parent deadline after parent settlement', {timeout: 15_000}, async () => {
  const parent = withDeadline({timeoutMs: 5000}); assert.ok(parent.ok);
  const child = withDeadline({parent: parent.value, timeoutMs: 5000}); assert.ok(child.ok);
  assert.deepEqual(await run(parent.value, () => ok('parent')), ok('parent'));
  assert.equal(child.value.signal.aborted, false);
  const result = await run(child.value, async () => { await new Promise(resolve => setTimeout(resolve, remainingMs(child.value) + 50)); return ok('late'); });
  assert.equal(result.ok, false); if (!result.ok) assert.equal(result.error.reason, 'deadline_exceeded');
  assert.ok(child.value.signal.aborted); assert.equal(remainingMs(parent.value), 0);
});
test('dead identity module and branding re-export are removed', async () => {
  assert.equal(existsSync(new URL('../src/identity.ts', import.meta.url)), false);
  const brand = await import('../src/brand.ts');
  assert.equal(Object.hasOwn(brand, 'brand'), false); assert.equal(Object.hasOwn(brand, 'isBranded'), false);
});
test('adapter constructor rejects invalid adapter, stage, and attempt', () => {
  for (const adapter of ['unknown', null, undefined, 1]) assert.throws(() => errors.adapterError('invalid_request', adapter as never, 'sign', 1), TypeError);
  for (const stage of ['unknown', null, undefined, 1]) assert.throws(() => errors.adapterError('invalid_request', 'req', stage as never, 1), TypeError);
  for (const attempt of [-1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '1', null, undefined]) assert.throws(() => errors.adapterError('invalid_request', 'req', 'sign', attempt as never), TypeError);
  for (const adapter of ['req', 'finch', 'plug'] as const) for (const stage of ['attach', 'capture', 'sign', 'verify'] as const) for (const attempt of [0, 1, Number.MAX_SAFE_INTEGER]) {
    const value = errors.adapterError('invalid_request', adapter, stage, attempt);
    assert.equal(value.adapter, adapter); assert.equal(value.stage, stage); assert.equal(value.attempt, attempt);
  }
});
test('base64 codecs accept the compact ceiling and reject one byte beyond it', async () => {
  const {JOSE_MAX_COMPACT_BYTES} = await import('../src/constants.ts');
  for (const decode of [decodeBase64, decodeBase64Url]) {
    const atCap = decode('A'.repeat(JOSE_MAX_COMPACT_BYTES)); assert.ok(atCap.ok); assert.equal(atCap.value.length, JOSE_MAX_COMPACT_BYTES * 3 / 4);
    const overCap = decode('A'.repeat(JOSE_MAX_COMPACT_BYTES + 1)); assert.equal(overCap.ok, false); if (!overCap.ok) assert.equal(overCap.error.reason, 'limit');
  }
});
