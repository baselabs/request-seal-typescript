import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ERROR_PARITY, ERROR_RETRYABLE, ELIXIR_ERROR_PIN } from '../src/errors/parity.ts';
const fixture = JSON.parse(readFileSync(new URL('./fixtures/elixir-reasons-0a6568a.json', import.meta.url), 'utf8'));
test('every pinned Elixir reason has a unique parity rule, including the known positive', () => {
  assert.equal(ELIXIR_ERROR_PIN, '0a6568aa246326617f760e94e21b359285c6ddfc');
  assert.equal(fixture.commit, ELIXIR_ERROR_PIN);
  assert.ok(fixture.entries.some((e: {rule_id: string}) => e.rule_id === 'core/crypto.invalid_signature'));
  assert.equal(fixture.entries.length, 222);
  assert.equal(fixture.modules.reduce((n: number, m: {reasons: string[]}) => n + m.reasons.length, 0), 220);
  assert.equal(new Set(ERROR_PARITY.map(e => e.rule_id)).size, 222);
  assert.deepEqual(ERROR_PARITY, fixture.entries);
  assert.deepEqual(ERROR_RETRYABLE, Object.fromEntries(fixture.modules.map((m: {kind: string; retryable: {rules: unknown}}) => [m.kind, m.retryable.rules])));
});
import { coreError, custodyError, discoveryError, joseError, adapterError, messageError, structuredFieldsError, signatureBaseError, digestError, cryptoError, replayError, isRequestSealError } from '../src/errors/types.ts';
import { renderParity } from '../scripts/render-parity.ts';
test('parity documentation is generated from the same table', () => {
  assert.equal(readFileSync(new URL('../docs/reference/error-parity.md', import.meta.url), 'utf8'), renderParity());
});
test('error shapes, closed fields, branding and retryability match the pinned structs', () => {
  for (const m of fixture.modules) {
    for (const entry of fixture.entries.filter((e: {kind: string}) => e.kind === m.kind)) {
      const reason = entry.reason;
      const factories = {message: messageError, structured_fields: structuredFieldsError, signature_base: signatureBaseError, digest: digestError, crypto: cryptoError, custody: custodyError, discovery: discoveryError, replay: replayError};
      const factory = factories[m.kind as keyof typeof factories] as ((r: never) => object) | undefined;
      const e = m.kind === 'core' ? coreError(reason, entry.layer) : m.kind === 'jose' ? joseError(reason, entry.layer) : m.kind === 'adapter' ? adapterError(reason, 'req', 'sign', 1) : factory!(reason as never);
      assert.ok(isRequestSealError(e)); assert.ok(Object.isFrozen(e)); assert.equal(e instanceof Error, false);
      assert.deepEqual(Object.keys(e).sort(), ['kind', ...m.fields].sort());
      if ('retryable' in e) assert.equal(e.retryable, m.retryable.constructor.includes(reason));
      if ('correlation' in e && m.kind !== 'jose') assert.match(e.correlation as string, /^[a-f0-9]{16}$/);
    }
  }
  assert.equal(isRequestSealError({kind: 'core', reason: 'invalid_signature'}), false);
  assert.equal(coreError('invalid_signature', 'crypto', 'caller secret' as never).detail, null);
  assert.throws(() => adapterError('invalid_request', 'req', 'capture', 0, {bytes: new Uint8Array([1])} as never), TypeError);
});
test('parity data cannot be rewritten through the public API', () => {
  assert.ok(Object.isFrozen(ERROR_PARITY));
  for (const entry of ERROR_PARITY) assert.ok(Object.isFrozen(entry));
});

test('retryable documentation renders each constant and status-derived rule from parity data', () => {
  const doc = renderParity();
  for (const [kind, rules] of Object.entries(ERROR_RETRYABLE)) {
    for (const [reason, rule] of Object.entries(rules)) if (rule.kind === 'constant' && rule.value) assert.ok(doc.includes(`${kind}/${reason}`));
  }
  const status = ERROR_RETRYABLE.discovery.unexpected_status;
  assert.ok(doc.includes(`discovery/unexpected_status: ${status.minimum}–${status.maximum}`));
});
