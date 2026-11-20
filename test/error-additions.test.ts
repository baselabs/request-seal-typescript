import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {additions, validateAdditions, withErrorAdditions} from '../scripts/error-additions.ts';
import {signatureBaseError, isRequestSealError} from '../src/errors/types.ts';

test('parse refusals have the declared reason and exact public source provenance', () => {
  validateAdditions(additions);
  assert.equal(additions.commit, '0ce86730c7c70e92efdabc9a3b4867b90fc67053');
  const error = signatureBaseError('malformed');
  assert.ok(isRequestSealError(error));
  assert.deepEqual(error, {kind: 'signature_base', reason: 'malformed'});
  assert.ok(Object.isFrozen(error));
  const modified = structuredClone(additions);
  modified.sources[0]!.body += '\n';
  assert.throws(() => validateAdditions(modified), /pinned Git blob/);
});

test('error additions are idempotent and refuse a conflicting rule', () => {
  const base = JSON.parse(readFileSync(new URL('./fixtures/elixir-reasons-511fed1.json', import.meta.url), 'utf8'));
  const once = withErrorAdditions(base);
  assert.deepEqual(withErrorAdditions(once), once);
  once.entries.find((entry: {rule_id: string; reason: string}) => entry.rule_id === 'signature_base/malformed')!.reason = 'different';
  assert.throws(() => withErrorAdditions(once), /Conflicting/);
  assert.equal(base.entries.some((entry: {rule_id: string}) => entry.rule_id === 'signature_base/malformed'), false);
});
