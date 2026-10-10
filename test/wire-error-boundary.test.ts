import test from 'node:test';
import assert from 'node:assert/strict';
import { StructuredFields, Message, SignatureBase, isRequestSealError } from '../src/index.ts';
function payload(kind: string): object {
  return { kind, reason: 'syntax', callerBytes: 'error-boundary-canary' };
}
test('caller-thrown objects never become library errors', async () => {
  const m = await Message.request('GET', 'https://example.com/', [], null);
  assert.ok(m.ok);
  const sf = StructuredFields.serialize({
    get kind() {
      throw payload('structured_fields');
    },
  });
  const signature = SignatureBase.build(m.value, {
    get kind() {
      throw payload('signature_base');
    },
  });
  const pair: unknown[] = [];
  Object.defineProperty(pair, 0, {
    get() {
      throw payload('message');
    },
  });
  pair.length = 2;
  const message = await Message.request('GET', 'https://example.com/', [pair], null);
  for (const result of [sf, signature, message]) {
    assert.ok(!result.ok);
    assert.ok(isRequestSealError(result.error));
    assert.equal(JSON.stringify(result.error).includes('error-boundary-canary'), false);
    assert.equal(Object.keys(result.error).sort().join(','), 'kind,reason');
  }
});
test('throwing error discriminants remain bounded results', async () => {
  const hostile = {
    get kind() {
      throw new Error('error-boundary-canary');
    },
  };
  assert.doesNotThrow(() =>
    StructuredFields.serialize({
      get kind() {
        throw hostile;
      },
    }),
  );
  const m = await Message.request('GET', 'https://example.com/', [], null);
  assert.ok(m.ok);
  assert.doesNotThrow(() =>
    SignatureBase.build(m.value, {
      get kind() {
        throw hostile;
      },
    }),
  );
});
