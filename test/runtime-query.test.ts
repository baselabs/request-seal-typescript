import test from 'node:test';
import assert from 'node:assert/strict';
import {Custody} from '../src/index.ts';
import {signRequest} from '../src/adapters/fetch/index.ts';
import {runtime} from '../src/adapters/fetch/runtime.ts';

test('empty-query Fetch signing follows the measured Node major boundary', async () => {
  const owner = await Custody.local('hmac-sha256', {hmac: crypto.getRandomValues(new Uint8Array(32))});
  assert.ok(owner.ok);
  try {
    const result = await signRequest(new Request('http://127.0.0.1/empty?'),
      {label: 'sig', components: '("@request-target")', algorithm: 'hmac-sha256', expiresIn: 60}, owner.value);
    const refused = runtime.startsWith('node:') && Number(runtime.slice(5).split('.')[0]) < 24;
    assert.equal(result.ok, !refused);
    if (!result.ok) {assert.equal(result.error.kind, 'adapter'); assert.equal(result.error.reason, 'invalid_request');}
    else assert.equal(result.value.message.rawTarget, '/empty?');
  } finally {await owner.value.release();}
});
