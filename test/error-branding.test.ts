import test from 'node:test';
import assert from 'node:assert/strict';
import * as api from '../src/index.ts';
import {adapterError, custodyError, cryptoError} from '../src/errors/types.ts';
test('error Results reject foreign payloads', () => {
  for (const foreign of [null, {}, {kind: 'custody', reason: 'invalid_options'}, new Error('private')]) assert.throws(() => api.err(foreign as never), TypeError);
  assert.equal(api.err(custodyError('invalid_options')).ok, false);
});
test('adapter source validation rejects foreign and incompatible errors', () => {
  for (const foreign of [{}, cryptoError('invalid_key')]) assert.throws(() => adapterError('invalid_request', 'req', 'sign', 1, foreign as never), TypeError);
  assert.equal(adapterError('invalid_request', 'req', 'sign', 1).source, null);
  const source = custodyError('invalid_options');
  assert.equal(adapterError('invalid_request', 'req', 'sign', 1, source).source, source);
});
test('error branding rejects foreign Results after intrinsic replacement', () => {
  const original = WeakSet.prototype.has;
  const genuine = custodyError('invalid_options');
  WeakSet.prototype.has = () => true;
  try {
    assert.throws(() => api.err({kind: 'custody', reason: 'invalid_options', retryable: false} as api.CustodyError), TypeError);
    assert.equal(api.err(genuine).ok, false);
  } finally {WeakSet.prototype.has = original;}
});
