import test from 'node:test';
import assert from 'node:assert/strict';
import * as tls from 'node:tls';
import {Discovery, DiscoverySource} from '../src/discovery/node.ts';
import {DiscoverySource as CoreSource} from '../src/discovery/index.ts';

test('unavailable or permission-denied system roots produce a bounded source rejection', async () => {
  let available = false, denied = false;
  try {available = typeof tls.getCACertificates === 'function' && tls.getCACertificates('system').length > 0;} catch {denied = true;}
  if (process.env.REQUEST_SEAL_EXPECT_DENIED_ROOTS === '1') {
    assert.equal(denied, true, 'The dedicated CI step must execute the denied-roots branch');
    console.log('Denied system roots: transport_unavailable is required for source creation and fetch');
  }
  const input = {type: 'jwks_uri', location: 'https://127.0.0.1/keys', cacerts: 'os', permittedAddresses: ['127.0.0.1']};
  const result = DiscoverySource.create(input);
  assert.equal(result.ok, available);
  if (!result.ok) assert.deepEqual(result.error, denied
    ? {kind: 'discovery', reason: 'transport_unavailable', retryable: false}
    : {kind: 'custody', reason: 'unsupported_format', retryable: false});
  if (denied) {
    const core = CoreSource.create(input); assert.ok(core.ok);
    const fetched = await Discovery.fetch(core.value);
    assert.equal(fetched.ok, false);
    if (!fetched.ok) assert.deepEqual(fetched.error, {kind: 'discovery', reason: 'transport_unavailable', retryable: false});
  }
});

test('OS trust permission classification preserves unrelated real TLS errors', async () => {
  const {systemCertificateError} = await import('../src/discovery/node-trust.ts');
  let actual: unknown;
  try {tls.getCACertificates('invalid' as 'system');} catch (error) {actual = error;}
  assert.ok(actual instanceof Error, 'The real TLS API must reject an invalid store');
  assert.throws(() => systemCertificateError(actual), error => error === actual);
});

test('a trust-store denial terminates the address retry loop unchanged', async () => {
  const {allowConnectionRetry} = await import('../src/discovery/node-connection.ts');
  const {discoveryError} = await import('../src/errors/types.ts');
  const denial = discoveryError('transport_unavailable');
  assert.throws(() => allowConnectionRetry(denial), error => error === denial);
  assert.doesNotThrow(() => allowConnectionRetry(discoveryError('connect_failed')));
  assert.doesNotThrow(() => allowConnectionRetry(discoveryError('tls_failed')));
});
