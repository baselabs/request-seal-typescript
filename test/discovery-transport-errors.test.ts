import test from 'node:test';
import assert from 'node:assert/strict';
import {sslError} from '../src/discovery/support.ts';
// Error-code inputs exercise the transport mapping, not a replacement TLS peer.
test('TLS failure codes follow the reference transport allowlist and retryability', () => {
  for (const code of ['ECONNREFUSED', 'ENETUNREACH', 'EHOSTUNREACH', 'CLOSED', 'EADDRNOTAVAIL', 'ETIMEDOUT', 'ECONNRESET', 'EPIPE', 'EPROTO', 'ERR_TLS_CERT_ALTNAME_INVALID', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNKNOWN']) {
    const connect = ['ECONNREFUSED', 'ENETUNREACH', 'EHOSTUNREACH', 'ECONNRESET', 'EPIPE', 'EADDRNOTAVAIL'].includes(code);
    assert.deepEqual(sslError({code}), {kind: 'discovery', reason: connect ? 'connect_failed' : 'tls_failed', retryable: connect}, code);
  }
  for (const input of [null, {}, {code: 1}, new Error('private')]) assert.deepEqual(sslError(input), {kind: 'discovery', reason: 'tls_failed', retryable: false});
});
