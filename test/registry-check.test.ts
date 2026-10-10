import test from 'node:test';
import assert from 'node:assert/strict';
import {isUnpublished} from '../scripts/registry-check.ts';
test('registry unpublished responses accept npm stdout and stderr E404 only', () => {
  assert.equal(isUnpublished({stdout: '{"error":{"code":"E404","summary":"Not Found"}}', stderr: ''}), true);
  assert.equal(isUnpublished({stdout: '', stderr: 'npm error code E404\nnpm error 404 Not Found - GET https://registry.npmjs.org/@request-seal%2fcore\n'}), true);
  for (const failure of [{stdout: '{"error":{"code":"E404"}}', stderr: 'npm error code E401\n'}, {stdout: '{"error":{"code":"E401"}}', stderr: ''}, {stdout: '', stderr: 'npm error code E401\n'}, {stdout: '', stderr: 'arbitrary E404 text'}, {stdout: 'garbled', stderr: ''}, {stdout: '', stderr: 'npm error code E404\nnpm error code ECONNRESET\n'}]) assert.equal(isUnpublished(failure), false);
});
