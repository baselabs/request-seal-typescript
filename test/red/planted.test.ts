import test from 'node:test';
import assert from 'node:assert/strict';
test('planted lane failure must produce a nonzero exit', () => { assert.fail('Intentional red proof: this lane must reject a failing test'); });
