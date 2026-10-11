import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import * as Seal from '../src/index.ts';
import {DiscoverySource} from '../src/discovery/index.ts';
type DenoInspect = {inspect(value: unknown, options?: {colors: boolean; depth: number}): string};
const deno = (globalThis as unknown as {Deno?: DenoInspect}).Deno;
function value<T>(r: Seal.Result<T>): T {assert.equal(r.ok, true, JSON.stringify(r)); if (!r.ok) throw new Error('rejected'); return r.value;}

test('Deno inspection prints the redacted view of every inspectable value', {skip: !deno}, async () => {
  const options = {colors: false, depth: 10};
  const handle = value(await Seal.Custody.local('ed25519', await readFile('test/fixtures/upstream/crypto/ed25519_private.pem', 'utf8')));
  try {
    const publicKey = value(await handle.publicKey());
    const cases: [string, unknown, unknown][] = [
      ['KeyHandle', handle, JSON.parse(JSON.stringify(handle))],
      ['PublicKey', publicKey, JSON.parse(JSON.stringify(publicKey))],
      ['KeyIdentity', value(Seal.KeyIdentity.fromPublic(publicKey)), JSON.parse(JSON.stringify(value(Seal.KeyIdentity.fromPublic(publicKey))))],
      ['DiscoverySource', value(DiscoverySource.create({type: 'jwks_uri', location: 'https://agent.example/keys'})), {kind: 'DiscoverySource', type: 'jwks_uri'}],
      ['WebBotAuthPolicy', value(Seal.WebBotAuth.Policy.create({
        algorithms: ['ed25519'], agents: (_request: unknown) => Seal.ok(null), cache: null,
        freshness: {clock: () => 100, maxAge: null, skew: 0}, content: 'not_required', replay: 'not_required',
      })), null],
    ];
    for (const [name, inspected, expected] of cases) {
      const printed = deno!.inspect(inspected, options);
      assert.notEqual(printed, '[object Object]', name);
      if (expected !== null) assert.equal(printed, deno!.inspect(expected, options), name);
      assert.doesNotMatch(printed, /BEGIN|PRIVATE|"d":|agents|clock/, name);
    }
  } finally {await handle.release();}
});
