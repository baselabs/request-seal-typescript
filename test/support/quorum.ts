import assert from 'node:assert/strict';
import * as api from '../../src/index.ts';
import { inner } from '../../src/signature-fields.ts';
export const value = <T>(r: api.Result<T>): T => { assert.equal(r.ok, true, JSON.stringify(r)); return r.value; };
export function policy(extra: Record<string, unknown> = {}) {
  return value(api.Policy.create({algorithms: ['hmac-sha256'], components: '()', keyResolver: () => api.ok(null), freshness: 'not_evaluated', content: 'not_required', replay: 'not_required', ...extra}));
}
export function quorum(slots: unknown[], extra: Record<string, unknown> = {}) {
  return value(api.Quorum.create({mode: 'any', unit: 'keys', slots, unexpected: 'ignore', invalid: 'ignore', ...extra}));
}
export const input = (wire = '()') => value(inner(wire));
// Real local signatures exercise policy composition, not external conformance.
export async function signedPool(n: number) {
  const base = value(await api.Message.request('POST', 'https://example.com/a', [], 'hello'));
  const handles: api.KeyHandle[] = [];
  const fields = [...base.fields];
  try {
    for (let i = 0; i < n; i++) {
      const secret = crypto.getRandomValues(new Uint8Array(32));
      const h = value(await api.Custody.local('hmac-sha256', {hmac: secret, identity: `key${i}`}));
      handles.push(h);
      const signed = value(await api.sign(base, {label: `s${i}`, signatureInput: `("@method");keyid="${i}";alg="hmac-sha256"`, algorithm: 'hmac-sha256'}, (algorithm: api.SigningAlgorithm, data: Uint8Array, context = value(api.withDeadline())) => h.sign(algorithm, data, context)));
      fields.push(...signed.fields.slice(base.fields.length));
    }
    let calls = 0;
    const p = policy({keyResolver: ({keyid}: {keyid: string | null}) => { calls++; return api.ok({algorithm: 'hmac-sha256', key: handles[Number(keyid)]!}); }});
    return {message: value(api.Message.create({...base, fields})), policy: p, calls: () => calls, release: async () => { for (const h of handles) await h.release(); }};
  } catch (e) { for (const h of handles) await h.release(); throw e; }
}
