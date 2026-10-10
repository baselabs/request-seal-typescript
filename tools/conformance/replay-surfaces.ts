import {decoded} from './wire.ts';
import {Replay, createMemoryStore, withDeadline, ok, Custody, PublicKey, Message, Policy, sign, verify} from '../../src/index.ts';
import type {ReplayClaim, ReplayStore, KeyHandle, Result, SigningAlgorithm} from '../../src/index.ts';
import type {Surface} from './loader.ts';
function value<T>(r: Result<T>): T {if (!r.ok) throw r.error; return r.value;}
export const replaySurface: Surface = async (m, resources) => {
  let handle: KeyHandle | undefined;
  try {
    const i = decoded(m.inputs, resources);
    const context = withDeadline(); if (!context.ok) return context;
    if (i.operation === 'sweep') {
      if (!Object.keys(i).every(k => ['operation', 'now'].includes(k))) return {ok: false, loaderReason: 'invalid_manifest'};
      const store = createMemoryStore({maxEntries: 1}); if (!store.ok) return store;
      const result = await Replay.sweep(store.value, i.now, context.value);
      return result.ok ? ok({valid: true as const}) : result;
    }
    if (!Object.keys(i).every(k => ['namespace', 'key', 'created', 'expires', 'max_age', 'skew', 'row'].includes(k)) || typeof i.row !== 'boolean') return {ok: false, loaderReason: 'invalid_manifest'};
    const text = (path: string) => new TextDecoder().decode(value(resources.read(path)));
    handle = value(await Custody.local('ed25519', text('sources/rfc9421/keys/ed25519_private.pem')));
    const publicKey = value(await PublicKey.import(text('sources/rfc9421/keys/ed25519_public.pem'), 'pem'));
    const message = value(await Message.request('GET', 'https://example.com/', [], null));
    const signatureInput = `("@method");created=${i.created};nonce="corpus"` + (i.expires === null ? '' : `;expires=${i.expires}`);
    const signer = handle;
    const signed = await sign(message, {label: 's', algorithm: 'ed25519', signatureInput}, (a: SigningAlgorithm,b: Uint8Array,c = context.value) => signer.sign(a,b,c));
    if (!signed.ok) return signed;
    const memory = value(createMemoryStore({maxEntries: 16}));
    const received: ReplayClaim[] = [];
    const store: ReplayStore = {
      claim: async (claim, c) => {const result = await memory.claim(claim, c); if (result.ok && result.value === 'claimed') received.push(claim); return result;},
      sweep: (now, c) => memory.sweep(now, c),
    };
    const policy = Policy.create({
      algorithms: ['ed25519'], components: '()', keyResolver: () => ok({algorithm: 'ed25519', key: publicKey}),
      freshness: {clock: () => decoded(m.now, resources), skew: i.skew, maxAge: i.max_age, requireExpires: i.expires !== null},
      content: 'not_required', replay: {identifier: 'nonce', namespace: i.namespace, commitment: () => ok(i.key), store, timeoutMs: 5000},
    });
    if (!policy.ok) return policy;
    const verified = await verify(signed.value, policy.value, {label: 's', context: context.value});
    if (!verified.ok) return verified;
    if (received.length !== 1 || verified.value.replay === 'not_required' || verified.value.replay.retainUntil !== received[0]!.retainUntil) return {ok: false, loaderReason: 'invalid_manifest'};
    const row = Replay.row(received[0]); if (!row.ok) return row;
    return ok({facts: {retain_until: {int: verified.value.replay.retainUntil.toString()}, ...(i.row ? {row: row.value} : {})}});
  } catch {return {ok: false, loaderReason: 'invalid_manifest'};}
  finally {await handle?.release();}
};
