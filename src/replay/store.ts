import { snapshotOptions } from '../brand.ts';
import { isContext, run, remainingMs, type Context } from '../context.ts';
import { isRequestSealError, replayError } from '../errors/types.ts';
import { ok, err, type Result } from '../result.ts';
import type { ReplayStore, ReplayClaim } from '../replay-port.ts';
import { isReplayClaim, validSeconds } from './claim.ts';
const stores = new WeakSet<object>();
/** Check the private brand of a replay store. */
export function isReplayStore(value: unknown): value is ReplayStore {
  return typeof value === 'object' && value !== null && stores.has(value);
}
/** Normalize caller ports once, binding own methods to the caller's receiver. */
export function createReplayStore(input: unknown): Result<ReplayStore> {
  try {
    const r = snapshotOptions(input, ['identity', 'claim', 'sweep']);
    if (!r.ok || typeof r.value.claim !== 'function' || typeof r.value.sweep !== 'function' || Object.hasOwn(r.value, 'identity') && (typeof r.value.identity !== 'string' || !/^[\x21-\x7e]{1,256}$/.test(r.value.identity))) return err(replayError('invalid_store'));
    const store = Object.freeze({identity: typeof r.value.identity === 'string' ? r.value.identity : 'caller', claim: (r.value.claim as ReplayStore['claim']).bind(input), sweep: (r.value.sweep as ReplayStore['sweep']).bind(input)});
    stores.add(store); return ok(store);
  } catch { return err(replayError('invalid_store')); }
}
export async function storeOperation<T>(context: Context, operation: (c: Context) => Promise<Result<T>> | Result<T>): Promise<Result<T>> {
  if (!isContext(context)) return err(replayError('invalid_options'));
  const r = await run(context, c => remainingMs(c) > 0 ? operation(c) : err(replayError('store_timeout')));
  return !r.ok && r.error.kind === 'custody' ? err(replayError(r.error.reason === 'deadline_exceeded' ? 'store_timeout' : 'store_failed')) : r;
}
function storeFailure(r: Result<Readonly<Partial<Record<'ok' | 'value' | 'error', unknown>>>>): Result<never> {
  if (r.ok && Object.keys(r.value).length === 2 && r.value.ok === false) {
    const error = r.value.error;
    if (isRequestSealError(error) && error.kind === 'replay') return err(error);
    switch (error) {
      case 'unavailable': return err(replayError('store_unavailable'));
      case 'timeout': return err(replayError('store_timeout'));
      case 'full': return err(replayError('store_full'));
      case 'failure': return err(replayError('store_failed'));
    }
  }
  return err(replayError('store_failed'));
}
export async function claim(store: unknown, input: unknown, context: Context): Promise<Result<'claimed' | 'already_claimed'>> {
  const s = isReplayStore(store) ? ok(store) : createReplayStore(store);
  if (!s.ok) return s;
  if (!isReplayClaim(input)) return err(replayError('invalid_claim'));
  return storeOperation(context, async c => {
    const raw = await s.value.claim(input as ReplayClaim, c);
    const r = snapshotOptions(raw, ['ok', 'value', 'error']);
    return r.ok && r.value.ok === true && Object.keys(r.value).length === 2 && (r.value.value === 'claimed' || r.value.value === 'already_claimed') ? ok(r.value.value) : storeFailure(r);
  });
}
export async function sweep(store: unknown, now: unknown, context: Context): Promise<Result<number>> {
  const s = isReplayStore(store) ? ok(store) : createReplayStore(store);
  if (!s.ok) return s;
  if (!validSeconds(now)) return err(replayError('invalid_options'));
  return storeOperation(context, async c => {
    const raw = await s.value.sweep(now, c);
    const r = snapshotOptions(raw, ['ok', 'value', 'error']);
    return r.ok && r.value.ok === true && Object.keys(r.value).length === 2 && typeof r.value.value === 'number' && Number.isSafeInteger(r.value.value) && r.value.value >= 0 ? ok(r.value.value) : storeFailure(r);
  });
}
