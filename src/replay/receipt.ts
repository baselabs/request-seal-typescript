import { snapshotOptions } from '../brand.ts';
import { replayError } from '../errors/types.ts';
import { ok, err, type Result } from '../result.ts';
import type { ReplayReceipt } from '../replay-port.ts';
import { validRetention } from './claim.ts';
// Verification produces safe-number ends; share the claim bounds for those ends.
const receipts = new WeakSet<object>();
export function isReplayReceipt(value: unknown): value is ReplayReceipt {
  return typeof value === 'object' && value !== null && receipts.has(value);
}
export function createReceipt(input: unknown): Result<ReplayReceipt> {
  try {
    const r = snapshotOptions(input, ['store', 'retainUntil']);
    if (!r.ok || typeof r.value.store !== 'string' || !/^[\x21-\x7e]{1,256}$/.test(r.value.store) || typeof r.value.retainUntil !== 'number' || !validRetention(r.value.retainUntil)) return err(replayError('invalid_options'));
    const receipt = Object.freeze({store: r.value.store, retainUntil: r.value.retainUntil});
    receipts.add(receipt); return ok(receipt);
  } catch { return err(replayError('invalid_options')); }
}
