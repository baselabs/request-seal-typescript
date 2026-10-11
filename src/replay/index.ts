import { claim, sweep, createReplayStore } from './store.ts';
import { retainUntil, claimRow } from './claim.ts';
export { Claim, createClaim, isReplayClaim } from './claim.ts';
export { isReplayReceipt } from './receipt.ts';
export { createReplayStore, isReplayStore } from './store.ts';
/** Atomic claim, expiration sweep, and retention helper operations. */
export const Replay = Object.freeze({
  /** Atomically reserve the claim or report that it was already claimed. */
  claim,
  /** Remove expired replay claims and return the removal count. */
  sweep,
  /** Compute the retention deadline from validated freshness facts. */
  retainUntil,
  /** Encode a branded claim as namespace, key, and retention database values. */
  row: claimRow,
  /** Validate and brand a caller-owned atomic replay store. */
  store: createReplayStore});
