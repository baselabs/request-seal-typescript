import { snapshotOptions } from '../brand.ts';
import { replayError } from '../errors/types.ts';
import { ok, err, type Result } from '../result.ts';
import type { ReplayStore } from '../replay-port.ts';
import { isReplayClaim, hex, validSeconds } from './claim.ts';
import { createReplayStore, storeOperation } from './store.ts';
/** Atomic within one isolate. No timers, eviction on claim, persistence, or cross-isolate coordination. */
export function createMemoryStore(options: unknown): Result<ReplayStore> {
  try {
    const r = snapshotOptions(options, ['maxEntries']);
    if (!r.ok || typeof r.value.maxEntries !== 'number' || !Number.isSafeInteger(r.value.maxEntries) || r.value.maxEntries < 1 || r.value.maxEntries > 10_000_000) return err(replayError('invalid_options'));
    const max = r.value.maxEntries, entries = new Map<string, number | bigint>();
    return createReplayStore({
      identity: 'memory',
      claim: (input, context) => {
        if (!isReplayClaim(input)) return Promise.resolve(err(replayError('invalid_claim')));
        return storeOperation(context, () => {
          const id = hex(input.namespace) + ':' + hex(input.key);
          if (entries.has(id)) return ok('already_claimed' as const);
          if (entries.size >= max) return err(replayError('store_full'));
          entries.set(id, input.retainUntil); return ok('claimed' as const);
        });
      },
      sweep: (now, context) => {
        if (!validSeconds(now)) return Promise.resolve(err(replayError('invalid_options')));
        return storeOperation(context, () => {
          let removed = 0;
          for (const [key, end] of entries) if (end <= now) { entries.delete(key); removed++; }
          return ok(removed);
        });
      },
    } satisfies ReplayStore);
  } catch { return err(replayError('invalid_options')); }
}
