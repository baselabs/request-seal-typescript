import { snapshotOptions } from '../brand.ts';
import { remainingMs, type Context } from '../context.ts';
import { replayError, type ReplayError } from '../errors/types.ts';
import { ok, err, type Result } from '../result.ts';
import type { ReplayStore } from '../replay-port.ts';
import { claimRow, isReplayClaim, validSeconds } from './claim.ts';
import { createReplayStore, storeOperation } from './store.ts';
/** Caller-owned, autocommit query. Affected-row count only; no connection is retained by the library. */
export type Query = (sql: string, params: readonly string[], context: Readonly<{signal: AbortSignal; remainingMs: number}>) => Promise<number>;
const tableName = (value: unknown): value is string => typeof value === 'string' && value.length >= 1 && value.length <= 63 && /^[a-z][a-z0-9_]*$/.test(value);
/** Validate a table name and return replay-store creation SQL. */
export function ddl(table: unknown): Result<string> {
  return tableName(table) ? ok(`CREATE TABLE "${table}" (namespace bytea NOT NULL, key bytea NOT NULL, retain_until bigint NOT NULL, PRIMARY KEY (namespace, key))`) : err(replayError('invalid_store'));
}
function failure(error: unknown): ReplayError {
  try {
    if (error !== null && typeof error === 'object') {
      const code: unknown = Reflect.get(error, 'code'), name: unknown = Reflect.get(error, 'name');
      if (name === 'AbortError' || code === 'ABORT_ERR' || code === 'ETIMEDOUT' || code === '57014') return replayError('store_timeout');
      if (typeof code === 'string' && ['ECONNREFUSED', 'ENOTFOUND', 'EHOSTUNREACH', 'ENETUNREACH'].includes(code)) return replayError('store_unavailable');
    }
  } catch { /* Backend diagnostics never escape. */ }
  return replayError('store_failed');
}
/** No database, pool, transaction, or timer starts here. Late commits remain indeterminate. */
export function createStore(options: unknown): Result<ReplayStore> {
  try {
    const r = snapshotOptions(options, ['query', 'table']);
    if (!r.ok || typeof r.value.query !== 'function' || !tableName(r.value.table)) return err(replayError('invalid_store'));
    const query = r.value.query as Query, table = r.value.table;
    const execute = (sql: string, params: readonly string[], context: Context) => storeOperation(context, async c => {
      try {
        const count = await query(sql, params, Object.freeze({signal: c.signal, remainingMs: remainingMs(c)}));
        return typeof count === 'number' && Number.isSafeInteger(count) && count >= 0 ? ok(count) : err(replayError('store_failed'));
      } catch (e) {return err(failure(e));}
    });
    return createReplayStore({
      identity: 'postgres',
      claim: async (input, context) => {
        if (!isReplayClaim(input)) return err(replayError('invalid_claim'));
        const row = claimRow(input); if (!row.ok) return row;
        const count = await execute(`INSERT INTO "${table}" (namespace, key, retain_until) VALUES (decode($1,'hex'), decode($2,'hex'), $3::bigint) ON CONFLICT (namespace, key) DO NOTHING`, row.value, context);
        if (!count.ok) return count;
        return count.value === 1 ? ok('claimed' as const) : count.value === 0 ? ok('already_claimed' as const) : err(replayError('store_failed'));
      },
      sweep: (now, context) => {
        if (!validSeconds(now)) return Promise.resolve(err(replayError('invalid_options')));
        return execute(`DELETE FROM "${table}" WHERE retain_until <= $1::bigint`, Object.freeze([now.toString()]), context);
      },
    } satisfies ReplayStore);
  } catch {return err(replayError('invalid_store'));}
}
