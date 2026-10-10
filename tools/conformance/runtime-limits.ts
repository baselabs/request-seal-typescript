import type {BatchCheck} from './batch.ts';

export type RuntimeLimit = Readonly<{id: string; items: readonly number[]; observed: string; reason: string}>;
export type RuntimeLimits = Readonly<Record<string, Readonly<Record<string, readonly RuntimeLimit[]>>>>;
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
/** Consumer policy only: validate once, then select by exact runtime version. */
export function selectRuntimeLimits(table: unknown, versions: Readonly<Record<string, string | undefined>>): readonly RuntimeLimit[] {
  if (!record(table)) throw new Error('invalid_runtime_limits');
  for (const [runtime, releases] of Object.entries(table)) {
    if (!['bun', 'deno', 'node'].includes(runtime) || !record(releases)) throw new Error('invalid_runtime_limits');
    for (const [version, entries] of Object.entries(releases)) {
      if (!/^\d+\.\d+\.\d+$/.test(version) || !Array.isArray(entries)) throw new Error('invalid_runtime_limits');
      const seen = new Set<string>();
      for (const entry of entries) {
        if (!record(entry) || Object.keys(entry).sort().join(',') !== 'id,items,observed,reason' || typeof entry.id !== 'string' || !/^[a-z_]+\/[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(entry.id) || !Array.isArray(entry.items) || !entry.items.length || typeof entry.observed !== 'string' || !entry.observed.trim() || typeof entry.reason !== 'string' || !entry.reason.trim()) throw new Error('invalid_runtime_limits');
        for (const item of entry.items) {
          const key = `${entry.id}/${item}`;
          if (!Number.isSafeInteger(item) || item < 1 || seen.has(key)) throw new Error('invalid_runtime_limits');
          seen.add(key);
        }
      }
    }
  }
  // Bun and Deno also expose a Node compatibility version; their own identity wins.
  const runtime = versions.bun ? 'bun' : versions.deno ? 'deno' : 'node';
  const version = versions[runtime];
  const releases = table[runtime];
  return version && record(releases) && Object.hasOwn(releases, version)
    ? releases[version] as readonly RuntimeLimit[] : [];
}

export function classifyRuntimeResult(limits: readonly RuntimeLimit[], id: string, item: string, result: BatchCheck): 'executed' | 'runtime_limited' | 'stale_runtime_limitation' | 'outcome_mismatch' {
  const limit = limits.find(entry => entry.id === id && entry.items.some(n => String(n) === item));
  if (!limit) return result.ok ? 'executed' : 'outcome_mismatch';
  if (result.ok) return 'stale_runtime_limitation';
  return result.expected === 'valid' && record(result.actual) && Object.keys(result.actual).join(',') === 'rule_id' && result.actual.rule_id === limit.observed
    ? 'runtime_limited' : 'outcome_mismatch';
}
