import type {BatchCheck} from './batch.ts';

export type RuntimeLimit = Readonly<{id: string; items: readonly number[]; observed: string; reason: string; platforms?: readonly string[]}>;
export type RuntimeLimits = Readonly<Record<string, Readonly<Record<string, readonly RuntimeLimit[]>>>>;
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function platformName(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const [os, arch, extra] = value.split('-');
  return extra === undefined && ['aix', 'android', 'darwin', 'freebsd', 'haiku', 'linux', 'openbsd', 'sunos', 'win32'].includes(os!)
    && ['arm', 'arm64', 'ia32', 'loong64', 'mips', 'mipsel', 'ppc', 'ppc64', 'riscv64', 's390', 's390x', 'x64'].includes(arch!);
}
/** Consumer policy only: validate the whole table, then select version and platform. */
export function selectRuntimeLimits(table: unknown, versions: Readonly<Record<string, string | undefined>>, platform = `${process.platform}-${process.arch}`): readonly RuntimeLimit[] {
  if (!record(table)) throw new Error('invalid_runtime_limits');
  for (const [runtime, releases] of Object.entries(table)) {
    if (!['bun', 'deno', 'node'].includes(runtime) || !record(releases)) throw new Error('invalid_runtime_limits');
    for (const [version, entries] of Object.entries(releases)) {
      if (!/^\d+\.\d+\.\d+$/.test(version) || !Array.isArray(entries)) throw new Error('invalid_runtime_limits');
      const seen = new Set<string>();
      for (const entry of entries) {
        if (!record(entry) || !['id,items,observed,reason', 'id,items,observed,platforms,reason'].includes(Object.keys(entry).sort().join(',')) || typeof entry.id !== 'string' || !/^[a-z_]+\/[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(entry.id) || !Array.isArray(entry.items) || !entry.items.length || typeof entry.observed !== 'string' || !entry.observed.trim() || typeof entry.reason !== 'string' || !entry.reason.trim()) throw new Error('invalid_runtime_limits');
        if (Object.hasOwn(entry, 'platforms') && (!Array.isArray(entry.platforms) || !entry.platforms.length || !entry.platforms.every(platformName) || new Set(entry.platforms).size !== entry.platforms.length)) throw new Error('invalid_runtime_limits');
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
    ? (releases[version] as readonly RuntimeLimit[]).filter(entry => !entry.platforms || entry.platforms.includes(platform)) : [];
}

export function classifyRuntimeResult(limits: readonly RuntimeLimit[], id: string, item: string, result: BatchCheck): 'executed' | 'runtime_limited' | 'stale_runtime_limitation' | 'outcome_mismatch' {
  const limit = limits.find(entry => entry.id === id && entry.items.some(n => String(n) === item));
  if (!limit) return result.ok ? 'executed' : 'outcome_mismatch';
  if (result.ok) return 'stale_runtime_limitation';
  return result.expected === 'valid' && record(result.actual) && Object.keys(result.actual).join(',') === 'rule_id' && result.actual.rule_id === limit.observed
    ? 'runtime_limited' : 'outcome_mismatch';
}
