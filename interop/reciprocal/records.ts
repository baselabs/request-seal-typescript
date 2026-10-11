import assert from 'node:assert/strict';

/** Public inputs and public JWK components only; custody material never enters the artifact. */
export function publicRecord(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(publicRecord);
  if (!value || typeof value !== 'object') return value;
  const out: Record<string, unknown> = Object.create(null);
  const privateFields = new Set(['secret', 'key', 'cek', 'd', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'stdout', 'stderr']);
  for (const [name, entry] of Object.entries(value)) {
    if (!privateFields.has(name)) out[name] = publicRecord(entry);
  }
  return out;
}

export function assertRejection(response: {accepted?: boolean; rule?: string}, expected: string) {
  assert.equal(response.accepted, false);
  assert.equal(response.rule, expected, 'the intended rule rejected the input');
}

export function runDate(now = new Date()) {
  return new Intl.DateTimeFormat('en-US', {month: 'long', day: 'numeric', year: 'numeric', timeZone: 'UTC'}).format(now);
}

export async function cleanupDatabase(db: {query(sql: string): Promise<unknown>; end(): Promise<unknown>}, table: string, original?: unknown) {
  let failure = original;
  try {await db.query(`DROP TABLE IF EXISTS "${table}"`);} catch (error) {failure ??= error;}
  finally {try {await db.end();} catch (error) {failure ??= error;}}
  if (failure !== undefined) throw failure;
}
