type Connection = {query(sql: string): Promise<unknown>; release(): void};
type Database = {query(sql: string): Promise<unknown>; end(): Promise<unknown>};

/** Attempt every cleanup operation; a test-body failure retains precedence. */
export async function cleanupReplay(options: {
  peer?: {stop(): Promise<unknown>}; control: Connection; claimant: Connection;
  db: Database; table: string; bodyFailed: boolean;
}) {
  const {peer, control, claimant, db, table, bodyFailed} = options;
  let failed = false, failure: unknown;
  const attempt = async (operation: () => unknown) => {
    try {await operation();} catch (error) {if (!failed) {failed = true; failure = error;}}
  };
  await attempt(() => peer?.stop());
  for (const connection of [control, claimant]) {
    await attempt(() => connection.query('SELECT pg_advisory_unlock_all()'));
    await attempt(() => connection.release());
  }
  await attempt(() => db.query(`DROP TABLE IF EXISTS "${table}"`));
  await attempt(() => db.end());
  if (failed && !bodyFailed) throw failure;
}
