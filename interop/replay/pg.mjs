import pg from 'pg';
export const pool = url => new pg.Pool({connectionString: url, max: 8, connectionTimeoutMillis: 5000});
export const query = (pool, observe = () => {}) => async (sql, params, context) => {
  if (context.signal.aborted) { const error = new Error('Canceled query'); error.name = 'AbortError'; throw error; }
  observe(sql, params, context);
  const result = await pool.query({text: sql, values: [...params], query_timeout: Math.max(1, Math.ceil(context.remainingMs))});
  return result.rowCount;
};
