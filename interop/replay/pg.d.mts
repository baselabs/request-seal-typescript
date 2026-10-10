import type {Query} from '../../src/replay/postgres.ts';
export interface Connection {
  query(sql: string, params?: readonly unknown[]): Promise<{rowCount: number; rows: Record<string, any>[]} >;
  release(): void;
}
export interface Pool {
  query(sql: string, params?: readonly unknown[]): Promise<{rowCount: number; rows: Record<string, any>[]} >;
  connect(): Promise<Connection>;
  end(): Promise<void>;
}
export function pool(url: string): Pool;
export function query(pool: Pool, observe?: (sql: string, params: readonly string[], context: {signal: AbortSignal; remainingMs: number}) => void): Query;
