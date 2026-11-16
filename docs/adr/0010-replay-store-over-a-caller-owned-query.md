# 0010 — Run the PostgreSQL replay store over a caller-provided query

## Context

Replay protection needs one atomic claim per nonce in a shared store. Bundling a PostgreSQL
client would break the zero-dependency rule ([0002](0002-zero-runtime-dependencies-and-webcrypto.md))
and would make the library own pools, transactions and connection lifetimes that applications
already manage.

## Decision

1. `@request-seal/core/replay-postgres` takes a caller-provided, autocommit `Query` function
   that returns only an affected-row count; the library retains no connection
   (`src/replay/postgres.ts:8`). No database, pool, transaction or timer starts in
   `createStore` (`src/replay/postgres.ts:31`).
2. A claim is one `INSERT ... ON CONFLICT (namespace, key) DO NOTHING`
   (`src/replay/postgres.ts:48`). One affected row is `claimed`, zero is `already_claimed`,
   and any other count is `store_failed`.
3. Failures map to a closed set: abort and timeout codes to `store_timeout`, connection
   refusal and unreachable hosts to `store_unavailable`, anything else to `store_failed`
   (`src/replay/postgres.ts:21`). Backend diagnostics never escape.
4. `ddl(table)` and `ddlIndex(table)` return the table and retention-index SQL for a validated
   name (`src/replay/postgres.ts:12-19`); a sweep deletes rows whose `retain_until` has passed
   (`src/replay/postgres.ts:54`).

## Consequences

The application chooses the driver and pool and passes the query function. A commit that lands
after the deadline is indeterminate, and the store says so rather than guessing. The same table
shape is claimed by both implementations in the reciprocal exchange
([0008](0008-reciprocal-exchange-with-the-published-elixir-package.md)).
