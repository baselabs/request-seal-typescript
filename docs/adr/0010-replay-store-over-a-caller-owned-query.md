<!-- Status: accepted · Kind: decision record · Updated: 2026-11-15 · Governed by: public API, compatibility contract, and cited decisions · Review when: the implementation or a governing decision changes -->

# 0010 — Run the PostgreSQL replay store over a caller-provided query
Status: Accepted

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

## Alternatives

1. **Depend on a PostgreSQL driver.** Turnkey setup. It adds a runtime dependency and a second
   holder of connection state.
2. **Advisory locks or transactions inside the library.** More control. A conflict-free insert
   is already atomic, and the library would have to manage a session.
3. **A generic key-value port only.** Smaller surface. Applications would each write the claim
   SQL and its row-count rules, which is where replay bugs occur.

## Consequences

The application chooses the driver and pool and passes the query function. A commit that lands
after the deadline is indeterminate, and the store says so rather than guessing. The same table
shape is claimed by both implementations in the reciprocal exchange
([0008](0008-reciprocal-exchange-with-the-published-elixir-package.md)).
