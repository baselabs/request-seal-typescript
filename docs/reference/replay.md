**Status:** maintained · **Kind:** reference · **Updated:** October 10, 2026 · **Governed by:** ADR 0005 and the shared v0.4.0 conformance corpus · **Review when:** replay contracts, retention bounds, or driver interfaces change

# Replay protection

Required replay is an explicit Policy choice: `{identifier: "nonce", namespace,
commitment, store, timeoutMs}` with bounded freshness. Verification authenticates
all required layers before calling commitment once and claiming once, last.
Commitment receives frozen `{identifier, algorithm, keyid, tag, created, expires,
profile}` without the signature label. Return `Result<Uint8Array>` with 1–256
bytes. Namespace also contains 1–256 bytes. A namespace must use one freshness
bound; duplicate claims never extend retention. The caller defines security scope
and uniqueness. For interoperability, independently encode the same exact UTF-8
identifier and SHA-256 it in both languages, with identical namespace bytes. This
recipe suits only callers whose authenticated identifier defines their entire
uniqueness scope; include additional authenticated facts when their scope needs them.

The library passes the profile to commitment but does not prefix the namespace
or commitment output. This matches the reference: a nonce-only commitment in a
shared namespace collides across generic verification and Web Bot Auth. Separate
profiles with distinct caller namespaces or encode the profile name and revision
inside the commitment. For a scope defined by authenticated nonces, this recipe
works with both fact shapes and separates equal nonces in the same namespace:

```js
// Profile-aware commitment; import ok from @request-seal/core.
const commitment = async (facts) => {
  const identifiers = "signatures" in facts
    ? facts.signatures.map((signature) => signature.identifier).sort()
    : [facts.identifier];
  const encoded = JSON.stringify([
    facts.profile.name,
    "revision" in facts.profile ? facts.profile.revision : null,
    identifiers,
  ]);
  return ok(new Uint8Array(await crypto.subtle.digest(
    "SHA-256", new TextEncoder().encode(encoded),
  )));
};
```

Include stable authenticated key and agent identities in that encoding when they
define the caller's uniqueness scope. Use the same encoding and namespace for
every verifier of that scope. A profile-aware claim still rejects repeats within
its own profile. See [Web Bot Auth](web-bot-auth.md) for envelope facts.

`Claim.create({namespace, key, retainUntil})` returns a frozen, privately branded
claim with copied byte getters. Retention is integer Unix seconds from
−9,223,372,036,854,775,808 through 253,402,300,799, matching the reference claim
domain. Use safe integer numbers or bigint for exact ends outside the safe number
range. Negative ends are valid already-expired claims. `Replay.retainUntil({created, expires, maxAge, skew})` computes
`min(expires + skew, created + maxAge + skew + 1)` over present bounds. Expiration
is exclusive; max age includes its final second. An end above the maximum rejects
with `core/replay.retention_exceeded` before commitment or storage.

`Replay.claim(store, claim, context)` returns `Result<"claimed" | "already_claimed">`.
`Replay.sweep(store, now, context)` returns the removed count; `now` is an integer
from 0 through 253,402,300,799. Caller ports must have exactly the own keys
`claim`, `sweep`, and optional visible ASCII `identity` (1–256 bytes); extra own keys
reject with `invalid_store`. Prototype methods must be bound explicitly into an
object with those own keys. `Replay.store(port)` snapshots these choices into a
branded store. Claims produced by `verify` carry safe-integer numbers. A
bigint end arrives only from a direct `Claim.create`; the ReplayStore type remains
`number | bigint`. A callback may return `{ok: false, error: "unavailable" | "timeout" |
"full" | "failure"}`; claim and sweep map these to `store_unavailable`,
`store_timeout`, `store_full`, and `store_failed`. Library replay errors remain
accepted; all other error values map to `store_failed`. Required verification
preserves unavailable and timeout; full and other store failures become
`core/replay.store_failed`. All these errors are nonretryable.

Successful Verification carries a frozen `{store, retainUntil}` receipt with no
namespace or key. Receipts have no public constructor. `isReplayReceipt` checks
receipt shape and provenance within this library; binding to the authenticated
result is through the Verification brand, not the receipt's own brand.
Verification normalizes only the serialized store label to `"store"`.
The replay deadline is capped by the caller's Context, stricter than the
reference's independent timeout.

`createMemoryStore({maxEntries})` accepts 1–10,000,000 entries. It protects one
isolate, uses byte identity rather than array identity, and starts no timers.
Claims never evict. Explicit sweep deletes only ends at or before `now`; loss
of the isolate loses its claims. Coordinate trusted verification and sweep clocks;
with multiple nodes, sweep at `now - maxInternodeSkew` without making `now` negative.

## PostgreSQL

Import `{createStore, ddl}` from `@request-seal/core/replay-postgres`.
`ddl(table)` returns a Result containing SQL for the caller to execute. Table names
start with a lowercase ASCII letter, contain lowercase letters, digits, or
underscores, and occupy 1–63 bytes. The caller owns the database and connections.
`createStore({table, query})` snapshots an autocommit query function:
`query(sql, params: readonly string[], {signal, remainingMs}) => Promise<number>`.
Return the affected-row count. Claims accept 1 as claimed and 0 as already claimed;
other counts reject. SQL decodes lowercase hexadecimal namespace and key parameters
and casts decimal retention to bigint. Conflicts never update rows.

Configure the caller-owned [pg pool](https://node-postgres.com/apis/pool) with
server lock and statement timeouts through the `options` connection setting:

```js
import {Pool} from 'pg';
const pool = new Pool({connectionString, options: '-c lock_timeout=1000 -c statement_timeout=4000'});
const query = async (text, params, {remainingMs}) => (await pool.query({text, values: [...params], query_timeout: Math.max(1, Math.ceil(remainingMs))})).rowCount;
```

With an existing [postgres.js client](https://github.com/porsager/postgres#unsafe-queries):

```js
const query = async (text, params, {signal}) => { const pending = sql.unsafe(text, [...params]); const cancel = () => { void pending.cancel(); }; signal.addEventListener('abort', cancel, {once: true}); try { if (signal.aborted) cancel(); return (await pending).count; } finally { signal.removeEventListener('abort', cancel); } };
```

With an existing [Neon HTTP client](https://github.com/neondatabase/serverless/blob/main/CONFIG.md):

```js
const query = async (text, params, {signal}) => (await sql.query(text, [...params], {fullResults: true, fetchOptions: {signal}})).rowCount;
```

The library passes the Context signal to query and bounds settlement even when a
driver cannot cancel work. pg query timeouts bound the driver's wait; they do not
promise server cancellation. Use autocommit, never a surrounding caller transaction.
A timed-out claim may still commit: its outcome is indeterminate, and required
verification must fail closed. Cancellation cannot undo a commit. Required
verification errors are nonretryable. Query exceptions
expose only bounded reasons; neither SQL nor backend diagnostics appear in Results.
Connection-error classification is per driver: this PostgreSQL adapter maps
`ECONNREFUSED`, `ENOTFOUND`, `EHOSTUNREACH`, and `ENETUNREACH` to `store_unavailable`.
A pg read timeout without a code maps to `store_failed`; a Context deadline or
coded timeout maps to `store_timeout`. All are nonretryable. The reference's
Postgrex driver classifies ordinary connection errors as `store_failed`.

For real database checks, install the isolated driver with
`npm ci --prefix interop --ignore-scripts`, set `REQUESTSEAL_REPLAY_PG_URL`, and run
`npm test`. Without the URL, local PostgreSQL tests print their skip reason; when `CI` is set,
they fail instead. Cross-language
checks additionally require `REQUESTSEAL_REPLAY_ELIXIR=1` and dependencies installed
with `mix deps.get` in `interop/replay`; the peer pins published RequestSeal 0.4.1. Its lock checksum is
`834b005ddebd610e647c42f934c3120a659b7f316cdf81f9a064037194daef02`.
The peer and error vocabulary follow v0.4.1; the corpus stays v0.4.0 because
its index is byte-identical between the tags and v0.4.1 supplied no corpus assets.

`ddl()` preserves the reference table definition byte for byte. For a large table,
the caller may add an index on `retain_until`; otherwise retention sweep scans the
table. Index creation remains caller-owned.

A caller abort during the replay stage reports nonretryable `store_timeout`, since
the claim may already have committed. An abort during an earlier verification stage
reports the retryable `custody/deadline_exceeded` deadline.

The cross-language replay check runs only when `REQUESTSEAL_REPLAY_ELIXIR=1` and an Elixir toolchain are present. The main CI workflow does not enable this opt-in replay check.
