**Status:** maintained · **Kind:** guide · **Updated:** October 11, 2026 · **Governed by:** RFC 9421 and the executed examples in this guide · **Review when:** replay contracts, retention bounds, or store interfaces change

# Replay protection

A valid signature stays valid until it expires. Anyone who captures a signed request can send it again, and the signature still verifies. Replay protection closes that gap: each signed request is accepted once, and a second arrival is refused.

You choose it per policy. RequestSeal does the cryptography and the ordering; you choose what counts as "the same request" and where claims are stored. The [replay reference](../reference/replay.md) lists every bound.

## How it works

A required replay policy has five parts: `identifier: "nonce"`, a `namespace`, a `commitment` function, a `store`, and a `timeoutMs`. Verification does this, in order:

1. It checks the signature, covered components, freshness, and any required content digest. Nothing touches the store until all of those pass, so an attacker cannot fill your store with unauthenticated junk.
2. It calls your `commitment` once with the authenticated facts: the nonce, the algorithm, the `keyid`, the tag, the created and expires times, and the profile. You return 1 to 256 bytes, usually a hash. Together with the namespace, that is the key of the claim.
3. It makes one atomic claim in the store. `"claimed"` means this is the first use. `"already_claimed"` becomes the error `replayed`.

The claim is kept until no verifier could still accept the signature: the earlier of `expires + skew` and `created + maxAge + skew + 1`. Expiration is exclusive and the maximum age includes its last second, so those bounds leave no gap. A policy that requires replay protection must therefore set `requireExpires` or a `maxAge`, so a claim never has to live forever.

Three design choices are yours, and they matter.

- **The commitment is your scope.** A nonce-only commitment treats two different keys that happen to choose the same nonce as one request. Include the `keyid` as well, as the example does, or any other authenticated fact that defines uniqueness for your service.
- **One namespace, one freshness bound.** Repeated claims never extend a claim's retention, so mixing policies with different lifetimes in one namespace lets an old claim expire early. Use a namespace per freshness bound.
- **A request with no nonce cannot be tracked.** A policy that requires replay protection refuses a signature without a nonce and returns `missing_replay_identifier`. Generated signatures carry a random nonce by default.

## In-process store

`createMemoryStore({ maxEntries })` is an atomic, single-process store with no timers. It fits tests, command-line tools, and a service that runs in one process. It never evicts: when it reaches `maxEntries` the next claim returns the store error `store_full`, so a flood of valid signatures turns into refusals and does not silently drop old claims. You reclaim space with `Replay.sweep(store, now, context)`, which removes claims that have expired. Restarting the process loses its claims.

The program races twenty verifiers against one signed request: exactly one wins and the rest get `replayed`. It then shows the missing-nonce refusal and a sweep.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { Custody, Message, Policy, PublicKey, Replay, createMemoryStore, ok, sign, verify, withDeadline, type KeyResolver, type ReplayFacts, type Result } from "@request-seal/core";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
const pair = generateKeyPairSync("ed25519");
const signer = must(await Custody.local("ed25519", pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string));
const trusted = must(await PublicKey.import(pair.publicKey.export({ format: "jwk" })));

// One store per process. A multi-process service needs a shared store (see the PostgreSQL section).
const store = must(createMemoryStore({ maxEntries: 10_000 }));
const components = '("@method" "@authority" "@path")';
// Single sender: select by keyid when you have several.
const keyResolver: KeyResolver = () => ok({ algorithm: "ed25519", key: trusted });
// The commitment decides what "the same request" means. Here: the same key and the same nonce.
const commitment = async (facts: ReplayFacts) => ok(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify([facts.profile, facts.keyid, facts.identifier])))));
const clock = () => Math.floor(Date.now() / 1000);
const policy = must(Policy.create({
  algorithms: ["ed25519"], components, keyResolver,
  freshness: { clock, maxAge: 60, skew: 5, requireExpires: true },
  content: "not_required",
  replay: { identifier: "nonce", namespace: new TextEncoder().encode("orders-api"), commitment, store, timeoutMs: 1000 },
}));

const request = must(await Message.request("GET", "https://api.example.com/orders", [], ""));
const signed = must(await sign(request, { label: "sig", components, algorithm: "ed25519", expiresIn: 60, keyid: "client-1" }, signer));

// Twenty verifiers race to use the same signed request: exactly one wins.
const outcomes = await Promise.all(Array.from({ length: 20 }, () => verify(signed, policy, { label: "sig" })));
assert.equal(outcomes.filter((outcome) => outcome.ok).length, 1);
const loser = outcomes.find((outcome) => !outcome.ok);
assert.ok(loser && !loser.ok && loser.error.kind === "core" && loser.error.reason === "replayed");

// A request signed without a nonce cannot be tracked, so a policy that requires replay protection refuses it.
const unnamed = must(await sign(request, { label: "sig", components, algorithm: "ed25519", expiresIn: 60, keyid: "client-1", nonce: null }, signer));
const untracked = await verify(unnamed, policy, { label: "sig" });
assert.ok(!untracked.ok && untracked.error.kind === "core" && untracked.error.reason === "missing_replay_identifier");

// Claims are kept until their signatures can no longer verify. Sweep reclaims them afterward.
assert.equal(must(await Replay.sweep(store, clock(), must(withDeadline()))), 0);
assert.equal(must(await Replay.sweep(store, clock() + 3600, must(withDeadline()))), 1);
```

## PostgreSQL store

Several processes need a shared store. `@request-seal/core/replay-postgres` builds one over a database you own. The library opens no connection, starts no pool, and runs no transaction. You give it a `query` function that runs one statement in autocommit mode and returns the affected-row count.

`ddl(table)` returns the schema as a string. Run it with your migration tool. The table name must be lowercase letters, digits, and underscores, so a configuration value can never become SQL.

```ts
import assert from "node:assert/strict";
import { ddl } from "@request-seal/core/replay-postgres";

// The library never connects to a database. It gives you the schema and you run it with your own migration tool.
const schema = ddl("replay_claims");
assert.ok(schema.ok);
assert.match(schema.value, /^CREATE TABLE "replay_claims" \(namespace bytea NOT NULL, key bytea NOT NULL, retain_until bigint NOT NULL, PRIMARY KEY \(namespace, key\)\)$/);
// A table name outside the safe pattern is refused, so a configuration value can never become SQL.
assert.equal(ddl('replay"; DROP TABLE users; --').ok, false);
```

Then connect your driver. This fragment needs a database, so the guides do not run it. The repository's own tests exercise the adapter against a real PostgreSQL server whenever `REQUESTSEAL_REPLAY_PG_URL` is set, and CI sets it.

```js
import { Pool } from "pg";
import { createStore } from "@request-seal/core/replay-postgres";

// Server-side timeouts bound lock waits and statements; the driver timeout bounds the client's wait.
const pool = new Pool({ connectionString, options: "-c lock_timeout=1000 -c statement_timeout=4000" });
const created = createStore({
  table: "replay_claims",
  query: async (sql, params, { remainingMs }) =>
    (await pool.query({ text: sql, values: [...params], query_timeout: Math.max(1, Math.ceil(remainingMs)) })).rowCount,
});
if (!created.ok) throw new Error(created.error.reason);
const store = created.value; // pass as the `store` of a replay policy
```

The reference shows the same function for postgres.js and for Neon's HTTP client. Never run these claims inside a surrounding transaction.

### Failure behavior

A store failure never lets a request through. `store_unavailable`, `store_timeout`, `store_failed`, and `store_full` all reject the verification, and none is marked retryable. Retrying inside the library could hide a claim that did commit: a timed-out claim may have landed. The right response is to answer with a transient error (see the status table in the [README](../../README.md#reason-to-http-status-recommendation)) and have the client sign again.

The replay deadline is capped by the caller's `Context`. If the caller aborts during the replay stage, the error is the nonretryable `store_timeout`, because the claim may already have committed; an abort earlier in verification is the retryable `custody/deadline_exceeded`.

## Several nodes

Sweep with a trusted clock that agrees with your verifiers. With more than one node, sweep at `now - maxInternodeSkew` (never below zero) so a claim is not removed while another node would still accept the signature. For a large table, add an index on `retain_until` yourself; otherwise a sweep scans the table.

## Web Bot Auth

A Web Bot Auth envelope can carry several signatures, and it takes a single claim after every selected signature and nested check has passed. Your commitment receives a different shape, `{ profile, signatures: [...] }`, with one entry per signature. The library does not add the profile to your namespace or your commitment, so put the profile into the commitment yourself: a nonce-only commitment in a namespace shared by generic and Web Bot Auth verification lets one profile's nonce consume the other's. The program signs with a held key, verifies once, and sees the second use refused.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { Custody, Message, PublicKey, WebBotAuth, createMemoryStore, ok, type KeyResolver, type Result, type WebBotAuthReplayFacts } from "@request-seal/core";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
const now = Math.floor(Date.now() / 1000);
const pair = generateKeyPairSync("ed25519");
const botKey = must(await PublicKey.import(pair.publicKey.export({ format: "jwk" })));
const pinned = must(await botKey.thumbprint());
const signer = must(await Custody.local("ed25519", pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string));
const heldKeys: KeyResolver = ({ keyid }) => ok(keyid === pinned ? { algorithm: "ed25519", key: botKey } : null);

const policy = must(WebBotAuth.Policy.create({
  algorithms: ["ed25519"], agents: () => ok(null), unresolved: { heldKeys }, cache: null,
  freshness: { clock: () => now, maxAge: 60, skew: 5 }, content: "not_required",
  replay: {
    identifier: "nonce",
    namespace: new TextEncoder().encode("crawlers"),
    // A Web Bot Auth envelope can hold several signatures, so the facts list them. Put the profile in the commitment
    // so an identical nonce under another profile in the same namespace never collides with this one.
    commitment: async (facts: WebBotAuthReplayFacts) => ok(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(
      JSON.stringify([facts.profile, facts.signatures.map((signature) => [signature.keyid, signature.identifier]).sort()]))))),
    store: must(createMemoryStore({ maxEntries: 10_000 })),
    timeoutMs: 1000,
  },
}));

const request = must(await Message.request("GET", "https://site.example/page", [], ""));
const signed = must(await WebBotAuth.sign(request, {
  label: "bot", key: botKey, algorithm: "ed25519",
  agent: { location: "https://bot.example", type: "directory" }, created: now, expires: now + 60, nonce: crypto.randomUUID(),
}, signer));
must(await WebBotAuth.verify(signed, policy));
const again = await WebBotAuth.verify(signed, policy);
assert.ok(!again.ok && again.error.kind === "core" && again.error.reason === "replayed");
```

## Where to go next

- [Signing and verifying](signing-and-verifying.md) explains the other five policy choices.
- [Web Bot Auth](web-bot-auth.md) covers agent identity.
- [Testing](testing.md) explains how to prove your store refuses a replay under concurrency.
