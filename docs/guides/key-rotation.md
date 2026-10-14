**Status:** maintained · **Kind:** guide · **Updated:** October 14, 2026 · **Governed by:** RFC 9421, RFC 7517, RFC 7638, and the executed examples in this guide · **Review when:** key resolution, discovery snapshots, or custody contracts change

# Rotating keys

You will replace a sender's signing key without a moment where valid requests fail. The pattern is the same whether you configure keys yourself or learn them from a published key set: accept both keys for an overlap period, move the sender to the new key, then stop accepting the old one.

## Rotate configured keys

A `keyid` selects among keys you already trust, so a rotation is a change to your own key table. The receiver below reads its table on every call, which means adding or retiring a key takes effect for the next request without rebuilding the policy.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { Custody, Message, Policy, PublicKey, ok, sign, verify, type KeyResolver, type PublicKey as TrustedKey, type Result } from "@request-seal/core";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
const reasonOf = (r: Result<unknown>) => (r.ok ? "ok" : r.error.reason);

// The sender's current key and its replacement. Load real keys from your secret store.
const previous = generateKeyPairSync("ed25519");
const next = generateKeyPairSync("ed25519");
const signerFor = async (pair: typeof previous) => must(await Custody.local("ed25519", pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string));
const publicFor = async (pair: typeof previous) => must(await PublicKey.import(pair.publicKey.export({ format: "jwk" })));

// The receiver's key table. In production this is configuration you can change at run time.
const trusted = new Map<string, TrustedKey>([["build-agent-2026-09", await publicFor(previous)]]);
const keyResolver: KeyResolver = ({ keyid }) => {
  const key = keyid === null ? undefined : trusted.get(keyid);
  return ok(key ? { algorithm: "ed25519", key } : null);
};
const components = '("@method" "@authority" "@path")';
const policy = must(Policy.create({
  algorithms: ["ed25519"], components, keyResolver,
  freshness: { clock: () => Math.floor(Date.now() / 1000), maxAge: 60, skew: 5, requireExpires: true },
  content: "not_required", replay: "not_required",
}));
const request = must(await Message.request("POST", "https://builds.example/artifacts", [], ""));
const signWith = async (pair: typeof previous, keyid: string) =>
  must(await sign(request, { label: "sig", components, algorithm: "ed25519", expiresIn: 60, keyid }, await signerFor(pair)));

// 1. Overlap: trust the new key before any sender uses it.
trusted.set("build-agent-2026-10", await publicFor(next));
assert.equal(reasonOf(await verify(await signWith(previous, "build-agent-2026-09"), policy, { label: "sig" })), "ok");
assert.equal(reasonOf(await verify(await signWith(next, "build-agent-2026-10"), policy, { label: "sig" })), "ok");

// 2. Retire the old key once every sender has switched and old signatures have expired.
trusted.delete("build-agent-2026-09");
assert.equal(reasonOf(await verify(await signWith(previous, "build-agent-2026-09"), policy, { label: "sig" })), "unknown_key");

// The keyid only selects; the key you trust decides. An old key under the new keyid fails.
assert.equal(reasonOf(await verify(await signWith(previous, "build-agent-2026-10"), policy, { label: "sig" })), "invalid_signature");
```

Practical notes:

- Give each key its own `keyid`. Reusing a `keyid` for a different key makes signatures from the overlap period fail until both sides agree.
- Keep the old key trusted for at least your freshness window (`maxAge` plus `skew`) after the last sender switches, so signatures already in flight still verify.
- HMAC keys rotate the same way, with a KeyHandle or a verification function in place of the public key. See [key custody](key-custody.md).

## Rotate published keys

When a sender publishes its keys as a JWKS or a key directory, the publisher adds the new key, waits, then removes the old one. Each snapshot you build reflects what the publisher listed when you fetched it, so a refreshed snapshot that no longer lists a key stops resolving it. Keys in a published set are selected by RFC 7638 thumbprint.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { Discovery, DiscoverySource, PublicKey, type Result } from "@request-seal/core";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
const now = Math.floor(Date.now() / 1000);
const previous = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" });
const next = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" });
const previousThumbprint = must(await must(await PublicKey.import(previous)).thumbprint());
const nextThumbprint = must(await must(await PublicKey.import(next)).thumbprint());

// Fetch these bytes with your own HTTP client. Here they are literal responses from two fetches.
const source = must(DiscoverySource.create({ type: "jwks_uri", location: "https://builds.example/keys" }));
const snapshot = async (keys: object[], fetchedAt: number) => must(await Discovery.resolver.fromSnapshot(source,
  new TextEncoder().encode(JSON.stringify({ keys })), fetchedAt, [["content-type", "application/json"], ["cache-control", "max-age=600"]]));

// During the overlap the publisher lists both keys, and both resolve.
const overlap = await snapshot([previous, next], now);
assert.ok((await overlap.lookup(previousThumbprint, ["ed25519"], now)).ok);
assert.ok((await overlap.lookup(nextThumbprint, ["ed25519"], now)).ok);

// After the publisher drops the old key, the next fetch no longer resolves it.
const after = await snapshot([next], now + 1);
const retired = await after.lookup(previousThumbprint, ["ed25519"], now + 1);
assert.ok(!retired.ok && retired.error.kind === "discovery" && retired.error.reason === "unknown_key");
assert.ok((await after.lookup(nextThumbprint, ["ed25519"], now + 1)).ok);
```

A snapshot is served only until its cache lifetime ends, so an old key disappears no later than the publisher's `max-age` after removal. To stop trusting a key at once, even while the publisher still lists it, use the cache's `remove(source, thumbprint)` or the source's `revoked` option; both are described in [revoking and removing keys](key-discovery.md#revoking-and-removing-keys). A caller-owned cache also refuses an older snapshot than one it already holds, so a stale copy cannot bring a retired key back.

## Where to go next

- [Key custody](key-custody.md): where signing keys live while you rotate them.
- [Key discovery](key-discovery.md): fetching and caching published key sets.
- [Testing](testing.md): prove your resolver refuses a retired key.
