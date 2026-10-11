**Status:** maintained · **Kind:** overview · **Updated:** October 11, 2026 · **Governed by:** RFC 9421, RFC 9530, the Web Bot Auth protocol draft, and the executed examples in this file · **Review when:** package scope, installation, or the public API changes

# RequestSeal

RequestSeal signs and verifies HTTP messages ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html)) and compact JOSE tokens in TypeScript, for services and clients that need to know who sent a request and that its bytes arrived unchanged. It uses WebCrypto, has no runtime dependencies, and runs on Node, Deno, and Bun.

## Install

```sh
npm install @request-seal/core
```

See [CHANGELOG.md](CHANGELOG.md) for published versions and unreleased changes. The package is ESM. It needs Node 22.12.0 or newer, and the core API also runs on Deno and Bun (see Compatibility below). In TypeScript, use `nodenext` or `bundler` module resolution so subpath imports such as `@request-seal/core/fetch` resolve. Complete programs generate keys, close their loopback servers, and assert results; the labeled verification excerpts need the setup in their expanded programs.

Save a complete program as `example.ts` in a project whose `package.json` has `"type": "module"`. On Node 22, run `node --experimental-strip-types example.ts`; on Node 24 and later, run `node example.ts`. For programs marked Deno, run `deno run --allow-read --allow-net=127.0.0.1,jsr.io example.ts`; for Bun, run `bun run example.ts`.

## Sign a request

`signedFetch` is `fetch` plus a signature. It signs every attempt afresh, so a retry is never a replay.

```ts
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { Custody } from "@request-seal/core";
import { signedFetch } from "@request-seal/core/fetch";
const key = await Custody.local("hmac-sha256", { hmac: crypto.getRandomValues(new Uint8Array(32)) });
const server = createServer((req, res) => res.end(String(req.headers["signature-input"]))).listen(0, "127.0.0.1");
await new Promise((ready) => server.once("listening", ready));
const spec = { label: "sig", components: '("@method" "@authority" "@path")', algorithm: "hmac-sha256", expiresIn: 60 };
const sent = await signedFetch(`http://127.0.0.1:${(server.address() as { port: number }).port}/orders`, { method: "GET" }, { spec, signer: key.ok ? key.value : assert.fail() });
assert.ok(sent.ok && (await sent.value.response.text()).startsWith('sig=("@method" "@authority" "@path")')); server.close();
```

Next: [getting started](docs/guides/getting-started.md) for a core sign/verify round trip, or [Node HTTP](docs/guides/node-http.md) for server verification. The Fetch adapter cannot verify `@path`; see the [Fetch guide](docs/guides/fetch.md#verify-incoming-requests).

## Verify an RFC 9421 request

Build an explicit policy, then call `verify(message, policy, { label: "sig" })`. This bodyless example signs a GET, verifies it with a configured key, and rejects a changed method. The [strict RFC 9421 recipe](#strict-rfc-9421) below also checks a body digest and rejects a second use.

```ts
import assert from "node:assert/strict";
import { Custody, Message, Policy, ok, sign, verify, type Result } from "@request-seal/core";
const must = <T>(r: Result<T>): T => { assert.ok(r.ok); return (r as { value: T }).value; };
const key = must(await Custody.local("hmac-sha256", { hmac: crypto.getRandomValues(new Uint8Array(32)) }));
const components = '("@method" "@authority" "@path")';
const policy = must(Policy.create({ algorithms: ["hmac-sha256"], components, keyResolver: () => ok({ algorithm: "hmac-sha256", key }), freshness: { clock: () => Math.floor(Date.now() / 1000), maxAge: 60, skew: 5, requireExpires: true }, content: "not_required", replay: "not_required" }));
const signed = must(await sign(must(await Message.request("GET", "https://api.example/orders", [], "")), { label: "sig", components, algorithm: "hmac-sha256", expiresIn: 60 }, key));
must(await verify(signed, policy, { label: "sig" }));
const altered = must(Message.create({ ...signed, method: "DELETE" }));
const rejected = await verify(altered, policy, { label: "sig" });
assert.ok(!rejected.ok && rejected.error.kind === "core" && rejected.error.reason === "invalid_signature");
```

## Verify a Web Bot Auth request

[Web Bot Auth](docs/guides/web-bot-auth.md) lets automated agents sign their requests so a site can tell who is calling. A Web Bot Auth signature covers `@authority` by default, not the body. To authenticate the body, the agent signs `content-digest` and the verification policy requires content checking; the excerpts below do not. Verification trusts only the agent directories you configure, checks the signature against keys from them, and returns the verified agent. It never authorizes: that stays your decision.

`content: "not_required"` skips body digest checks; `replay: "not_required"` allows repeated signatures within their freshness window. These local test programs use unsigned snapshots with `requireSignedDirectory: false`; production directories should keep the signed-directory default. See the [signed directory program](docs/guides/web-bot-auth.md).

Each verification excerpt below is at most fifteen lines and matches the code between the `----` markers in its complete runnable program. The documentation check compares the two byte-for-byte, so edits cannot silently drift. Expand the program to see key generation, the caller-owned offline directory snapshot, and signed and unsigned requests with asserted outcomes.

### Express

This GET route accepts bodyless requests. `captureRequest` runs first so the exact request line, headers, and body are kept before any parser touches them. See [Node HTTP](docs/guides/node-http.md) for Fastify, proxies, and body parsers.

In your project, run `npm install express` and use `import express from "express";`. Replace the complete program's `createRequire` setup with that import; it loads the repository's pinned dependency only for these executable examples.

Verification excerpt (14 lines):

<!-- verification-excerpt: express -->
```typescript
const policy = must(WebBotAuth.Policy.create({
  algorithms: ["ed25519"],
  agents: ({ location }: AgentRequest) => ok(location === keys.origin ? keys : null), // Trust only the directory you configured.
  cache: null,
  freshness: { clock: now, maxAge: 60, skew: 5 },
  content: "not_required",
  replay: "not_required",
}));
const app = express();
app.get("/", async (req: any, res: any) => {
  const captured = await captureRequest(req); // Before any body parser.
  const verified = captured.ok ? await verifyWebBotAuth(req, policy) : captured;
  res.status(verified.ok ? 200 : 401).end(verified.ok ? verified.value.verification.signatures.crawler!.principal.kind : "");
});
```

<details>
<summary>Complete runnable Express program</summary>

```ts
import assert from "node:assert/strict";
import { once } from "node:events";
import { generateKeyPairSync } from "node:crypto";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { Custody, Discovery, DiscoverySource, Message, PublicKey, WebBotAuth, ok, type AgentRequest, type Result } from "@request-seal/core";
import { captureRequest, verifyWebBotAuth } from "@request-seal/core/node-http";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
// In your project: import express from "express". This repository loads the version its tests pin.
const express = createRequire(new URL("../../interop/adapters/package.json", import.meta.url))("express");
const now = () => Math.floor(Date.now() / 1000);

// Test-only unsigned local snapshot. In production, keep the signed-directory default.
const crawler = generateKeyPairSync("ed25519");
const jwk = crawler.publicKey.export({ format: "jwk" });
const source = must(DiscoverySource.create({ type: "directory", location: "https://crawler.example", requireSignedDirectory: false }));
const keys = must(await Discovery.resolver.fromSnapshot(source, new TextEncoder().encode(JSON.stringify({ keys: [jwk] })), now(),
  [["content-type", "application/http-message-signatures-directory+json"]]));

// ---- Your server: verify Web Bot Auth requests (14 lines) ----
const policy = must(WebBotAuth.Policy.create({
  algorithms: ["ed25519"],
  agents: ({ location }: AgentRequest) => ok(location === keys.origin ? keys : null), // Trust only the directory you configured.
  cache: null,
  freshness: { clock: now, maxAge: 60, skew: 5 },
  content: "not_required",
  replay: "not_required",
}));
const app = express();
app.get("/", async (req: any, res: any) => {
  const captured = await captureRequest(req); // Before any body parser.
  const verified = captured.ok ? await verifyWebBotAuth(req, policy) : captured;
  res.status(verified.ok ? 200 : 401).end(verified.ok ? verified.value.verification.signatures.crawler!.principal.kind : "");
});
// ---- End of the verification code ----

const server = createServer(app).listen(0, "127.0.0.1");
await once(server, "listening");
const url = `http://127.0.0.1:${(server.address() as { port: number }).port}/`;
const signer = must(await Custody.local("ed25519", crawler.privateKey.export({ type: "pkcs8", format: "pem" }) as string));
const signed = must(await WebBotAuth.sign(must(await Message.request("GET", url, [], "")), {
  label: "crawler", key: must(await PublicKey.import(jwk)), algorithm: "ed25519",
  agent: { location: "https://crawler.example", type: "directory" }, created: now(), expires: now() + 60, nonce: null,
}, signer));
const headers = signed.fields.map((f) => [f.name, new TextDecoder().decode(f.value)] as [string, string]);
const accepted = await fetch(url, { headers });
assert.equal(accepted.status, 200);
assert.equal(await accepted.text(), "agent");
assert.equal((await fetch(url)).status, 401);
server.close();
server.closeAllConnections();
```

</details>

### Hono on Deno

The example runs under Deno and pins Hono from JSR at `jsr:@hono/hono@4.10.3`. Hono is your dependency, not RequestSeal's. Fetch Headers merges duplicate field occurrences; this excerpt cannot recover them. Use the Node adapter when separate occurrences matter. The program builds a `Message` from the incoming request using the origin your service owns, never the request's own `Host`, and passes it to `WebBotAuth.verify`.

Verification excerpt (15 lines):

<!-- verification-excerpt: hono -->
<!-- run: deno -->
```typescript
let origin = ""; // The public origin you serve. Take it from your configuration, never from the request.
const policy = must(WebBotAuth.Policy.create({
  algorithms: ["ed25519"], components: '("@method" "@path" "@query")',
  agents: ({ location }: AgentRequest) => ok(location === keys.origin ? keys : null), // Trust only the directory you configured.
  cache: null,
  freshness: { clock: now, maxAge: 60, skew: 5 },
  content: "not_required",
  replay: "not_required",
}));
const app = new Hono();
app.get("/*", async (c) => {
  const message = await Message.request("GET", origin + new URL(c.req.url).pathname + new URL(c.req.url).search, [...c.req.raw.headers.entries()], "");
  const verified = message.ok ? await WebBotAuth.verify(message.value, policy) : message;
  return verified.ok ? c.text(verified.value.signatures.crawler!.principal.kind) : c.text("denied", 401);
});
```

<details>
<summary>Complete runnable Hono on Deno program</summary>

<!-- run: deno -->
```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
// Hono is your dependency, pinned here so the example runs as written.
import { Hono } from "jsr:@hono/hono@4.10.3";
import { Custody, Discovery, DiscoverySource, Message, PublicKey, WebBotAuth, ok, type AgentRequest, type Result } from "@request-seal/core";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
const now = () => Math.floor(Date.now() / 1000);

// Test-only unsigned local snapshot. In production, keep the signed-directory default.
const crawler = generateKeyPairSync("ed25519");
const jwk = crawler.publicKey.export({ format: "jwk" });
const source = must(DiscoverySource.create({ type: "directory", location: "https://crawler.example", requireSignedDirectory: false }));
const keys = must(await Discovery.resolver.fromSnapshot(source, new TextEncoder().encode(JSON.stringify({ keys: [jwk] })), now(),
  [["content-type", "application/http-message-signatures-directory+json"]]));

// ---- Your server: verify Web Bot Auth requests (15 lines) ----
let origin = ""; // The public origin you serve. Take it from your configuration, never from the request.
const policy = must(WebBotAuth.Policy.create({
  algorithms: ["ed25519"], components: '("@method" "@path" "@query")',
  agents: ({ location }: AgentRequest) => ok(location === keys.origin ? keys : null), // Trust only the directory you configured.
  cache: null,
  freshness: { clock: now, maxAge: 60, skew: 5 },
  content: "not_required",
  replay: "not_required",
}));
const app = new Hono();
app.get("/*", async (c) => {
  const message = await Message.request("GET", origin + new URL(c.req.url).pathname + new URL(c.req.url).search, [...c.req.raw.headers.entries()], "");
  const verified = message.ok ? await WebBotAuth.verify(message.value, policy) : message;
  return verified.ok ? c.text(verified.value.signatures.crawler!.principal.kind) : c.text("denied", 401);
});
// ---- End of the verification code ----

const server = Deno.serve({ hostname: "127.0.0.1", port: 0, onListen: ({ port }) => { origin = `http://127.0.0.1:${port}`; } }, app.fetch);
const signer = must(await Custody.local("ed25519", crawler.privateKey.export({ type: "pkcs8", format: "pem" }) as string));
const signed = must(await WebBotAuth.sign(must(await Message.request("GET", origin + "/page?x=1&x=2", [], "")), {
  label: "crawler", components: '("@method" "@path" "@query")', key: must(await PublicKey.import(jwk)), algorithm: "ed25519",
  agent: { location: "https://crawler.example", type: "directory" }, created: now(), expires: now() + 60, nonce: null,
}, signer));
const headers = signed.fields.map((f) => [f.name, new TextDecoder().decode(f.value)] as [string, string]);
assert.equal(await (await fetch(origin + "/page?x=1&x=2", { headers })).text(), "agent");
const changedQuery = await fetch(origin + "/page?x=1&x=3", { headers });
assert.equal(changedQuery.status, 401);
await changedQuery.body?.cancel();
const refused = await fetch(origin + "/");
assert.equal(refused.status, 401);
await refused.body?.cancel();
await server.shutdown();
```

</details>

## Policy recipes

A verifier states six choices: algorithms, required components, a key resolver, freshness, content checking, and replay. Nothing is defaulted. Copy the recipe closest to your case.

### Strict RFC 9421

Accepts one algorithm, requires exact coverage, recomputes the body digest, bounds the signature count, and lets each signature work once. `createMemoryStore` is per process; use the [PostgreSQL store](docs/guides/replay-protection.md#postgresql-store) for multi-instance deployments.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { Custody, Message, Policy, PublicKey, createMemoryStore, ok, sign, verify, type KeyResolver, type ReplayFacts, type Result } from "@request-seal/core";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
const pair = generateKeyPairSync("ed25519");
const trusted = must(await PublicKey.import(pair.publicKey.export({ format: "jwk" })));
const keyResolver: KeyResolver = ({ keyid }) => ok(keyid === "partner-1" ? { algorithm: "ed25519", key: trusted } : null); // Your configured keys only.
const sha256 = async (text: string) => new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));

// Strict generic RFC 9421 policy: copy this and change the key resolver.
const components = '("@method" "@scheme" "@authority" "@path" "@query" "content-digest")';
const policy = must(Policy.create({
  algorithms: ["ed25519"],                                    // Only what your partners use.
  components,                                                 // Every accepted signature must cover these.
  extraComponents: "reject",                                  // ...and nothing else, so coverage cannot drift.
  maxSignatures: 4,                                           // Bound the work an attacker can request.
  keyResolver,                                                // Maps keyid to a key you trust; ok(null) for strangers.
  freshness: { clock: () => Math.floor(Date.now() / 1000), maxAge: 300, skew: 5, requireExpires: true },
  content: { kind: "content", algorithms: ["sha-256"], section: "headers" },  // Recompute the body digest.
  replay: {                                                   // Each signature works once.
    identifier: "nonce", namespace: new TextEncoder().encode("partner-api"), timeoutMs: 1000,
    store: must(createMemoryStore({ maxEntries: 100_000 })),
    commitment: async (facts: ReplayFacts) => ok(await sha256(JSON.stringify([facts.keyid, facts.identifier]))),
  },
}));

// A partner signs a request, and it verifies exactly once.
const signer = must(await Custody.local("ed25519", pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string));
const request = must(await Message.request("POST", "https://api.example.com/orders?id=7", [], '{"qty":2}', { digest: ["sha-256"] }));
const signed = must(await sign(request, { label: "sig", components, algorithm: "ed25519", expiresIn: 60, keyid: "partner-1", digest: ["sha-256"] }, signer));
must(await verify(signed, policy, { label: "sig" }));
const again = await verify(signed, policy, { label: "sig" });
assert.ok(!again.ok && again.error.kind === "core" && again.error.reason === "replayed");
```

### Strict Web Bot Auth

Trusts one configured directory, refuses long-lived signatures and unrelated labels, and claims each nonce once. `createMemoryStore` is per process; use the [PostgreSQL store](docs/guides/replay-protection.md#postgresql-store) for multi-instance deployments.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { Custody, Discovery, DiscoverySource, Message, PublicKey, WebBotAuth, createMemoryStore, ok, type AgentRequest, type Result, type WebBotAuthReplayFacts } from "@request-seal/core";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
const now = () => Math.floor(Date.now() / 1000);
const sha256 = async (text: string) => new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
const agent = generateKeyPairSync("ed25519");
const jwk = agent.publicKey.export({ format: "jwk" });
// Test-only unsigned snapshot; use the signed-directory default in production.
const source = must(DiscoverySource.create({ type: "directory", location: "https://agent.example", requireSignedDirectory: false }));
const keys = must(await Discovery.resolver.fromSnapshot(source, new TextEncoder().encode(JSON.stringify({ keys: [jwk] })), now(),
  [["content-type", "application/http-message-signatures-directory+json"]]));

// Strict Web Bot Auth policy: copy this and change the trust callback.
const policy = must(WebBotAuth.Policy.create({
  algorithms: ["ed25519"],                                  // HMAC is never allowed for Web Bot Auth.
  agents: ({ location }: AgentRequest) => ok(location === keys.origin ? keys : null),  // Trust only directories you configured.
  cache: null,                                              // Or a createCache() capability when agents return sources.
  freshness: { clock: now, maxAge: 60, skew: 5 },           // Expiry is always required.
  maxLifetime: 300,                                         // Refuse long-lived signatures (default 86,400 seconds).
  untagged: "reject",                                       // Refuse extra signatures that are not Web Bot Auth.
  testKeys: "reject",                                       // Refuse published example keys (this is the default).
  content: "not_required",
  replay: {                                                 // One use per nonce, across every selected signature.
    identifier: "nonce", namespace: new TextEncoder().encode("crawlers"), timeoutMs: 1000,
    store: must(createMemoryStore({ maxEntries: 100_000 })),
    commitment: async (facts: WebBotAuthReplayFacts) => ok(await sha256(JSON.stringify([facts.profile, facts.signatures.map((s) => [s.keyid, s.identifier]).sort()]))),
  },
}));

const signer = must(await Custody.local("ed25519", agent.privateKey.export({ type: "pkcs8", format: "pem" }) as string));
const request = must(await Message.request("GET", "https://site.example/page", [], ""));
const signed = must(await WebBotAuth.sign(request, {
  label: "bot", key: must(await PublicKey.import(jwk)), algorithm: "ed25519",
  agent: { location: "https://agent.example", type: "directory" }, created: now(), expires: now() + 60, nonce: crypto.randomUUID(),
}, signer));
assert.equal(must(await WebBotAuth.verify(signed, policy)).signatures.bot!.principal.kind, "agent");
const again = await WebBotAuth.verify(signed, policy);
assert.ok(!again.ok && again.error.kind === "core" && again.error.reason === "replayed");
```

## Reason to HTTP status (recommendation)

Every failure is a `Result` with a bounded `error`; branch on `error.kind` and `error.reason`. This table is a recommendation, not a requirement. It is derived from the error vocabulary in [error parity](docs/reference/error-parity.md), and the [signing guide](docs/guides/signing-and-verifying.md#respond-to-a-rejection) holds the same mapping as a program that checks it covers every reason. Selectors use `kind/layer.reason` or `kind/reason`; `*` covers that family. An exact reason overrides its family row. The guide program is authoritative. Adapters wrap the underlying reason in `error.source`; map that. Any `retryable: true` error overrides the table with 503. For `adapter/limit`, 413 is an optional alternative to 400.

The reasoning, stated once: 400 means the message cannot be read, so resending the same bytes cannot help. 401 means the sender did not prove what your policy requires, and a fresh correct signature can. 403 means your configuration refuses a sender it understood. 500 means your own code or configuration is wrong. 503 means the failure is transient or the replay store is in trouble.

| Status | Reasons |
| --- | --- |
| 400 | `core/fields.*`, `core/negotiation.*`, `message/*`, `structured_fields/*`, `signature_base/*`, `digest/*`, `jose/input.*`, `jose/nesting.*`, `core/content.body_unavailable`, `core/content.digest_unsupported`, `core/crypto.signature_base_failed`, `core/input.invalid_message`, `core/input.invalid_request`, `core/input.limit`, `core/input.unsupported_component`, `crypto/invalid_data`, `adapter/invalid_request`, `adapter/limit`, `adapter/body_unavailable`, `adapter/digest_conflict`, `adapter/untrusted_proxy` |
| 401 | `core/content.*`, `core/freshness.*`, `core/key.*`, `core/policy.*`, `core/quorum.*`, `core/replay.*`, `discovery/*`, `jose/crypto.*`, `jose/key.*`, `core/crypto.invalid_signature`, `core/fields.missing_signature`, `core/fields.missing_signature_input`, `core/fields.no_web_bot_auth_signature`, `core/fields.unknown_label`, `core/negotiation.negotiation_unfulfilled`, `crypto/invalid_signature`, `custody/invalid_signature`, `custody/decryption_failed`, `adapter/request_rejected`, `adapter/response_rejected` |
| 403 | `core/binding.*`, `core/policy.test_key_rejected`, `discovery/revoked_key` |
| 500 | `core/crypto.*`, `core/input.*`, `crypto/*`, `custody/*`, `adapter/*`, `core/binding.invalid_binding`, `core/binding.invalid_verification`, `core/fields.label_in_use`, `core/freshness.invalid_clock`, `core/key.key_resolver_failed`, `core/quorum.ambiguous_key_identity`, `core/replay.commitment_failed`, `discovery/invalid_options`, `discovery/invalid_source`, `discovery/ambiguous_key_source`, `discovery/transport_unavailable`, `jose/crypto.entropy_failure`, `jose/crypto.signer_failed`, `jose/input.invalid_options`, `jose/input.invalid_policy`, `jose/key.key_resolver_failed`, `replay/invalid_claim`, `replay/invalid_options`, `replay/invalid_store` |
| 503 | `replay/*`, `core/replay.store_failed`, `core/replay.store_timeout`, `core/replay.store_unavailable` |

For core `agent_unresolved`, `timeout` and `source_unavailable` map to 503; `untrusted_agent` and `revoked_key` map to 403; other details map to 401.

## Standards

| Standard | What RequestSeal implements |
| --- | --- |
| [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) HTTP Message Signatures | Signing and verification, derived components, multiple signatures, `Accept-Signature`, and the six algorithms in the [IANA registry](https://www.iana.org/assignments/http-message-signature) that the library supports. |
| [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html) Digest Fields | `Content-Digest` and `Repr-Digest` with SHA-256 and SHA-512, including streamed bodies. |
| [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941.html) and [RFC 9651](https://www.rfc-editor.org/rfc/rfc9651.html) Structured Field Values | Parsing and serialization under explicit schemas. |
| [draft-ietf-webbotauth-httpsig-protocol-00](https://www.ietf.org/archive/id/draft-ietf-webbotauth-httpsig-protocol-00.html) | Web Bot Auth signing, verification, key directories, and nested signatures. A draft can change; pin your version. |
| [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html), [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html), [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) JOSE | Compact JWS and JWE, and one-level nesting. |
| [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html), [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html), [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html) | JWK parsing, thumbprints, and Ed25519 keys. |
| [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html) HTTP/2 | Pseudo-header handling in the Node HTTP adapter. |

## Integrations

| Integration | Entry point | Proved by |
| --- | --- | --- |
| Node `http`, `https`, and `http2` | `@request-seal/core/node-http` | Real servers and clients on loopback. |
| Express 5.2.1 | `captureRequest`, `verifyRequest` | The [Node HTTP guide](docs/guides/node-http.md) program, and the framework tests. |
| Fastify 5.12.5 | `capture`, `captureRequest` | The Node HTTP guide program, and the framework tests. |
| Fetch, signing on Node, Deno, and Bun; verification on Deno 2.5.6 | `@request-seal/core/fetch` | The [Fetch guide](docs/guides/fetch.md) programs, and wire tests on each runtime. |
| Hono on Deno | `WebBotAuth.verify` | The Hono program above. |
| PostgreSQL replay store, with `pg` 8.23.1 | `@request-seal/core/replay-postgres` | A real PostgreSQL 18 server in CI. |
| OpenSSH agent custody | `@request-seal/core/custody-ssh-agent` | A real `ssh-agent`, with signatures checked by OpenSSL. |
| RequestSeal for Elixir 0.4.1 | HTTP and JWS algorithms, JWE, Web Bot Auth directories, replay claims | A two-way exchange in CI. |
| `http-message-signatures` 1.0.6 | RFC 9421 wire format | The [migration guide](docs/guides/migrating-from-http-message-signatures.md) tests. |

## Security

RequestSeal reports what was cryptographically established and nothing more: the verified bytes, the key that signed them, and the trusted source of that key. It does not authorize anything. Private keys stay behind custody handles, and no error, log view, or serialization carries key material, stack traces, or caller bytes. Inputs are bounded in size, depth, and time, every operation takes a deadline, and discovery and replay run only where you configure them. Report a vulnerability privately through [GitHub security advisories](https://github.com/baselabs/request-seal-typescript/security/advisories/new); see [SECURITY.md](SECURITY.md) and the [threat model](docs/design/threat-model.md).

## Guides

- [Getting started](docs/guides/getting-started.md)
- [Signing and verifying](docs/guides/signing-and-verifying.md)
- [Fetch](docs/guides/fetch.md)
- [Node HTTP, Express, and Fastify](docs/guides/node-http.md)
- [Web Bot Auth](docs/guides/web-bot-auth.md)
- [Replay protection](docs/guides/replay-protection.md)
- [Key discovery](docs/guides/key-discovery.md)
- [Signed and encrypted tokens (JOSE)](docs/guides/jose.md)
- [Key custody](docs/guides/key-custody.md)
- [Testing](docs/guides/testing.md)
- [Migrating from http-message-signatures](docs/guides/migrating-from-http-message-signatures.md)

API: [generated reference](https://baselabs.github.io/request-seal-typescript/). Build it locally with `npm ci --ignore-scripts && npm run docs`, then open the generated `site-dist/index.html`.

Reference: [signing and verification](docs/reference/sign-and-verify.md), [adapters](docs/reference/adapters.md), [Web Bot Auth](docs/reference/web-bot-auth.md), [replay](docs/reference/replay.md), [discovery](docs/reference/discovery.md), [JOSE](docs/reference/jose.md), [wire APIs](docs/reference/wire.md), [multiple signatures](docs/reference/quorum.md), [extension profiles](docs/reference/profiles.md), [error parity](docs/reference/error-parity.md), and [corpus format](docs/reference/corpus-format.md). Design records: the [threat model](docs/design/threat-model.md) and the [architecture decisions](docs/adr/README.md). To contribute, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Compatibility

The core runs on Node 22.12.0, 24.21.0, and 26.11.1, Deno 2.5.6, and Bun 1.3.14. Fetch signs on those runtimes, but Fetch verification supports only Deno 2.5.6. HTTPS discovery requires Node; use caller-owned snapshots elsewhere. In browsers (Chromium 156.0.8078.4, Firefox 157.0, WebKit 27.2), the Fetch adapter signs only. Core `verify` checks a caller-built `Message` under an explicit policy without using the Fetch adapter. See the [runtime matrix](docs/reference/runtime-matrix.md) for exact tested versions, permissions, and limitations.

Crypto, custody, and error vocabulary follow RequestSeal for Elixir 0.4.1; conformance uses its byte-preserved 0.4.0 corpus. See [the corpus pin](CONTRIBUTING.md) and [replay protection](docs/reference/replay.md).
