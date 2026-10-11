**Status:** maintained · **Kind:** overview · **Updated:** October 11, 2026 · **Governed by:** RFC 9421, RFC 9530, the Web Bot Auth protocol draft, and the executed examples in this file · **Review when:** package scope, installation, or the public API changes

# RequestSeal

RequestSeal signs and verifies HTTP messages ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html)) and compact JOSE tokens in TypeScript, for services and clients that need to know who sent a request and that its bytes arrived unchanged. It uses WebCrypto, has no runtime dependencies, and runs on Node, Deno, and Bun.

## Install

```sh
npm install @request-seal/core
```

Version 0.1.0 is published; the next release is 0.2.0. The package is ESM. It needs Node 22.12.0 or newer, and the core API also runs on Deno and Bun (see Compatibility below). In TypeScript, use `nodenext` or `bundler` module resolution so subpath imports such as `@request-seal/core/fetch` resolve. Every example below is a complete program: it generates its own keys, starts any server on loopback, closes it, and asserts its result.

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
const sent = await signedFetch(`http://127.0.0.1:${(server.address() as { port: number }).port}/orders`, { method: "POST", body: "hi" }, { spec, signer: key.ok ? key.value : assert.fail() });
assert.ok(sent.ok && (await sent.value.response.text()).startsWith('sig=("@method" "@authority" "@path")')); server.close();
```

## Verify a Web Bot Auth request

[Web Bot Auth](docs/guides/web-bot-auth.md) lets automated agents sign their requests so a site can tell who is calling. Verification trusts only the agent directories you configure, checks the signature against keys from them, and returns the verified agent. It never authorizes: that stays your decision.

Each verification excerpt below is at most fifteen lines and matches the code between the `----` markers in its complete runnable program. The documentation check compares the two byte-for-byte, so edits cannot silently drift. Expand the program to see key generation, the caller-owned offline directory snapshot, and signed and unsigned requests with asserted outcomes.

### Express

`captureRequest` runs first so the exact request line, headers, and body are kept before any parser touches them. See [Node HTTP](docs/guides/node-http.md) for Fastify, proxies, and body parsers.

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
app.use(async (req: any, res: any) => {
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

// The crawler's key, published in a directory you trust. This example uses the offline snapshot API.
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
app.use(async (req: any, res: any) => {
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

The example runs under Deno and pins Hono from JSR at `jsr:@hono/hono@4.10.3`. Hono is your dependency, not RequestSeal's. The program builds a `Message` from the incoming request using the origin your service owns, never the request's own `Host`, and passes it to `WebBotAuth.verify`.

Verification excerpt (15 lines):

<!-- verification-excerpt: hono -->
```typescript
let origin = ""; // The public origin you serve. Take it from your configuration, never from the request.
const policy = must(WebBotAuth.Policy.create({
  algorithms: ["ed25519"],
  agents: ({ location }: AgentRequest) => ok(location === keys.origin ? keys : null), // Trust only the directory you configured.
  cache: null,
  freshness: { clock: now, maxAge: 60, skew: 5 },
  content: "not_required",
  replay: "not_required",
}));
const app = new Hono();
app.get("/*", async (c) => {
  const message = await Message.request("GET", origin + c.req.path, [...c.req.raw.headers], "");
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

// The crawler's key, published in a directory you trust. This example uses the offline snapshot API.
const crawler = generateKeyPairSync("ed25519");
const jwk = crawler.publicKey.export({ format: "jwk" });
const source = must(DiscoverySource.create({ type: "directory", location: "https://crawler.example", requireSignedDirectory: false }));
const keys = must(await Discovery.resolver.fromSnapshot(source, new TextEncoder().encode(JSON.stringify({ keys: [jwk] })), now(),
  [["content-type", "application/http-message-signatures-directory+json"]]));

// ---- Your server: verify Web Bot Auth requests (15 lines) ----
let origin = ""; // The public origin you serve. Take it from your configuration, never from the request.
const policy = must(WebBotAuth.Policy.create({
  algorithms: ["ed25519"],
  agents: ({ location }: AgentRequest) => ok(location === keys.origin ? keys : null), // Trust only the directory you configured.
  cache: null,
  freshness: { clock: now, maxAge: 60, skew: 5 },
  content: "not_required",
  replay: "not_required",
}));
const app = new Hono();
app.get("/*", async (c) => {
  const message = await Message.request("GET", origin + c.req.path, [...c.req.raw.headers], "");
  const verified = message.ok ? await WebBotAuth.verify(message.value, policy) : message;
  return verified.ok ? c.text(verified.value.signatures.crawler!.principal.kind) : c.text("denied", 401);
});
// ---- End of the verification code ----

const server = Deno.serve({ hostname: "127.0.0.1", port: 0, onListen: ({ port }) => { origin = `http://127.0.0.1:${port}`; } }, app.fetch);
const signer = must(await Custody.local("ed25519", crawler.privateKey.export({ type: "pkcs8", format: "pem" }) as string));
const signed = must(await WebBotAuth.sign(must(await Message.request("GET", origin + "/", [], "")), {
  label: "crawler", key: must(await PublicKey.import(jwk)), algorithm: "ed25519",
  agent: { location: "https://crawler.example", type: "directory" }, created: now(), expires: now() + 60, nonce: null,
}, signer));
const headers = signed.fields.map((f) => [f.name, new TextDecoder().decode(f.value)] as [string, string]);
assert.equal(await (await fetch(origin + "/", { headers })).text(), "agent");
const refused = await fetch(origin + "/");
assert.equal(refused.status, 401);
await refused.body?.cancel();
await server.shutdown();
```

</details>

## Policy recipes

A verifier states six choices: algorithms, required components, a key resolver, freshness, content checking, and replay. Nothing is defaulted. Copy the recipe closest to your case.

### Strict RFC 9421

Accepts one algorithm, requires exact coverage, recomputes the body digest, bounds the signature count, and lets each signature work once.

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
  freshness: { clock: () => Math.floor(Date.now() / 1000), maxAge: 300, skew: 30, requireExpires: true },
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

Trusts one configured directory, refuses long-lived signatures and unrelated labels, and claims each nonce once.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { Custody, Discovery, DiscoverySource, Message, PublicKey, WebBotAuth, createMemoryStore, ok, type AgentRequest, type Result, type WebBotAuthReplayFacts } from "@request-seal/core";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
const now = () => Math.floor(Date.now() / 1000);
const sha256 = async (text: string) => new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
const agent = generateKeyPairSync("ed25519");
const jwk = agent.publicKey.export({ format: "jwk" });
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

Every failure is a `Result` with a bounded `error`; branch on `error.kind` and `error.reason`. This table is a recommendation, not a requirement. It is derived from the error vocabulary in [error parity](docs/reference/error-parity.md), and the [signing guide](docs/guides/signing-and-verifying.md#respond-to-a-rejection) holds the same mapping as a program that checks it covers every reason. Core reasons appear as `layer.reason`. Adapters wrap the underlying reason in `error.source`; map that.

The reasoning, stated once: 400 means the message cannot be read, so resending the same bytes cannot help. 401 means the sender did not prove what your policy requires, and a fresh correct signature can. 403 means your configuration refuses a sender it understood. 500 means your own code or configuration is wrong. 503 means the failure is transient or the replay store is in trouble.

| Status | Reasons |
| --- | --- |
| 400 | `fields.invalid_signature_input`, `fields.invalid_signature_field`, `fields.invalid_signature_agent`, `fields.duplicate_label`, `fields.duplicate_parameter`, `fields.label_mismatch`, `crypto.signature_base_failed`, `content.body_unavailable`, `content.digest_unsupported`, `input.invalid_message`, `input.invalid_request`, `input.limit`, `input.unsupported_component`, `negotiation.invalid_accept_signature`, `negotiation.inapplicable_component`, `negotiation.negotiation_unfulfillable`; adapter `invalid_request`, `limit`, `body_unavailable`, `digest_conflict`, `untrusted_proxy`; every `message`, `structured_fields`, `signature_base`, and `digest` error; malformed JOSE input and nesting |
| 401 | `fields.missing_signature`, `fields.missing_signature_input`, `fields.no_web_bot_auth_signature`, `fields.unknown_label`, `crypto.invalid_signature`, `content.digest_mismatch`, `content.digest_not_covered`, `freshness.created_in_future`, `freshness.expired`, `freshness.lifetime_exceeded`, `freshness.missing_created`, `freshness.missing_expires`, `freshness.too_old`, `key.unknown_key`, `key.agent_unresolved` (unless noted below), `policy.algorithm_mismatch`, `policy.algorithm_not_permitted`, `policy.invalid_keyid`, `policy.missing_required_component`, `policy.nested_coverage_incomplete`, `policy.unexpected_component`, `policy.unexpected_signature`, `quorum.binding_unsatisfied`, `quorum.nonqualifying_signature`, `quorum.quorum_not_met`, `quorum.unexpected_signature`, `negotiation.negotiation_unfulfilled`, `replay.missing_replay_identifier`, `replay.replayed`, `replay.retention_exceeded`; invalid JOSE signatures and decryption failures; discovery failures other than those below |
| 403 | `policy.test_key_rejected`, `binding.unattributed`, `binding.actor_unbound`, `binding.tenant_unbound`; discovery `revoked_key`; `key.agent_unresolved` with detail `untrusted_agent` or `revoked_key` |
| 500 | `binding.invalid_binding`, `binding.invalid_verification`, `crypto.signer_failed`, `crypto.signing_failed`, `crypto.verifier_failed`, `fields.label_in_use`, `freshness.invalid_clock`, `input.algorithm_mismatch`, `input.invalid_options`, `input.invalid_policy`, `input.invalid_profile`, `input.invalid_quorum`, `input.signer_algorithm_mismatch`, `key.key_resolver_failed`, `quorum.ambiguous_key_identity`, `replay.commitment_failed`; an adapter used in the wrong order (`parser_order`, `not_captured`, `already_verified`); invalid options anywhere; `custody` and `crypto` errors other than an invalid signature or invalid data |
| 503 | Any error with `retryable: true` (custody and discovery timeouts, unavailable sources); `replay.store_failed`, `replay.store_timeout`, `replay.store_unavailable`, and replay store errors; `key.agent_unresolved` with detail `timeout` or `source_unavailable` |

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
| Express 5.2.1 | `captureBody`, `verifyRequest` | The [Node HTTP guide](docs/guides/node-http.md) program, and the framework tests. |
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

Reference: [signing and verification](docs/reference/sign-and-verify.md), [adapters](docs/reference/adapters.md), [Web Bot Auth](docs/reference/web-bot-auth.md), [replay](docs/reference/replay.md), [discovery](docs/reference/discovery.md), [JOSE](docs/reference/jose.md), [wire APIs](docs/reference/wire.md), [multiple signatures](docs/reference/quorum.md), [extension profiles](docs/reference/profiles.md), [error parity](docs/reference/error-parity.md), and [corpus format](docs/reference/corpus-format.md). Design records: the [threat model](docs/design/threat-model.md) and the [architecture decisions](docs/adr/README.md). To contribute, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Compatibility

Crypto and custody behavior and the error vocabulary follow RequestSeal `v0.4.1`. Compatibility is checked against the byte-preserved RequestSeal `v0.4.0` corpus. The pins differ because the corpus index is unchanged and v0.4.1 supplied no corpus release assets. See [the corpus pin and update command](CONTRIBUTING.md). Development reports pending surfaces; releases require complete coverage.

The CI lane set is exact. Browser versions come from the private Playwright
1.64.0 workspace. The release workflow runs the same lanes.

| Runtime lane | Version | Declared runtime limitations |
| --- | --- | --- |
| Node 22.12.0 | 22.12.0 | OS trust requires a nonempty system store; empty-query Fetch signing returns `adapter/invalid_request`. |
| Node 24.21.0 | 24.21.0 | Fetch verification returns `adapter/invalid_request` outside the measured allowlist. |
| Node 26.11.1 | 26.11.1 | Required check name: `Node 26`; same Fetch verification restriction. |
| Deno 2.5.6 | 2.5.6 | `test_file/discovery-node.test.ts` item 1: `discovery/invalid_response`. `test_file/discovery-fixes.test.ts` item 1: `discovery/invalid_response`. |
| Deno 2.9.7 | 2.9.7 | Denied OS roots check only; without `--allow-sys=ca`, source creation and fetch return `discovery/transport_unavailable`. Full-suite support is not asserted. |
| Bun 1.3.14 | 1.3.14 | `crypto/ecdsa_secp256r1_sha256_p1363_test` items 261, 262 on darwin-arm64: `crypto/invalid_signature`. `test_file/discovery-node.test.ts` item 1: `discovery/invalid_response`. `test_file/discovery-fixes.test.ts` item 1: `discovery/invalid_response`. |
| Chromium | 156.0.8078.4 | Browser Fetch verification returns `adapter/invalid_request`. |
| Firefox | 157.0 | Browser Fetch verification returns `adapter/invalid_request`. |
| WebKit | 27.2 | `custody/ed25519_empty_message` item 1 on darwin-arm64: `custody/invalid_key`. Browser Fetch verification returns `adapter/invalid_request`. |

The consumer policy in
[`tools/conformance/runtime-limits.json`](tools/conformance/runtime-limits.json)
asserts exact release, platform where listed, and rejection. A stale entry,
different rejection, or unlisted divergence fails. Published corpus verdicts
stay unchanged. Firefox signs requests through its materialized body reader.
WebKit's empty-message Ed25519 failure is probed directly in real pages using
RFC 8032 test 1; declared refusals count as executed limitation checks.
See the [runtime matrix](docs/reference/runtime-matrix.md) for the Node floor,
additional runtime observations, OS trust permissions, and local browser commands,
and the [consumer limitation contract](docs/reference/corpus-format.md#consumer-runtime-limitations).

See [replay protection](docs/reference/replay.md) for the memory store and the
optional `@request-seal/core/replay-postgres` query adapter.
