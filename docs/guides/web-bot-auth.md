**Status:** maintained · **Kind:** guide · **Updated:** October 11, 2026 · **Governed by:** draft-ietf-webbotauth-httpsig-protocol-00, RFC 9421, and the executed examples in this guide · **Review when:** the Web Bot Auth draft, discovery behavior, or the policy contract changes

# Web Bot Auth

Web Bot Auth lets an automated agent, such as a crawler or an AI assistant, sign its HTTP requests so that a site can tell who is calling. The agent publishes its public keys at a URL it controls, names that URL in a `Signature-Agent` header, and signs each request. The site decides which agents to trust, checks the signature against keys it learned from that trusted source, and gets back a verified agent identity.

RequestSeal implements [draft-ietf-webbotauth-httpsig-protocol-00](https://www.ietf.org/archive/id/draft-ietf-webbotauth-httpsig-protocol-00.html) from the IETF Web Bot Auth working group. A draft can change, so pin your RequestSeal version and read the changelog before upgrading. The [Web Bot Auth reference](../reference/web-bot-auth.md) lists every option and rule.

## What a signed agent request carries

Every Web Bot Auth signature has the tag `web-bot-auth`, a `created` and `expires` time, a key ID that is the key's RFC 7638 SHA-256 thumbprint, and coverage of either `@authority` or `@target-uri`. When the request carries a `Signature-Agent` dictionary, the signature also covers its matching member. HMAC is forbidden. A signer may choose a lifetime of at most 86,400 seconds. A verifier's `maxLifetime` defaults to 86,400 and can be raised to 604,800.

## Verify as a site

You decide whom to trust before any request arrives. Two trust choices cover most sites.

**Trust an agent's directory.** Your `agents` callback receives the agent URL a request names and returns the key set you already trust for it, or `ok(null)` to refuse. The request never selects the network destination. A key set comes from a directory the agent publishes, fetched and cached by you ([key discovery](key-discovery.md)) or supplied as a snapshot you already hold. By default a directory snapshot must carry a signed proof that the publisher holds its keys.

The first program builds that whole path locally. The publisher signs its directory response with one of the keys in it, the site loads the response as a key set, and the policy trusts exactly that directory. The last lines show a request that names an agent you did not configure being refused before any key is used.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { Custody, Discovery, DiscoverySource, Message, PublicKey, WebBotAuth, ok, sign, type AgentRequest, type Result } from "@request-seal/core";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
const now = Math.floor(Date.now() / 1000);
const pair = generateKeyPairSync("ed25519");
const jwk = pair.publicKey.export({ format: "jwk" });
const botKey = must(await PublicKey.import(jwk));
const thumbprint = must(await botKey.thumbprint());
const signer = must(await Custody.local("ed25519", pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string));

// 1. The publisher answers GET https://bot.example/.well-known/http-message-signatures-directory
//    with its keys, signed by one of those keys so a reader knows the publisher holds it.
const probe = must(await Message.request("GET", "https://bot.example/.well-known/http-message-signatures-directory", [], ""));
const body = new TextEncoder().encode(JSON.stringify({ keys: [jwk] }));
const response = must(await Message.response(200, [["content-type", "application/http-message-signatures-directory+json"]], body, { request: probe, digest: ["sha-256"] }));
const proof = must(await sign(response, {
  label: "directory", components: '("@authority";req "content-digest")', algorithm: "ed25519", expiresIn: 3600,
  keyid: thumbprint, tag: "http-message-signatures-directory", nonce: null,
}, signer));
const headers = proof.fields.map((f) => [f.name, new TextDecoder().decode(f.value)] as [string, string]);

// 2. The site turns those fetched bytes into a key set. The default requires the proof to verify.
const source = must(DiscoverySource.create({ type: "directory", location: "https://bot.example" }));
const keys = must(await Discovery.resolver.fromSnapshot(source, body, now, headers));

// 3. The site trusts exactly the directory it configured, and nothing a request names.
const policy = must(WebBotAuth.Policy.create({
  algorithms: ["ed25519"],
  agents: ({ location }: AgentRequest) => ok(location === keys.origin ? keys : null),
  cache: null,
  freshness: { clock: () => now, maxAge: 60, skew: 5 },
  content: "not_required",
  replay: "not_required",
}));

// 4. The bot signs a request that points at its directory.
const request = must(await Message.request("GET", "https://site.example/page", [], ""));
const agent = { location: "https://bot.example", type: "directory" } as const;
const signed = must(await WebBotAuth.sign(request, { label: "bot", key: botKey, algorithm: "ed25519", agent, created: now, expires: now + 60, nonce: null }, signer));

const envelope = must(await WebBotAuth.verify(signed, policy));
const principal = envelope.signatures.bot!.principal;
assert.equal(principal.kind, "agent");
assert.equal(envelope.authorization, "not_evaluated");

// A request that names an agent you did not configure is refused before any key is used.
const stranger = must(await WebBotAuth.sign(request, { label: "bot", key: botKey, algorithm: "ed25519", agent: { location: "https://other.example", type: "directory" }, created: now, expires: now + 60, nonce: null }, signer));
const refused = await WebBotAuth.verify(stranger, policy);
assert.ok(!refused.ok && refused.error.kind === "core" && refused.error.reason === "agent_unresolved");
```

**Pin a key.** With no directory at all, you can trust a specific public key that you obtained by another route. Set `agents` to refuse everything and give `unresolved.heldKeys` a resolver for the pinned thumbprint. The result then records a `key` principal rather than an `agent` principal, because possession of the key does not certify the URL the request advertises.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { Custody, Message, PublicKey, WebBotAuth, ok, type KeyResolver, type Result } from "@request-seal/core";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
const now = Math.floor(Date.now() / 1000);
const pair = generateKeyPairSync("ed25519");
const botKey = must(await PublicKey.import(pair.publicKey.export({ format: "jwk" })));
const pinned = must(await botKey.thumbprint()); // Configure this thumbprint out of band, for example in your settings.
const signer = must(await Custody.local("ed25519", pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string));

// Trust no agent URL. Trust exactly one public key, by its RFC 7638 thumbprint.
const heldKeys: KeyResolver = ({ keyid }) => ok(keyid === pinned ? { algorithm: "ed25519", key: botKey } : null);
const policy = must(WebBotAuth.Policy.create({
  algorithms: ["ed25519"],
  agents: () => ok(null),
  unresolved: { heldKeys },
  cache: null,
  freshness: { clock: () => now, maxAge: 60, skew: 5 },
  content: "not_required",
  replay: "not_required",
}));

const request = must(await Message.request("GET", "https://site.example/page", [], ""));
const signed = must(await WebBotAuth.sign(request, {
  label: "bot", key: botKey, algorithm: "ed25519",
  agent: { location: "https://bot.example", type: "directory" }, created: now, expires: now + 60, nonce: null,
}, signer));
const envelope = must(await WebBotAuth.verify(signed, policy));
const principal = envelope.signatures.bot!.principal;
// A held key proves possession of a key you pinned. It does not certify the advertised URL.
assert.deepEqual(principal, { kind: "key", thumbprint: pinned });

// A key you did not pin is refused, even when it claims the pinned agent URL.
const other = generateKeyPairSync("ed25519");
const otherKey = must(await PublicKey.import(other.publicKey.export({ format: "jwk" })));
const otherSigner = must(await Custody.local("ed25519", other.privateKey.export({ type: "pkcs8", format: "pem" }) as string));
const forged = must(await WebBotAuth.sign(request, {
  label: "bot", key: otherKey, algorithm: "ed25519",
  agent: { location: "https://bot.example", type: "directory" }, created: now, expires: now + 60, nonce: null,
}, otherSigner));
const refused = await WebBotAuth.verify(forged, policy);
assert.ok(!refused.ok && refused.error.kind === "core" && refused.error.reason === "agent_unresolved");
```

### Reading the result

`WebBotAuth.verify(message, policy)` validates every selected `web-bot-auth` label independently and returns a frozen envelope: `signatures` (a map from label to a verified result with a `principal`), `evidence` for nested signatures, `ignored` labels, a `replay` receipt, and `authorization: "not_evaluated"`. The principal is `{ kind: "agent", identifier, type, origin, thumbprint, provenance }` when a trusted source vouched for the key, or `{ kind: "key", thumbprint }` for a held key. Authentication is not authorization: decide what the agent may do after you have its identity.

### Policy choices

`WebBotAuth.Policy.create` takes the generic policy choices plus agent trust:

| Choice | Meaning |
| --- | --- |
| `algorithms` | Accepted HTTP algorithms. HMAC is not allowed. |
| `agents` | Callback `({ identifier, location, type }) => Result` returning a `DiscoverySource`, a fresh `KeySet`, or `null` to refuse. |
| `cache` | A caller-owned discovery cache, or `null` when `agents` returns key sets. |
| `freshness` | `{ clock, maxAge, skew }`. Expiry is always required. |
| `content`, `replay` | As for generic policies. Replay claims once, after every selected signature and nested check passes. See [replay protection](replay-protection.md). |
| `components` | Extra coverage to require. Default `"()"`; authority or target URI coverage is always required. |
| `maxLifetime` | 1 to 604,800 seconds, default 86,400. |
| `testKeys` | `"reject"` (default) refuses published example keys; `"allow"` is for tests. |
| `untagged` | `"ignore"` (default) records labels that are not Web Bot Auth in `ignored`; `"reject"` refuses them. |
| `unresolved` | `"reject"` (default) or `{ heldKeys }` to pin keys. |

Time-limited work runs under one deadline: `timeoutMs` (1 to 300,000 milliseconds, default 5,000) covers trust, discovery, verification, content, and replay. A deadline during trust or discovery is `agent_unresolved` with detail `timeout`; a deadline inside signature checking is a retryable `custody/deadline_exceeded`.

### Express, Hono, and the Node adapter

[`verifyWebBotAuth` in the Node adapter](node-http.md) verifies a captured Node request, which is how the Express example in the [README](../../README.md) works. On Deno, build a `Message` from the incoming `Request` with the origin your service owns and call `WebBotAuth.verify`, as the Hono example in the README does. Hono is your dependency, not RequestSeal's: the README example pins `jsr:@hono/hono@4.10.3` so it runs as written, and you install the version you choose. The Fetch adapter's `verifyRequest` takes generic policies only.

## Sign as an agent

`WebBotAuth.sign(message, spec, signer)` takes a request message and a spec with `label`, `agent: { location, type }`, the agent's public `key`, `algorithm`, explicit `created` and `expires` times, and a `nonce` (a non-empty string, or `null`). The signer is a key handle or a signing function. Signing derives the key ID from the key, adds the `Signature-Agent` member and the `@authority` coverage, and stamps the parameters in the order the draft expects. Lifetimes are positive and at most 86,400 seconds. A conflicting existing `Signature-Agent` member is refused before the signing key is touched.

Include a fresh `nonce` whenever the site may require replay protection; a `null` nonce signs without one and a site that requires replay refuses it with `missing_replay_identifier`.

## Errors you will see

| Reason | Meaning |
| --- | --- |
| `agent_unresolved` | Trust could not connect the signature to a key. The detail says why: `untrusted_agent`, `unknown_key`, `source_mismatch`, `revoked_key`, `missing_member`, `unsupported_type`, `not_an_origin`, `source_unavailable`, or `timeout`. It does not claim the signature is invalid. |
| `invalid_signature_agent` | The `Signature-Agent` field breaks the draft's dictionary rules, or uses the legacy string form. |
| `lifetime_exceeded` | `expires` minus `created` is longer than `maxLifetime`. |
| `nested_coverage_incomplete` | An outer signature does not cover the inner signature and its components. |
| `test_key_rejected` | The key is a published example key. |
| `no_web_bot_auth_signature` | No signature carries the `web-bot-auth` tag. |

The [README](../../README.md#reason-to-http-status-recommendation) maps each of these to an HTTP status.

## Where to go next

- [Key discovery](key-discovery.md) shows how to fetch and cache an agent's directory over HTTPS.
- [Replay protection](replay-protection.md) adds one-time use of each nonce.
- [Node HTTP](node-http.md) verifies live Node requests.
