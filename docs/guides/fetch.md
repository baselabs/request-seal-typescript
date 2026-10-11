**Status:** maintained · **Kind:** guide · **Updated:** October 11, 2026 · **Governed by:** RFC 9421, the Fetch standard, and executed Node and Deno transport tests · **Review when:** a supported runtime version or the Fetch adapter contract changes

# Fetch

`@request-seal/core/fetch` signs outgoing `Request` and `Response` objects and sends signed requests with `fetch`. It also verifies incoming requests and responses on the runtime versions the tests have measured. It exports `signedFetch`, `signRequest`, `signResponse`, `verifyRequest`, and `verifyResponse`. The [adapter reference](../reference/adapters.md#fetch) has the complete option list.

## Send a signed request

`signedFetch(input, init, { spec, signer }, options)` is `fetch` plus signing. `spec` is the same signature spec that `sign` takes, and `signer` is a key handle or a signing function. The call returns a `Result` holding `{ response, request }`: the response, and the exact signed request that was sent.

Three behaviors matter in production.

- **Every attempt is signed afresh.** A retry or redirect builds a new signature with a new `created` time and a new nonce, so a retried request is never a replay of the first one.
- **Redirects and retries are off by default.** `maxRedirects` and `maxRetries` each default to 0 and accept up to 10. Only 5xx responses are retried. A redirect that leaves the original origin needs that origin in `allowedOrigins`, and the adapter then removes `Authorization`, `Cookie`, `Proxy-Authorization`, and any `credentialHeaders` you list.
- **One deadline covers the exchange.** Pass `context: withDeadline({ timeoutMs })` to bound every body read, signature, redirect, retry, and delivery together. The default is five seconds.

The program signs a POST, receives a 503, retries once, and checks that the two attempts carry different nonces.

```ts
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { Custody, type Result } from "@request-seal/core";
import { signedFetch } from "@request-seal/core/fetch";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
const signer = must(await Custody.local("hmac-sha256", { hmac: crypto.getRandomValues(new Uint8Array(32)) }));

// A server that fails once, then succeeds, and remembers what it was sent.
const seen: string[] = [];
const server = createServer((req, res) => {
  seen.push(String(req.headers["signature-input"]));
  req.resume();
  res.statusCode = seen.length === 1 ? 503 : 200;
  res.end("done");
}).listen(0, "127.0.0.1");
await once(server, "listening");
const url = `http://127.0.0.1:${(server.address() as { port: number }).port}/orders`;

const spec = { label: "sig", components: '("@method" "@authority" "@path" "content-digest")', algorithm: "hmac-sha256", expiresIn: 60, digest: ["sha-256"] };
const sent = must(await signedFetch(url, { method: "POST", body: "hello" }, { spec, signer }, { maxRetries: 1 }));
assert.equal(sent.response.status, 200);
assert.equal(seen.length, 2);
// Each attempt is signed afresh: the nonce differs, so a retry never replays an old signature.
const nonce = (input: string) => /nonce="([^"]+)"/.exec(input)![1];
assert.notEqual(nonce(seen[0]!), nonce(seen[1]!));
// The exact request that went out is returned for logging or inspection.
assert.equal(sent.request.request.method, "POST");
server.close();
server.closeAllConnections();
```

`signedFetch` sets `redirect` to manual and `Accept-Encoding` to `identity`, because a decoded body is not the body that was signed. A caller-supplied `Host`, or an `Accept-Encoding` other than `identity`, returns `invalid_options` before anything is sent. The body is read once and retained within `maxBytes` (1 MiB, which is both the default and the maximum) so each attempt can sign the same bytes.

### Fields the runtime controls

A runtime sets some fields itself, so a signature that covers them could never verify. Signing refuses `host`, `content-length`, `accept-encoding`, `connection`, `transfer-encoding`, `trailer`, `keep-alive`, `proxy-connection`, `te`, and `upgrade`. Node also refuses `sec-fetch-mode`, which undici overrides. Cover `@authority` instead of `host`, and `content-digest` instead of `content-length`.

## Sign a request or a response yourself

`signRequest(request, spec, signer, options)` returns `{ request, message }`: a rebuilt `Request` with the signature headers, and the `Message` that was signed. `signResponse(response, spec, signer, { request })` does the same for a `Response`; pass the request so the signature can cover request components with `;req`. The body of the input is consumed once, so always use the rebuilt value that comes back.

## Verify incoming requests

`verifyRequest(request, policy, { label, scheme, authority })` verifies a `Request` against a generic `Policy` and returns `{ request, message, verification, bytes }`. `bytes` is a copy of the verified body, and `request` is a rebuilt request holding exactly those bytes, so read the body from it and not from the original.

Two rules keep Fetch verification honest.

1. **You supply `scheme` and `authority`.** A `Request` seen by a server often carries a rewritten URL. Give the adapter the origin your service owns, from configuration, and never copy it from the request.
2. **Verification runs only on measured runtimes.** The `FETCH_VERIFICATION_RUNTIMES` export lists them; today it is `deno:2.5.6`. On any other runtime or version both verify functions return `invalid_request` before they read the body, call a clock, or resolve a key. Fetch implementations differ in how they treat header whitespace, duplicate fields, cookies, and unusual methods, and RequestSeal verifies only where the tests recorded the behavior. Use [Node HTTP](node-http.md) on Node.

The adapter also refuses components that Fetch cannot reproduce exactly. A policy that requires `@request-target`, `@target-uri`, `@path`, `@query`, `cookie`, or a `bs` or `tr` parameter makes verification return `unsupported_component` before key resolution. Cover `@method`, `@scheme`, `@authority`, `@query-param`, header fields, and `content-digest` instead.

The next program runs under Deno. A `Deno.serve` handler verifies a request that `signedFetch` signed, and a plain unsigned request gets 401.

<!-- run: deno -->
```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { Custody, Policy, PublicKey, ok, type KeyResolver, type Result } from "@request-seal/core";
import { signedFetch, verifyRequest } from "@request-seal/core/fetch";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
const pair = generateKeyPairSync("ed25519");
const signer = must(await Custody.local("ed25519", pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string));
const trusted = must(await PublicKey.import(pair.publicKey.export({ format: "jwk" })));
const components = '("@method" "@scheme" "@authority" "content-digest")';
const keyResolver: KeyResolver = () => ok({ algorithm: "ed25519", key: trusted });
const policy = must(Policy.create({
  algorithms: ["ed25519"], components, keyResolver,
  freshness: { clock: () => Math.floor(Date.now() / 1000), maxAge: 60, skew: 5, requireExpires: true },
  content: { kind: "content", algorithms: ["sha-256"], section: "headers" }, replay: "not_required",
}));

let authority = "";
const server = Deno.serve({ hostname: "127.0.0.1", port: 0, onListen: ({ port }) => { authority = `127.0.0.1:${port}`; } }, async (request) => {
  // Scheme and authority come from your configuration, never from the request itself.
  const verified = await verifyRequest(request, policy, { label: "sig", scheme: "http", authority });
  return verified.ok ? new Response(new TextDecoder().decode(verified.value.bytes)) : new Response(null, { status: 401 });
});
const spec = { label: "sig", components, algorithm: "ed25519", expiresIn: 60, digest: ["sha-256"] };
const sent = must(await signedFetch(`http://${authority}/orders`, { method: "POST", body: "hello" }, { spec, signer }));
assert.equal(await sent.response.text(), "hello");
const unsigned = await fetch(`http://${authority}/orders`, { method: "POST", body: "hello" });
assert.equal(unsigned.status, 401);
await unsigned.body?.cancel();
await server.shutdown();
```

## Verify responses

`verifyResponse(response, policy, { label, request })` verifies a response and, with `request` set to the signed request you sent, binds it to that request. `signedFetch` can do this for you: pass `{ verify: { policy, label } }` in the options and it withholds every response until it verifies. Response content checks do not apply on this adapter, because Fetch hides content encodings: a policy that requires a content digest on a response returns `body_unavailable`. Verify response digests only when the response arrives through [Node HTTP](node-http.md).

## Where to go next

- [Node HTTP](node-http.md) verifies incoming requests on Node, behind Express or Fastify.
- [Replay protection](replay-protection.md) rejects a verified request that is sent a second time.
- [Testing](testing.md) explains the runtime lanes and what each measured runtime proves.
