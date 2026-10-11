**Status:** maintained · **Kind:** guide · **Updated:** October 11, 2026 · **Governed by:** RFC 9421, RFC 9113, and executed Node, Express, and Fastify transport tests · **Review when:** a supported Node version, framework version, or adapter contract changes

# Node HTTP, Express, and Fastify

`@request-seal/core/node-http` connects RequestSeal to Node servers and clients. It turns a live request into a `Message` that keeps the exact target, the raw header occurrences in order, the trailers, and the body bytes, and it verifies that message against your policy. The [adapter reference](../reference/adapters.md#node-http) lists every option.

## Why capture comes first

A signature covers bytes. By the time a framework has parsed a request, the raw target may be rewritten, header names may be lowercased and merged, and the body may be a JavaScript object. The adapter therefore **captures** the request before anything else touches it, and verification runs against the capture.

- `captureRequest(req, options)` runs as the first middleware, or first in a plain handler. It reads the body, retains at most `maxBytes` (1 MiB, the default and the maximum), and records the request line and headers.
- `capture(server, options)` installs a listener that runs before the application listener and returns a registration you can close. Use it with frameworks that give you no early hook.
- `captureBody(req, bytes)` hands the adapter bytes that a body parser has already read. It is the Express recipe below.

Capture owns the request stream. A second data listener, or a flowing consumer reading while capture reads, returns `parser_order`. A declared `Content-Length` that disagrees with the retained bytes returns `body_unavailable`.

`verifyRequest(req, policy, { label })` returns `{ capture, verification, bytes }`. `bytes` are copies of the authenticated body. Parse those bytes, not the original stream: the stream is consumed. The adapter allows one verification per request, so a second call returns `already_verified`, and `verification(req)` returns the stored result.

## A plain Node server

The server captures first, verifies, and reads the JSON from the authenticated bytes. An unsigned request gets 401.

```ts
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { Custody, Policy, ok, type KeyResolver, type Result } from "@request-seal/core";
import { captureRequest, signedRequest, verifyRequest } from "@request-seal/core/node-http";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
const key = must(await Custody.local("hmac-sha256", { hmac: crypto.getRandomValues(new Uint8Array(32)) }));
const components = '("@method" "@request-target" "content-digest")';
const keyResolver: KeyResolver = () => ok({ algorithm: "hmac-sha256", key });
const policy = must(Policy.create({
  algorithms: ["hmac-sha256"], components, keyResolver,
  freshness: { clock: () => Math.floor(Date.now() / 1000), maxAge: 60, skew: 5, requireExpires: true },
  content: { kind: "content", algorithms: ["sha-256"], section: "headers" }, replay: "not_required",
}));

const server = createServer(async (req, res) => {
  const captured = await captureRequest(req); // First, before anything reads the body.
  const verified = captured.ok ? await verifyRequest(req, policy, { label: "sig" }) : captured;
  if (!verified.ok) return void res.writeHead(401).end();
  res.end(`hello ${JSON.parse(new TextDecoder().decode(verified.value.bytes)).name}`);
}).listen(0, "127.0.0.1");
await once(server, "listening");
const url = `http://127.0.0.1:${(server.address() as { port: number }).port}/greet?lang=en`;

const spec = { label: "sig", components, algorithm: "hmac-sha256", expiresIn: 60, digest: ["sha-256"] };
const body = new TextEncoder().encode('{"name":"Ada"}');
const reply = must(await signedRequest({ url, method: "POST", body }, spec, key));
assert.equal(reply.status, 200);
assert.equal(new TextDecoder().decode(reply.bytes), "hello Ada");
const unsigned = await fetch(url, { method: "POST", body });
assert.equal(unsigned.status, 401);
server.close();
server.closeAllConnections();
```

`signedRequest` is the matching client. It sends through `http.request` or `https.request`, signs every hop and retry afresh, and defaults to no redirects and no retries.

## Behind a reverse proxy

Behind a proxy or load balancer the socket peer is the proxy, and the public scheme and host arrive in a `Forwarded` or `X-Forwarded-*` header. Anyone can send those headers, so the adapter ignores them unless you configure `trustedProxies: { peers, field }`: the CIDR ranges or addresses of the proxies you trust, and which field to read (`forwarded` or `x-forwarded`). When the actual socket peer matches, the last element supplies the external scheme and authority. Observed connection facts stay separate in `capture.ingress`.

The program below signs a request for `https://api.example.com`, delivers it to a private listener through a trusted proxy address, and shows that the same bytes fail when the forwarding header is missing.

```ts
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { Custody, Message, Policy, ok, sign, type KeyResolver, type Result } from "@request-seal/core";
import { captureRequest, verifyRequest } from "@request-seal/core/node-http";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
const key = must(await Custody.local("hmac-sha256", { hmac: crypto.getRandomValues(new Uint8Array(32)) }));
const components = '("@method" "@scheme" "@authority" "@path")';
const keyResolver: KeyResolver = () => ok({ algorithm: "hmac-sha256", key });
const policy = must(Policy.create({
  algorithms: ["hmac-sha256"], components, keyResolver,
  freshness: { clock: () => Math.floor(Date.now() / 1000), maxAge: 60, skew: 5, requireExpires: true },
  content: "not_required", replay: "not_required",
}));

// Behind a proxy the socket peer is the proxy. Trust its Forwarded header only when the peer matches.
const trustedProxies = { peers: ["127.0.0.0/8"], field: "forwarded" };
const server = createServer(async (req, res) => {
  const captured = await captureRequest(req, { trustedProxies });
  const verified = captured.ok ? await verifyRequest(req, policy, { label: "sig" }) : captured;
  res.writeHead(verified.ok ? 200 : 401).end(verified.ok ? `${captured.ok && captured.value.origin.authority}` : "");
}).listen(0, "127.0.0.1");
await once(server, "listening");

// The client signed for the public origin; the proxy forwards it to the private listener.
const request = must(await Message.request("GET", "https://api.example.com/orders", [], ""));
const signed = must(await sign(request, { label: "sig", components, algorithm: "hmac-sha256", expiresIn: 60 }, key));
const headers = signed.fields.map((f) => [f.name, new TextDecoder().decode(f.value)] as [string, string]);
const url = `http://127.0.0.1:${(server.address() as { port: number }).port}/orders`;
const viaProxy = await fetch(url, { headers: [...headers, ["forwarded", "proto=https;host=api.example.com"]] });
assert.equal(await viaProxy.text(), "api.example.com");
// Without the Forwarded header the origin is the private listener, so the signature does not match.
const direct = await fetch(url, { headers });
assert.equal(direct.status, 401);
server.close();
server.closeAllConnections();
```

## Express

Express parses the body before your route runs, so capture the parser bytes with its `verify` hook and verify afterward. Set `inflate: false`: only identity (undecoded) bodies can be authenticated byte for byte. Capture must happen before any middleware rewrites `req.url`; the adapter reads `originalUrl` when Express has rewritten it.

```ts
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { once } from "node:events";
import { Custody, Policy, ok, type KeyResolver, type Result } from "@request-seal/core";
import { captureBody, signedRequest, verifyRequest } from "@request-seal/core/node-http";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
// In your project: import express from "express". This repository loads the version its tests pin.
const express = createRequire(new URL("../../interop/adapters/package.json", import.meta.url))("express");
const key = must(await Custody.local("hmac-sha256", { hmac: crypto.getRandomValues(new Uint8Array(32)) }));
const components = '("@method" "@request-target" "content-digest")';
const keyResolver: KeyResolver = () => ok({ algorithm: "hmac-sha256", key });
const policy = must(Policy.create({
  algorithms: ["hmac-sha256"], components, keyResolver,
  freshness: { clock: () => Math.floor(Date.now() / 1000), maxAge: 60, skew: 5, requireExpires: true },
  content: { kind: "content", algorithms: ["sha-256"], section: "headers" }, replay: "not_required",
}));

const app = express();
app.use(express.json({
  inflate: false, // Only identity bodies can be authenticated byte for byte.
  verify(req: unknown, _res: unknown, buf: Buffer) { must(captureBody(req, buf)); }, // Hands the parser's raw bytes to RequestSeal.
}));
app.use(async (req: any, res: any) => {
  const verified = await verifyRequest(req, policy, { label: "sig" });
  if (!verified.ok) return res.status(401).end();
  // req.body is the parser's output for exactly the bytes that were verified.
  assert.deepEqual(req.body, JSON.parse(new TextDecoder().decode(verified.value.bytes)));
  res.json({ accepted: req.body.name });
});
const server = createServer(app).listen(0, "127.0.0.1");
await once(server, "listening");
const url = `http://127.0.0.1:${(server.address() as { port: number }).port}/people?x=1`;

const spec = { label: "sig", components, algorithm: "hmac-sha256", expiresIn: 60, digest: ["sha-256"] };
const body = new TextEncoder().encode('{"name":"Ada"}');
const reply = must(await signedRequest({ url, method: "POST", headers: [["Content-Type", "application/json"]], body }, spec, key));
assert.equal(new TextDecoder().decode(reply.bytes), '{"accepted":"Ada"}');
const unsigned = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body });
assert.equal(unsigned.status, 401);
server.close();
server.closeAllConnections();
```

Express is your dependency. In your project install it with `npm install express` and import it normally. The `createRequire` line exists only so this repository can run the program against the version its tests pin.

## Fastify

Fastify parses after `preParsing`, so capture the raw request there and return the retained bytes as the stream Fastify parses. Register `capture(app.server)` first so the adapter snapshots the request line and headers before Fastify handles them. Returning a different stream would change what the parser reads and defeat the check: the replay stream verifies that every byte it handed out matches the capture.

```ts
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { Custody, Policy, ok, type KeyResolver, type Result } from "@request-seal/core";
import { capture, captureRequest, signedRequest, verifyRequest } from "@request-seal/core/node-http";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
// In your project: import Fastify from "fastify". This repository loads the version its tests pin.
const fastify = createRequire(new URL("../../interop/adapters/package.json", import.meta.url))("fastify");
const key = must(await Custody.local("hmac-sha256", { hmac: crypto.getRandomValues(new Uint8Array(32)) }));
const components = '("@method" "@request-target" "content-digest")';
const keyResolver: KeyResolver = () => ok({ algorithm: "hmac-sha256", key });
const policy = must(Policy.create({
  algorithms: ["hmac-sha256"], components, keyResolver,
  freshness: { clock: () => Math.floor(Date.now() / 1000), maxAge: 60, skew: 5, requireExpires: true },
  content: { kind: "content", algorithms: ["sha-256"], section: "headers" }, replay: "not_required",
}));

const app = fastify({ logger: false });
must(capture(app.server)); // Snapshots each request's raw target and headers before Fastify touches them.
app.addHook("preParsing", async (request: any) => {
  const captured = must(await captureRequest(request.raw));
  const replay = must(captured.replay()); // The retained bytes, handed to Fastify's parser.
  Object.defineProperty(replay, "receivedEncodedLength", { value: captured.message.body.bytes!.length });
  return replay;
});
app.post("/*", async (request: any, reply: any) => {
  const verified = await verifyRequest(request.raw, policy, { label: "sig" });
  if (!verified.ok) return reply.code(401).send();
  return { accepted: request.body.name };
});
await app.listen({ port: 0, host: "127.0.0.1" });
const address = app.server.address() as { port: number };
const url = `http://127.0.0.1:${address.port}/people?x=1`;

const spec = { label: "sig", components, algorithm: "hmac-sha256", expiresIn: 60, digest: ["sha-256"] };
const body = new TextEncoder().encode('{"name":"Ada"}');
const reply = must(await signedRequest({ url, method: "POST", headers: [["Content-Type", "application/json"]], body }, spec, key));
assert.equal(new TextDecoder().decode(reply.bytes), '{"accepted":"Ada"}');
const unsigned = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body });
assert.equal(unsigned.status, 401);
await app.close();
```

As with Express, Fastify is your dependency and the program loads the copy this repository pins.

## Responses, Web Bot Auth, and quorums

- `signResponse(res, spec, signer, { body, request })` signs a final response over exactly the bytes it will send, then writes and ends the response. Do not write to the response afterward.
- `verifyWebBotAuth(req, policy, { timeoutMs })` verifies a Web Bot Auth request over the same capture. See [Web Bot Auth](web-bot-auth.md).
- `verifyQuorum(req, quorum, options)` verifies several signatures from one request. See [multiple signatures](../reference/quorum.md).

All three share the one-verification-per-request rule.

## Where to go next

- [Replay protection](replay-protection.md) rejects a verified request that is sent again.
- [Signing and verifying](signing-and-verifying.md) lists the status codes to send when verification fails.
- [Testing](testing.md) shows how the framework tests run against real Express and Fastify.
