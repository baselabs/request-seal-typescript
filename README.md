**Status:** development · **Kind:** overview · **Updated:** October 10, 2026 · **Governed by:** RequestSeal v0.4.1 behavior and error vocabulary, and the shared v0.4.0 conformance corpus · **Review when:** package scope or installation changes

# RequestSeal

RequestSeal will provide standards-based HTTP message signatures and JOSE for TypeScript applications using WebCrypto. The first npm release is pending.

After publication:

```sh
npm install @request-seal/core
```

For development, use Node 22.12.0 or newer:

```sh
npm ci --ignore-scripts
npm run check
```

The current package contains results, bounded errors, byte codecs, ordered JSON, numeric guards, deadline contexts, option snapshots, Structured Fields, lossless HTTP messages, RFC 9421 signature-base construction, cryptographic verification, public key formats, caller-owned local custody, HTTP signing and verification, explicit policies, the Profile extension surface, content digests, quorum verification and Accept-Signature negotiation, compact JWS/JWE with one-level nesting, discovery snapshots and caches, and an explicit HTTPS discovery transport through `@request-seal/core/discovery-node`. See [extension profiles](docs/reference/profiles.md), [multiple signatures](docs/reference/quorum.md), [JOSE APIs](docs/reference/jose.md), [signing and verification](docs/reference/sign-and-verify.md), [wire APIs](docs/reference/wire.md), [discovery](docs/reference/discovery.md), [error parity](docs/reference/error-parity.md), and [corpus format](docs/reference/corpus-format.md).

```ts
import { Custody, Crypto } from "@request-seal/core";

// Generate example material; applications supply their own private PEM.
const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
const der = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
const privatePem = "-----BEGIN PRIVATE KEY-----\n" +
  btoa(Array.from(der, b => String.fromCharCode(b)).join("")) +
  "\n-----END PRIVATE KEY-----";
der.fill(0);
const messageBytes = new TextEncoder().encode("RequestSeal example");
const imported = await Custody.local("ed25519", privatePem);
if (imported.ok) {
  const handle = imported.value;
  try {
    const signature = await Crypto.sign("ed25519", handle, messageBytes);
    if (signature.ok) {
      const verified = await Crypto.verify("ed25519", handle, signature.value, messageBytes);
      console.log(verified.ok);
    }
  } finally {
    await handle.release();
  }
}
```

HTTP tokens and JWS selectors are separate: use `{jws: "EdDSA"}` explicitly for
a JWS-bound handle. Handle methods accept a `withDeadline()` context.
`PublicKey.import()` accepts public JWK, PEM, or SPKI DER; public exports preserve
metadata restrictions and thumbprints follow RFC 7638. HMAC identities are optional
caller-supplied nonsecret values, never hashes of secrets. RSA-OAEP handles unwrap
into an AES operation capability; they return neither key bytes nor CryptoKey
references. See the [custody threat model](docs/design/threat-model.md).

## HTTP signing, verification, and digests

Use `sign()` and `verify()` with explicit `Policy` values, caller-owned key
resolvers, and replay storage. `Digest` handles RFC 9530 content digests;
`DigestState` supports incremental hashing. See [signing and verification](docs/reference/sign-and-verify.md).

## Web Bot Auth

Verify a protocol-00 request with a caller-trusted, fresh directory `keySet`
and captured branded `message`. The application supplies `now` in Unix seconds.

```ts
import { WebBotAuth, ok, type AgentRequest } from "@request-seal/core";

const policy = WebBotAuth.Policy.create({
  algorithms: ["ed25519"],
  agents: ({ location }: AgentRequest) => ok(location === keySet.origin ? keySet : null),
  cache: null,
  freshness: { clock: () => now, maxAge: 60, skew: 5 },
  content: "not_required",
  replay: "not_required",
});
if (!policy.ok) throw new Error(policy.error.reason);
const authenticated = await WebBotAuth.verify(message, policy.value);
```

Supply your own signed directory snapshot or explicitly configured discovery
cache. Add required replay storage for nonce uniqueness. See
[Web Bot Auth](docs/reference/web-bot-auth.md) for signing, trust, held keys,
nested signatures, result facts, and replay commitments.

## JOSE

Use `JWS` for compact signing and verification, `JWE` for encryption and
authenticated decryption, and `Nested` for one-level nesting. Supply explicit
algorithm policies and caller-owned custody or `KeyManagement` capabilities.
See [JOSE APIs](docs/reference/jose.md).

## HTTP adapters and SSH custody

Use `@request-seal/core/node-http` for Node ingress and clients, `@request-seal/core/fetch`
for Fetch signing and proven Deno verification, and
`@request-seal/core/custody-ssh-agent` for caller-selected OpenSSH custody.
See [adapter contracts and framework recipes](docs/reference/adapters.md).

```ts
import {captureRequest, verifyRequest} from "@request-seal/core/node-http";

async function authenticate(req, policy) {
  const captured = await captureRequest(req); // Before body parsers.
  if (!captured.ok) return captured;
  const verified = await verifyRequest(req, policy, {label: "sig"});
  if (!verified.ok) return verified;
  // Feed the parser these authenticated bytes; the original stream is consumed.
  req.body = JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(verified.value.bytes));
  return verified;
}
```

For Web Bot Auth, supply a branded `WebBotAuth.Policy` with caller-configured
agent trust and discovery. The result is also available through `verification(req)`:

```ts
import {captureRequest, verifyWebBotAuth} from "@request-seal/core/node-http";

async function authenticateBot(req, policy) {
  const captured = await captureRequest(req); // Before body parsers.
  if (!captured.ok) return captured;
  return verifyWebBotAuth(req, policy, {timeoutMs: 5000});
}
```

```ts
import {signedFetch} from "@request-seal/core/fetch";

async function send(url, spec, signer) {
  return signedFetch(url, {method: "POST", body: "hello"}, {spec, signer});
}
```

```ts
import {createSshAgent} from "@request-seal/core/custody-ssh-agent";

async function bindAgent(socketPath, publicKey) {
  return createSshAgent("ed25519", socketPath, publicKey);
}
```

The caller supplies the socket and branded public key and owns agent startup
and key loading. Every returned signature is verified locally.

Fetch verification returns `invalid_request` outside the tested Deno 2.5.6
allowlist. Exact-target, cookie, and per-occurrence byte coverage remain refused.

## Compatibility

Crypto and custody behavior and the error vocabulary follow RequestSeal `v0.4.1`. Compatibility is checked against the byte-preserved RequestSeal `v0.4.0` corpus. The pins differ because the corpus index is unchanged and v0.4.1 supplied no corpus release assets. See [the corpus pin and update command](CONTRIBUTING.md). Development reports pending surfaces; releases require complete coverage.

Node 22.12.0 and 24.21.0 and Deno 2.5.6 verify the pinned published vectors.
Bun 1.3.14 WebCrypto rejects two valid Wycheproof ECDSA P-256 signatures:
items 261 (`s = 2^128`) and 262 (`s = n - 2^128`). The consumer policy in
[`tools/conformance/runtime-limits.json`](tools/conformance/runtime-limits.json)
applies only to that exact version and reports both as `runtime_limited`.
Published corpus verdicts stay valid. A stale entry, different rejection, unlisted
divergence, or divergence on another Bun version fails conformance. See the
[consumer runtime limitation contract](docs/reference/corpus-format.md#consumer-runtime-limitations)
and [test API compatibility](CONTRIBUTING.md#runtime-test-compatibility).

See [replay protection](docs/reference/replay.md) for the memory store and the
optional `@request-seal/core/replay-postgres` query adapter.
