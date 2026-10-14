**Status:** maintained · **Kind:** guide · **Updated:** October 14, 2026 · **Governed by:** RFC 7517, RFC 7638, draft-ietf-webbotauth-httpsig-protocol-00, and the executed examples in this guide · **Review when:** discovery policy, body formats, or runtime compatibility changes

# Key discovery

To verify a signature you need the sender's public key. When the sender publishes its keys at an HTTPS address, discovery turns that address into keys you can use without hard-coding them. RequestSeal keeps the two halves apart: the core validates key documents you hand it and never opens a connection, and an optional Node module fetches them over HTTPS under strict network rules. The [discovery reference](../reference/discovery.md) lists every bound.

Three rules hold in both halves.

- **You configure the source.** A `keyid` in a request selects among keys from a source you chose. It never supplies a URL.
- **Keys age out.** A key set carries a freshness time. Stale keys are not served, and a failed refresh never extends an old key set.
- **Nothing is trusted by default.** A found key proves a source published it. Whether you trust that source is your configuration.

## Sources and key sets

`DiscoverySource.create` describes where keys live. There are three types:

| Type | Location | What it serves |
| --- | --- | --- |
| `directory` | An origin such as `https://agent.example`. RequestSeal expands it to `/.well-known/http-message-signatures-directory`. | A signed key directory, as Web Bot Auth agents publish. |
| `jwks_uri` | The full address of a JSON Web Key Set. | Public JWKs, as many identity providers publish. |
| `cimd` | A client metadata document address, with a path. | A client document that holds or points to a key set. |

Addresses must be HTTPS and may not carry user information, fragments, dot segments, or malformed escapes. Other options include `permittedAddresses`, `cacerts`, `revoked` thumbprints, `requireSignedDirectory`, `redirectScope`, and the limits below.

| Limit | Default | Ceiling |
| --- | --- | --- |
| Response bytes, decoded bytes | 65,536 each | 1,048,576 each |
| Keys per set | 32 | 256 |
| Timeout | 5,000 ms | 300,000 ms |
| Redirects | 0 | 3 |
| Cache time when the response has no `max-age` or `Expires` (`minTtl`), and the cap on any cache time (`maxTtl`) | 300 s and 86,400 s | 604,800 s each |
| Negative cache time | 30 s | 300 s |

A key set is the validated result. Look a key up with `keySet.lookup(thumbprint, algorithms, now)`. Lookup selects only a key compatible with the algorithms you allow, and it returns `unknown_key` for an unknown, stale, or revoked key. Key IDs are RFC 7638 thumbprints by default. A `jwks_uri` or `cimd` source can use `keyId: "directory"` for key sets that assign their own IDs; `directory` sources always use thumbprints.

## Snapshots: the path for any runtime

`Discovery.resolver.fromSnapshot(source, bodyBytes, fetchedAt, headers)` validates a response that you fetched yourself and returns a key set. It starts no connection, imports no Node module, and runs on Node, Deno, and Bun. Use it when you already have a trusted fetch path (your own HTTP client, a proxy, a build-time download) or when you run outside Node.

You own the network when you take this path: DNS, address filtering, redirects, TLS, and timeouts. Pass the response body bytes unchanged, the Unix time you received them, and the response headers as ordered pairs, including a `content-type` that matches the source type (otherwise the snapshot fails with `unexpected_media_type`), so cache headers are honored. `Discovery.resolver(keySet, { algorithms })` then gives you a resolver that you can use inside a policy's `keyResolver`.

The program runs under Deno. It turns a literal JWKS response into a key set, looks a key up, shows that unknown and stale keys are refused, and verifies a signature through the key set.

<!-- run: deno -->
```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { Custody, Discovery, DiscoverySource, Message, Policy, PublicKey, ok, sign, verify, type KeyResolver, type Result } from "@request-seal/core";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
const now = Math.floor(Date.now() / 1000);
const pair = generateKeyPairSync("ed25519");
const jwk = pair.publicKey.export({ format: "jwk" });
const thumbprint = must(await must(await PublicKey.import(jwk)).thumbprint());

// Fetch these bytes with your own HTTP client, under your own network policy. Here they are a literal response.
const body = new TextEncoder().encode(JSON.stringify({ keys: [jwk] }));
const headers: [string, string][] = [["content-type", "application/json"], ["cache-control", "max-age=600"]];
const source = must(DiscoverySource.create({ type: "jwks_uri", location: "https://partner.example/keys" }));
const keys = must(await Discovery.resolver.fromSnapshot(source, body, now, headers));

// The key set answers lookups by RFC 7638 thumbprint, for the algorithms you allow, at a time you give.
const found = must(await keys.lookup(thumbprint, ["ed25519"], now));
assert.equal(found.algorithm, "ed25519");
assert.equal((await keys.lookup("unknown-thumbprint", ["ed25519"], now)).ok, false);
assert.equal((await keys.lookup(thumbprint, ["ed25519"], now + 1_000_000)).ok, false); // stale keys are never served

// The same key set can resolve signatures in a policy.
const resolve = must(Discovery.resolver(keys, { algorithms: ["ed25519"] }));
const signer = must(await Custody.local("ed25519", pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string));
const components = '("@method" "@authority")';
// An unknown key is not an error: return ok(null) and verification reports unknown_key.
const keyResolver: KeyResolver = async ({ keyid }) => {
  const resolved = keyid === null ? null : await resolve({ keyid });
  return resolved?.ok ? resolved : ok(null);
};
const policy = must(Policy.create({
  algorithms: ["ed25519"], components, keyResolver,
  freshness: { clock: () => now, maxAge: 60, skew: 5, requireExpires: true }, content: "not_required", replay: "not_required",
}));
const request = must(await Message.request("GET", "https://api.example.com/", [], ""));
const signed = must(await sign(request, { label: "sig", components, algorithm: "ed25519", expiresIn: 60, keyid: thumbprint }, signer, { clock: () => now }));
must(await verify(signed, policy, { label: "sig" }));
```

The same program also passes under Node and Bun 1.3.14. Return `ok(null)` for a key the set does not hold; the policy then reports `unknown_key`.

A signed directory carries a proof that its publisher holds the keys in it. By default a directory snapshot must verify that proof, and `requireSignedDirectory: false` is an explicit opt-out for key sets you already trust by other means. The [Web Bot Auth guide](web-bot-auth.md) builds a signed directory end to end.

## Fetching over HTTPS on Node

`@request-seal/core/discovery-node` adds `Discovery.fetch`, which retrieves a source under network rules meant for fetching from untrusted places:

- It checks every literal address and every DNS answer against the IANA special-purpose registries and refuses private, loopback, link-local, and other reserved ranges. `permittedAddresses` lists up to 16 exact exceptions you choose.
- It connects to the vetted numeric address, verifies the TLS certificate and host name against the CA list you gave it, and checks the connected peer before it sends any HTTP bytes. It ignores proxy environment variables. Behind an egress proxy, fetch with your own client and validate snapshots instead.
- Redirects are manual, bounded, and checked again. The default scope is the same origin. `redirectScope: "any_https"` permits cross-origin HTTPS redirects: for SSRF protection, allow only destinations your application intends to contact, especially if you configured private `permittedAddresses`.
- Context cancellation and the deadline destroy the sockets it owns. Errors carry only bounded facts, such as the reason and whether a retry may help.

`cacerts` takes 1 to 256 DER certificates, or `"os"` (the default) for the operating system trust store. `"os"` needs a Node that exposes a non-empty system store (22.15 or newer on the 22 line, or 24 and newer); otherwise the `discovery-node` `DiscoverySource.create` and `Discovery.fetch` both refuse with `custody/unsupported_format`, and you should supply DER roots.

Wrap the fetch in a cache. `createCache({ fetch: Discovery.fetch })` returns a capability that fetches on demand and reuses fresh keys. Concurrent callers share one fetch. It follows `Cache-Control` and `Expires`, capped by your maximum, caches negative results briefly, serves nothing stale, and starts no background timers; call `cache.close()` when you are done.

The program runs a local HTTPS key server with a throwaway certificate and resolves a key through the cache. It needs the `openssl` command-line tool to make the certificate. Two concurrent lookups cause one fetch, and a third finds the key still fresh.

```ts
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { once } from "node:events";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PublicKey, createCache, type Result } from "@request-seal/core";
import { Discovery, DiscoverySource } from "@request-seal/core/discovery-node";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };

// A throwaway certificate for 127.0.0.1 stands in for your partner's public certificate.
const dir = mkdtempSync(join(tmpdir(), "seal-"));
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
  "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem")], { stdio: "ignore" });
const der = execFileSync("openssl", ["x509", "-in", join(dir, "cert.pem"), "-outform", "DER"]);

// The partner's key server.
const pair = generateKeyPairSync("ed25519");
const jwk = pair.publicKey.export({ format: "jwk" });
let hits = 0;
const server = createServer({ key: readFileSync(join(dir, "key.pem")), cert: readFileSync(join(dir, "cert.pem")) }, (_req, res) => {
  hits++;
  res.writeHead(200, { "content-type": "application/json", "cache-control": "max-age=600" });
  res.end(JSON.stringify({ keys: [jwk] }));
}).listen(0, "127.0.0.1");
await once(server, "listening");

// You configure the source. `cacerts: "os"` would use the operating system trust store instead of this certificate.
// Loopback is private address space, so it needs an explicit exception that a public source would not.
const source = must(DiscoverySource.create({
  type: "jwks_uri",
  location: `https://127.0.0.1:${(server.address() as { port: number }).port}/keys`,
  cacerts: [new Uint8Array(der)],
  permittedAddresses: ["127.0.0.1"],
}));
const thumbprint = must(await must(await PublicKey.import(jwk)).thumbprint());

// The cache owns fetching, freshness, and sharing one fetch between concurrent callers.
const cache = must(createCache({ fetch: Discovery.fetch }));
const [first, second] = await Promise.all([
  cache.resolve(source, thumbprint, { algorithms: ["ed25519"] }),
  cache.resolve(source, thumbprint, { algorithms: ["ed25519"] }),
]);
assert.equal(must(first).algorithm, "ed25519");
assert.equal(must(second).algorithm, "ed25519");
assert.equal(hits, 1); // one fetch served both callers
must(await cache.resolve(source, thumbprint, { algorithms: ["ed25519"] }));
assert.equal(hits, 1); // the key is still fresh, so there is no new fetch
cache.close();
server.close();
server.closeAllConnections();
rmSync(dir, { recursive: true, force: true });
```

On Deno and Bun the HTTPS transport is not supported: the real HTTPS probe returned `invalid_response` on both, and Deno's socket cancellation probe did not settle. Use snapshots on those runtimes.

## Revoking and removing keys

`remove(source, thumbprint)` on a cache records a denial (at most 256 per source) that survives refresh and invalidation, so a key you pulled stays out even when the publisher still lists it. `invalidate(source)` discards freshness and keeps removals. A source's `revoked` option (at most 256 thumbprints) does the same at configuration time. The cache's `resolve` refuses a revoked or removed key with `revoked_key`; a key set's `lookup` reports it as `unknown_key`. For a planned change of keys, see [rotating keys](key-rotation.md).

## Where to go next

- [Web Bot Auth](web-bot-auth.md) uses discovery to learn an agent's keys.
- [Signing and verifying](signing-and-verifying.md) shows how a key resolver plugs into a policy.
- [Testing](testing.md) explains why the discovery tests run against real TLS peers.
