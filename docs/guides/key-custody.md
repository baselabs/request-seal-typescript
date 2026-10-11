**Status:** maintained · **Kind:** guide · **Updated:** October 11, 2026 · **Governed by:** WebCrypto, the OpenSSH agent protocol, and the executed examples in this guide · **Review when:** custody mechanics, adapter contracts, or runtime behavior changes

# Key custody

Custody decides where a private key lives and who can use it. RequestSeal never asks for a private key to travel through its API after import. You import the key once and get a **handle**: an object that can sign and verify but cannot hand the key back. Everything that signs, from HTTP signatures to JOSE tokens, accepts a handle.

The [threat model](../design/threat-model.md#custody-and-cryptographic-boundaries) states exactly what the boundary does and does not defend against.

## Local keys

`Custody.local(algorithm, material, options)` imports a key you hold in process.

| Material | Form |
| --- | --- |
| Asymmetric private key | PEM text (a string), PKCS #8 DER bytes (a `Uint8Array`), or a private JWK (an object). The form follows the type you pass; the `format` option (`"pem"`, `"pkcs8"`, or `"jwk"`) overrides it. |
| HMAC secret | `{ hmac: bytes, identity? }` with 32 to 16,384 bytes. `identity` is an optional nonsecret label you choose; it is never a hash of the secret. |

The `algorithm` is an HTTP algorithm token such as `"ed25519"`, or a JOSE selector such as `{ jws: "EdDSA" }` or `{ jwe: "RSA-OAEP-256" }`. The two registries are separate on purpose.

Import checks the key before the runtime sees it: RSA moduli, exponents, and CRT parameters; matching public components for EC and OKP keys; and the PSS and OAEP restrictions a container carries. The operational key is held non-extractably. Printing, `JSON.stringify`, and `util.inspect` show public facts only, and a structured clone of a handle exposes no usable key. Releasing a handle drops its key reference, and later calls return `key_not_found`.

The program below imports a key, signs under a deadline, checks that nothing secret appears in the handle's printed forms, applies a per-call byte bound, and releases the handle.

<!-- run: bun -->
```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { inspect } from "node:util";
import { Custody, withDeadline, type Result } from "@request-seal/core";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
const { privateKey } = generateKeyPairSync("ed25519");

// Import once, at startup. The PEM text can then go out of scope; the handle holds a non-extractable runtime key.
const handle = must(await Custody.local("ed25519", privateKey.export({ type: "pkcs8", format: "pem" }) as string));
const data = new TextEncoder().encode("bytes to sign");

// Every operation shares an absolute deadline.
const context = must(withDeadline({ timeoutMs: 2000 }));
const signature = must(await handle.sign("ed25519", data, context));
const publicKey = must(await handle.publicKey());
must(await publicKey.verify("ed25519", signature, data)); // Only public components ever leave the handle.
assert.equal((await publicKey.verify("ed25519", signature, new TextEncoder().encode("other bytes"))).ok, false);

// Printing, serializing, or inspecting a handle shows public facts only.
const secret = (privateKey.export({ format: "jwk" }) as { d: string }).d;
assert.ok(!JSON.stringify(handle).includes(secret) && !inspect(handle, { depth: 5 }).includes(secret));

// A per-call byte bound stops oversized input before any cryptography runs.
const oversized = await handle.sign("ed25519", new Uint8Array(2048), context, { maxBytes: 1024 });
assert.ok(!oversized.ok && oversized.error.kind === "custody" && oversized.error.reason === "invalid_data");

// Release drops the key reference. Later calls fail with key_not_found instead of signing.
must(await handle.release());
const afterRelease = await handle.sign("ed25519", data, context);
assert.ok(!afterRelease.ok && afterRelease.error.kind === "custody" && afterRelease.error.reason === "key_not_found");
```

### What import cannot erase

The library overwrites the byte buffers it copies while importing. It cannot overwrite JavaScript strings, so the PEM text you passed, the Base64 body, and private JWK strings stay in memory until garbage collection. If that matters, import from a source that gives you bytes, keep the lifetime short, and prefer an external custodian.

## Deadlines and cancellation

Every operation on a handle takes a `Context`, which is an absolute deadline plus an abort signal. `withDeadline({ timeoutMs, signal, parent })` creates one. A deadline expiring returns `deadline_exceeded`, which is retryable, and a late result is discarded. Cancellation cannot interrupt a native operation that WebCrypto already started, so a canceled signing call may still finish in the background; its result is never returned.

When `sign` takes a handle, the signing deadline begins just before the custody call and is capped at `signingTimeout` (5,000 ms by default, up to 300,000). A caller `Context` can only shorten it.

## Hardware, vaults, and key services

Anything that can sign can be a custodian: a cloud key service, a hardware module, a vault. Implement the `Custodian` interface (`sign`, `verify`, `publicKey`, `identity`, `unwrap`, `release`) and wrap it with `createKeyHandle(algorithm, custodian)`. The wrapper puts every call under the deadline, contains exceptions, and checks that results have the right type, so a faulty custodian cannot return garbage as a signature. Custodian code is trusted code: it must pass the `Context` along to its own network calls, and it must not log secrets. For a function-sized integration you do not need a custodian at all: `sign` accepts a function `(algorithm, base, context) => Result<Uint8Array>`.

## OpenSSH agent custody

`@request-seal/core/custody-ssh-agent` signs through a running `ssh-agent`, so the private key stays inside the agent.

`createSshAgent(algorithm, socketPath, publicKey)` needs three things from you: an absolute POSIX socket path of 1 to 103 bytes, the algorithm, and the branded `PublicKey` that you expect the agent to hold. It reads no environment variable and starts no agent. At construction it proves the agent holds that key. Each signature opens a new connection, checks the agent's current identities, bounds every frame, and verifies the returned signature locally with the public key before it releases the bytes. A bad reply, a missing key, or a closed socket becomes a bounded error with no socket path in it.

Supported algorithms are `ed25519`, `rsa-v1_5-sha256`, `ecdsa-p256-sha256`, and `ecdsa-p384-sha384`, plus the JOSE selectors `EdDSA`, `RS256`, `ES256`, and `ES384`. RSA-PSS and HMAC are rejected, because the agent protocol cannot produce them.

The program starts a real `ssh-agent`, loads a freshly generated key, signs a request through it, and verifies the signature with the public key. It needs the OpenSSH tools `ssh-agent`, `ssh-keygen`, and `ssh-add`. In production the agent already runs and you only pass the socket and public key.

```ts
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Message, Policy, PublicKey, ok, sign, verify, type KeyResolver, type Result } from "@request-seal/core";
import { createSshAgent } from "@request-seal/core/custody-ssh-agent";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };

// Start a real OpenSSH agent and load one key. In production the agent already runs and already holds your key.
const dir = mkdtempSync(join(tmpdir(), "seal-agent-"));
const socket = join(dir, "agent.sock"), keyFile = join(dir, "key");
const agent = spawn("ssh-agent", ["-D", "-a", socket], { stdio: "ignore" });
try {
  for (let i = 0; !existsSync(socket); i++) { assert.ok(i < 500, "agent socket did not appear"); await new Promise((r) => setTimeout(r, 10)); }
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", keyFile]);
  execFileSync("ssh-add", [keyFile], { env: { ...process.env, SSH_AUTH_SOCK: socket }, stdio: "ignore" });
  // An OpenSSH public key line holds a length-prefixed type name and then a length-prefixed 32-byte Ed25519 key.
  const blob = Buffer.from(readFileSync(`${keyFile}.pub`, "utf8").split(" ")[1]!, "base64");
  const publicKey = must(await PublicKey.import({ kty: "OKP", crv: "Ed25519", x: blob.subarray(4 + blob.readUInt32BE(0) + 4).toString("base64url") }));

  // You name the socket and the public key. The adapter proves the agent holds that key, and re-checks every signature locally.
  const handle = must(await createSshAgent("ed25519", socket, publicKey));
  const components = '("@method" "@authority")';
  const request = must(await Message.request("GET", "https://api.example.com/", [], ""));
  const signed = must(await sign(request, { label: "sig", components, algorithm: "ed25519", expiresIn: 60, keyid: "agent-key" }, handle));
  // Single sender: select by keyid when you have several.
  const keyResolver: KeyResolver = () => ok({ algorithm: "ed25519", key: publicKey });
  const policy = must(Policy.create({
    algorithms: ["ed25519"], components, keyResolver,
    freshness: { clock: () => Math.floor(Date.now() / 1000), maxAge: 60, skew: 5, requireExpires: true },
    content: "not_required", replay: "not_required",
  }));
  must(await verify(signed, policy, { label: "sig" }));
  must(await handle.release());
  // A released handle no longer signs.
  const afterRelease = await sign(request, { label: "late", components, algorithm: "ed25519", expiresIn: 60 }, handle);
  assert.ok(!afterRelease.ok);
} finally {
  agent.kill("SIGTERM");
  await once(agent, "exit");
  rmSync(dir, { recursive: true, force: true });
}
```

## Where to go next

- [Signing and verifying](signing-and-verifying.md) passes handles to `sign`.
- [JOSE](jose.md) uses handles bound to JOSE algorithms.
- The [threat model](../design/threat-model.md) explains what custody does not defend against: holders who misuse their handle, memory disclosure, debugger access, malicious custodian code, and code that patches globals before RequestSeal loads.
