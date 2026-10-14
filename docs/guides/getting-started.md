**Status:** maintained · **Kind:** guide · **Updated:** October 14, 2026 · **Governed by:** RFC 9421, RFC 9530, and the executed examples in this guide · **Review when:** the public signing or verification API changes

# Getting started

You will sign an HTTP request, verify it under an explicit policy, and watch a tampered copy fail. Everything runs in one file with locally generated keys and no network.

## Install

```sh
npm install @request-seal/core
```

The package has no runtime dependencies and uses WebCrypto for every cryptographic operation. It targets Node 22.12.0 or newer, plus Deno and Bun for the core API. The ESM package needs the `nodenext` or `bundler` module resolution in TypeScript, because it exposes subpath exports such as `@request-seal/core/fetch`.

Save a complete program as `example.ts` in a project whose `package.json` has `"type": "module"`. On Node 22, run `node --experimental-strip-types example.ts`; on Node 24 and later, run `node example.ts`. For fences marked Deno, run `deno run --allow-read --allow-net=127.0.0.1,jsr.io example.ts`; for Bun, run `bun run example.ts`.

## Sign and verify in one file

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { Custody, Message, Policy, PublicKey, ok, sign, verify, type KeyResolver, type Result } from "@request-seal/core";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };

// The sender holds the private key; the receiver trusts only the public key.
// In production, load persisted keys from your secret store.
const pair = generateKeyPairSync("ed25519");
const signer = must(await Custody.local("ed25519", pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string));
const trusted = must(await PublicKey.import(pair.publicKey.export({ format: "jwk" })));

// Sign a request. The body digest is computed over the exact bytes.
const components = '("@method" "@scheme" "@authority" "@path" "content-digest")';
const request = must(await Message.request("POST", "https://api.example.com/notes",
  [["content-type", "application/json"]], '{"title":"draft"}', { digest: ["sha-256"] }));
const signed = must(await sign(request,
  { label: "sig", components, algorithm: "ed25519", expiresIn: 60, keyid: "notes-client", digest: ["sha-256"] }, signer));

// Verify under a policy that states every acceptance choice.
const keyResolver: KeyResolver = ({ keyid }) => ok(keyid === "notes-client" ? { algorithm: "ed25519", key: trusted } : null);
const policy = must(Policy.create({
  algorithms: ["ed25519"],
  components,
  keyResolver,
  freshness: { clock: () => Math.floor(Date.now() / 1000), maxAge: 60, skew: 5, requireExpires: true },
  content: { kind: "content", algorithms: ["sha-256"], section: "headers" },
  replay: "not_required",
}));
const verification = must(await verify(signed, policy, { label: "sig" }));
assert.equal(verification.authorization, "not_evaluated"); // RequestSeal authenticates; you authorize.

// A body changed after signing is rejected with a named reason.
const forged = must(Message.create({ ...signed, body: { ...signed.body, bytes: new TextEncoder().encode('{"title":"final"}') } }));
const rejected = await verify(forged, policy, { label: "sig" });
assert.ok(!rejected.ok && rejected.error.kind === "core" && rejected.error.reason === "digest_mismatch");
```

## What just happened

1. `Custody.local` imported the private key into a handle. The handle can sign but never gives the key back. The receiver gets only a `PublicKey`.
2. `Message.request` built a lossless request model and added a `Content-Digest` header over the body bytes (RFC 9530).
3. `sign` appended `Signature-Input` and `Signature` header occurrences and returned a new `Message`. It never modifies the message you passed in.
4. `Policy.create` took the six choices a verifier must make: allowed `algorithms`, required `components`, a `keyResolver` that maps `keyid` to a trusted key, `freshness`, `content` checking, and `replay`. None of the six has a default, so a policy never guesses a security choice. Optional `extraComponents` defaults to `"allow"`; set `"reject"` to refuse coverage beyond what you listed.
5. `verify` checked the signature, the covered components, the clock, and the digest, then returned a frozen `Verification`. It records `authorization: "not_evaluated"` and a principal of `"unattributed"`: a valid signature proves the holder of the key sent these covered bytes, and says nothing about what that sender may do.

Every operation that can fail returns a `Result`: `{ ok: true, value }` or `{ ok: false, error }`. Errors are small frozen objects with a stable `kind` and `reason`, never stack traces and never your bytes. Branch on `error.reason`; the [error reasons](../reference/errors.md) page explains every one.

## Habits that keep you safe

- Cover `@scheme` and `@authority` when scheme and host matter. Covering `@authority` alone accepts the same signature for `http` and `https`, because RFC 9421 omits default ports from the derived value.
- Resolve keys from your own configuration. A `keyid` in a request selects among keys you already trust; it never tells the library where to fetch one.
- Treat `verify` success as authentication only. Decide authorization after it.
- Use a few seconds of `skew` on NTP-synchronized hosts. Set `maxAge` deliberately, and add [replay protection](replay-protection.md) when a repeated request would do harm.

## Where to go next

- [Signing and verifying](signing-and-verifying.md): policies in depth, streaming digests, multiple signatures, and HTTP status codes for rejections.
- [Fetch](fetch.md) and [Node HTTP](node-http.md): sign outgoing requests and verify incoming ones in real servers.
- [Web Bot Auth](web-bot-auth.md): identify and verify automated agents.
- [Key custody](key-custody.md) and [key discovery](key-discovery.md): where keys live and how you learn a sender's public key.
- [Testing](testing.md): how to test your own integration with real cryptography.
