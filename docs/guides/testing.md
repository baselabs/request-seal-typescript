**Status:** maintained · **Kind:** guide · **Updated:** October 11, 2026 · **Governed by:** AGENTS.md, the shared conformance corpus, and the executed examples in this guide · **Review when:** an advertised capability, test runner, or evidence source changes

# Testing

This guide covers two jobs: testing your own integration of RequestSeal, and running the checks in this repository. Both rest on one idea. A check proves something only if it can fail, so every test here uses real keys and real cryptography, asserts an exact outcome, and has a positive control beside each rejection.

## What each kind of evidence establishes

| Evidence | Establishes |
| --- | --- |
| A published vector from a standard or a vendor | Agreement with the exact bytes someone else published. |
| A round trip with a generated key | The code works with itself on this runtime. |
| A real independent implementation (OpenSSL, the OpenSSH agent, another RequestSeal release) | Agreement with that implementation on the cases you ran. |
| A real framework, socket, or database | That integration's observed byte and lifecycle behavior. |
| A deployed counterpart accepting your request | Acceptance by that peer under its stated conditions. |

A passing round trip does not show that a peer will accept your bytes, and a vector does not show that your server wires the library correctly. State which kind of evidence you have.

## Test your own integration

Write the positive case first, then one rejection per mutation, and assert the exact `reason` each time. If the unmodified request fails, every rejection after it proves nothing, so the positive control stays in the file.

The program is a runnable test file. It signs with a real Ed25519 key and runs five tests: an accepted request, a changed body, a key you do not trust, an expired signature, and a second use of the same request. Copy it into your project and replace the policy with yours.

```ts
import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { Custody, Message, Policy, PublicKey, createMemoryStore, ok, sign, verify, type KeyResolver, type Result } from "@request-seal/core";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
const reasonOf = <T>(r: Result<T>) => (r.ok ? "accepted" : r.error.reason);

// Real keys, real cryptography, no network. Each test builds exactly what it needs.
const pair = generateKeyPairSync("ed25519");
const signer = must(await Custody.local("ed25519", pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string));
const trusted = must(await PublicKey.import(pair.publicKey.export({ format: "jwk" })));
const strangerPair = generateKeyPairSync("ed25519");
const stranger = must(await Custody.local("ed25519", strangerPair.privateKey.export({ type: "pkcs8", format: "pem" }) as string));

const now = Math.floor(Date.now() / 1000);
const components = '("@method" "@authority" "@path" "content-digest")';
// Single sender: select by keyid when you have several.
const keyResolver: KeyResolver = () => ok({ algorithm: "ed25519", key: trusted });
const policy = (replay: unknown = "not_required") => must(Policy.create({
  algorithms: ["ed25519"], components, keyResolver,
  freshness: { clock: () => now, maxAge: 60, skew: 0, requireExpires: true },
  content: { kind: "content", algorithms: ["sha-256"], section: "headers" }, replay,
}));
const signed = async (body = '{"amount":5}', key = signer, at = now) => {
  const request = must(await Message.request("POST", "https://api.example.com/payments", [], body, { digest: ["sha-256"] }));
  return must(await sign(request, { label: "sig", components, algorithm: "ed25519", expiresIn: 60, digest: ["sha-256"] }, key, { clock: () => at }));
};

// A positive control first: if the unmodified request fails, every rejection below proves nothing.
test("accepts the unmodified request", async () => {
  assert.equal(reasonOf(await verify(await signed(), policy(), { label: "sig" })), "accepted");
});

// Each negative changes exactly one thing and asserts the specific reason.
test("rejects a body changed after signing", async () => {
  const original = await signed();
  const forged = must(Message.create({ ...original, body: { ...original.body, bytes: new TextEncoder().encode('{"amount":5000}') } }));
  assert.equal(reasonOf(await verify(forged, policy(), { label: "sig" })), "digest_mismatch");
});

test("rejects a signature made by a key you do not trust", async () => {
  // The resolver returns the trusted public key, so another key's signature cannot verify against it.
  assert.equal(reasonOf(await verify(await signed('{"amount":5}', stranger), policy(), { label: "sig" })), "invalid_signature");
});

test("rejects a signature that has expired", async () => {
  assert.equal(reasonOf(await verify(await signed('{"amount":5}', signer, now - 3600), policy(), { label: "sig" })), "expired");
});

test("rejects the second use of a signed request", async () => {
  const store = must(createMemoryStore({ maxEntries: 100 }));
  const replaying = policy({
    identifier: "nonce", namespace: new TextEncoder().encode("test"), store, timeoutMs: 1000,
    commitment: async (facts: { identifier: string }) => ok(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(facts.identifier)))),
  });
  const request = await signed();
  assert.equal(reasonOf(await verify(request, replaying, { label: "sig" })), "accepted");
  assert.equal(reasonOf(await verify(request, replaying, { label: "sig" })), "replayed");
});
```

Some rules that keep tests honest:

- **Change meaningful bytes.** Alter a covered header or the body, not a byte the signature ignores.
- **Use real clocks and keys.** Pass a `clock` to `sign` and to the policy rather than faking time.
- **Run real servers on loopback.** Start the server, send a request to it, and close it. The guides do this throughout.
- **Race the store.** For replay, issue many verifications of one request at once and assert exactly one succeeds, as the [replay guide](replay-protection.md) does.
- **Check the default path.** Run the configuration you ship, with no options added, once.

## Run this repository's checks

Use Node 22.12.0 or newer on macOS or Linux. Windows developers use WSL2. CI runs on Linux.

```sh
npm ci --ignore-scripts
npm run check
```

`npm run check` runs, in order: `typecheck`, `typecheck:web`, `build`, `test`, `self-checks`, `conformance`, and `pack:check`. The packaging check verifies the allowlist and loads exports and types from an unpacked tarball. TypeScript programs and byte-matched excerpts in repository Markdown run under their declared runtime: Node by default, or the exact `<!-- run: deno -->` or `<!-- run: bun -->` marker within two lines above the fence. API sketches are labeled `text` and need caller-supplied values.

CI also runs `npm run docs` (warnings fail) and `node --experimental-strip-types --no-warnings --test interop/migration/claims.test.ts` after installing its dependencies. Build the [API reference](https://baselabs.github.io/request-seal-typescript/) locally with `npm run docs`; output is in `site-dist/`. Deno programs receive only cache/home/PATH settings, read access to the repository, and network access to loopback and JSR; they receive no environment permission.

For focused work, run one file with `node --experimental-strip-types --no-warnings --test test/<name>.test.ts`. `npm run test:red` plants a failing test and must exit nonzero on every runtime; it proves the runner reports failures. `npm run conformance` runs the shared corpus.

Some checks need extra tools and say so when they skip:

| Check | Needs |
| --- | --- |
| SSH agent custody | `ssh-agent`, `ssh-add`, `ssh-keygen` |
| JOSE and signature cross-checks | the `openssl` command-line tool, with development headers and a C compiler for the AES-GCM peer |
| PostgreSQL replay store | a database you provide, with its URL in `REQUESTSEAL_REPLAY_PG_URL` |
| Express and Fastify adapters | `npm ci --prefix interop/adapters --ignore-scripts` |
| Error vocabulary extraction, reciprocal exchange | an Elixir toolchain and a checkout of the RequestSeal reference release |

The tests start no database and no container. A local run prints the reason when it skips an optional check; CI supplies the tools and fails when one is missing.

### Interop workspaces

Dependencies that are not part of the package live in separate workspaces under `interop/`, each with its own lockfile:

- `interop/adapters` pins Express and Fastify for the framework tests and for the guides.
- `interop/reciprocal` exchanges signatures, tokens, and replay claims with the published RequestSeal release for Elixir in both directions.
- `interop/replay` holds the cross-language replay peer.
- `interop/migration` compares RequestSeal with the `http-message-signatures` package. Run it with `npm ci --prefix interop/migration --ignore-scripts` and then `node --experimental-strip-types --no-warnings --test interop/migration/claims.test.ts`. Every comparison in the [migration guide](migrating-from-http-message-signatures.md) is proved there.

## Runtimes

| Runtime | What the tests prove |
| --- | --- |
| Node 22.12.0, 24.21.0, and current 26 | The full suite, build, conformance corpus, and packed-package import checks. |
| Deno 2.5.6 | The core suite and conformance on Deno's own WebCrypto. Fetch verification runs only here. |
| Bun 1.3.14 | The core suite and conformance. On macOS arm64, Bun's WebCrypto rejected two valid ECDSA P-256 vectors; a declared limitation, scoped to the exact version and platform, reports them instead of weakening a check. |

The Node adapters run in real Node subprocesses even when the suite is started by Deno or Bun. HTTPS key discovery is Node only. Linux is the only CI platform; macOS and Linux are supported for development.

## Conformance corpus

The corpus under `conformance/` holds public vectors, vendor bytes, and canonical expectations. It is shared with the Elixir implementation. Neither implementation may regenerate an expected value: the corpus is the oracle. The runner verifies a pinned index digest and refuses to run a corpus that does not match it. It also reports what ran, what was not applicable, what was limited by the runtime, and what is still pending, and the counts must add up. Release builds run the corpus with no pending surfaces allowed.

## Where to go next

- [Signing and verifying](signing-and-verifying.md) lists the reasons your tests will assert.
- [Replay protection](replay-protection.md) shows the concurrency check.
- [The threat model](../design/threat-model.md) states what each control is tested to prevent.
