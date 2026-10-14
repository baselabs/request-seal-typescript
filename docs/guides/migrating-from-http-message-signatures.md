**Status:** maintained · **Kind:** guide · **Updated:** October 14, 2026 · **Governed by:** RFC 9421 and the comparison tests in `interop/migration` · **Review when:** the compared package version, or either library's signing or verification behavior, changes

# Migrating from http-message-signatures

This guide is for projects that sign or verify HTTP messages with the npm package [`http-message-signatures`](https://www.npmjs.com/package/http-message-signatures) and want RequestSeal's explicit policies, replay protection, and body checks. It compares exactly one release: **`http-message-signatures` 1.0.6**.

Every comparison below is proved by a test that runs both libraries on the same inputs, in [`interop/migration/claims.test.ts`](../../interop/migration/claims.test.ts). That workspace pins the exact version in its own `package.json` and lockfile; it is not a dependency of RequestSeal. Run it yourself:

```sh
npm ci --prefix interop/migration --ignore-scripts
node --experimental-strip-types --no-warnings --test interop/migration/claims.test.ts
```

Where a statement rests on a standard instead, it cites [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html). Behavior that no test or standard covers is left out. If you use a different release, rerun the tests against it before you rely on this page.

## You can migrate without a flag day

Both libraries produce RFC 9421 signature headers, and they agree on the bytes. Given the same message, the same covered components, the same parameters, and an Ed25519 key, they produce identical `Signature-Input` and `Signature` header values (claim 1). RequestSeal verifies signatures that `http-message-signatures` made (claim 2), and `http-message-signatures` verifies signatures that RequestSeal made (claim 3). You can move senders and receivers independently, in either order.

The program below verifies the example signature printed in the package's own README with RequestSeal. The secret is only 12 bytes, which is shorter than RequestSeal's 32-byte minimum for an HMAC key handle (claim 13), so the program verifies through a callback. Inside the signature's lifetime it verifies, and after `expires` it is refused.

```ts
import assert from "node:assert/strict";
import { createHmac, timingSafeEqual } from "node:crypto";
import { Message, Policy, ok, verify, type KeyResolver, type Result } from "@request-seal/core";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };

// Headers copied from the library's own README example output. The secret is 12 bytes, shorter than RequestSeal's
// 32-byte HMAC key minimum, so verify through a callback instead of importing the secret into a handle.
const secret = "sharedsecret";
const message = must(await Message.request("POST", "https://example.com", [
  ["content-type", "application/json"],
  ["signature", "sig=:RkplfaUzQ4xIkSVP9hT+Y55yAYX9VwSeHmjS5X7d0fE=:"],
  ["signature-input", 'sig=();keyid="my-key-id";alg="hmac-sha256";created=1700669009;expires=1700669309'],
], '{"hello": "world"}\n'));

const keyResolver: KeyResolver = ({ keyid }) => ok(keyid === "my-key-id" ? {
  algorithm: "hmac-sha256",
  verify: async (_algorithm, base, signature) => ok(timingSafeEqual(createHmac("sha256", secret).update(base).digest(), Buffer.from(signature))),
} : null);
const policy = (clock: () => number) => must(Policy.create({
  algorithms: ["hmac-sha256"], components: "()", keyResolver,
  freshness: { clock, maxAge: 600, skew: 0, requireExpires: true },
  content: "not_required", replay: "not_required",
}));

// Inside the signature's lifetime the other library's signature verifies.
must(await verify(message, policy(() => 1_700_669_100), { label: "sig" }));
// After `expires` RequestSeal refuses it.
const late = await verify(message, policy(() => 1_700_669_400), { label: "sig" });
assert.ok(!late.ok && late.error.kind === "core" && late.error.reason === "expired");
```

## What differs, and why it matters

The older package is a signing and verification toolkit that leaves most security decisions to the caller. RequestSeal makes those decisions explicit in a policy and fails closed when one is missing. The table below lists the differences that change what a service accepts.

| Topic | `http-message-signatures` 1.0.6 | RequestSeal | Proved by |
| --- | --- | --- | --- |
| Compared standard | Its README says it was last updated against revision 13 of the HTTP working group draft, and it also ships a module for the older Cavage draft. | RFC 9421 only. A Cavage-only request is refused with `missing_signature_input`. | pinned-version test, claim 12 |
| Missing signature or unknown key | `verifyMessage` resolves `null` ("indeterminate"), which is neither `true` nor `false`. | An error with a named reason: `missing_signature_input`, `unknown_key`. | claim 5 |
| Failures | Throws typed errors such as `ExpiredError`, or returns `false`. | `verify` resolves a `Result` for malformed messages/options, invalid policies, expired signatures, and throwing key-resolver callbacks. | claim 10 |
| Several signatures | Returns the verdict of the last signature it processes, so a forged first signature beside a good second one still returns `true`. | `verify` checks exactly the label you name. | claim 11 |
| Body integrity | It signs and compares header values only and never sees a body. A signed `Content-Digest` header proves nothing about the bytes. | With `content` required, it recomputes the digest over the retained bytes and rejects `digest_mismatch`. | claim 6 |
| Replay | No replay check; the same signed request verifies again. | A required replay policy claims each nonce once and rejects the second use with `replayed`. | claim 7 |
| Declared algorithm is not checked | A key without an `algs` list uses its configured verifier without checking the declared `alg`: the tested HMAC signature declares `ed25519` and verifies. | The policy lists the allowed algorithms (`algorithm_not_permitted`), and the resolver's algorithm must match the signature's (`algorithm_mismatch`). | claim 8 |
| Coverage and freshness | Accepts a signature with no `created` or `expires` under `maxAge`, and one that covers no components, unless you set `requiredFields`. | The policy states the required components and refuses missing coverage (`missing_required_component`) and missing times (`missing_created`). | claim 9 |
| Generated parameters | Defaults to `keyid`, `alg`, `created`, and `expires` five minutes after creation. No nonce. | `expiresIn` is required, a random `nonce` is on by default, and `alg` is on. | claim 4 |
| HMAC secrets | The 12-byte published example signs. | A key handle refuses that short secret; an application verification callback can verify it. | claim 13 |
| Algorithms | `ed25519`, `ecdsa-p256-sha256`, `ecdsa-p384-sha384`, `rsa-pss-sha512`, `rsa-v1_5-sha256`, `hmac-sha256`, and `rsa-v1_5-sha1`. | `ed25519`, `ecdsa-p256-sha256`, `ecdsa-p384-sha384`, `rsa-pss-sha512`, `rsa-v1_5-sha256`, `hmac-sha256`. No SHA-1. | claim 12 |

The package's README describes its own examples as "minimal" signatures: they prove the sender holds the key and give no integrity over the message, and callers add the fields and checks they need. RequestSeal's policy is where those choices become code.

## How the pieces map

| Task | `http-message-signatures` | RequestSeal |
| --- | --- | --- |
| Hold a key | `createSigner(key, alg, id)` | `Custody.local(alg, material)`, returning a key handle. See [key custody](key-custody.md). |
| Describe a message | `{ method, url, headers }` (a `body` property is ignored, claim 6) | `Message.request(method, url, [[name, value], ...], body)`. Headers are ordered pairs that keep repeats and case. |
| Sign | `signMessage({ key, fields, ... }, message)` | `sign(message, { label, components, algorithm, expiresIn, ... }, handle)` |
| Find a key | `keyLookup(params)` | `Policy.create({ keyResolver })` |
| Verify | `verifyMessage(config, message)` | `verify(message, policy, { label })` |
| Accept rules | `maxAge` and `requiredFields` (claim 9), and a key's optional `algs` list (claim 8) | The six policy choices: algorithms, components, key resolver, freshness, content, replay. See [signing and verifying](signing-and-verifying.md). |

The old package's own example, for reference (this fragment needs that package, so it is not run):

```js
const { httpbis: { signMessage }, createSigner } = require("http-message-signatures");
const key = createSigner("sharedsecret", "hmac-sha256", "my-key-id");
const signed = await signMessage({ key }, { method: "POST", url: "https://example.com", headers: { "content-type": "application/json" } });
```

## Keep your call sites while you migrate

If your code passes `{ method, url, headers, body }` objects around, wrap RequestSeal in the same shape and change the internals first. The program below does that with two small helpers, signs through RequestSeal, verifies under an explicit policy that requires coverage and freshness, and shows the missing-signature case as a named rejection.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { Custody, Message, Policy, PublicKey, ok, sign, verify, type KeyHandle, type KeyResolver, type Policy as VerifyPolicy, type Result } from "@request-seal/core";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };

// Call sites that pass { method, url, headers, body } objects can keep doing so while the internals change.
type Plain = { method: string; url: string; headers: Record<string, string>; body?: string };
const toMessage = async (plain: Plain) => must(await Message.request(plain.method, plain.url, Object.entries(plain.headers), plain.body ?? ""));

async function signPlain(plain: Plain, key: KeyHandle): Promise<Plain> {
  const signed = must(await sign(await toMessage(plain), {
    label: "sig", components: '("@method" "@authority" "@path" "content-type")', algorithm: "ed25519", expiresIn: 300, keyid: "partner-key",
  }, key));
  const headers = Object.fromEntries(signed.fields.map((field) => [field.name, new TextDecoder().decode(field.value)]));
  return { ...plain, headers };
}
async function verifyPlain(plain: Plain, policy: VerifyPolicy) {
  return verify(await toMessage(plain), policy, { label: "sig" });
}

const pair = generateKeyPairSync("ed25519");
const key = must(await Custody.local("ed25519", pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string));
const trusted = must(await PublicKey.import(pair.publicKey.export({ format: "jwk" })));
const keyResolver: KeyResolver = ({ keyid }) => ok(keyid === "partner-key" ? { algorithm: "ed25519", key: trusted } : null);
// The explicit policy is the new part: it states coverage, freshness, content, and replay choices the old library left to you.
const policy = must(Policy.create({
  algorithms: ["ed25519"], components: '("@method" "@authority" "@path" "content-type")', keyResolver, extraComponents: "reject",
  freshness: { clock: () => Math.floor(Date.now() / 1000), maxAge: 300, skew: 5, requireExpires: true },
  content: "not_required", replay: "not_required",
}));

const outgoing = await signPlain({ method: "POST", url: "https://example.com/articles", headers: { "content-type": "application/json" }, body: '{"id":1}' }, key);
must(await verifyPlain(outgoing, policy));
const unsigned = await verifyPlain({ method: "POST", url: "https://example.com/articles", headers: { "content-type": "application/json" } }, policy);
assert.ok(!unsigned.ok && unsigned.error.kind === "core" && unsigned.error.reason === "missing_signature_input");
```

## Migration steps

1. **Install RequestSeal** beside the old package and keep both while you move.
2. **Move receivers first, or senders first; either order works.** The headers are compatible (claims 1 to 3). Match the receiver policy to the sender's algorithms, keys, coverage, and timestamps. The old package adds `created` and `expires` by default (claim 4).
3. **Write the policy from what you accept today.** List the components your senders cover and make them required. Choose `maxAge` and `skew`. If you relied on a signed `Content-Digest` header, set `content` so the body is checked. If a repeated request would do harm, add [replay protection](replay-protection.md).
4. **Replace "falsy means reject" with explicit branching.** Branch on `result.ok`, and map the reason to a status as the [signing guide](signing-and-verifying.md#respond-to-a-rejection) shows.
5. **Retire the old package** once no sender or receiver uses it. If something still signs with SHA-1 RSA or a Cavage header, it needs to change algorithm or draft first, because RequestSeal accepts neither.

## Where to go next

- [Getting started](getting-started.md) is the shortest path to a first signature.
- [Testing](testing.md) explains how to prove your new policy rejects what the old code let through.
