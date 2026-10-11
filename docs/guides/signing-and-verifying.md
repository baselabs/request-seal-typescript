**Status:** maintained · **Kind:** guide · **Updated:** October 11, 2026 · **Governed by:** RFC 9421, RFC 9530, and the executed examples in this guide · **Review when:** signing, policy, digest, or verification contracts change

# Signing and verifying

This guide covers the core of RequestSeal: building messages, signing them, and verifying them under an explicit policy. It uses [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) signatures and [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html) content digests. Start with [getting started](getting-started.md) if you have not signed anything yet. The [signing and verification reference](../reference/sign-and-verify.md) lists every option and bound.

## Messages are lossless models

`sign` and `verify` work on a `Message`, not on a framework object. A message keeps the method, target, header occurrences in order, trailers, and body bytes exactly as given, because a signature covers those bytes.

- `Message.request(method, url, headers, body, { digest })` builds a request from an absolute URL, an ordered list of `[name, value]` pairs, and a body. Passing `digest: ["sha-256"]` adds a `Content-Digest` header computed over the body.
- `Message.response(status, headers, body, { request, digest })` builds a response. Link the `request` when the response signature covers request components such as `"@authority";req`.
- `Message.create(fields)` builds a message from every field by hand. Use it for HTTP/2 pseudo-headers, trailers, a body you stream, or transport facts that an adapter observed.

The [Node HTTP](node-http.md) and [Fetch](fetch.md) adapters build messages from live requests for you, so you rarely construct one by hand on a server.

## Sign

`sign(message, spec, signer, options)` appends one `Signature-Input` and one `Signature` header occurrence and returns a new message. Existing signatures stay in place. A generated spec has four required members and sensible optional ones:

| Member | Meaning |
| --- | --- |
| `label` | The dictionary key for this signature, for example `"sig"`. |
| `components` | The covered components as an RFC 9421 inner list, for example `'("@method" "@authority")'`. |
| `algorithm` | A registered HTTP algorithm: `ed25519`, `ecdsa-p256-sha256`, `ecdsa-p384-sha384`, `rsa-pss-sha512`, `rsa-v1_5-sha256`, or `hmac-sha256`. |
| `expiresIn` | Seconds until the signature expires. It is required, so no signature lives forever by accident. |
| `created`, `nonce`, `alg`, `keyid`, `tag` | Metadata. Defaults are `created: true`, a random `nonce`, and `alg: true`. `keyid` and `tag` are optional. |
| `digest` | `["sha-256"]` or `["sha-512"]` to add or check `Content-Digest` while signing. |

The signer is a `KeyHandle` from [key custody](key-custody.md), or any function `(algorithm, base, context) => Result<Uint8Array>`. A function is how you reach a key management service. The signature base is built for you; the function receives its bytes and returns signature bytes. For exact control over the serialized parameters, use an exact-input spec with `signatureInput` in place of `components`; nothing is generated.

The next program signs through a function and through an exact-input spec, then verifies both with a strict policy. `extraComponents: "reject"` makes the policy accept only the coverage you named, so a sender cannot pad a signature with extra components you did not plan for.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { Message, Policy, PublicKey, ok, sign, verify, type KeyResolver, type Result, type Signer } from "@request-seal/core";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
const pair = generateKeyPairSync("ed25519");
const trusted = must(await PublicKey.import(pair.publicKey.export({ format: "jwk" })));
// A function signer receives the signature base and returns signature bytes; a key service would sit here.
const signer: Signer = async (_algorithm, base) => ok(new Uint8Array(nodeSign(null, base, pair.privateKey)));

const components = '("@method" "@authority" "@path")';
const request = must(await Message.request("GET", "https://api.example.com/orders", [], ""));
const generated = must(await sign(request, { label: "g", components, algorithm: "ed25519", expiresIn: 60, keyid: "client-1" }, signer));
const now = Math.floor(Date.now() / 1000);
const exact = must(await sign(request, {
  label: "e", algorithm: "ed25519",
  signatureInput: `${components};created=${now};expires=${now + 60};keyid="client-1";alg="ed25519"`,
}, signer));

const keyResolver: KeyResolver = ({ keyid }) => ok(keyid === "client-1" ? { algorithm: "ed25519", key: trusted } : null);
const policy = must(Policy.create({
  algorithms: ["ed25519"], components, keyResolver, extraComponents: "reject",
  freshness: { clock: () => now, maxAge: 60, skew: 5, requireExpires: true },
  content: "not_required", replay: "not_required",
}));
must(await verify(generated, policy, { label: "g" }));
must(await verify(exact, policy, { label: "e" }));

// Coverage beyond the policy is refused.
const padded = must(await sign(request, { label: "p", components: '("@method" "@authority" "@path" "@query")', algorithm: "ed25519", expiresIn: 60, keyid: "client-1" }, signer));
const refused = await verify(padded, policy, { label: "p" });
assert.ok(!refused.ok && refused.error.kind === "core" && refused.error.reason === "unexpected_component");
```

Cover `@scheme` as well as `@authority` when the scheme matters. RFC 9421 omits default ports from the derived authority, so a signature covering only `@authority` verifies for `http` and `https` alike.

## Verify

`Policy.create` requires six choices. None has a default, because each is a security decision.

| Choice | What you decide |
| --- | --- |
| `algorithms` | Which algorithms you accept. The resolver's key must use one of them, and a sender's `alg` parameter must agree. |
| `components` | Which components every accepted signature must cover. |
| `keyResolver` | Which key a `keyid`, label, and tag select. Return `ok(null)` for an unknown key. The resolver's algorithm is authoritative. |
| `freshness` | `"not_evaluated"`, or a clock, `maxAge`, `skew`, and whether `expires` is required. |
| `content` | `"not_required"`, or which digest algorithms must be present and recomputed. |
| `replay` | `"not_required"`, or a nonce commitment and a store. See [replay protection](replay-protection.md). |

Optional members are `extraComponents` (`"allow"` or `"reject"`), `maxSignatures`, and `fieldSchemas` for Structured Fields you cover.

`verify(message, policy, { label })` checks exactly the signature you name. It does not try every label and accept the first that passes. It returns a frozen `Verification` only after the cryptography, coverage, freshness, content, and replay layers all succeed. Calling `serializeVerification` gives the ordered, language-neutral facts if you need to log or compare them; the default JSON form hides parameters and key identifiers.

### Stream large bodies

A receiver does not have to hold a body in memory. Hash the chunks as they arrive with a `DigestState`, then pass the state to `verify` instead of a retained body. `createNodeHasher` from `@request-seal/core/node-hasher` supplies the SHA-2 hashing on Node-compatible runtimes. A different body than the one signed produces `digest_mismatch`.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { Custody, DigestState, Message, Policy, PublicKey, ok, sign, verify, type KeyResolver, type Result } from "@request-seal/core";
import { createNodeHasher } from "@request-seal/core/node-hasher";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
const pair = generateKeyPairSync("ed25519");
const signer = must(await Custody.local("ed25519", pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string));
const trusted = must(await PublicKey.import(pair.publicKey.export({ format: "jwk" })));
const components = '("@method" "@authority" "content-digest")';
const chunks = ["first chunk, ", "second chunk"].map((text) => new TextEncoder().encode(text));
const request = must(await Message.request("PUT", "https://api.example.com/upload", [], new TextEncoder().encode("first chunk, second chunk"), { digest: ["sha-256"] }));
const signed = must(await sign(request, { label: "sig", components, algorithm: "ed25519", expiresIn: 60, digest: ["sha-256"] }, signer));
// The receiving side keeps the headers but not the body bytes.
const received = must(Message.create({ ...signed, body: { state: "consumed", bytes: null, source: null, ownership: "caller", maxBytes: 1_048_576 } }));

const keyResolver: KeyResolver = () => ok({ algorithm: "ed25519", key: trusted });
const policy = must(Policy.create({
  algorithms: ["ed25519"], components, keyResolver,
  freshness: { clock: () => Math.floor(Date.now() / 1000), maxAge: 60, skew: 5, requireExpires: true },
  content: { kind: "content", algorithms: ["sha-256"], section: "headers" }, replay: "not_required",
}));
const hasher = must(createNodeHasher());
const honest = must(await DigestState.create("content", ["sha-256"], hasher));
for (const chunk of chunks) must(await honest.update(chunk));
must(await verify(received, policy, { label: "sig", digestState: honest }));

const altered = must(await DigestState.create("content", ["sha-256"], hasher));
must(await altered.update(new TextEncoder().encode("different bytes")));
const rejected = await verify(received, policy, { label: "sig", digestState: altered });
assert.ok(!rejected.ok && rejected.error.kind === "core" && rejected.error.reason === "digest_mismatch");
```

A representation digest (`kind: "representation"`) needs the complete representation, passed as `representation` to `verify`. A content body does not stand in for it.

### Several signatures

A message can carry more than one signature, for example one from the sender and one from a gateway. Verify the label you expect with `verify`. When a request must carry several, build a `Quorum` and call `verifyQuorum`: each assigned signature must meet its own complete policy, and coverage is never pooled across signatures. See [multiple signatures](../reference/quorum.md).

## Respond to a rejection

Every failure is a `Result` with a bounded `error`. Branch on `error.kind` and `error.reason`; never on message text. The adapters wrap the underlying reason in `error.source`.

The function below maps any error to an HTTP status. It is a recommendation, not a requirement; change a status if your service has a reason to. The reasoning, stated once:

- **400** when the message cannot be read: malformed signature fields, a covered component the message lacks, an unreadable body, or input over a limit. Retrying the same bytes cannot succeed.
- **401** when the sender did not prove what your policy requires: no signature, a bad signature, a stale or replayed one, an unknown key, or coverage your policy refuses. A fresh, correct signature can succeed.
- **403** when the signature is understood and your configuration refuses it: a revoked key, an untrusted agent, a published test key, or no principal bound to the actor.
- **500** when your own code or configuration is wrong: an invalid policy, a resolver that threw, or an adapter used in the wrong order. The sender cannot fix these.
- **503** when the failure is transient: anything the library marks `retryable`, a replay store that is down or slow, or key discovery that timed out. A timed-out replay claim may have committed, so the same signed request can come back as `replayed`; the sender should sign again.

The program checks that the table covers every reason in the error vocabulary, so a future reason cannot slip through unmapped.

```ts
import assert from "node:assert/strict";
import { ERROR_PARITY } from "@request-seal/core";

type Rejection = { kind: string; reason: string; layer?: string; detail?: string | null; retryable?: boolean; source?: Rejection | null };

// The default status for every kind (and layer); the exceptions below name single reasons.
const families: Record<string, number> = {
  "core/binding": 403, "core/content": 401, "core/crypto": 500, "core/fields": 400, "core/freshness": 401, "core/input": 500, "core/key": 401,
  "core/negotiation": 400, "core/policy": 401, "core/quorum": 401, "core/replay": 401,
  message: 400, structured_fields: 400, signature_base: 400, digest: 400, crypto: 500, custody: 500, discovery: 401,
  "jose/crypto": 401, "jose/input": 400, "jose/key": 401, "jose/nesting": 400, replay: 503, adapter: 500,
};
const exceptions: Record<string, number> = {
  "core/binding.invalid_binding": 500, "core/binding.invalid_verification": 500,
  "core/content.body_unavailable": 400, "core/content.digest_unsupported": 400,
  "core/crypto.invalid_signature": 401, "core/crypto.signature_base_failed": 400,
  "core/fields.missing_signature": 401, "core/fields.missing_signature_input": 401, "core/fields.no_web_bot_auth_signature": 401, "core/fields.unknown_label": 401,
  "core/fields.label_in_use": 500, "core/freshness.invalid_clock": 500,
  "core/input.invalid_message": 400, "core/input.invalid_request": 400, "core/input.limit": 400, "core/input.unsupported_component": 400,
  "core/key.key_resolver_failed": 500, "core/negotiation.negotiation_unfulfilled": 401, "core/policy.test_key_rejected": 403,
  "core/quorum.ambiguous_key_identity": 500, "core/replay.commitment_failed": 500,
  "core/replay.store_failed": 503, "core/replay.store_timeout": 503, "core/replay.store_unavailable": 503,
  "crypto/invalid_signature": 401, "crypto/invalid_data": 400, "custody/invalid_signature": 401, "custody/decryption_failed": 401,
  "discovery/revoked_key": 403, "discovery/invalid_options": 500, "discovery/invalid_source": 500, "discovery/ambiguous_key_source": 500, "discovery/transport_unavailable": 500,
  "jose/crypto.entropy_failure": 500, "jose/crypto.signer_failed": 500, "jose/input.invalid_options": 500, "jose/input.invalid_policy": 500, "jose/key.key_resolver_failed": 500,
  "replay/invalid_claim": 500, "replay/invalid_options": 500, "replay/invalid_store": 500,
  "adapter/invalid_request": 400, "adapter/limit": 400, "adapter/body_unavailable": 400, "adapter/digest_conflict": 400, "adapter/untrusted_proxy": 400,
};

function statusFor(error: Rejection): number {
  const e = error.kind === "adapter" && error.source ? error.source : error; // adapters wrap the underlying reason
  if (e.retryable) return 503; // the library marks only transient failures retryable
  if (e.kind === "core" && e.reason === "agent_unresolved") {
    return e.detail === "timeout" || e.detail === "source_unavailable" ? 503 : e.detail === "untrusted_agent" || e.detail === "revoked_key" ? 403 : 401;
  }
  if (e.kind === "adapter" && (e.reason === "request_rejected" || e.reason === "response_rejected")) return 401;
  const family = e.layer ? `${e.kind}/${e.layer}` : e.kind;
  const status = exceptions[e.layer ? `${e.kind}/${e.layer}.${e.reason}` : `${e.kind}/${e.reason}`] ?? families[family];
  if (status === undefined) throw new TypeError(`No status for ${family}.${e.reason}`);
  return status;
}

// Every reason in the vocabulary maps to a status, and every exception names a real reason.
const known = new Set<string>(ERROR_PARITY.map((entry) => entry.rule_id));
for (const entry of ERROR_PARITY) assert.ok([400, 401, 403, 500, 503].includes(statusFor(entry)), entry.rule_id);
for (const id of Object.keys(exceptions)) assert.ok(known.has(id), id);

assert.equal(statusFor({ kind: "core", layer: "fields", reason: "missing_signature_input" }), 401);
assert.equal(statusFor({ kind: "core", layer: "content", reason: "digest_mismatch" }), 401);
assert.equal(statusFor({ kind: "core", layer: "key", reason: "agent_unresolved", detail: "timeout" }), 503);
assert.equal(statusFor({ kind: "core", layer: "key", reason: "agent_unresolved", detail: "untrusted_agent" }), 403);
assert.equal(statusFor({ kind: "adapter", reason: "request_rejected", source: { kind: "core", layer: "freshness", reason: "expired" } }), 401);
assert.equal(statusFor({ kind: "discovery", reason: "connect_failed", retryable: true }), 503);
assert.equal(statusFor({ kind: "core", layer: "replay", reason: "replayed" }), 401);
```

Use the status inside your handler, for example `res.status(statusFor(result.error)).end()`. Send the status and a short fixed body. Do not echo `error.reason` to untrusted callers if you want a quiet failure mode; reasons are stable, bounded, and safe to log.

## Where to go next

- [Replay protection](replay-protection.md) closes the window in which a captured request could be sent again.
- [Fetch](fetch.md) and [Node HTTP](node-http.md) verify real requests.
- [Testing](testing.md) shows how to prove your policy rejects what it should.
