**Status:** maintained · **Kind:** guide · **Updated:** October 11, 2026 · **Governed by:** RFC 7515, RFC 7516, RFC 7518, RFC 8725, and the executed examples in this guide · **Review when:** JOSE policies or custody boundaries change

# Signed and encrypted tokens (JOSE)

The JOSE API signs and encrypts compact tokens: `JWS` for signatures, `JWE` for encryption, and `Nested` for a signed token inside an encrypted one. It follows [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html) and [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html), and it takes the same position as the HTTP side: you state what you accept, and nothing in the token chooses an algorithm or a key. The [JOSE reference](../reference/jose.md) lists every option and bound.

RequestSeal checks that a token is authentic and unmodified. It does not read JWT claims, so it does not check `iss`, `aud`, or `exp` for you. Do that after a successful verify, following [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html).

## Policies are explicit

Verification and decryption take a policy object with exact keys. Unknown keys are rejected.

| Operation | Policy keys |
| --- | --- |
| `JWS.verify` | `algorithms`, `timeout` (1 to 300,000 ms), `key_resolver` |
| `JWE.decrypt` | `algorithms`, `encryption`, `max_plaintext` (1 to 1,048,576), `timeout`, `key_resolver` |
| `Nested.decrypt` | `{ jwe, jws }` with the two policies above, and a `content_types` option |

The JWS algorithms are RS256, PS256, PS384, PS512, HS256, ES256, ES384, and EdDSA. JWE supports RSA-OAEP, RSA-OAEP-256, A128GCMKW, A256GCMKW, and `dir`, with A128GCM or A256GCM content encryption. The resolver receives the algorithm and the parsed header, and returns `ok({ algorithm, key })` where `key` is a `PublicKey` or a key handle. Return `err(...)` for an unknown key.

HTTP algorithm names (`ed25519`) and JOSE names (`EdDSA`) are different registries, and no alias connects them. A key handle for JOSE is bound to a JOSE algorithm when you create it: `Custody.local({ jws: "EdDSA" }, pem)` or `Custody.local({ jwe: "RSA-OAEP-256" }, pem)`.

## What the parser refuses

Compact tokens are limited to 1,048,576 bytes and protected headers to 16,384 bytes, depth four, and 64 members per object. A protected header with a duplicate member name at any depth is refused. The headers `crit`, `zip`, `jku`, `x5u`, `jwk`, and `b64` are refused whatever their value, so a token cannot compress its content, pick its own key, or point at a key URL. JSON serializations and detached payloads are refused. The received protected bytes are never reserialized before verification.

## A complete example

The program signs and verifies a token, checks that a changed payload and a narrower policy are refused, seals and opens a message with RSA-OAEP-256, shows the single decryption error, and verifies a signed token inside an encrypted envelope.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { Custody, JWE, JWS, Nested, PublicKey, ok, type Result } from "@request-seal/core";

const must = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };
const text = new TextEncoder(), decode = new TextDecoder();

// Signing: a handle bound to the JWS algorithm EdDSA, and the matching public key for the verifier.
const signing = generateKeyPairSync("ed25519");
const signer = must(await Custody.local({ jws: "EdDSA" }, signing.privateKey.export({ type: "pkcs8", format: "pem" }) as string));
const verifierKey = must(await PublicKey.import(signing.publicKey.export({ format: "jwk" })));
const token = must(await JWS.sign([["alg", "EdDSA"], ["typ", "JWT"]], text.encode('{"sub":"ada"}'), signer));

// The policy names every algorithm you accept and resolves the key. Nothing in the token chooses either.
const jwsPolicy = { algorithms: ["EdDSA"], timeout: 5000, key_resolver: () => ok({ algorithm: "EdDSA", key: verifierKey }) };
const verified = must(await JWS.verify(token, jwsPolicy));
assert.equal(decode.decode(verified.payload), '{"sub":"ada"}');
assert.equal(verified.authorization, "not_evaluated"); // The envelope is authentic; its claims are still yours to judge.

const [header, , signature] = token.split(".") as [string, string, string];
const forgedPayload = Buffer.from('{"sub":"mallory"}').toString("base64url");
const tampered = await JWS.verify(`${header}.${forgedPayload}.${signature}`, jwsPolicy);
assert.ok(!tampered.ok && tampered.error.kind === "jose" && tampered.error.reason === "invalid_signature");
const narrower = await JWS.verify(token, { ...jwsPolicy, algorithms: ["ES256"] });
assert.ok(!narrower.ok && narrower.error.kind === "jose" && narrower.error.reason === "algorithm_not_permitted");

// Encryption: seal to an RSA public key; only the holder of the private key can open it.
const recipient = generateKeyPairSync("rsa", { modulusLength: 2048 });
const sealTo = must(await PublicKey.import(recipient.publicKey.export({ format: "jwk" })));
const owner = must(await Custody.local({ jwe: "RSA-OAEP-256" }, recipient.privateKey.export({ type: "pkcs8", format: "pem" }) as string));
const jwePolicy = {
  algorithms: ["RSA-OAEP-256"], encryption: ["A256GCM"], max_plaintext: 1024, timeout: 5000,
  key_resolver: () => ok({ algorithm: "RSA-OAEP-256", key: owner }),
};
const sealed = must(await JWE.encrypt([["alg", "RSA-OAEP-256"], ["enc", "A256GCM"]], text.encode("secret"), sealTo));
assert.equal(decode.decode(must(await JWE.decrypt(sealed, jwePolicy)).plaintext), "secret");
// Every decryption failure is one error, so an attacker learns nothing from which step failed.
const damaged = await JWE.decrypt(sealed.slice(0, -4) + "AAAA", jwePolicy);
assert.ok(!damaged.ok && damaged.error.kind === "jose" && damaged.error.reason === "decryption_failed");

// Nested: a signed token inside an encrypted envelope. The outer cty must name the inner type.
const inside = must(await JWE.encrypt([["alg", "RSA-OAEP-256"], ["enc", "A256GCM"], ["cty", "JWT"]], text.encode(token), sealTo));
const nested = must(await Nested.decrypt(inside, { jwe: jwePolicy, jws: jwsPolicy }, { content_types: ["JWT"] }));
assert.equal(decode.decode(nested.jws.payload), '{"sub":"ada"}');
```

## Decryption failures look the same

Every decryption failure that depends on secret material returns the same complete error, `{ kind: "jose", reason: "decryption_failed", layer: "crypto", correlation: null, retryable: false }`. That covers a wrong key, a bad RSA-OAEP padding block, and a changed authentication tag. The library always attempts authentication with a fresh fallback key after a failed key unwrap, and it releases no plaintext until authentication succeeds. Malformed framing, headers, initialization vectors, and tags keep their specific input reasons, because those errors do not depend on the secret.

Equal errors do not make equal timings. The [threat model](../design/threat-model.md#jose-key-custody-and-uniform-failure) reports measured timing differences and makes no constant-time claim.

## Keep keys in custody

A `PublicKey` recipient encrypts. To decrypt, the resolver returns a key handle for the RSA private key, or an `unwrap` function that returns an operation-only AES capability. For `dir` and the AES key-wrapping algorithms, `KeyManagement.local` holds the key as a caller-owned capability. The library borrows capabilities you provide and never releases them, so release them yourself after use. See [key custody](key-custody.md) for handles.

## Where to go next

- [Key custody](key-custody.md) explains handles, deadlines, and SSH agent custody.
- [Key discovery](key-discovery.md) fetches public keys for verification.
- [Testing](testing.md) covers the OpenSSL checks that run beside the JOSE tests.
