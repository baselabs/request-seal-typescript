**Status:** maintained · **Kind:** reference · **Updated:** October 14, 2026 · **Governed by:** RFC 7515, RFC 7516, RFC 7518, and the v0.4.0 corpus · **Review when:** JOSE policies or custody boundaries change

# Compact JOSE

`JWS.sign(pairs, payload, signer, options)` serializes ordered protected pairs.
`JWS.signProtected(bytes, payload, signer, options)` signs caller-serialized JSON
exactly. A signer is a branded KeyHandle or any callable receiving
`(selector, signingInputBytes)` and returning `Result<Uint8Array>`, synchronously
or asynchronously. Function length does not determine validity; returned Results
and signature bytes do. The selector is `{jws: algorithm}`; a KeyHandle must be
bound to that algorithm or signing returns `algorithm_mismatch`. Function signers run under
the operation deadline and failures become `signer_failed`. Payloads must be nonempty; an empty payload returns
`detached_payload`.
`JWS.verify(compact, policy, options)` requires exactly `algorithms`, `timeout`
(milliseconds, 1–300,000), and `key_resolver`. Supported names are RS256, PS256,
PS384, PS512, HS256, ES256, ES384, and EdDSA.

The resolver receives `{algorithm, header}` and a Context. `header` is an ordered
array of pairs containing the owned JSON nodes; numbers retain their lexemes.
Return `ok({algorithm, key})` with a PublicKey or KeyHandle, or
`ok({algorithm, verify})`. A verifier receives `(selector, base, signature, context)`
and returns `Result<true>`. The selector is `{jws: algorithm}`. Resolver errors
mean `unknown_key`; throws and malformed entries mean `key_resolver_failed`.
An entry must have exactly two keys and must match the selected wire algorithm
(otherwise `algorithm_mismatch`).

`JWE.encrypt(pairs, plaintext, recipient, options)` supports RSA-OAEP,
RSA-OAEP-256, A128GCMKW, A256GCMKW, and dir with A128GCM or A256GCM.
A recipient is a compatible PublicKey, an RSA-OAEP handle whose public key is
resolved, or a trusted wrapper `(algorithm, generatedCekBytes, context)` returning
`ok({encrypted_key: bytes, header: pairs})`. Protected additions may contain only
GCMKW `iv` and `tag`; they follow the caller's members in name order. For dir,
the wrapper provisions the generated key through its own custody and returns
an empty encrypted key. The wrapper's temporary key bytes are overwritten after
settlement; copy them explicitly when provisioning recipient custody.

`KeyManagement.local(algorithm, material)` creates a separately branded,
caller-owned custodian capability. AES material is 16 or 32 bytes; RSA material
uses the validated custody PEM, PKCS #8, or JWK import. Its `wrap` method supports
GCMKW; `unwrap` returns an operation-only, non-extractable AES capability.
Custodian-side `decrypt` authenticates and returns bytes for published primitive
stages, including OAEP messages that are not content keys. `release` drops its
key reference. Every operation returns a Result.

`JWE.decrypt(compact, policy, options)` requires exactly `algorithms`, `encryption`,
`max_plaintext` (1–1,048,576), `timeout`, and `key_resolver`. Resolution receives
`{algorithm, encryption, header}` and Context, and returns
`ok({algorithm, key: rsaHandle})` or `ok({algorithm, unwrap})`. An unwrapper accepts
`(encryptedKeyBytes, header, context)` and returns a Result containing an
UnwrappedKey or 16/32-byte CEK. Callback capabilities remain caller owned:
decrypt borrows them and never releases them. Release or replace them in caller
custody after use. Raw callback bytes are copied before import and are not erased
by decrypt. Decrypt releases only capabilities created inside the operation,
including fallback keys and results from custody-handle unwrap. A handle may also occupy `unwrap`. Wrong bindings,
released handles, unwrap failures, and authentication failures yield the same
complete `jose/crypto.decryption_failed` error. Deadlines remain distinct.

`Nested.decrypt(compact, {jwe: outerPolicy, jws: innerPolicy}, options)` verifies
one JWS inside one authenticated JWE. Options require a unique nonempty
`content_types` array. The outer `cty` must match; an inner envelope or inner JWS
with `cty` rejects. Each stage retains its own policy timeout. All APIs accept an
optional branded `context` to share a parent deadline. Signing and encryption
also accept `timeout` (1–300,000 ms, default 5,000); all other option keys reject
with `invalid_options`.

Successful results are frozen and independently branded. `JWS.isResult`,
`JWE.isResult`, and `Nested.isResult` (also exported as `isJwsResult`, `isJweResult`, and
`isNestedResult`) validate their respective types; `KeyManagement.isHandle` (also
`isKeyManagementHandle`) and `isUnwrappedKey` check those capabilities. Header
nodes are frozen; `payload` and `plaintext` return fresh byte copies. JSON and
inspection show public facts only. Protected segments are received bytes,
never reserialized for verification or authentication.

Compact input and output are bounded to 1,048,576 bytes; protected JSON is bounded
to 16,384 bytes, depth four, and 64 members or array entries per container.
Duplicate names reject at every depth. Headers reject `crit` (`unsupported_critical_header`), `zip`
(`compression_unsupported`), and `jku`, `x5u`, `jwk`, and `b64` (`unsupported_header`)
regardless of value. JSON serializations, detached JWS,
floats, and integers outside ±999,999,999,999,999 reject. Malformed framing,
headers, IVs, and tags retain their specific input errors; uniform failure covers
unwrap and authentication. Cryptography establishes envelope integrity;
callers supply trust, identity, claims, replay, and authorization policy.

# Declared reference differences

For JWS signing, the reference requires a two-argument function, while this package accepts any callable or a KeyHandle without changing wire bytes.

A non-string wrapper addition value gives `unsupported_header`; the reference
gives `invalid_base64`. A function signer signals a deadline only with a branded error
whose reason is `deadline_exceeded`; an unbranded error with that reason gives
`signer_failed`. The reference also accepts a bare `deadline_exceeded` reason.

A key-management unwrap obtained through a callback remains caller owned.
Decrypt releases the returned capability only when decrypt created it. Callbacks
that create capabilities must retain and release their own references after use.
Decrypt generates its fallback key with WebCrypto `generateKey`, non-extractably,
so fallback key bytes never enter library memory.

For objects with 32 members or fewer, header validation walks UTF-8 member-name
order, and nested objects serialize in that order, matching reference small maps.
For 33–64 members, TypeScript uses deterministic UTF-8 name order for both walks
and emitted nested bytes. The reference uses runtime-specific hash-map order,
which is not portable across runtimes. Consequently, two invalid members in a
larger object can produce a different first reason, and nested serialized bytes
can differ. Top-level caller pair order and all received protected bytes remain
verbatim. Use `signProtected` when exact caller-serialized bytes are required.

JOSE header strings accept Unicode noncharacters, matching the reference's UTF-8
validation. The generic I-JSON decoder retains its stricter default; JOSE enables
noncharacters explicitly. `JoseHeader` is internal; use the JWS and JWE APIs. The exported
`JoseProtectedHeader` type is the ordered-pair header that resolvers and unwrappers
receive.
