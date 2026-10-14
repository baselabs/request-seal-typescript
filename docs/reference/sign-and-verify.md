**Status:** maintained · **Kind:** reference · **Updated:** October 14, 2026 · **Governed by:** RequestSeal for Elixir 0.4.1 crypto and custody behavior, RFC 9421, RFC 9530, and the shared conformance corpus · **Review when:** signing, policy, digest, or verification contracts change

# Signing and verification

`sign(message, spec, signer, options)` appends ordered `Signature-Input` and
`Signature` header occurrences and returns a new branded Message in a Result.
The signer is a branded KeyHandle or a callable `(algorithm, base, context) =>
Result<Uint8Array>` (asynchronous results are supported) that returns 1 to 1,024
signature bytes. Function length does not determine validity; returned Results and
signature bytes do.

Exact-input specs contain only `label`, `signatureInput`, and `algorithm`; their
options are `fieldSchemas`, `signingTimeout`, and `context`. Generated specs contain
`label`, `components`, `algorithm`, and `expiresIn`; their options are `clock`, a fresh
32-byte `nonce`, `signingTimeout`, and `context`. `signingTimeout` accepts integer
milliseconds from 1 through 300,000, default 5,000.

Deadlines depend on the signer:

- A KeyHandle's deadline starts immediately before the custody call, after
  signature-base construction, and is capped at `signingTimeout` even under a longer
  caller Context. A caller Context can shorten it.
- A function signer, on either spec form, runs under the caller's `context` when one
  is passed, and otherwise under `signingTimeout`. A function that has not settled by
  then returns `signer_failed`. This differs from RequestSeal for Elixir, whose
  synchronous function signers are not interrupted.

Errors: an exact-input handle algorithm mismatch returns `signer_algorithm_mismatch`
at `input` with message `"signer algorithm does not match signature specification"`;
a generated spec reports the same mismatch as `invalid_options`. Handle failures on
both forms return `signing_failed` at `crypto`, with a bounded custody error in
`source`. The outer error is nonretryable; `source.retryable` can be true for
`deadline_exceeded` or `custodian_unavailable`. Empty, non-binary, or over-1,024-byte
handle signatures use source `invalid_signing_output`; malformed custody errors use
`custodian_failure`. Function failures on both forms return `signer_failed` with null
`source`. Other core errors have null `message` and `source`. A label already present
returns `label_in_use` at `fields`. Generated specs report signature-base failures as
`limit` or `unsupported_component` at `input`, and refuse the `host` component, the
`;tr` parameter, and `;req` on a request with `unsupported_component`; exact-input
specs report base failures as `signature_base_failed` at `crypto`.

Generated defaults are `created: true`, `nonce: "random"`, and `alg: true` for HTTP
algorithms (false for JWS selections, where an explicit `alg: true` rejects). Optional
`keyid` and `tag` are printable ASCII of at most 1,024 characters, or null. A numeric
`expiresIn` requires `created: true`. A nested `parameters` object accepts the same
metadata choices and `expiresIn`, and excludes the top-level metadata keys. Complete
specs put all six choices in `parameters` and also provide `digest` and
`fieldSchemas`; only those permit `expiresIn: null`. Metadata order is created,
expires, nonce, alg, keyid, tag. `digest` lists `sha-256`, `sha-512`, or both, needs
a retained body (otherwise `body_unavailable` at `content`), and adds
`Content-Digest`; an existing `Content-Digest` must carry exactly those algorithms
(otherwise `digest_mismatch` at `content`).

`Policy.create()` requires six explicit choices: `algorithms`, serialized
`components`, `keyResolver`, `freshness`, `content`, and `replay`; every failure is
`invalid_policy` at `input`. `algorithms` holds 1 to 64 unique entries. HTTP algorithms
are exact tokens from `Crypto.algorithms()`. JWS selections use `{jws: name}`
for RS256, PS256, PS384, PS512, HS256, ES256, ES384, or EdDSA; sender `alg`
must be absent for these selections. A resolver receives `{keyid, label,
tag}` and Context, and returns a Result containing `{algorithm, key}` or
`{algorithm, verify}`; `null` means unknown key. A verification callback receives
`(algorithm, base, signature, context)` and returns `Result<boolean>`; true succeeds, false or an error rejects the signature.
Malformed callback results map to `verifier_failed`. Every non-ok resolver
result, malformed binding, or resolver exception maps to `key_resolver_failed`
at the key layer; `ok(null)` maps to `unknown_key`. Callback errors never pass
through as resolver reasons. HMAC keys must be verification functions or
KeyHandles; public keys reject at resolution.
The resolver's algorithm is authoritative. Optional identity is a branded
KeyIdentity and must agree with a supplied public key.

Freshness is `"not_evaluated"` or `{clock, maxAge, skew, requireExpires}`.
`maxAge` is null or a positive integer through 253,402,300,799 seconds; skew is
0 through 86,400 seconds. Expiration is exclusive, max age inclusive. Clocks
return integer Unix seconds from 0 through 253,402,300,799.
Content is `"not_required"` or `{kind, algorithms, section}`, where kind is
`"content"` or `"representation"`, algorithms select SHA-256/SHA-512, and section
is `"headers"` or `"trailers"`. Optional `extraComponents` is `"allow"` (the default)
or `"reject"`, which requires exact coverage; `maxSignatures` defaults to 16 and may be 1 through 64.
`fieldSchemas` supplies explicit Structured Fields schemas by lowercase field name.

`verify(message, policy, {label, context?, representation?, digestState?})`
returns a frozen branded Verification only after required layers succeed.
Without `context`, verification runs under a 5,000 ms deadline. `profile` or
`principal` keys return `invalid_profile` at `input`. Representation and digest state
are mutually exclusive. Representation must be an explicit complete retained Body and
needs a `"representation"` content policy; a digest state's kind must match the
policy's content kind; otherwise `invalid_options`. Content checks require complete signed
coverage of the selected digest field. Every SHA-256 or SHA-512 member the field
carries must be one of the policy's algorithms (otherwise `digest_unsupported`), at
least one must be present, and each is recomputed.
Unknown algorithms are recorded but cannot establish integrity.
`serializeVerification()` emits the ordered language-neutral facts documented in
[corpus format](corpus-format.md#canonical-verification).
Every Verification prints and serializes to JSON as `label`, `profile`, `replay`, and `authorization` only.
Callers who need the full facts call `serializeVerification()`.
Generic success records `principal: "unattributed"` and
`authorization: "not_evaluated"`; callers decide authorization.

`Verification.profile` and `Verification.principal` are unions once Web Bot Auth
is present: the profile is `rfc9421`, the `web_bot_auth` profile, or extension stamps
selected through `Profile.verifyLabel`, and the
principal is `"unattributed"`, an agent principal, or a held-key principal.
Generic callers narrow `principal` before use, checking for `"unattributed"`
and then the `kind` discriminator (`"agent"` or `"key"`).

`digest(bytes, algorithms, {maxBytes?})` returns RFC 9530 dictionary bytes using
captured WebCrypto, with a 16 MiB hard work ceiling; `maxBytes` lowers it. `DigestState.create(kind, algorithms,
hasher, {maxBytes?})` validates a caller-injected IncrementalHasher against SHA-2
empty and multichunk known answers before use. `create`, session `update`,
and session `finish` must be own properties; explicitly bind prototype methods
when adapting class instances. Its `update()` and `finish()` methods return Results;
updates consume exact copied chunks and retain no body bytes. Finish marks EOF
at the caller's direction. Only incremental hashing permits a larger explicit
work budget. `createNodeHasher()` from `@request-seal/core/node-hasher` supplies the
Node-compatible SHA-2 port.

Replay is `"not_required"` or `{identifier: "nonce", namespace, commitment,
store, timeoutMs}`, with a 1–256-byte namespace and `timeoutMs` from 1 through
300,000. It needs bounded freshness: `requireExpires: true` or a non-null `maxAge`.
A signature without a nonce returns `missing_replay_identifier` at `replay`. The caller-owned ReplayStore port
reads `claim`, `sweep`, and optional `identity` by own property; prototype
methods must be explicitly bound to own properties. `identity` is a public
ASCII adapter name (1 through 256 visible characters), defaulting to `"caller"`
for unnamed implementations. The port provides atomic `claim(claim, context)` and `sweep(now, context)` operations.
A claim returns a Result containing `"claimed"` or `"already_claimed"`.
Commitment receives authenticated facts without the label and returns 1 through
256 key bytes. One claim runs strictly after cryptography and required content
checks. The receipt carries only `store` (the public adapter identity) and
`retainUntil`; it exposes neither namespace nor commitment key. Cancellation
cannot undo an already committed claim. Replay deadlines map to nonretryable
`store_timeout`. A Context deadline during required content returns retryable
`custody/deadline_exceeded` with no commitment or store call. Hasher failures remain `digest_unsupported` at content.
Caller cancellation before a clock, resolver, or verifier call returns
`custody/deadline_exceeded`. Handle signing failures, including deadlines, return `signing_failed` at the
crypto layer with a bounded custody source. Callable signing failures return
`signer_failed` with null source. Unrequired content skips digest work;
a deadline before required content begins remains retryable `custody/deadline_exceeded`.

See [replay protection](replay.md) for stores, retention, and PostgreSQL driver glue.

Canonical Verification serialization renders `replay.store` as the literal `"store"`.
The runtime receipt can retain the caller's store identity; canonical bytes use the
stable literal for cross-language comparisons.

A caller abort during the replay stage reports nonretryable `store_timeout`, since
the claim may already have committed. An abort during an earlier stage reports the
retryable `custody/deadline_exceeded` deadline instead.

## Per-call primitive and custody byte bounds

RequestSeal for Elixir 0.4.1 adds `max_bytes` on crypto and custody signing and verification.
The TypeScript counterpart is an optional trailing `{maxBytes}` object:
`Crypto.sign(algorithm, handle, data, options?)`,
`Crypto.verify(algorithm, key, signature, data, options?)`,
`handle.sign(algorithm, data, context, options?)`,
`handle.verify(algorithm, signature, data, context, options?)`, and
`publicKey.verify(algorithm, signature, data, options?)`.
Context continues to carry the deadline and cancellation signal.

`maxBytes` is an integer from 1 through `Crypto.maxBytesCeiling()` (16,777,216).
The default stays 1,048,576. Invalid, unknown, or malformed options return
`invalid_options` before algorithm, handle, or capability validation. Own option
keys are read once. Arrays, including repeated-key entries, reject; JavaScript
object keys are unique before the call. Input over the selected bound returns
`invalid_data`. `Crypto.sign`, `Crypto.verify`, and `publicKey.verify` check the
data size before key validity, so oversized data with an unusable key reports
`invalid_data`. Existing octet-string and Uint8Array input shapes are preserved.
Unwrap does not accept this option.

Direct custodian callbacks require Uint8Array input within the ceiling before
reading their private reference. A custodian using another handle or primitive
must explicitly pass the ceiling after the managed boundary has checked the
caller's bound. A Body defaults to 1 MiB and its `maxBytes` can raise that; message
fields, JWS, adapters, and SignatureBase keep their fixed limits.

Source: [RequestSeal for Elixir 0.4.1 crypto](https://github.com/baselabs/request_seal/blob/v0.4.1/lib/request_seal/crypto.ex)
and [custody](https://github.com/baselabs/request_seal/blob/v0.4.1/lib/request_seal/custody.ex).
The error vocabulary pin is v0.4.1; the shared corpus remains v0.4.0 because its
index is byte-identical across the tags and v0.4.1 supplied no corpus assets.
