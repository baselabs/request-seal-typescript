**Status:** maintained · **Kind:** reference · **Updated:** October 10, 2026 · **Governed by:** RFC 9421, RFC 9530, and the shared conformance corpus · **Review when:** signing, policy, digest, or verification contracts change

# Signing and verification

`sign(message, spec, signer, options)` appends ordered `Signature-Input` and
`Signature` header occurrences and returns a new branded Message in a Result.
Exact-input specs accept a callable signer `(algorithm, base, context) => Result<Uint8Array>`
(with asynchronous results supported) or a branded KeyHandle. Function length
does not determine validity; returned Results and signature bytes do.
Exact-input specs contain `label`,
`signatureInput`, and `algorithm`; their options are `fieldSchemas`, `signingTimeout`, and `context`.
`signingTimeout` accepts integer milliseconds from 1 through 300,000, default
5,000. On both forms, the handle deadline starts immediately before the custody
call, after signature-base construction, and is capped at `signingTimeout` even
under a longer caller Context. A caller Context can shorten that deadline.
Explicit callable execution remains unchanged. An explicit handle algorithm
mismatch returns `signer_algorithm_mismatch` at `input` with message
`"signer algorithm does not match signature specification"`.
Both explicit and generated handle failures return `signing_failed` at `crypto`,
with a bounded custody error in `source`. The outer error is nonretryable;
`source.retryable` can be true for `deadline_exceeded`. Empty, non-binary, or
over-1,024-byte HTTP signatures use source `invalid_signing_output`; malformed
custody errors use `custodian_failure`. Other core errors have null `message`
and `source`. Callable failures on both paths retain `signer_failed` and null
`source`. The reference now accepts KeyHandle on both forms too; the remaining
signer divergence is accepting any callable rather than requiring an arity-two
function.
Generated specs accept a KeyHandle or a signer function and contain `label`,
`components`, `algorithm`, and `expiresIn`.
Defaults are `created: true`, `nonce: "random"`, and `alg: true` for HTTP algorithms (false for JWS selections). Optional `keyid`
and `tag` are printable ASCII. A nested `parameters` object accepts the same
metadata choices. Complete specs also provide `digest`, `fieldSchemas`, and all
six parameter choices; only those permit `expiresIn: null`. Metadata order is
created, expires, nonce, alg, keyid, tag. Generated options are `clock`, a fresh
32-byte `nonce`, `signingTimeout`, and `context`.

`Policy.create()` requires six explicit choices: `algorithms`, serialized
`components`, `keyResolver`, `freshness`, `content`, and `replay`. HTTP algorithms
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
is `"headers"` or `"trailers"`. Optional `extraComponents: "reject"` requires
exact coverage; `maxSignatures` defaults to 16 and may be 1 through 64.
`fieldSchemas` supplies explicit Structured Fields schemas by lowercase field name.

`verify(message, policy, {label, context?, representation?, digestState?})`
returns a frozen branded Verification only after required layers succeed.
Representation and digest state are mutually exclusive. Representation must be
an explicit complete retained Body. Content checks require complete signed
coverage of the selected digest field and every supported checksum present.
Unknown algorithms are recorded but cannot establish integrity.
`serializeVerification()` emits the ordered language-neutral facts documented in
[corpus format](corpus-format.md#canonical-verification).
Every Verification prints and serializes to JSON as `label`, `profile`, `replay`, and `authorization` only.
Callers who need the full facts call `serializeVerification()`.
Generic success records `principal: "unattributed"` and
`authorization: "not_evaluated"`; callers decide authorization.

`Verification.profile` and `Verification.principal` are unions once Web Bot Auth
is present: the profile is `rfc9421` or the `web_bot_auth` profile, and the
principal is `"unattributed"`, an agent principal, or a held-key principal.
Generic callers narrow `principal` before use, checking for `"unattributed"`
and then the `kind` discriminator (`"agent"` or `"key"`).

`digest(bytes, algorithms)` returns RFC 9530 dictionary bytes using captured
WebCrypto, with a 16 MiB hard work ceiling. `DigestState.create(kind, algorithms,
hasher, {maxBytes?})` validates a caller-injected IncrementalHasher against SHA-2
empty and multichunk known answers before use. `create`, session `update`,
and session `finish` must be own properties; explicitly bind prototype methods
when adapting class instances. Its `update()` and `finish()` methods return Results;
updates consume exact copied chunks and retain no body bytes. Finish marks EOF
at the caller's direction. Only incremental hashing permits a larger explicit
work budget. `createNodeHasher()` from `@request-seal/core/node-hasher` supplies the
Node-compatible SHA-2 port.

Replay is `"not_required"` or `{identifier: "nonce", namespace, commitment,
store, timeoutMs}` with bounded freshness. The caller-owned ReplayStore port
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
