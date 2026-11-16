# RequestSeal threat model

RequestSeal processes attacker-controlled wire data at an authentication boundary. Its primary security goal is to report exactly what was cryptographically established, by which trusted association, under which profile, without granting the caller any authorization.

This package and the RequestSeal library for Elixir are two native implementations of one contract. They share an independently sourced conformance corpus and an error vocabulary, and they share these invariants. The first part of this document restates the invariants and the threat table that both implementations answer to. The second part, [TypeScript boundaries](#typescript-boundaries), records what is specific to this package. The rest of the file details custody, JOSE, and timing boundaries.

## Assets and trust boundaries

Assets are private signing authority, private recipient keys, verified message bytes, content-integrity state, principal attribution, replay uniqueness, nested signature binding, and diagnostic confidentiality.

Trust boundaries exist between wire input and the lossless message model; the model and a profile; a profile and key discovery; verification and the replay store; RequestSeal and each framework adapter; independent corpus data and each implementation; and an authenticated principal and caller authorization.

The caller controls accepted profiles, trusted origins and proxies, trust anchors, discovery endpoints, key handles, clocks, the replay store, resource limits, and authorization. An input message controls none of those merely by naming a key, URL, label, algorithm, tag, or identity.

## Security invariants

1. **Verified means exact bytes under a named policy.** Verification covers exactly the selected bytes, validated under an explicitly selected source-bound profile. `verify` takes a `Policy` and a label; `WebBotAuth.verify` takes its own policy. Enforced in `test/sign-verify-contract.test.ts` and `test/web-bot-auth.test.ts`.
2. **A signature covers only what it names.** A signed digest field authenticates body content only after digest recomputation succeeds. Enforced in `test/sign-verify.test.ts` (`digest_mismatch`) and `test/digest-policy-negotiation.test.ts`; the migration tests in `interop/migration/claims.test.ts` show the contrast with a library that never reads a body.
3. **Key possession is not identity.** Identity needs a trusted, profile-valid key association with provenance. A generic verification records `principal: "unattributed"`; Web Bot Auth records an agent principal only when a configured source vouched for the key, and a held-key principal otherwise. Enforced in `test/sign-verify-contract.test.ts` and `test/web-bot-auth-discovery.test.ts`.
4. **Authentication is not authorization.** Every verification, JWS result, and JWE result carries `authorization: "not_evaluated"`. RequestSeal never permits an application action.
5. **Replay success needs one atomic claim over covered facts.** The claim runs last, after cryptography and required content checks. Required Web Bot Auth replay accepts exactly one selected signature and omits its uncovered label; multiple selected signatures reject before commitment or storage. Enforced in `test/replay-verify.test.ts`, `test/replay-fixes.test.ts`, `test/web-bot-auth-replay.test.ts`, and the real PostgreSQL store tests.
6. **Private keys stay behind custody handles.** No error, inspection, serialization, or telemetry path exports them. See [custody and cryptographic boundaries](#custody-and-cryptographic-boundaries).
7. **Failed or incomplete verification never yields a partially trusted principal.** A verification is a frozen, branded value that exists only after every required layer succeeds; every other outcome is an error `Result`.
8. **Profile labels do not weaken rules.** There is no generic or legacy fallback after a named-profile failure.

## Threats and controls

| Threat | Control | Proof in this package |
| --- | --- | --- |
| Canonicalization confusion | Preserve the raw target, ordered field occurrences, trailers, parameter order, and ordered JSON occurrences; derive every component through one source-bound rule set. | The published RFC 9421 vectors (`test/sign-corpus.test.ts`), `test/signature-base.test.ts`, and adapter tests that keep raw targets such as `/a%2Fb?` (`test/adapters-node-http.test.ts`, `test/adapters-fetch-wire.test.ts`). |
| Algorithm and key confusion | Exact algorithm identifiers; a policy allowlist; key type, use, and operation checks; separate HTTP and JOSE registries. | `conformance/cases/verify/algorithm-denied.json`, run by `test/sign-corpus.test.ts`, proves allowlist denial; `test/policy.test.ts` proves exact-identifier validation. `test/crypto-corpus.test.ts`, `test/crypto.test.ts`, and `test/jose-conformance.test.ts` cover cryptographic key and algorithm checks. |
| Component omission | The policy requires coverage explicitly; results expose covered components; digest recomputation is independent. | `test/policy.test.ts`, `test/sign-verify.test.ts`, `test/digest.test.ts`. |
| Signature substitution | Verify each label you accept against its complete policy. Map its verified key to application identity or authority; coverage never pools. | `test/sign-verify.test.ts`, `test/target-uri-fidelity.test.ts`, and `test/accept-signature.test.ts`. |
| Replay race or poisoning | Validate the signature, profile, and linked objects before the caller commitment function or the atomic store runs. Bind the verified nonce to caller-defined scope. Reject ambiguous required input and required callback or store failures. | `test/replay-verify.test.ts`, `test/replay-memory.test.ts`, `test/replay-postgres.test.ts` against a real server, the twenty-way race in the [replay guide](../guides/replay-protection.md), and `test/replay-reciprocal.test.ts`. |
| Discovery SSRF | Caller-configured sources only; HTTPS; manual, bounded, re-checked redirects; DNS and IP revalidation; denial of private, loopback, link-local, and other special-purpose ranges; response, decompression, key-count, and time bounds. | `test/discovery-node.test.ts` and `test/discovery-fixes.test.ts` against real TLS peers, IPv4 and IPv6 literals, redirects, oversized bodies, and cancellation. |
| Stale or removed key acceptance | Source-bound cache expiry and fetch-time metadata; explicit removal that survives refresh; no stale resurrection. | `test/discovery-cache.test.ts` and `test/web-bot-auth-discovery.test.ts`, which rotate and remove keys on a real signed TLS directory. |
| Key exfiltration | Opaque handles; signing and unwrapping inside custody; public-only serialization; redaction; no secret fields in inspection. | `test/custody.test.ts`, `test/crypto-fixes.test.ts`, and the allocation tracker in `test/support/zeroing.ts`. |
| Forwarded-header spoofing | An explicit trusted-proxy policy and one authoritative external origin; ingress and reconstructed facts stay separate. | `test/adapters-node-http.test.ts` and `test/adapters-node-fixes.test.ts`, and the proxy program in the [Node HTTP guide](../guides/node-http.md). |
| Retry or redirect reuse | Every hop and attempt signs afresh with new time and nonce; a cross-origin hop needs approval and drops credential fields; responses bind to the supplied request. | `test/adapters-node-fixes.test.ts`, `test/adapters-fetch-fixes.test.ts`, and the retry program in the [Fetch guide](../guides/fetch.md). |
| Parser and resource exhaustion | Bounded bytes, members, depth, signature, component, and key counts, numeric magnitudes, deadlines, and streaming work. | `test/structured-fields.test.ts`, `test/json.test.ts`, `test/numbers.test.ts`, `test/discovery-core-fixes.test.ts`, and the context tests. |
| Error oracle and data leak | Stable, bounded public reasons; redacted default inspection; one uniform decryption error. | `test/errors.test.ts`, `test/error-branding.test.ts`, `test/jose-uniform.test.ts`. |
| Cross-profile replay | The trusted profile is part of the replay facts, and callers include it in the commitment. No fallback between profiles. | `test/web-bot-auth-replay.test.ts`, `test/profile.test.ts`. |
| Corpus compromise | Immutable provenance, independent expected values, a pinned index digest, and a consumer that never regenerates expectations. | `test/conformance.test.ts`, `test/conformance-vendor.test.ts`, `test/upstream-integrity.test.ts`, and `npm run conformance`. |
| Supply-chain substitution | Zero runtime dependencies, exact development pins, locked dependencies, a package file allowlist, CI actions pinned by commit, release provenance through the trusted publisher with human approval. | `scripts/pack-check.ts`, `test/ci-workflow.test.ts`, and the release workflow. |

## Profile-specific hazards

Web Bot Auth discovery can turn a signed field into a network capability. The selected draft permits more than one discovery type. Selection is configuration, not content negotiation by an attacker. Directory signatures and requests have their own profile rules; support for `req` in one does not imply support in the other. Nested signatures must independently satisfy required coverage. Required replay accepts exactly one selected signature and omits its uncovered label (RFC 9421 Section 7.2.5), preventing relabeled, stripped, or recombined captures from claiming afresh. Nested envelopes require `replay: "not_required"`.

## Generic JOSE threats

HTTP and JOSE use separate parsers and exact algorithm registries. Protected headers and finalized ciphertext bytes stay exact. Decryption withholds plaintext until complete authenticated-encryption validation. Recipient integrity alone establishes neither origin, identity, nor request association. Caller callbacks select keys and application trust explicitly; generic JOSE cannot infer them from wire data.

## Failure behavior

Malformed or unsupported input returns a stable error before cryptographic work when that is safe. Verification continues past a failure only when an explicit multi-signature policy needs it; it never silently accepts the first convenient label. Required digest, discovery, clock, custody, replay, or related-request data that is unavailable fails closed for that profile.

Custody, discovery, JOSE callbacks, Web Bot Auth trust callbacks, and required replay receive bounded deadlines and caller cancellation. A timeout is distinct from invalid cryptography and from policy rejection, and none produces an authenticated principal. Replay errors are always nonretryable, because a timed-out claim may have committed. Discovery separates transient failures, such as a 5xx status, from nonretryable ones, such as a 4xx status. Callers own retry scheduling and whether repeating the whole operation is safe. Errors retain no attacker-controlled diagnostics.

## Residual boundaries

RequestSeal cannot establish that a caller's trust anchors, proxy configuration, authorization policy, or external key-custody service are correct. It makes their inputs, provenance, and unevaluated state explicit so the caller cannot receive an accidental success signal. Assurance for a configured adapter comes from the real-substrate tests listed above, not from the existence of an interface.

# TypeScript boundaries

The invariants above hold in this package through the mechanisms below. Each is a decision a maintainer must not undo by accident, so each names the code that enforces it and the tests that fail without it. The explanations and test references below describe the public implementation boundaries.

## The WebCrypto boundary

All cryptography runs on WebCrypto. The core imports no Node module, which `npm run typecheck:web` enforces by compiling it against browser-style globals with no Node types; only the four locations that need Node (`src/node_hasher.ts`, `src/discovery/node.ts`, `src/adapters/node-http/`, `src/custody/ssh-agent/`) are excluded, and each ships as its own subpath. `src/crypto/subtle.ts` captures `crypto.subtle` methods and `getRandomValues` once, at module load, so code that replaces those globals later cannot change a verdict. This includes `Content-Digest` generation in `Message.request` and `Message.response`. Verification accepts only a literal `true` from the runtime. The library implements no cryptographic primitive.

This boundary trades portability for exposure to each runtime's WebCrypto behavior, which is why [runtime limitations](#runtime-limitations) are declared and not hidden. The accepted decision: zero runtime dependencies and WebCrypto primitives only.

## Option snapshots are read once

Every public function that takes an options object reads it through `snapshotOptions` (`src/brand.ts`). That function accepts only own, string-keyed properties from an allowlist, rejects the whole object if any other own key is present, reads each allowed value exactly once into a null-prototype snapshot, and freezes the snapshot. Inherited properties never become choices, a getter runs at most once, and a getter that throws, or an input that is an array or not an object, becomes `invalid_options` with no detail. This closes time-of-check to time-of-use gaps for options supplied by hostile or buggy callers. `test/options-probes.test.ts` and `test/brand.test.ts` count getter reads and pollute prototypes for every option key.

## Branding uses private WeakSets

Values that carry trust, such as policies, messages, verifications, key handles, public keys, contexts, replay claims, receipts and stores, and errors, are recognized by membership in a module-private `WeakSet`, not by their shape or a public symbol. A caller cannot forge a `Verification` or an error with a lookalike object, and a spread copy loses its brand. The consequences are visible in the API: `isVerification({...v})` is false, adapters reject foreign errors, and `Result` values carrying a foreign error payload throw a `TypeError`. `test/error-branding.test.ts`, `test/brand.test.ts`, and the brand checks in each subsystem's tests cover this.

## Context deadlines

Every operation that can wait takes a `Context`: an absolute deadline plus an `AbortSignal`. A run holds one referenced timer only while it is active, so a callback that never settles still ends with `deadline_exceeded`, and an idle context keeps nothing alive. Contexts with external signals keep one unreferenced timer so their listeners are released at the deadline. The race that decides the outcome uses an owned promise receiver, so replacing `Promise.race` or `Promise.resolve` later cannot forge a result. A callback that ignores the signal is abandoned, not stopped; cancellation cannot interrupt a native operation already submitted to the runtime. The accepted decision: one referenced timer per active run, one unreferenced timer per externally signaled context, and an owned promise receiver for the deciding race.

## Runtime limitations

Where a runtime's WebCrypto or `node:https` disagrees with a published vector or with the other runtimes, the package records the exact runtime version in `tools/conformance/runtime-limits.json` and reports the affected items as `runtime_limited`. It does not weaken the assertion or add a cryptographic fallback. Stale entries, a different rejection, and an unlisted divergence all fail the run. This keeps a green result meaningful. The accepted decision: divergences are declared per runtime version, never silently weakened. See the [observed runtime conformance](#observed-runtime-conformance) results below.

## The Fetch verification allowlist

Fetch implementations differ in how they treat whitespace in repeated fields, cookies, `Set-Cookie`, unusual methods, and the exact request target. Because a signature covers those bytes, the Fetch adapter verifies only on runtimes whose behavior was measured in `test/fixtures/adapters-fetch-wire.json` and `test/adapters-fetch-wire.test.ts`. `FETCH_VERIFICATION_RUNTIMES` is that list, and it is currently `deno:2.5.6`. On any other runtime or version, `verifyRequest` and `verifyResponse` return `invalid_request` before they read the body, call a clock, or resolve a key. Even on an allowed runtime they refuse `@request-target`, `@target-uri`, `@path`, `@query`, `cookie`, and `bs` or `tr` parameters, because the `Request` object cannot reproduce the wire target. The runtime marker is checked against the runtime's own user agent, so a planted `Deno` global on Node does not enable verification.

## Adapter capture

The Node HTTP adapter captures a request before any parser runs and verifies against the capture, not against what a framework later exposes. Capture keeps the raw header occurrences in order, the exact request target, trailers after the body ends, and at most `maxBytes` of body, and it marks the connection facts it observed separately from anything declared. The captured body is handed to a parser only through a replay stream, and verification checks a digest of every byte the stream delivered, so a parser that read a partial or transformed stream is detected. One verification is allowed per request. Forwarded headers have no authority unless the socket peer matches an explicit `trustedProxies` list. See `test/adapters-node-http.test.ts`, `test/adapters-express.test.ts`, and `test/adapters-fastify.test.ts`, which run against real servers and the pinned Express and Fastify versions.

# Custody and cryptographic boundaries

The boundary confines references within one JavaScript realm. Local handles retain
CryptoKey references only in private fields, behind a frozen, independently branded
handle. Public resolution returns public components, not a runtime key. Signing
returns signature bytes. RSA-OAEP unwrapping returns a separately branded AES
operation capability with a private, non-extractable key; it can authenticate and
decrypt content without exporting the content key. Both 128-bit and 256-bit content
keys are supported; callers select the expected length explicitly.

OBSERVED: `test/custody.test.ts` imports a real HMAC CryptoKey as a positive control. On
Node, `KeyObject.from(key).export()` returns the secret even when `extractable: false`;
that flag constrains WebCrypto export only. Deno 2.5.6 rejects that Node compatibility
conversion. OBSERVED: `test/crypto-fixes.test.ts` confirms that structuredClone and
postMessage of a CryptoKey yield a usable copy on Node 22.12.0 and 24.21.0, Deno 2.7.13,
and Bun 1.3.14. On Deno 2.5.6, both copies lose the CryptoKey brand and signing rejects
with TypeError. This version difference does not establish reference confinement:
handles therefore never let a CryptoKey escape their private fields. A CryptoKey
reference is still a cryptographic capability. OBSERVED: boundary tests traverse
results, JSON, inspection output, and structured clones with a visited set and an actual
CryptoKey positive control. Cloning a handle or an unwrapped capability yields no
reachable CryptoKey. The Node conversion rejects the handle itself. Inspection hooks
expose public facts only. These checks describe the tested representations, not heap
confidentiality.

Local import accepts explicit PEM, PKCS #8 DER, and private JWK material. RSA
moduli, exponents, and CRT components are checked before runtime import. EC/OKP
public components supplied with private material must pass a real agreement check.
When public components are absent, import performs one temporary extractable
import, exports a JWK, retains only public members, and imports the operational key
non-extractably. The temporary key is discarded. The DER decoder creates strings
only for public n, e, x, and y components, curve names, and algorithm OIDs; CRT
checks consume INTEGER content bytes directly. Owned DER copies, parser content
buffers (including rejected trees), and the final PKCS #8 import buffer are
overwritten after import. The wrapper copies private octets directly into one
preallocated final buffer. OBSERVED: the allocation tracker with positive controls
in `test/support/zeroing.ts` checks RSA d, a P-256 scalar, and an Ed25519 seed
on PEM, PKCS #8 DER, and JWK imports and rejections. It also checks that DER
decoder results and imported public JWKs contain no private component members.
Caller PEM text and Base64 body strings, caller JWK private component strings,
and private strings from a temporary runtime JWK export still exist and cannot
be zeroed. Exported private members are deleted after public projection. JavaScript
strings and bigints cannot be overwritten, and garbage collection provides no
memory-erasure guarantee.

PSS-only containers retain their binding to RSA-PSS algorithms. Only absent parameters
are accepted. An empty sequence selects SHA-1, MGF1 SHA-1, and salt 20 default
restrictions under RFC 4055 and rejects, as do all present parameters. They cannot
become PKCS #1 or OAEP keys. PSS-only public keys cannot export to JWK, which has no
equivalent type restriction. Metadata-restricted public keys cannot export to SPKI or
PEM, which would discard their restrictions.

HMAC equivalence is an optional nonsecret caller-supplied identity, never a digest
of the secret. Unknown identities never establish equality. Asymmetric equivalence
uses canonical public members; RSA and PSS-only RSA normalize to the same public
identity. Identity inspection omits the equivalence value.

Every operational handle call shares a branded absolute deadline. Late signature
results are discarded, and late AES capabilities are released. Releasing a handle
drops its operational references and subsequent operations return `key_not_found`.
Cancellation cannot interrupt a native operation already submitted to WebCrypto.
Trusted custom custodians must propagate the context and avoid logging secrets;
the handle wrapper bounds exceptions and validates successful result types.

Subtle methods are captured at module load. The library uses exact HTTP and JWS
registries, fixed PSS salt lengths, raw ECDSA widths and scalar bounds, canonical
Ed25519 S, and `subtle.verify` for HMAC. Verification accepts only literal `true`.
The codec accepts definite, canonical DER lengths under byte, depth, and node
ceilings. It never implements cryptographic primitives.

Handle, PublicKey, KeyIdentity, and content-key prototypes and constructors are
frozen at module load. Crypto verification calls captured module functions, so
replacing the library's own prototype methods cannot forge a verdict. Promise
statics and explicit Promise method calls are captured at module load.

The boundary does not defend against a holder using its handle capability, heap
snapshots, debugger/inspector access, memory disclosure, malicious trusted
custodian code, globals patched before module load, or after-load patches to
Object.prototype (such as a `then` getter) or Promise.prototype. Callers own
authorization,
trust, replay policy, and the decision to expose authenticated plaintext.

# Observed runtime conformance

OBSERVED: published vectors and reciprocal OpenSSL commands execute in
`test/crypto.test.ts`, `test/crypto-corpus.test.ts`, and `test/openssl.test.ts`.
The pinned Wycheproof source is commit `12fd3aa`. Node 24.21.0, Node 22.12.0, and
Deno 2.5.6 assert all 151 Ed25519 and all 262 ECDSA P-256 P1363 items.

Bun 1.3.14 on `darwin-arm64` rejects valid ECDSA items 261 (`s = 2^128`) and 262 (`s = n - 2^128`).
Direct WebCrypto calls reproduce both rejections through raw, SPKI, and JWK imports.
Node and OpenSSL verify those same published signatures. The merged batch adapter asserts
all 262 ECDSA items against their published verdicts. The CLI and crypto tests
share the exact-version consumer policy in `tools/conformance/runtime-limits.json`,
which reports these two divergences as `runtime_limited` only on Bun 1.3.14 on `darwin-arm64`; Linux is outside this exception.
Stale entries and other divergences fail. Corpus semantics stay unchanged;
the core adds no cryptographic fallback or acceptance override.

The Linux Bun CI lane runs without `--isolate`: Bun 1.3.14 per-file isolation
intermittently recreates process stdio and returns `EEXIST` from `epoll_ctl`
([upstream issue](https://github.com/oven-sh/bun/issues/37968)). The lane still
runs every test file and its declared documentation fences. See the
[runtime matrix](../reference/runtime-matrix.md) for the runtime and platform boundaries.

The complete boundary has distinguishable distributions because valid and invalid
results take different error-handling paths. Callers receive that validity bit
explicitly. The measurement does not establish resistance to all timing attacks
or attribute every timing difference to a cryptographic comparison.

# JOSE key custody and uniform failure

JWE encryption imports its operational content key non-extractably. RSA public
wrapping encrypts operation-local CEK bytes. GCMKW uses WebCrypto wrapKey, which
requires a temporary extractable content key; that key stays inside the
custodian operation and is discarded. The content operation and recovered AES
capability use independent non-extractable keys. Caller wrappers and unwrap
callbacks are trusted custody code; they can retain explicitly supplied key bytes.
No CryptoKey reference leaves a key-management handle. Primitive decrypt on a
caller-owned key-management handle deliberately returns authenticated bytes;
JWE's RSA and GCMKW handle unwrap uses native `unwrapKey` into a non-extractable
AES capability; recovered CEK bytes never enter library memory. Recovered capability
width must match the selected enc algorithm. Released and mismatched capabilities
follow the same failure path as failed unwrap.

Every decryption generates a fresh non-extractable AES fallback key through
WebCrypto `generateKey`, including successful unwraps. No fallback key bytes
enter library memory. Failed unwrap still attempts authentication
using the fallback. No plaintext is released before authentication and the valid
unwrap check. Malformed input retains the pinned input reasons; the uniform
complete error covers OAEP and authentication failures. Cancellation cannot
interrupt an already submitted native operation. Late operation results are
withheld and owned temporary plaintext buffers are overwritten.

OBSERVED: `test/jose-uniform.test.ts` uses OpenSSL raw RSA operations to change
the OAEP leading zero, masked seed, and masked data block independently. Both
RSA-OAEP hash selections and a changed GCM tag return the complete object
`{kind: "jose", reason: "decryption_failed", layer: "crypto", correlation: null,
retryable: false}`. Independent OpenSSL EVP GCM and CLI OAEP operations execute
in both directions in `test/jose-openssl.test.ts`, including A128GCMKW and
A256GCMKW with empty wrapping AAD and both AES-GCM content widths.

`bench/ceilings.ts` measures HMAC and OAEP failure timing with real keys,
positive controls, warmups, and pairwise distribution comparisons.
Run it from the repository root:

```sh
node --experimental-strip-types --no-warnings bench/ceilings.ts
```

OAEP failure classes may have distinguishable timing at the runtime boundary.
Uniform decryption errors do not guarantee indistinguishable timing.
No constant-time claim is made.
