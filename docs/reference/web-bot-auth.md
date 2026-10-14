**Status:** maintained · **Kind:** reference · **Updated:** October 14, 2026 · **Governed by:** draft-ietf-webbotauth-httpsig-protocol-00 and the shared v0.4.0 conformance corpus · **Review when:** profile acceptance, discovery, or replay contracts change

# Web Bot Auth

`WebBotAuth` signs and verifies the source-bound protocol-00 request profile.
A `web-bot-auth` tag selects each signature. The profile requires created and
expires, a canonical SHA-256 JWK thumbprint key ID, authority or target URI
coverage, and the matching dictionary member of `Signature-Agent` when present.
Legacy string fields reject. No discovery connection starts implicitly in core.

`WebBotAuth.Policy.create()` requires `algorithms`, a callable `agents` trust
callback, `cache` (a caller-owned DiscoveryCache or null), `freshness`
(`clock`, `maxAge`, `skew`), `content`, and `replay`. These use the generic
[policy contracts](sign-and-verify.md); expiration is always required and HMAC
is forbidden. Optional choices are `components` (default `"()"`),
`maxLifetime` (1–604,800 seconds, default 86,400), `testKeys` (`"reject"` by
default or explicit `"allow"` for published test material), `untagged`
(`"ignore"` by default or `"reject"`), `maxSignatures` (1–64, default 16),
`fieldSchemas`, and `unresolved` (`"reject"` or `{heldKeys: resolver}`). A held-key
resolver receives `({label, keyid, tag}, context)` and returns a Result containing
`{algorithm, key}` or null; the algorithm must equal one of the policy's algorithms,
or the signature is `agent_unresolved` with detail `unknown_key`.
Construction invokes no callbacks. Each own option value is read once.

Trust receives `{identifier, location, type}` and returns a Result containing a
branded DiscoverySource or fresh KeySet, or null to refuse trust. Directory
members contain canonical HTTPS origins without a trailing slash. Their
identifier is the normalized well-known directory URL. JWKS and CIMD members
retain their exact location without the fragment; comparison identifiers
normalize the origin and path separately. Query-bearing locations remain
distinct principals. Configuration selects the source, never the key ID.
Redirect-enabled sources reject. Key resolution checks source type, location,
origin, actual key thumbprint, revocation, freshness, and required possession
proof. HTTP and explicit JOSE algorithm selections remain separate.

The TypeScript origin check normalizes the host as the WHATWG URL parser does.
Thus `https://[0:0::1]` and `https://0x7f.1` reject as `not_an_origin` here,
while the reference compares the host text. TypeScript fails closed for these
noncanonical host spellings. No corpus case covers this difference.

The three-key `sign()` form and `WebBotAuth.sign` accept a branded
KeyHandle and any callable, while the reference requires a two-argument function.
No wire bytes change; callable results still undergo signature validation.
`agents` and `heldKeys` accept any callable, while the reference requires arity-one functions.
Results are validated at invocation.

For a directory snapshot, default discovery requires a signed possession proof
covering `@authority;req` and `content-digest`. The response proof and request
profile use separate rules. An explicit `requireSignedDirectory: false` permits
caller-owned unsigned snapshots. See [discovery](discovery.md).

`WebBotAuth.verify(message, policy, options)` validates every selected label
independently. Options are `representation`, `digestState`, `context`, and
`timeoutMs` (1–300,000, default 5,000). Trust, discovery, verification, content,
and replay share the caller's absolute Context deadline. Agent resolution
failures carry bounded details; URLs, key IDs, nonces, and callback diagnostics
never enter errors. Held-key fallback returns only a thumbprint principal and
cannot bypass source mismatch, revocation, non-origin directory members, or a
present field missing the selected member.

A deadline that fires during trust or discovery is reported as `agent_unresolved`
with detail `timeout`, matching the reference's resolution behavior.
A deadline that fires inside the per-signature check is reported as retryable
`custody/deadline_exceeded`. These are the agent-resolution and per-signature
verification phases, respectively.

Held-key fallback is attempted after refused trust, an unsupported agent type, an unknown key,
an unavailable source, or a timeout; never after `revoked_key`, `source_mismatch`, or `not_an_origin`.
It also handles an absent agent field, but a present field without the selected
member rejects before resolution. Fallback shares the Context deadline: an
expired Context prevents the held-key callback from starting. A source timeout
with time remaining in that Context permits the callback to run.

An outer signature covering `signature;key="inner"` must also cover the inner
label's `signature-input` member and its entire component set, including its
agent member. Coverage never pools across independently insufficient signatures.
An outer covering only `signature-input;key="inner"` authenticates metadata,
not the inner signature bytes; it adds no nested evidence. This matches the
reference's member-specific completeness rule.
The frozen, separately branded WebBotAuthVerification contains `profile`,
`signatures`, `evidence` of these inner labels, `ignored`, `replay`, and
`authorization: "not_evaluated"`. Individual signature facts retain their own
Verification brands, full trusted source provenance, and either an agent or
held-key principal. Inspection omits those principals and signature metadata.
`serializeVerification()` emits the pinned corpus's sorted per-label map;
canonical agent facts contain `{agent: origin, source: type, thumbprint}`.
Runtime attribution retains the directory identifier and origin separately.

Nested evidence records coverage only. An inner label listed in evidence may be
untagged or unverified. Callers intersect the evidence labels with the `signatures`
map before relying on them as verified signatures.

Required replay commits once after every selected signature, content check, and
nested-coverage check succeeds. The commitment callback receives frozen
`{profile: {name: "web_bot_auth", revision}, signatures: [...]}`. Each entry
contains `label`, `identifier` (nonce), `algorithm`, `keyid`, stable `agent`
facts, `created`, and `expires`. Agent facts are `{kind, identifier, type, origin, thumbprint}`
without `provenance`, so they omit source proof, cache revision, and fetch time;
held-key facts are `{kind: "key", thumbprint}`.
Include the profile name and revision in the caller's commitment encoding to
separate generic and Web Bot Auth claims. The library does not prefix the
namespace or commitment output with the profile; a nonce-only commitment in a
shared namespace collides across profiles, matching the reference. Use distinct
caller namespaces or the [profile-aware commitment recipe](replay.md).
Sort stable signature identities when
wire-order-independent replay scope is required. Hash the encoded bytes and
return a Result containing 1–256 commitment bytes. Labels and retention are
metadata, not automatic uniqueness scope. Retention is the earliest acceptance
end across the complete envelope; the clock ceiling applies to that end. One
receipt is shared by all selected signature facts. See [replay](replay.md).

Matching the reference, verification reads the freshness clock separately for
the profile check, associated-key lookup, and generic signature check. Each
stage uses its own sample; final freshness facts record the generic sample.
Use a consistent caller clock. An advancing clock can expire a key or signature
between those checks and cause rejection.

`WebBotAuth.sign(message, spec, signer, {fieldSchemas?, context?})` requires a
request, `label`, `agent: {location, type}`, branded public `key`, `algorithm`,
explicit `created`, `expires`, and `nonce` (1 to 1,024 characters, or null). A signer
function of any arity receives `(algorithm, base, context)` and returns
a Result containing real signature bytes, synchronously or asynchronously.
A branded KeyHandle is also accepted. Function length is not a contract;
callback behavior is validated through its Result. Signing adds authority and the matching
agent member to optional `components`, derives the key ID from the public key,
and stamps protocol parameters in created, keyid, alg (HTTP only), expires,
nonce, tag order. Lifetime is positive and at most 86,400 seconds. Verification
policies may allow up to 604,800 seconds; the signing limit stays
86,400 seconds, matching the reference's distinct signing and policy bounds.
Existing agent members are preserved; conflicting members and incomplete nesting reject
before signing custody is invoked.
