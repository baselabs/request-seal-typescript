**Status:** maintained · **Kind:** reference · **Updated:** October 10, 2026 · **Governed by:** RFC 9421 and the shared conformance corpus · **Review when:** quorum assignment, bindings, or negotiation changes

# Multiple-signature verification

`Quorum.create({mode, unit, slots, unexpected, invalid, bindings?, maxSignatures?})`
returns a frozen branded policy. Node and Deno custom inspection and
`JSON.stringify()` show only `mode`, `unit`, and `maxSignatures`, omitting
slots and callbacks. Mode is `"all"`, `"any"`, or `{threshold: n}`.
Unit is `"keys"`, `"principals"`, or `"roles"`; roles additionally require the
Boolean `sharedPrincipal` choice. Every mode fills all required slots and needs
at least one counting unit. `all` requires at least one required slot; with
unshared principals it also requires distinct principals for the required roles.

Each of 1–16 slots has a unique string `id`, a branded single-label `policy`,
and Boolean `required`. Optional `label` and `tag` select eligible signatures.
`principal` is required for principal and role counting; `role` is additionally
required for role counting. These trusted caller bindings establish counting,
while the single-label result remains unattributed. String identifiers and
bindings are bounded to 256 bytes. `unexpected` and `invalid` each select
`"reject"` or `"ignore"`. `maxSignatures` defaults to 16 and ranges from 1 to 64.

Every slot must use `replay: "not_required"`. Content can be `"not_required"`
or a Content-Digest policy over the retained message body. Representation
policies reject at construction, including in optional or unmatched slots.
`verifyQuorum(message, quorum, {context?, acceptSignature?})` accepts neither
representation nor incremental digest-state options. Construction accepts
replay policies; verification rejects every replay policy
with `invalid_policy` at `input`, after checking the quorum and before checking
the message, including optional or unmatched slots. No clock, resolver,
commitment, or store callback runs.

Signature dictionaries are parsed once under the quorum limit; slot policy
`maxSignatures` does not restrict that parse. Signature bases are cached per
label and field schema for the verification call.

Each label must satisfy its slot's entire policy independently. Coverage never
combines across signatures. Labels and keyid aliases do not count as keys.
Public keys use canonical public components; HMAC requires a trusted nonsecret
equivalence identity from its custodian. Asymmetric handle identities are
derived for quorum verification and checked against any resolver-supplied
identity. Plain single-label verification calls no handle identity operation
unless the resolver supplies an identity to check. Optional unknown identities do not
count under `keys`; a required slot having only unknown candidates rejects with
`ambiguous_key_identity`. Observations of one label merge every observed identity
class; unknown observations share one conservative pool. New bridging evidence
can therefore reduce assignment capacity.

Assignment maximizes counting units, then filled slots, in canonical slot ID
and label order, preferring requested labels. Declaration and wire order do not
change the assignment; result lists retain configured slot order. Unbound key,
principal, and shared-principal role assignment uses polynomial matching.
Other cases use exact search bounded to 131,072 nodes. On exhaustion a
best-so-far assignment succeeds only if required slots, mode, and bindings hold;
otherwise verification returns `limit` at `input`. Search uses matching within
each branch, branches on bound candidates and optional occupancy, and prunes
using the counting unit's upper bound. It checks context cancellation
and the deadline and yields to the event loop after about 10 ms of search
work, using a captured monotonic clock. Partial binding checks compare only
the newly fixed slot with the recorded parameter value; nested bindings are
checked when both members are present. Node accounting follows the reference.

Bindings are `{kind: "nested", outer, inner}` or
`{kind: "same_parameter", name, slots}`. Nested binding requires coverage of
both `"signature-input";key="<assigned-inner-label>"` and
`"signature";key="<assigned-inner-label>"` by the assigned outer signature.
Same-parameter binding requires equal present `nonce`, `tag`, or `created`
values in the selected slots. At most 64 unique bindings are accepted.

`AcceptSignature.parse(bytesOrOccurrences, {target: "request" | "response"})`
returns an ordered frozen branded request array. It rejects duplicate labels
and parameters, unknown parameters, timestamp values other than bare true,
and target-inapplicable components. Up to 16 requests and 65,536 bytes are
accepted. `AcceptSignature.serialize(requests)` produces canonical bytes with
parameter order keyid, alg, created, expires, nonce, tag.

Reference parity: the published RequestSeal v0.4.0 implementation drops
Structured Fields parameter types before validating requests. This port therefore
accepts `tag=abc` and `keyid=:YWJj:` as the string `"abc"` and serializes them
as quoted strings. This differs from RFC 9421 Section 5's string type
requirement. Values must still be valid Structured Fields strings; timestamps
must be bare true and algorithms must be HTTP registry names. Each request's
parameter validation precedes its applicability check, before the next request.

`AcceptSignature.fulfill(message, requests, chooser, signer, {fieldSchemas?, context?})`
returns a promise of a Result. The chooser receives each request and returns
`ok({algorithm, created, expires})`; times are bounded integers or null.
Requested times must be supplied, and a requested algorithm must agree before
signing starts. The caller's signer has the same contract as `sign`: any
callable signer, including bound and rest-argument functions, or a branded
KeyHandle. This intentionally differs from the reference's two-argument
function requirement. Fulfillment
appends signatures in request order, copies requested strings verbatim, and
returns `negotiation_unfulfillable` if selection, components, or signing fail,
without returning a partial message. Chooser failures are bounded. An optional
context bounds chooser and signing work with the same deadline. A deadline
during either selection or signing returns custody `deadline_exceeded`; a
signing rejection that is not a deadline returns `negotiation_unfulfillable`.

Passing requests as `acceptSignature` requires exact labels, component identity
sets, requested strings, and requested timestamps in the independently verified,
selector-eligible pool after key-unit filtering. A challenge may be fulfilled
without being assigned to a counted slot. This establishes challenge matching;
replay and authorization remain unevaluated.

A branded `QuorumVerification` exposes `required`, `satisfied`, deduplicated
`count`, `qualifying` label/slot pairs with counting bindings, label-keyed
`signatures` retaining independent Verification facts, bounded `nonqualifying`
reasons, bindings, and negotiation outcome. Its inspection exposes slot IDs and
counts, omitting signature labels and metadata. `JSON.stringify()` uses the
same redaction, matching the reference's restricted inspection (its result has
no Jason derivation). Use `serializeVerification()` explicitly for complete
label-bearing facts. `isQuorumVerification()` rejects
forged literals. `serializeVerification()` accepts either result type; see
[canonical serialization](corpus-format.md#canonical-verification).

Executed differential coverage (`test/quorum-evaluation.test.ts`):
2,160 count-only instances from the original brute force (any mode, up to 5 slots),
plus 2,160 instances checked on assignments and reasons with bindings, merged and
unknown identities, all modes and units, and 8 to 16 slots. Every slot in the
expanded differential draws choices from a shared label pool. The 14
recorded divergence cases are checked against the reference port.

Composite verification parses signature dictionaries once under the quorum's
`maxSignatures`. A slot policy's own `maxSignatures` does not gate that composite
parse, matching the reference evaluation path.

When the assignment search exhausts its budget, a best-so-far assignment is reported
as success if it meets the policy. The result does not expose search exhaustion,
matching the reference verification result. An exhausted search without a
policy-satisfying assignment reports `limit`.
