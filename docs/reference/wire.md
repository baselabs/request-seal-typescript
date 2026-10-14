**Status:** maintained · **Kind:** reference · **Updated:** October 14, 2026 · **Governed by:** RFC 8941, RFC 9651, and RFC 9421 · **Review when:** wire API contracts change

# Wire APIs

`StructuredFields.parse(fieldType, raw, options)` and
`StructuredFields.serialize(value, options)` return `Result`. Raw input accepts
`Uint8Array` or a ByteString whose code units each represent an octet. Output is
`Uint8Array`. Parsing requires an explicit `schema`; omission returns `invalid_schema`.
The string forms `schema: "rfc8941"` and `schema: "rfc9651"` enable their
revision's bare types but keep inner lists disabled. Select RFC 9651 for
Date and Display String types; enable inner lists explicitly in a schema. Parsed values retain their selected schema for
serialization. Caller-built trees require an explicit schema for serialization. To restrict item or parameter types, pass a schema created with
`createSchema({revision, type, itemTypes, parameterTypes, innerLists})`.

Items contain `{kind: "item", value: {kind, value}, parameters: []}`. Inner lists
contain ordered items and parameters; lists contain ordered members;
dictionaries contain ordered key/member pairs. Parsed decimals use
`{scaled, scale: 3}`. Direct decimal values accept safe integer `number` coefficients or exact
`bigint` coefficients with magnitude below 10³⁰ and scales from 0 through 18.
Serialization rounds ties to even at three places and rejects magnitudes
beyond the RFC 9651 limit of 999,999,999,999.999 after rounding. Integer and
decimal negative zero serialize as `0` and `0.0`, respectively. A standalone
inner-list root returns `schema_type`; wrap it in a list to serialize it.
`display_string` values are Unicode strings; `bytes` values are copied octets.
An empty list or dictionary serializes to empty bytes, meaning omit the field.

`mode: "rfc"` retains the last repeated value at its first position.
`mode: "unique"` rejects repeated dictionary keys and parameter names after
completing the bounded parse. `uniqueKeys: "all" | string[]` independently
selects dictionary keys whose repeats reject; other keys retain RFC behavior.
Listed keys reject immediately after a repeated key is read, before its value;
`"all"` waits until the bounded parse completes.
`uniqueParameters: boolean` independently controls parameter uniqueness at
every nesting level. Explicit settings override the corresponding `mode`
default. `limits` can lower any property of
`STRUCTURED_FIELDS_LIMITS`, never raise it. Unknown options reject.
Parsed structures are frozen; byte arrays follow the foundation's copied-byte
contract. Re-serialization validates every direct value.

`StructuredFields.parseField(message, name, schema, section = "headers", options)`
selects the branded message's ordered occurrences case-insensitively, combines
them with comma-space per RFC 9421 Section 2.1, and parses under the explicit
schema. Trailer selection requires an available trailer array. Missing fields
return `missing_field`; unavailable trailers return `unavailable_section`.
For Content-Digest, use a dictionary schema with bytes items and
`uniqueKeys: ["sha-256", "sha-512"]` to reject repeated digest algorithms
across occurrences while preserving the RFC rule for other dictionary keys.

```ts
import {StructuredFields} from '@request-seal/core';

const parsed = StructuredFields.parse('dictionary', 'a=1, b=2;p', {
  schema: 'rfc8941',
  mode: 'unique',
});
if (parsed.ok) {
  const canonical = StructuredFields.serialize(parsed.value);
}
```

`Message.create(attrs)` constructs lossless requests or responses.
`Message.validate(value)` applies the same rules and returns a new frozen
snapshot. Required attributes are `kind`, `fields`, `trailers`, `body`, and
`transport`. Requests additionally require `method`, `rawTarget`, and
`targetForm`, and may set `scheme` and `authority` together. Responses require an
integer `status` from 100 through 599; `relatedRequest` can link a validated
request. Related requests must be branded Message values. Field occurrences retain name case, whitespace, obs-text, duplicates,
and order. Header and trailer sections remain separate. Body and field byte
accessors return fresh copies so callers cannot mutate a constructed message.

Create nested values through `FieldOccurrence.create({name, value, section, provenance?})`
(provenance `caller`, the default, `http1`, `http2`, or `http3`),
`Body.create({state, bytes?, source?, ownership?, maxBytes?})` (ownership is only
`"caller"`; `maxBytes` defaults to 1,048,576 and has no fixed ceiling), and
`TransportFacts.create({httpVersion?, tls?, evidence?})` (`httpVersion` is `unknown`,
`http1_0`, `http1_1`, `http2`, or `http3`; `tls` is `unknown`, `plain`, or `tls`). Body states are
`retained`, `streaming`, `consumed`, and `unavailable`. Streaming requires a
caller-owned stream with a callable `getReader` (including streams from other realms); construction never reads or locks it.
`trailers: "pending"` requires streaming content. Transport evidence can only
be `declared`; unknown protocol and TLS declarations are preserved.

The asynchronous convenience builders
`Message.request(method, absoluteHttpUrl, orderedPairs, bytesOrNull, options)`
and `Message.response(status, orderedPairs, bytesOrNull, options)` retain body
bytes. The request builder lowercases scheme/host and omits HTTP(S) default
ports while preserving path and query octets. An absent path becomes `/`. Fragments and non-HTTP(S) schemes reject with
`invalid_message`.
Direct `Message.create` supports all four target forms without normalization.
Authorities follow RFC 3986 Section 3.2.2: bracketed hosts are IPv6 or IPvFuture
literals. Bracketed IPv4 (including shortened, decimal, or hex forms) and zone identifiers
reject with `invalid_message`; an unbracketed numeric host such as `127.1` is a
registered name and is kept as written. When parsing Structured Fields byte
sequences, `=` padding is optional, as RFC 9651 Section 4.2.7 recommends: absent or
partial padding is accepted (`:YQ:`, `:YQ=:`, and `:YQ==:` all decode to `a`). Nonzero
padding bits (`:YR==:`) reject with `syntax`; this is the shared decoding rule, stricter
than the RFC's recommendation.
Optional `digest: ["sha-256", "sha-512"]` adds Content-Digest over retained
bytes. Generating a digest rejects an existing Content-Digest occurrence.
A response builder accepts `request` to set its related request.

`SignatureBase.build(message, parameters, options)` synchronously returns exact
base bytes. `parameters` is serialized Signature-Input inner-list bytes or a
typed `InnerList`. Messages must be branded values from the Message API.
Caller-built inner lists are serialized once and re-parsed into a frozen tree
before their components are read for the base. Each caller accessor is read
once; the snapshot must contain exactly one inner list, and its canonical
serialization supplies the signature parameters line. The final `"@signature-params"` line has no trailing newline.
Derived components, field occurrence order, related requests, and trailers
follow RFC 9421. `sf` and `key` require an explicit schema in
`fieldSchemas`; `bs` wraps each trimmed occurrence individually.
`maxComponents` and `maxBytes` can only lower the exported ceilings.

```ts
import {Message, SignatureBase} from '@request-seal/core';

const message = await Message.request('GET', 'https://example.com/a%2Fb?', [], null);
if (message.ok) {
  const base = SignatureBase.build(message.value, '("@method" "@path")');
}
```

Origin facts never come from Host or Forwarded fields. `@query-param` uses
canonical encoded names, rejects ambiguous decoded names, and preserves empty
values. Query parsing eagerly decodes every key as UTF-8; malformed key
encoding rejects even when another key is covered. Only selected values are
decoded. Building a base establishes bytes only; cryptography and policy checks
are separate operations.

Parser-produced Structured Fields values retain their validated schema in a private
WeakMap. `serialize(value)` reuses that schema; an externally constructed tree needs
`{schema: ...}`. `StructuredFieldsOptions` describes the explicit schema path.

Contexts release caller and parent abort listeners when their absolute deadline
passes, including after all runs settle. Each run keeps the process alive until
it settles or its deadline passes, so a run whose only pending work is a caller
callback that never settles still returns `deadline_exceeded` on Node, Deno and
Bun. Idle and settled Contexts keep nothing alive: signal-free Contexts arm no
timer outside a run. Contexts with caller or parent signals arm an unreferenced
creation-time timer to release listeners even if never run. A
settled Context remains reusable until that deadline; reuse after internal
release reattaches its caller and parent listeners. A run that ends at its
deadline abandons its callback; callbacks should honor `context.signal`.
