**Status:** maintained · **Kind:** reference · **Updated:** October 10, 2026 · **Governed by:** the shared RequestSeal corpus contract · **Review when:** manifest schema or canonical serialization changes

# Conformance corpus format

The Elixir and TypeScript implementations consume the same corpus. Source bytes and expected outcomes are shared data. Neither consumer regenerates expectations from its own output.

## Layout and integrity

```text
corpus/
  index.json
  sources/<origin>/...
  cases/<surface>/<case-id>.json
```

`index.json` and case manifests use canonical JSON (RFC 8785), without a trailing newline. Source files retain upstream bytes. Each origin includes SHA256SUMS, PROVENANCE.md, and its upstream license when applicable. Origins include rfc9421, rfc6979, rfc8032, rfc7515, rfc7516, rfc7520, wycheproof, httpwg-structured-fields, web-bot-auth, rfc7517, rfc8037, and local-keys. Locally generated test keys carry a provenance note and are never reused as operational secrets.

Every source and case file is listed once, sorted by path, with a lowercase hexadecimal SHA-256. Consumers reject invalid digests, unlisted files, missing files, symlinks, duplicate cases, and path escapes. The root contains only index.json, sources/, and cases/. A regular file named exactly .DS_Store is skipped at the root or below sources/ or cases/ only when empty or carrying the Finder metadata signature; other entries by that name reject, even if listed. Each single case and asserted batch item executes exactly once. Executed plus not applicable plus consumer runtime limitations must equal listed for a complete run, and the named known-positive case must match successfully. Development runs with --pending-ok additionally count pending items in that tie-out; the release gate forbids pending items. The release tag, commit, and index SHA-256 are pinned together by the consuming repository.

## Index

```json
{
  "format": "request-seal-conformance-corpus-index/1",
  "elixir_release": "v0.4.0",
  "files": [{"path": "cases/signature_base/rfc9421-b2-1.json", "sha256": "<64 lowercase hex digits>"}],
  "cases": [{"id": "signature_base/rfc9421-b2-1", "manifest": "cases/signature_base/rfc9421-b2-1.json", "surface": "signature_base.build", "class": "byte_exact"}],
  "known_positive": "signature_base/rfc9421-b2-1"
}
```

Examples are expanded for readability; stored manifests have sorted keys and no insignificant whitespace. `files` inventories every file under `sources/` and `cases/`. `cases` inventories every case manifest. `known_positive` names a single case of class `byte_exact` or `verify_only`, never a batch or rejection. Other classes fail loading with `invalid_known_positive`.

## Case manifest

```json
{
  "format": "request-seal-conformance-case/1",
  "id": "signature_base/rfc9421-b2-1",
  "surface": "signature_base.build",
  "class": "byte_exact",
  "evidence_class": "published_vector",
  "source": {"document": "RFC 9421", "section": "B.2.1", "url": "https://www.rfc-editor.org/rfc/rfc9421.html#appendix-B.2.1"},
  "inputs": {},
  "keys": [{"name": "test-key-rsa-pss", "file": "sources/rfc9421/keys/rsa_pss_private.pem", "public": "sources/rfc9421/keys/rsa_pss_public.pem"}],
  "policy": {},
  "now": {"int": "1618884473"},
  "nonce": {"b64": "..."},
  "expected": {"base": {"b64": "..."}}
}
```

Required fields: `format`, `id`, `surface`, `class`, `evidence_class`, `source`, `inputs`, and `expected`. Key references, explicit policy, time, and nonce appear when required by the selected surface. Policies have the same required choices as the corresponding public API; no implicit defaults.

`class` is `byte_exact`, `verify_only`, or `rejection`. `evidence_class` is `published_vector` or `reviewed_derivation`. A reviewed derivation requires `derivation`: a description of the single introduced defect and its cited clause, written without running either implementation. HTTP Structured Fields `can_fail` cases additionally carry `pin: "request-seal"` and an explanation of the selected outcome.

`expected` selects the applicable outcome:

| Field | Meaning |
| --- | --- |
| `base: {b64}` | Exact signature-base bytes |
| `bytes: {b64}` | Exact serialization, field values, digest field, or deterministic compact JWS |
| `verification: {...}` | Canonical successful Verification |
| `valid: true` | Positive verification where randomized output cannot be reproduced |
| `rule_id: "core/fields.duplicate_label"` | Exact rejection rule from the error parity table |

Surface-specific successful facts may accompany `valid`, such as `payload: {b64}` for JOSE, `public: {jwk: {...}}` for key import, `keys: [thumbprints]` for discovery, and `retain_until: {int}` with `row: [hex, hex, decimal]` for replay. They must agree with the executed outcome. A rejection carries only the rule ID. Deterministic HTTP signing uses `bytes` as ordered `[field-name, {b64}]` pairs; byte-exact successful facts may use `valid`, `keys`, or replay facts. A `positive` reference requires reviewed_derivation and names a different listed case.

## Value encoding

| Value | Encoding |
| --- | --- |
| Bytes | `{"b64":"<base64url without padding>"}` |
| Exact integer | `{"int":"<decimal source text>"}` |
| Exact decimal | `{"dec":"<source text>"}` |
| Source reference | `{"ref":{"file":"sources/...","pointer":"/3/message"}}` using RFC 6901 |
| Ordered object | `{"pairs":[["k","v"],...]}` |

Never use a bare JSON number for a wire value. Explicit pairs preserve member order for JOSE headers, JWKS, and directories. The decoder preserves numeric lexemes and duplicate member names; the selected surface applies its duplicate policy.

## Surface inputs

| Surface | Minimum inputs and expected outcome |
| --- | --- |
| `structured_fields.parse` | `field_type` item/list/dictionary; `raw` bytes or reference; `schema` rfc8941/rfc9651; `mode` rfc/unique. Canonical serialized bytes or rejection. |
| `structured_fields.serialize` | Typed `value` tree with tagged numbers, bytes, strings, tokens, dates, and display strings. Bytes or rejection. |
| `message.validate` | `message`: kind, method, raw_target, target_form, scheme, authority, status, ordered field pairs, trailers, body bytes or unavailable, related_request. Valid or rejection. |
| `signature_base.build` | Message, serialized Signature-Input inner-list `parameters`, optional `field_schemas`. Base bytes or rejection. |
| `sign` | Message; explicit label/signature_input/algorithm spec or six-key signing spec; clock and nonce options. Exact appended field-value pair array for HMAC, Ed25519, and RSA PKCS #1; sign-then-verify for ECDSA and RSA-PSS; or rejection. |
| `verify` | Message, selected label, options, explicit policy. Verification or rejection. |
| `quorum.verify` | Message and quorum. Quorum verification or rejection. |
| `accept_signature.parse` | Raw bytes. Canonical bytes or rejection. |
| `digest.content` | Content bytes, algorithms, content-digest/repr-digest selector. Bytes or rejection. |
| `crypto.verify` | Algorithm, key reference, data, signature. Valid or rejection. |
| `key.import` | Material bytes or file; pem/pkcs8/jwk format; algorithm. Valid with public JWK/thumbprint, or rejection. |
| `jws.sign`, `jws.verify`, `jwe.decrypt`, `nested.decrypt` | Compact serialization and protected pairs; explicit policy. Deterministic signing bytes, valid with payload where applicable, or rejection. |
| `web_bot_auth.verify` | Message, signed directory body bytes, trusted agent origins, explicit policy, time. Verification or rejection. |
| `discovery.body` | Body bytes; jwks/directory/cimd kind; limits. Key thumbprints or rejection. |
| `replay.claim` | Namespace/key bytes; created, expires, max_age, and skew tagged integers, with nullable expires/max_age. Retention integer and hexadecimal row form, or rejection. |
| `profile.name` | Built-in profile name or package/kind pair. Valid or `core/input.invalid_profile`. |

An unregistered surface or batch item format is reported as pending with case IDs and case/item counts. It fails by default. `--pending-ok` reads the committed `tools/conformance/pending.json` allowlist. Pending surfaces, item formats, case IDs, and case/item counts must match their declared entries. A registered surface or item format appearing in pending, an unlisted entry, or changed counts fails the run; integrity errors and disagreements also fail. Update the allowlist and exact executed count deliberately as execution adapters land. A pending known-positive case is explicitly reported as unexecuted and blocks releases. The separate tooling smoke corpus registers `smoke` for the actual base64url and JSON decoders, plus all four wire surfaces, `crypto.verify`, `key.import`, and `discovery.body`. It exercises byte-exact, verify-only, and rejection classes and has its own pinned index. It is not a released protocol corpus. `--unpinned` allows a deliberate development run; ordinary release-corpus runs require `CORPUS_PIN`.

## Canonical Verification

Members appear in the following order. Covered identifiers retain base order; parameters retain wire order. Quorum serialization uses the corresponding quorum result shape.

HTTP algorithms use their token string. A JWS-algorithm selection uses the pair
`["jws", "<name>"]`, for example `["jws", "PS384"]`, in Verification facts.

```json
{
  "label": "sig1",
  "signature": {
    "algorithm": "ecdsa-p256-sha256",
    "covered": [["@method", []], ["@authority", []], ["content-digest", []], ["@query-param", [["name", "Pet"]]]],
    "parameters": [["created", {"int": "1618884473"}], ["keyid", "test-key-ecc-p256"]],
    "keyid": "test-key-ecc-p256",
    "crypto": "valid"
  },
  "profile": {"name": "rfc9421"},
  "content": "not_required",
  "freshness": "not_evaluated",
  "replay": "not_required",
  "principal": "unattributed",
  "authorization": "not_evaluated"
}
```

`profile` is `{name: "rfc9421"}`, `{name: "web_bot_auth", revision: "draft-ietf-webbotauth-httpsig-protocol-00"}`, or `{name: [package, kind]}`. `content` may be `{kind: "content-digest", checked: ["sha-256"], bytes: {int: "18"}, unsupported: []}`. `freshness` may carry tagged `now`, `created`, `expires`, `max_age`, and `skew`, with nullable expires/max_age. `replay` may carry `{store: "store", retain_until: {int: "<seconds>"}}`; receipts carry neither namespace nor commitment key. Store identity naming is a per-language label. Cross-language comparison uses the receipt's `retain_until` and the normalized store label `"store"`; the runtime receipt retains its public adapter identity. `principal` may carry the trusted agent origin, source kind, and thumbprint. Authorization remains unevaluated.

Web Bot Auth canonical serialization is a map keyed by selected signature label in
lexical order, each value using the single-label shape above with the protocol-00
profile. Canonical agent principals contain `{agent: origin, source: type,
thumbprint}`; held-key principals contain `{thumbprint}`. This intentionally
projects the full runtime provenance into the pinned comparison shape. Envelope
evidence and ignored labels remain runtime facts outside this canonical map.

Quorum facts have this member order: `profile`, `mode`, `unit`, `required`,
`satisfied`, `count`, `qualifying`, `signatures`, `nonqualifying`, `bindings`,
`negotiation`, `replay`, `principal`, `authorization`. Threshold mode is
`["threshold", {"int": "n"}]`; units are `"key"`, `"principal"`, or
`["role", [["shared_principal", boolean]]]`. Count is a tagged integer.
Required and satisfied slot IDs retain configured order. Qualifying entries
contain label, slot, principal, and role. Signatures are keyed by assigned label
in lexical order, with each value serialized as a single-label Verification.
Nonqualifying entries contain label, slot (nullable), bounded reason, and layer.
Bindings are `"not_required"` or ordered `[binding, "satisfied"]` pairs, with
nested binding encoded as `["nested", [["outer", id], ["inner", id]]]` and
same-parameter binding as `["same_parameter", name, [ids]]`. Negotiation is
`"not_requested"` or `"fulfilled"`. Replay stays `"not_required"`, principal
stays `"unattributed"`, and authorization stays `"not_evaluated"`.

## Crypto and key import execution

`crypto.verify` selects an exact HTTP token or an explicit `{jws: "ES256"}`
selector. `key` names a manifest key reference; `data` and `signature` are tagged
Base64url bytes. `format` is `pem` (default), `spki`, or `hmac`. Symmetric source
bytes remain inside a temporary handle, released after verification.

`key.import` takes `algorithm`, `material`, and `format` (`pem`, `pkcs8`, `spki`,
or `jwk`). `material` is tagged bytes, `{file: "sources/..."}`, a source reference,
or a JWK (including explicit ordered pairs). `mode` selects `private` (default)
or `public`; `public_only: true` projects a private source JWK to its public members for RFC 7638 Section 3.2.1 thumbprints. Successful asymmetric import reports `public: {jwk, thumbprint}`.
Private import uses a temporary handle that is always released.

## Wire batch items

A wire surface can execute an upstream vector array as one batch manifest with
`expected: {"valid": true}`. Its inputs contain exactly `format` and `cases`.
`cases` is either an array or a source reference resolving to an array. Source
JSON numbers retain their exact lexemes through the owned decoder.

- `httpwg-structured-fields/1`, on `structured_fields.parse` or
  `structured_fields.serialize`: HTTPWG case objects retain `name`,
  `header_type`, `raw`, `expected`, `canonical`, `must_fail`, and `can_fail`.
  Each provided parsing and serialization operation executes. Typed expected
  byte sequences use the upstream base32 encoding. All mandatory failures
  reject. A single-case manifest selects optional failures with `pin: "reject"`
  or acceptance with `pin: "accept"`; it never reads the repository fixture pins.
  Repository fixture tests alone use `PINNED.ts` and its cited `PINNED.md` table.
- `rfc9421-signature-bases/1`, on `signature_base.build`: each case contains
  `message`, serialized `parameters`, and the published `base` string. Optional
  `transformations` contain `message` and Boolean `same_base`, and may replace the parent's `parameters`; each executes
  and compares its base with the original case's published base.

Ordinary wire manifests encode Structured Fields trees with `kind` and `value`,
plus ordered `parameters` on items and inner lists. Lists contain members;
Dictionaries contain ordered key/member pairs. Integer/Date values use `{int}`;
decimals use `{dec}` or `{scaled: {int}, scale: {int}}`; bytes use `{b64}`.
A schema is a revision string for unrestricted types or an explicit object
with `revision`, `type`, `itemTypes`, `parameterTypes`, and `innerLists`.
`field_schemas` maps lowercase field names to explicit schemas.
Messages use the documented snake_case wire names and ordered field pairs.
Omitted body bytes mean unavailable; an explicit `{b64: ""}` means retained
empty content. Transport declarations default to unknown, with declared evidence.

## Released batch inventory

The `v0.4.0` corpus uses `request-seal-conformance-batch/1` with
`class: "mixed"`, source identity, evidence class, and `batch` containing
`file`, `item_format`, `count: {int}`, and `not_applicable: {int}`. The index
repeats both counts. The loader enumerates the source independently, verifies
both counts, and reports each disagreement with its item position and upstream
name or tcId. Parse and serialize operations for one HTTPWG item count once.
RFC 9421 originals and transformations each count separately, in source order;
the published batch has 12 originals and five transformations.

Each HTTPWG `can_fail` item requires exactly one `pins` entry with `outcome`
(accept or reject) and a clause-based `reason`; other items cannot have pins.
Released batches use their manifest pins, independently of the smoke fixture
pin table. `overrides` names existing upstream items by name or decimal tcId.
Only `wycheproof-aes-gcm/1`, `wycheproof-rsa-oaep/1`,
`wycheproof-ed25519/1`, and `wycheproof-ecdsa/1` support overrides.
An override is a declared pin with a cited clause and may replace any published
verdict: valid, invalid, or acceptable. A manifest carrying `overrides`, even an
empty object, fails loading with `unsupported_overrides` on
`httpwg-structured-fields/1` (which uses `pins`),
`rfc9421-signature-bases/1`, or any other unsupported format.
Rejection overrides contain outcome, rule_id, and clause. Not-applicable
overrides contain outcome and reason; their independently counted total must
match the declared count. Every other item retains its upstream verdict.

The inventory understands Wycheproof group/test layouts for AES-GCM, RSA-OAEP,
Ed25519, and ECDSA. An unfamiliar item format or source layout is reported as pending; its declared
counts remain visible and pending permission still requires an allowlisted entry.
Ed25519 and ECDSA execute on `crypto.verify`; AES-GCM and RSA-OAEP execute custodian-side primitive stages through the `jwe.decrypt` batch adapters. All four JOSE single-case surfaces are registered. Counts and override references are validated even when pending.
See the [published format contract](https://github.com/baselabs/request_seal/blob/v0.4.0/docs/reference/corpus-format.md)
for the complete surface and batch semantics.

Message validation constructs the message and appended fields first, then applies
`message_override` to the constructed members and revalidates the result. Raw
replacement values do not gain the validation of a constructor implicitly.

## Consumer runtime limitations

Runtime limitations are consumer policy, not corpus semantics. Neither source
vectors nor manifests change. `tools/conformance/runtime-limits.json` names the
runtime, exact version, manifest ID, item IDs, observed rule ID, and reason.
An optional nonempty `platforms` array restricts an entry to the listed Node-style
`${process.platform}-${process.arch}` names, such as `darwin-arm64` or `linux-x64`.
Omitting `platforms` applies the entry everywhere. Unknown entry keys, malformed
platform names, and duplicate platform names reject the table, including entries
for unselected runtimes and versions.
Selection uses `process.versions.bun`, `process.versions.deno`, or
`process.versions.node`; Bun and Deno take precedence over their Node compatibility
version. A different version selects no entry; re-pinning requires a deliberate
policy update and verification.

Bun 1.3.14 has one entry for
`crypto/ecdsa_secp256r1_sha256_p1363_test`, items 261 and 262, observed as
`crypto/invalid_signature`: its WebCrypto rejects published valid signatures
with `s = 2^128` and `s = n - 2^128` on `darwin-arm64`. The October 10, 2026
ubuntu-24.04 CI failure log reports that both items verify on `linux-x64`, so
this entry applies only to `darwin-arm64`.

Each item still runs actual cryptography. An entry scoped to another platform
does not exempt an outcome or trigger a stale check: the item must agree with
the corpus oracle. An exact listed divergence counts as
`runtime_limited`, separately from `executed` and `not_applicable`. A listed item
that agrees with the corpus fails as `stale_runtime_limitation`; a different
observed outcome or an unlisted divergence fails as `outcome_mismatch`. A listed
item removed or made not applicable also fails as stale. The CLI and crypto tests
use this same policy. The complete tie-out is
`executed + not_applicable + runtime_limited == listed`; development additionally
includes pending items. A runtime-limited item cannot establish the known positive.

With `--pending-ok`, the designated `known_positive` may remain pending only when
its case is in the exact pending allowlist. An executed or runtime-limited case
cannot use this exemption. The release workflow runs the complete runtime and
corpus battery as its closing gate; pending inventory must match in both directions.

`vendor-corpus <tag>` verifies the release assets and pin without writing the
working tree. `--update-pin` replaces the corpus only when the declared pin moves;
repeating it for the current pin preserves directory identity and source bytes.

Version-pinned `test_file/<filename>` entries in `runtime-limits.json` record native runtime limits for the Node discovery transport. Both files still enter each globbed lane; the matching runtime skips their transport checks and runs a separate real TLS probe that fails if the declared refusal becomes stale. These entries do not change corpus item counts or verdicts.
