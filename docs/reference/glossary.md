**Status:** maintained · **Kind:** reference · **Updated:** October 14, 2026 · **Governed by:** RFC 9421, RFC 9530, the public API in `src/index.ts`, and the guides and references it links · **Review when:** a public type, result field, or documented term changes

# Glossary

One term per concept, as the code and the other pages use it.

| Term | Meaning | Where it is described |
| --- | --- | --- |
| Message | A lossless model of one HTTP request or response: method or status, target, header and trailer occurrences in order, body bytes, and transport facts. `sign` and `verify` work on Messages, never on framework objects. | [Wire APIs](wire.md), [signing and verifying](../guides/signing-and-verifying.md#messages-are-lossless-models) |
| Field occurrence | One header or trailer line as received, with its name case, value bytes, and position preserved. Repeated fields stay separate occurrences. | [Wire APIs](wire.md) |
| Component | A field or derived value (such as `@method` or `@authority`) that a signature covers, named by an RFC 9421 component identifier and its parameters. | [Signing and verification](sign-and-verify.md) |
| Signature base | The exact ordered bytes a signature is computed over, built from the covered components and the signature parameters. | [Wire APIs](wire.md) |
| Label | The dictionary key that pairs one `Signature-Input` entry with one `Signature` entry, such as `sig`. `verify` checks exactly the label you name. | [Signing and verifying](../guides/signing-and-verifying.md#verify) |
| Generated spec, exact-input spec | The two forms of signing specification. A generated spec names components and lets `sign` build the parameters; an exact-input spec supplies the serialized `signatureInput` and nothing is generated. | [Signing and verification](sign-and-verify.md) |
| Policy | A frozen, branded statement of what a verifier accepts: algorithms, required components, key resolver, freshness, content checking, and replay. None of the six has a default. | [Signing and verifying](../guides/signing-and-verifying.md#verify) |
| Key resolver | Your callback that maps a `keyid`, label, and tag to a key you already trust, or to `null` for an unknown key. A `keyid` selects among trusted keys; it never says where to fetch one. | [Getting started](../guides/getting-started.md#habits-that-keep-you-safe) |
| Freshness | The clock, maximum age, skew, and expiry rules a signature must meet. | [Signing and verification](sign-and-verify.md) |
| Content digest, representation digest | `Content-Digest` covers the message content as sent; `Repr-Digest` covers the selected representation. They are different values and one cannot stand in for the other. | [Signing and verifying](../guides/signing-and-verifying.md#stream-large-bodies) |
| DigestState | An incremental hash over a streamed body, passed to `verify` instead of retained body bytes. | [Signing and verifying](../guides/signing-and-verifying.md#stream-large-bodies) |
| Verification | The frozen result of a successful `verify`: the label, signature, profile, principal, freshness, content, and replay facts, with `authorization: "not_evaluated"`. | [Signing and verification](sign-and-verify.md) |
| Authentication, authorization | Authentication is what a Verification establishes: these covered bytes were signed by a key you trust, under your policy. Authorization is your decision about what that sender may do; the library never makes it. | [Security](../../README.md#security) |
| Principal | Who a Verification attributes the signature to: `"unattributed"` for generic verification, an agent principal when a trusted Web Bot Auth source vouched for the key, or a held-key principal. | [Signing and verification](sign-and-verify.md) |
| Profile | The contract a Verification was checked under: `rfc9421`, `web_bot_auth`, or an extension stamp. | [Extension profiles](profiles.md) |
| KeyHandle | A custody handle that can sign, verify, or unwrap without ever returning the private key. `Custody.local`, `createKeyHandle`, and `createSshAgent` create them. | [Key custody](../guides/key-custody.md) |
| Custodian | Trusted code behind a KeyHandle, such as a key service or hardware module, wrapped by `createKeyHandle`. | [Key custody](../guides/key-custody.md#hardware-vaults-and-key-services) |
| PublicKey | A branded, validated public key used for verification and encryption. | [Key custody](../guides/key-custody.md) |
| Context | A deadline and cancellation signal created with `withDeadline` and passed through an operation. | [Key custody](../guides/key-custody.md#deadlines-and-cancellation) |
| Result | Every fallible operation returns `{ ok: true, value }` or `{ ok: false, error }`. Errors carry a bounded `kind`, `reason`, and, for some kinds, `layer`. | [Error vocabulary](error-parity.md) |
| Replay claim | One atomic record in a replay store, keyed by your namespace and commitment, that lets a signature be accepted once. | [Replay protection](../guides/replay-protection.md) |
| Commitment | Your callback that turns authenticated facts into the 1 to 256 bytes that identify "the same request" for replay. | [Replay protection](../guides/replay-protection.md#how-it-works) |
| Replay store | A caller-owned port with atomic `claim` and `sweep`; `createMemoryStore` and the PostgreSQL `createStore` provide two. | [Replay](replay.md) |
| Discovery source | A described location of public keys: a key directory, a JWKS URI, or a client metadata document. | [Key discovery](../guides/key-discovery.md#sources-and-key-sets) |
| Key set | The validated keys from one discovery response, looked up by RFC 7638 thumbprint for the algorithms you allow. | [Key discovery](../guides/key-discovery.md#sources-and-key-sets) |
| Snapshot | Response bytes you fetched yourself, turned into a key set with `Discovery.resolver.fromSnapshot`. | [Key discovery](../guides/key-discovery.md#snapshots-the-path-for-any-runtime) |
| Agent | In Web Bot Auth, an automated client that signs its requests and names its key directory in `Signature-Agent`. | [Web Bot Auth](../guides/web-bot-auth.md) |
| Quorum | A policy that requires several signatures on one message, each meeting its own complete single-label policy. | [Multiple signatures](quorum.md) |
| Capture | The Node adapter's retained copy of an incoming request's line, headers, and body, taken before any parser runs. | [Node HTTP](../guides/node-http.md#why-capture-comes-first) |
| Conformance corpus | The shared, checksummed set of published vectors and expected outcomes that both language implementations execute. | [Corpus format](corpus-format.md) |
| Runtime limitation | A declared, exactly scoped case where a runtime's WebCrypto or transport disagrees with the corpus, reported instead of loosening a check. | [Runtime matrix](runtime-matrix.md) |
