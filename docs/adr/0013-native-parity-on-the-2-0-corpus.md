# 0013 — Reach native parity with RequestSeal for Elixir 2.0 in 0.6

## Context

RequestSeal for Elixir 2.0 adds AES Key Wrap, ECDH-ES key agreement, protected-member policy for
JWS and JWE, embedded public keys for JWS, batch JWE decryption, strict JSON object decoding and
key handles in place of key closures. This package is pinned to the 1.0.0 corpus
(`src/constants.ts:4`) and has none of those surfaces: its JWE algorithms are RSA-OAEP-256,
RSA-OAEP, A128GCMKW, A256GCMKW and `dir` (`src/jose/support.ts:22-28`), and a signer may still be
a function (`src/signer.ts:7`).

The existing 1.0.0 corpus already uses cases/<surface prefix>/<name>.json, and this package reads it. The 2.0 contract additionally requires rejecting any disagreement among case ID, manifest path and surface prefix.

## Decision

1. Release 0.6.0 repins `CORPUS_PIN` and `ELIXIR_ERROR_PIN` to the published Elixir 2.0.0, enforces manifest === cases/<id>.json and the ID’s surface-prefix equality, with named rejection tests for every mismatch, and executes every 2.0 surface under the strict gate
   ([0005](0005-shared-corpus-and-separate-pins.md)).
2. Every new primitive is native WebCrypto with no added dependency
   ([0002](0002-zero-runtime-dependencies-and-webcrypto.md)): A128KW and A256KW wrap and unwrap
   with non-extractable key-encryption keys; ECDH-ES, ECDH-ES+A128KW and ECDH-ES+A256KW over
   P-256, P-384 and X25519 use `deriveBits` with the SHA-256 Concat KDF, zero the shared secret
   after derivation, and refuse an all-zero X25519 secret.
3. A runtime without X25519 returns `crypto/unsupported_algorithm` for it, declared in the
   runtime-limits table ([0006](0006-declared-runtime-limitations.md)).
4. The three Elixir allowlists hold here. Encryption: RSA-OAEP, RSA-OAEP-256, A128KW, A256KW and
   the three ECDH-ES forms. Primitive wrap: RSA-OAEP, RSA-OAEP-256, A128KW and A256KW.
   Decryption: those seven plus A128GCMKW, A256GCMKW and `dir`, which become unwrap-only.
5. JWS verification takes `protected` with `embeddedKey: "refuse" | "require"`, and JWE
   decryption takes `protected` and `content: "object"`, with the same member rules and error
   outcomes as Elixir.
6. `decryptMany` returns results in input order with the Elixir batch contract: aggregate
   limits before key work, one unwrap per exact handle, and each result equal to what a single
   decrypt would return. Unwrapped keys stay confined
   ([0012](0012-non-extractable-unwrapped-content-key.md)).
7. Every private-key operation takes a key handle; function signers and other key closures are
   removed.
8. Native custody parity includes indexed UnwrapItem delivery through an owned sink, independent per-index settlement with results returned in input order, and capability-identity cleanup without releasing an already accepted key. Derivation carries an explicit target/curve and domain, yields an unusable provisional child, and requires acknowledged atomic commit before use. A lost commit outcome triggers releaseChild under a fresh 1,000 ms context; unconfirmed destruction returns the cleanup variant. Required release/child-release operations are idempotent, and all published derivation families and hpke.derive_key_pair vectors execute under the strict gate. Local generation follows the public algorithm/option contract. Coordinator process and control-loop details remain subject to the 2.8 redesign.
9. The reciprocal exchange ([0008](0008-reciprocal-exchange-with-the-published-elixir-package.md))
   repins to the published 2.0.0 and adds rounds for the new algorithms. `CHANGELOG.md` lists
   each break under 0.6.0.

## Consequences

Work starts when Elixir 2.0.0 is published, after which 0.6.0 is released. The 0.6 line is
breaking for callers that encrypt with GCMKW or `dir` or pass function signers. Per-runtime
X25519 support must be observed on every lane, including the browsers
([0011](0011-pinned-browser-engine-lanes.md)). The camelCase option names here are this
package's spelling of the Elixir options; the final names are fixed when the work lands.
