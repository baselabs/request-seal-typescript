<!-- Status: accepted · Kind: decision record · Updated: 2026-11-15 · Governed by: public API, compatibility contract, and cited decisions · Review when: the implementation or a governing decision changes -->

# 0008 — Prove interoperability by a reciprocal exchange with the published Elixir package
Status: Accepted

## Context

The shared corpus ([0005](0005-shared-corpus-and-separate-pins.md)) proves each implementation
against fixed bytes. Generated output is different: fresh keys, random initialization vectors,
fresh nonces and live directories. Two implementations can each pass every published vector and
still disagree on what the other produces.

## Decision

1. A separate `reciprocal` CI job (`.github/workflows/ci.yml:172`) runs the exchange in
   `interop/reciprocal` against the published Hex package. The Elixir peer pins
   `{:request_seal, "== 1.0.0"}` (`interop/elixir/mix.exs:5`) with the release checksum in
   `interop/elixir/mix.lock:5`, on Node 24.21.0, Erlang/OTP 29.0.3 and Elixir 1.20.3
   (`docs/reference/runtime-matrix.md:6-8`).
2. Each direction runs 32 rounds for every HTTP algorithm, every shared JWS algorithm, and every
   combination of RSA-OAEP, RSA-OAEP-256, A128GCMKW, A256GCMKW and `dir` with A128GCM and
   A256GCM, plus nested JWE with an inner EdDSA JWS ([reciprocity](../reference/reciprocity.md)).
3. Web Bot Auth rounds serve real signed directories over loopback TLS from each runtime, with
   explicit test CA trust and hostname checks left on.
4. Replay rounds claim one PostgreSQL table through each implementation. A contention test
   releases 32 fresh nonces behind one advisory-lock barrier, then 32 more with a measured delay
   so the other side wins. Every nonce has one winner and one stored row; each side must win at
   least once. No fairness is claimed.
5. Tampered signatures, ciphertext tags and inner signatures must reject with their exact rule
   IDs; a wrong CA must reject with `discovery/tls_failed`, and a directory republished at the
   other origin with `discovery/directory_signature_invalid`.
6. The exchange record is kept as a CI artifact (`.github/workflows/ci.yml:217-219`).

## Alternatives

1. **Vectors only.** Simpler CI. Two implementations can pass every vector and still disagree on
   live output.
2. **Run against the Elixir main branch.** Earlier signal. Unreleased changes would fail this
   package's release line with no Elixir release behind them.
3. **Embed an Elixir port in the Node process.** One process, faster rounds. The exchange would
   no longer cross a real process and wire boundary.

## Consequences

The exchange proves agreement between two released versions on generated inputs; it is not a
substitute for the corpus, which remains a separate byte-preserved check. It covers only
released Elixir behavior, so a new Elixir line enters it only through a repin of the peer. The exchange covers the published Elixir peer and requires PostgreSQL plus its pinned Elixir/OTP toolchain. PostgreSQL also backs the Node, Deno and Bun replay lanes, and the Node lanes install Elixir/OTP to re-extract the pinned error vocabulary.
