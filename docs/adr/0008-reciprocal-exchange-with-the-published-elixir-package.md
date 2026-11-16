# 0008 — Prove interoperability by a reciprocal exchange with the published Elixir package

## Context

The shared corpus ([0005](0005-shared-corpus-and-separate-pins.md)) proves each implementation
against fixed bytes. Generated output is different: fresh keys, random initialization vectors,
fresh nonces and live directories. Two implementations can each pass every published vector and
still disagree on what the other produces.

## Decision

The exchange uses the published Hex `request_seal == 1.0.0` peer with its locked checksum,
Node 24.21.0, Erlang/OTP 29.0.3, and Elixir 1.20.3.
Each direction runs 32 rounds for every HTTP and shared JWS algorithm, every supported
JWE algorithm/content-cipher pair, and nested JWE with an EdDSA JWS.
Web Bot Auth serves real signed directories over loopback TLS with explicit CA trust
and hostname checks. Replay claims share a PostgreSQL table; barrier-controlled and
delayed rounds require one winner per nonce and a win for each peer, without claiming fairness.
Tampered signatures, tags, and inner signatures reject with exact rule IDs. Wrong CA and
wrong-origin directories reject with `discovery/tls_failed` and `discovery/directory_signature_invalid`.
CI retains sanitized exchange records for verification replay; see [reciprocity](../reference/reciprocity.md).

## Consequences

The exchange proves agreement between two released versions on generated inputs; it is not a
substitute for the corpus, which remains a separate byte-preserved check. It covers only
released Elixir behavior, so a new Elixir line enters it only through a repin of the peer. The exchange covers the published Elixir peer and requires PostgreSQL plus its pinned Elixir/OTP toolchain. PostgreSQL also backs the Node, Deno and Bun replay lanes, and the Node lanes install Elixir/OTP to re-extract the pinned error vocabulary.
