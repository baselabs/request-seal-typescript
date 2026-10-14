**Status:** maintained · **Kind:** reference · **Updated:** October 14, 2026 ·
**Governed by:** RFC 9421, RFC 7515, RFC 7516, protocol-00, and RequestSeal
v0.4.1 · **Review when:** peer pins, exchange protocol, or CI changes

# Reciprocal interoperability

The isolated exchange runs the TypeScript implementation and the published
RequestSeal Hex package against each other. Each direction executes 32 rounds
for every HTTP algorithm, every shared JWS algorithm, and every combination of
RSA-OAEP, RSA-OAEP-256, A128GCMKW, A256GCMKW, and dir with A128GCM and A256GCM.
Nested rounds authenticate JWE and its EdDSA JWS. Web Bot Auth runs all five
asymmetric HTTP algorithms and all seven asymmetric JOSE signing selectors (both
signing implementations reject HMAC) and serves real signed directories over
loopback TLS from each runtime, with explicit test CA trust. Both discovery
implementations enumerate HTTP algorithms for directory possession proofs
(`src/discovery/proof.ts` and Hex `discovery.ex`); JOSE bot rounds therefore
prove possession with an HTTP handle over the same private key. The bot request
retains its requested JOSE selector. Replay rounds independently hash
identifiers and claim one PostgreSQL table through each implementation. A
separate contention test uses 32 fresh nonces under simultaneous release. Both
implementations must block on the same PostgreSQL advisory-lock barrier before
release. It then runs 32 additional nonces with a measured TypeScript delay
after barrier release so Elixir wins. Every nonce must produce one winner and
one stored row; the loser sees `already_claimed`. Across both orderings, each
side must win at least once. The test proves one winner under simultaneous
release and that either side can win when release timing changes. It reports the
observed winner counts and measured delays without claiming fairness.

This establishes agreement between these two versions on generated inputs.
Published conformance vectors remain a separate, byte-preserved check. Tampered
signatures, ciphertext tags, and inner signatures must reject with their exact
rule IDs. Per direction, one wrong-CA round must reject with
`discovery/tls_failed`; a real signed directory republished at the other origin
must reject with `discovery/directory_signature_invalid`. Every successful Web
Bot Auth verification requires a signed directory possession proof; TLS hostname
and CA verification remain enabled.

## Install and run

Use Node 24.21.0, Elixir 1.20.3, and Erlang/OTP 29.0.3. The projects assert
Elixir 1.20.3 exactly in `mix.exs` and OTP release 29 at configuration load;
`.tool-versions` and CI select the same patch pair. Install Hex and rebar3
non-interactively before starting peers:

```sh
npm ci --ignore-scripts
npm ci --prefix interop --ignore-scripts
npm ci --prefix interop/adapters --ignore-scripts
npm ci --prefix interop/reciprocal --ignore-scripts
mix local.hex --force
mix local.rebar --force
npm run setup --prefix interop/reciprocal
(cd interop/replay && mix deps.get --check-locked && mix compile --warnings-as-errors)
```

Set `REQUESTSEAL_REPLAY_PG_URL` to an existing authorized PostgreSQL database
with permission to create and drop the exchange's temporary table. No check
starts a database. Then run:

```sh
elixir --version
npm run typecheck --prefix interop/reciprocal
REQUESTSEAL_RECIPROCAL_RECEIPT=interop/reciprocal/.cache/receipt.md \
  npm run exchange --prefix interop/reciprocal
REQUESTSEAL_REPLAY_ELIXIR=1 node --experimental-strip-types --no-warnings --test \
  test/peer-process.test.ts test/replay-reciprocal.test.ts test/reciprocal.test.ts \
  test/reciprocal-driver.test.ts test/reciprocal-record.test.ts
```

The full exchange requires the database URL; it never skips a surface. Each peer
readiness or response wait has a parent-owned deadline. Timeout or caller
cancellation kills its process group and rejects with the last 8 KiB of each
output stream. Captures retain at most the last 1 MiB per stream. Mix setup
failures use the same 8 KiB diagnostic tails. An independent watchdog also ends
the group when the harness dies, including during Mix startup. Tests SIGKILL the
harness during delayed startup and after readiness with a peer that ignores
stdin EOF. The watchdog also detects when its parent no longer matches the
recorded owner, including when the owner becomes a zombie or is reparented.
Closed children are never signaled again. Hex availability is checked with
closed stdin before Mix starts the driver. Elixir drivers read stdin as raw
bytes and write encoded JSON as UTF-8 bytes. Locale tests round-trip a non-ASCII
id and nonce with a UTF-8 locale, an empty locale, C.UTF-8, and LANG, LC_ALL,
and LC_CTYPE unset. Drivers retain stdin only for their JSON protocol; Mix runs
with compilation and dependency checking disabled after explicit setup. A
missing Hex archive fails with `PEER_HEX_UNAVAILABLE`, instead of prompting.

## Exchange records and replay

Both drivers read one JSON object per stdin line and write one JSON object per
stdout line. Startup is a JSON readiness record. `id` identifies the response;
`op` selects sign, verify, prepare, encrypt, decrypt, directory.start, release,
directory.read, directory.publish, selectors, or claim. `family` selects
rfc9421, jws, jwe, nested, web_bot_auth, or replay. `algorithm` and `enc` are
exact selectors. In Web Bot Auth rounds, `jws:` prefixes a JOSE selector; the
drivers construct the implementation’s JOSE selection object or tuple before
signing, directory proof, and verification. `bytes`, field values, CA
certificates, and test symmetric material use canonical unpadded base64url.
Exact integers (`now` and `retainUntil`) are decimal strings. The response
echoes `id` unchanged, including non-ASCII text. Public JWK components retain
their standard JWK representation. Compact JOSE and HTTP
component selections are wire strings. Headers retain their ordered occurrences.

The xorshift32 message seed is `942100 + round`; nonce inputs use that seed plus
7515. Replay uses namespace seed 751600. Each signer generates fresh asymmetric
keys in its own runtime. Key generation, IVs, and content keys use runtime
randomness. The exchange records public keys and exact inputs/outputs under
`interop/reciprocal/.cache/exchange.jsonl`, which is ignored and excluded from
the package. Signing private keys never leave their runtime. The record removes
TLS private keys, asymmetric private JWK fields, HMAC secrets, key-encryption
keys, and CEKs before serialization. Public certificates and public
inputs/outputs remain. Symmetric replay needs caller-owned custody material; the
artifact alone cannot reproduce those operations. Replay an asymmetric
verification by sending its recorded verify request to the corresponding driver:

```sh
npm run driver --silent --prefix interop/reciprocal
(cd interop/elixir && mix run --no-compile --no-deps-check driver.exs)
```

Directory replay also needs the recorded publisher running; RSA JWE replay needs
its original recipient capability. The public-key verification record alone does
not reconstruct those runtime resources. A disagreement prints the rule ID,
input, sender bytes, and receiver result, then fails. The final output reports
rounds, cases, rejections, and disagreements per family and direction.

## Pins and CI

The peer is Hex `request_seal == 0.4.1`, checksum
`834b005ddebd610e647c42f934c3120a659b7f316cdf81f9a064037194daef02`, locked in
both interop projects. This matches `ELIXIR_ERROR_PIN`'s v0.4.1 release, commit
`0a6568aa246326617f760e94e21b359285c6ddfc`. The corpus remains v0.4.0.
v0.4.1 changed no corpus bytes and supplied no corpus release assets. One test checks
both projects’ Elixir and OTP pins, both Hex versions and checksums, and every
CI setup-beam input against the error release. The exchange asserts its selector
sets equal to both implementations’ runtime registries. No local checkout
supplies the peer dependency.

The Linux CI job is named exactly `reciprocal`. It uses
`erlef/setup-beam@54075bcc5e249e4758d363f27d099f55d843f124`, locked Hex
dependency installation, the same PostgreSQL service as the Node lanes, and the
full exchange. The job has a 20-minute timeout and retains its public exchange
artifact for three days. `release.yml` calls this CI workflow before publishing.
A Hex outage fails the job. The required check names on `main` are
`Node 24.21.0`, `Node 22.12.0`, `Node 26`, `deno`, `bun`, `reciprocal`, `browsers`, and
`Deno denied OS roots`.
