<!-- Status: current · Kind: roadmap · Updated: 2026-11-15 · Governed by: public API, compatibility contract, and cited decisions · Review when: the implementation or a governing decision changes -->

# @request-seal/core roadmap

`@request-seal/core` is the zero-dependency TypeScript implementation of RequestSeal: HTTP Message Signatures (RFC 9421), content digests, Web Bot Auth, compact JOSE, discovery, replay protection and key custody on WebCrypto, for Node, Deno, Bun and browsers. Version 0.5.0 passes the RequestSeal for Elixir 1.0.0 corpus under one strict gate and exchanges live output with the published Hex package. The objective of this roadmap is native parity with RequestSeal for Elixir 2.0 in release 0.6.0. Rows are ordered by dependency, each with observable acceptance; decisions are in the records under `docs/adr`, starting with [0013](adr/0013-native-parity-on-the-2-0-corpus.md).

## Status board

<!-- status-board:start -->
One line per row, grouped by status and in roadmap order within each group; badges follow the evidence recorded in each row, and `test/roadmap-board.test.ts` checks that the board and the tables agree.

| Badge | Meaning |
|---|---|
| ✅ | Done and verified: landed, and the row records live, hosted or full-lifecycle evidence with no open item inside its claim |
| 🟢 | Done, not verified: landed, but the evidence is local or partial, or live, peer or production proof is still owed |
| 🟡 | Partly done: some increments landed, scoped work remains |
| 🔵 | Designed, ready to build: a judged design input or ADR with stated acceptance, nothing landed |
| ⚪ | Needs design: only a charter, strategy or posture reference |
| ⛔ | Blocked: waits on an owner decision or an outside release or service |
| ⚠️ | Watch: a known gap or risk (a flag in the Watch column beside any badge) |

Counts: ✅ 0 · 🟢 14 · 🟡 0 · 🔵 4 · ⚪ 0 · ⛔ 1

| Status | Row | Where it stands | Watch |
|---|---|---|---|
| 🟢 | RSC-core-signatures | RFC 9421 signing and verification, Structured Fields and content digests ship in 0.5.0 | ⚠️ Evidence carried from the repository's tests; not re-run for this board |
| 🟢 | RSC-jose | Compact JWS and JWE with nested envelopes ship in 0.5.0 | ⚠️ Evidence carried from the repository's tests; not re-run for this board |
| 🟢 | RSC-discovery | Key discovery with fail-closed operating system trust ships in 0.5.0 | ⚠️ Evidence carried from the repository's tests; not re-run for this board |
| 🟢 | RSC-web-bot-auth | Web Bot Auth with single selected signature under required replay ships in 0.5.0 | ⚠️ Evidence carried from the repository's tests; not re-run for this board |
| 🟢 | RSC-replay | Memory and PostgreSQL replay stores ship in 0.5.0 | ⚠️ Evidence carried from the repository's tests; not re-run for this board |
| 🟢 | RSC-adapters | Node HTTP and Fetch adapters ship in 0.5.0 | ⚠️ Evidence carried from the repository's tests; not re-run for this board |
| 🟢 | RSC-custody | Key handles, local custody and SSH agent custody ship in 0.5.0 | ⚠️ Evidence carried from the repository's tests; not re-run for this board |
| 🟢 | RSC-telemetry | Telemetry contract v1 ships since 0.4.0 | ⚠️ Evidence carried from the repository's tests; not re-run for this board |
| 🟢 | RSC-conformance | The 1.0.0 corpus executes under one strict gate | ⚠️ Evidence carried from the repository's tests; not re-run for this board |
| 🟢 | RSC-runtime-matrix | Node, Deno and Bun lanes with declared limitations | ⚠️ Evidence carried from the repository's tests; not re-run for this board |
| 🟢 | RSC-browser-lanes | Chromium, Firefox and WebKit lanes run through Playwright | ⚠️ Evidence carried from the repository's tests; not re-run for this board; see RSC-browser-pin-record |
| 🟢 | RSC-reciprocity | Reciprocal exchange against Hex `request_seal` 1.0.0 | ⚠️ Evidence carried from the repository's tests; not re-run for this board |
| 🟢 | RSC-red-proof | Every lane proves it rejects a planted failure | ⚠️ Evidence carried from the repository's tests; not re-run for this board |
| 🟢 | RSC-release-0.5 | Version 0.5.0 is the package version | ⚠️ Evidence carried from the repository's tests; not re-run for this board; npm publication not checked |
| 🔵 | RSC-browser-pin-record | The runtime matrix names Playwright 1.64.0; the browser lockfile resolves 1.64.1 | ⚠️ Engine versions under 1.64.1 not re-observed |
| 🔵 | RSC-jose-parity | Designed; nothing landed | ⚠️ X25519 support per runtime and browser not yet observed |
| 🔵 | RSC-reciprocity-2.0 | Designed; nothing landed |  |
| 🔵 | RSC-release-0.6 | Designed; nothing landed |  |
| ⛔ | RSC-corpus-repin-2.0 | Designed; waits on the published Elixir 2.0.0 | ⚠️ The required release is external to this package |

Updated November 15, 2026.
<!-- status-board:end -->

## Queue

| ID | Outcome | Acceptance | Waits on |
|---|---|---|---|
| RSC-browser-pin-record | The runtime matrix names the Playwright release the browser harness installs, with re-observed engine versions ([ADR 0011](adr/0011-pinned-browser-engine-lanes.md)) | `docs/reference/runtime-matrix.md` and `interop/browser/package-lock.json` name one Playwright release; the Chromium, Firefox and WebKit versions and every browser entry in `tools/conformance/runtime-limits.json` are observed under it; the `browsers` job passes | None |
| RSC-corpus-repin-2.0 | Repin the corpus, the error vocabulary and the reciprocal peer to Elixir 2.0.0 and read the 2.0 corpus layout ([ADR 0005](adr/0005-shared-corpus-and-separate-pins.md), [ADR 0013](adr/0013-native-parity-on-the-2-0-corpus.md)) | `CORPUS_PIN` and `ELIXIR_ERROR_PIN` name the 2.0.0 release commit and index digest; cases load from cases/<surface prefix>/<name>.json; the loader rejects any disagreement between ID, exact cases/<id>.json manifest path and the surface prefix, with named rejection tests; the vendor check, the inventory tie-out and the CI re-extraction pass; the Elixir peer pins `== 2.0.0` with its checksum | The RequestSeal for Elixir 2.0.0 release |
| RSC-jose-parity | Native JOSE parity with Elixir 2.0: AES Key Wrap, ECDH-ES, the three allowlists, protected-member policy, embedded JWS keys, object content, `decryptMany` and key handles only; native custody generation, derivation, commit and cleanup ([ADR 0013](adr/0013-native-parity-on-the-2-0-corpus.md)) | Every 2.0 surface executes under the strict gate on every lane, including `key_management.aes_kw/v1`, `key_management.ecdh_kdf/v1` and `key_management.agree/v1`; key-encryption keys are non-extractable; the ECDH shared secret is zeroed after derivation and an all-zero X25519 secret is refused; a runtime without X25519 returns `crypto/unsupported_algorithm` from a declared limitation; JWE encryption refuses A128GCMKW, A256GCMKW and `dir`; no entry point accepts a function signer or key closure. Indexed unwrap preserves accepted per-index results and cleans up distinct unaccepted capabilities. Native generation/derivation covers the public families and hpke.derive_key_pair vectors; provisional children cannot be used before atomic commit; lost commit outcomes use a fresh 1,000 ms releaseChild attempt and return the cleanup variant only when destruction remains unconfirmed. Required releases are idempotent. | RSC-corpus-repin-2.0 |
| RSC-reciprocity-2.0 | Extend the reciprocal exchange to the 2.0 algorithms against the published Hex 2.0.0 ([ADR 0008](adr/0008-reciprocal-exchange-with-the-published-elixir-package.md), [ADR 0013](adr/0013-native-parity-on-the-2-0-corpus.md)) | Each direction runs 32 rounds for A128KW, A256KW and the three ECDH-ES forms over P-256, P-384 and X25519, with each content encryption; tampered rounds reject with exact rule IDs; zero disagreements in the recorded exchange | RSC-jose-parity |
| RSC-release-0.6 | Release 0.6.0 ([ADR 0013](adr/0013-native-parity-on-the-2-0-corpus.md)) | `VERSION` and `package.json` read 0.6.0; `CHANGELOG.md` lists each break under 0.6.0 (GCMKW and `dir` encryption, function signers, option shapes); README, guides and reference pages match; the release workflow runs the full CI including browsers and the reciprocal job | RSC-reciprocity-2.0, RSC-browser-pin-record |

## Landed

| ID | Outcome | Acceptance | Evidence |
|---|---|---|---|
| RSC-core-signatures | HTTP Message Signatures with bounded Structured Fields and digests ([ADR 0002](adr/0002-zero-runtime-dependencies-and-webcrypto.md), [ADR 0003](adr/0003-trailing-options-object-for-max-bytes.md)) | Signature bases, signing and verification match the 1.0.0 corpus | `test/sign-verify.test.ts`, `test/signature-base.test.ts`, `test/structured-fields.test.ts`, `test/digest.test.ts` |
| RSC-jose | Compact JWS (RS256, PS256, PS384, PS512, HS256, ES256, ES384, EdDSA) and JWE (RSA-OAEP-256, RSA-OAEP, A128GCMKW, A256GCMKW, dir with A128GCM and A256GCM) ([ADR 0002](adr/0002-zero-runtime-dependencies-and-webcrypto.md)) | JOSE corpus surfaces pass; nested JWE authenticates its inner JWS | `src/jose/support.ts:12-29`, `test/jose-jws.test.ts`, `test/jose-jwe.test.ts`, `test/jose-nested.test.ts`, `test/jose-conformance.test.ts` |
| RSC-discovery | Key directory and client metadata discovery over HTTPS ([ADR 0007](adr/0007-fail-closed-os-trust-in-discovery.md)) | Discovery corpus passes; `cacerts: "os"` fails closed where the runtime has no system store | `test/discovery-corpus.test.ts`, `test/discovery-os-trust.test.ts`, `test/discovery-proof.test.ts` |
| RSC-web-bot-auth | Web Bot Auth verification with signed directories ([ADR 0005](adr/0005-shared-corpus-and-separate-pins.md)) | Web Bot Auth corpus passes; required replay accepts exactly one selected signature | `CHANGELOG.md:5-6`, `test/web-bot-auth-corpus.test.ts`, `test/web-bot-auth-replay.test.ts` |
| RSC-replay | Atomic replay claims over a caller-provided PostgreSQL query ([ADR 0010](adr/0010-replay-store-over-a-caller-owned-query.md)) | One winner per nonce; closed store error set; table and retention-index DDL | `src/replay/postgres.ts:8-54`, `test/replay-postgres.test.ts`, `test/replay-contract.test.ts` |
| RSC-adapters | Framework adapters at `./node-http` and `./fetch`, with Fetch verification limited to measured runtimes ([ADR 0001](adr/0001-package-name-and-subpath-exports.md), [ADR 0006](adr/0006-declared-runtime-limitations.md)) | Adapter tests pass; Fetch verification refuses outside `deno:2.5.6` | `src/adapters/fetch/runtime.ts:4-6`, `test/adapters-node-http.test.ts`, `test/adapters-fetch-wire.test.ts` |
| RSC-custody | Private-key operations through key handles, with a non-extractable unwrapped content key ([ADR 0003](adr/0003-trailing-options-object-for-max-bytes.md), [ADR 0004](adr/0004-context-deadline-timer-design.md), [ADR 0012](adr/0012-non-extractable-unwrapped-content-key.md)) | Custody tests pass; unwrapped keys are imported non-extractable with only `decrypt` | `src/custody/local.ts:110-117`, `src/custody/content_key.ts:14-34`, `test/custody.test.ts`, `test/custody-ssh-agent.test.ts` |
| RSC-telemetry | Opt-in telemetry with bounded, low-cardinality events | At most sixteen subscribers; frozen six-field events; a throwing subscriber never fails the operation | `CHANGELOG.md` 0.4.0 notes, `test/telemetry.test.ts` |
| RSC-conformance | Shared corpus and error vocabulary as the only oracle, with separate pins ([ADR 0005](adr/0005-shared-corpus-and-separate-pins.md)) | Inventory and index pin tie out; every item executes; the vocabulary re-extracts at the pinned commit | `src/constants.ts:4`, `src/errors/parity.ts:3`, `test/conformance.test.ts`, `test/parity-generation.test.ts`, `.github/workflows/ci.yml:52-58` |
| RSC-runtime-matrix | Exact-version runtime lanes with a strict limitations table ([ADR 0006](adr/0006-declared-runtime-limitations.md)) | Node 22.12.0, 22.23.1, 24.21.0, 26.11.1, Deno 2.5.6 and Bun 1.3.14 run the suite; stale or unlisted divergences fail | `docs/reference/runtime-matrix.md:6-8`, `tools/conformance/runtime-limits.json`, `test/runtime-matrix.test.ts`, `test/crypto-corpus.test.ts` |
| RSC-browser-lanes | Pinned browser engines as declared lanes ([ADR 0011](adr/0011-pinned-browser-engine-lanes.md)) | The browser harness runs the built bundle in each engine with declared limitations | `.github/workflows/ci.yml:154-171`, `test/browser-harness.test.ts`, `test/browser-selection.test.ts` |
| RSC-reciprocity | Live two-way exchange with the published Elixir package ([ADR 0008](adr/0008-reciprocal-exchange-with-the-published-elixir-package.md)) | 32 rounds each direction per family; exact rule IDs on tamper; one winner per contended nonce | [reciprocity](reference/reciprocity.md), `interop/elixir/mix.exs:5`, `.github/workflows/ci.yml:172-219` |
| RSC-red-proof | Runner proof for Node, Deno, Bun and each browser ([ADR 0009](adr/0009-planted-failure-runner-proof.md)) | `scripts/red-proof.sh` fails on a passing run, a missing marker or no failing count | `scripts/red-proof.sh`, `test/red-proof.test.ts`, `.github/workflows/ci.yml:61-63` |
| RSC-release-0.5 | Release 0.5.0 on the 1.0.0 corpus ([ADR 0001](adr/0001-package-name-and-subpath-exports.md)) | `VERSION` and `package.json` read 0.5.0; the changelog records the breaks | `src/constants.ts:2`, `package.json`, `CHANGELOG.md:3` |
