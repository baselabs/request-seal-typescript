**Status:** accepted · **Kind:** record · **Updated:** October 11, 2026 · **Governed by:** tools/conformance/runtime-limits.json and the Fetch verification allowlist · **Review when:** a supported runtime version changes, or a runtime divergence is found or fixed

# ADR 0006: Declare runtime limitations instead of weakening assertions

- Status: Accepted
- Date: October 11, 2026

## Context

The package runs on Node, Deno, and Bun, and all three implement WebCrypto and `fetch` differently. Real divergences exist. Bun 1.3.14 on `darwin-arm64` rejects two valid ECDSA P-256 signatures from the Wycheproof vectors (items 261 and 262). Deno 2.5.6 and Bun 1.3.14 return `invalid_response` from `node:https` for a valid key set through the vetted TLS agent. Fetch implementations differ in how they treat repeated-field whitespace, cookies, and request targets.

A test suite can respond in three bad ways: skip the runtime, loosen the assertion until every runtime passes, or add a fallback implementation. Each hides the defect from the next reader and can turn a real regression into a pass.

## Decision

1. **Record each known divergence exactly.** `tools/conformance/runtime-limits.json` maps a runtime to an exact version to entries of `{ id, items, observed, reason }`, with optional `platforms` such as `darwin-arm64`. The conformance runner reports matching items as `runtime_limited`, not as passed and not as failed.
2. **The record is strict.** An entry applies only to its exact version and platform. A listed item that now passes is a stale entry and fails. An item that fails with a different rejection fails. An unlisted divergence fails. A malformed table fails.
3. **There is one policy, shared.** The conformance CLI and the crypto tests read the same table. Never add a second, test-side exception.
4. **Corpus semantics do not change.** The expected verdicts stay as published, and the library adds no cryptographic fallback or acceptance override for a runtime.
5. **Product behavior follows the same rule.** The Fetch adapter verifies only on runtimes whose behavior is recorded in `test/fixtures/adapters-fetch-wire.json`: `FETCH_VERIFICATION_RUNTIMES` is `deno:2.5.6`. Elsewhere it refuses with `invalid_request` before reading anything, and the documentation lists the limitation. HTTPS discovery is supported on Node only.
6. **A limitation is not an excuse to guess.** Each entry carries the observed result and a reason that describes the evidence, and the platforms where it applies.

## Strongest alternatives

1. **Skip the affected tests on that runtime.** Simple. A skip is silent, does not say what is wrong, and never goes stale.
2. **Accept either verdict for the affected vectors.** Every runtime goes green. It also accepts a future regression that rejects a valid signature, or worse, one that accepts an invalid signature.
3. **Add a fallback implementation for the affected primitive.** Behavior would be uniform. It adds cryptographic code to a library whose design avoids it (ADR 0002) and makes the library's behavior differ from the runtime users will compare against.
4. **Drop the runtime.** The simplest policy, at the cost of the portability the package exists to offer.

## Deciding evidence and deletion test

`tools/conformance/runtime-limits.ts` selects entries by exact runtime version and platform. `test/crypto-corpus.test.ts` checks selection, platform scope, stale entries, and unlisted divergences against the shared table. The Bun P-256 entries in `tools/conformance/runtime-limits.json` name only `darwin-arm64`. These code and test checks describe the policy; no table or rule deletion mutation is claimed.

## Consequences

Every runtime upgrade must re-check the table, because stale entries fail. Platform-scoped entries need a CI or local observation on each platform they name; the Bun entry records that the Linux CI run did not reproduce the macOS rejection. The documentation of compatibility lists proven lanes only. Users of a runtime outside the recorded versions get a refusal for verification or an unproven result, never a quiet assumption.

## Acceptance

- `tools/conformance/runtime-limits.json` and `tools/conformance/runtime-limits.ts` hold the table and its schema checks.
- `test/crypto-corpus.test.ts` covers exact-version selection, platform scoping, stale entries, and unlisted divergences.
- `test/adapters-fetch-wire.test.ts` records each measured runtime in `test/fixtures/adapters-fetch-wire.json`, and `src/adapters/fetch/runtime.ts` exports `FETCH_VERIFICATION_RUNTIMES`.
- `CONTRIBUTING.md` states the single-policy rule, and `README.md` links the contract in `docs/reference/corpus-format.md`.
