# 0006 — Declare runtime limitations instead of weakening assertions

## Context

Exact runtime and platform limitations record divergences from published vectors without weakening assertions, skipping a runtime, or adding a cryptographic fallback.

## Decision

1. **Record each known divergence exactly.** `tools/conformance/runtime-limits.json` maps a runtime to an exact version to entries of `{ id, items, observed, reason }`, with optional `platforms` such as `darwin-arm64`. The conformance runner reports matching items as `runtime_limited`, not as passed and not as failed.
2. **The record is strict.** An entry applies only to its exact version and platform. A listed item that now passes is a stale entry and fails. An item that fails with a different rejection fails. An unlisted divergence fails. A malformed table fails.
3. **There is one policy, shared.** The conformance CLI and the crypto tests read the same table. Never add a second, test-side exception.
4. **Corpus semantics do not change.** The expected verdicts stay as published, and the library adds no cryptographic fallback or acceptance override for a runtime.
5. **Product behavior follows the same rule.** The Fetch adapter verifies only on runtimes whose behavior is recorded in `test/fixtures/adapters-fetch-wire.json`: `FETCH_VERIFICATION_RUNTIMES` is `deno:2.5.6`. Elsewhere it refuses with `invalid_request` before reading anything, and the documentation lists the limitation. HTTPS discovery is supported on Node only.
6. **A limitation is not an excuse to guess.** Each entry carries the observed result and a reason that describes the evidence, and the platforms where it applies.

## Consequences

Every runtime upgrade must re-check the table, because stale entries fail. Platform-scoped entries need a CI or local observation on each platform they name; the Bun entry records that the Linux CI run did not reproduce the macOS rejection. The documentation of compatibility lists proven lanes only. Users of a runtime outside the recorded versions get a refusal for verification or an unproven result, never a quiet assumption.
