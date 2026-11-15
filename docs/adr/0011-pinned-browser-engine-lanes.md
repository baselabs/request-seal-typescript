<!-- Status: accepted · Kind: decision record · Updated: 2026-11-15 · Governed by: public API, compatibility contract, and cited decisions · Review when: the implementation or a governing decision changes -->

# 0011 — Test in pinned browser engines as declared lanes
Status: Accepted

## Context

The package exports WebCrypto-based signing, verification, JOSE and custody that run in
browsers as well as in server runtimes. Browser engines implement WebCrypto and `fetch`
independently, and a server-only test matrix says nothing about them.

## Decision

1. A `browsers` CI job (`.github/workflows/ci.yml:154`) installs Chromium, Firefox and WebKit
   through Playwright and runs the browser harness in `interop/browser` against the built
   bundle. Playwright is the only dev dependency of `interop/browser`, pinned to an exact
   version (`test/runtime-matrix.test.ts:63-65`).
2. The engines are lanes in the runtime matrix: Chromium 156.0.8078.4, Firefox 157.0 and WebKit
   27.2 (`docs/reference/runtime-matrix.md:6-8`). Their divergences are declared in the shared
   runtime-limits table under the same strict rules as the server runtimes
   ([0006](0006-declared-runtime-limitations.md)).
3. Fetch verification refuses with `adapter/invalid_request` in every browser, because no
   browser's wire behavior is measured for it.
4. Every browser lane proves it rejects a planted failure
   ([0009](0009-planted-failure-runner-proof.md)).

## Alternatives

1. **Server runtimes only.** Smaller CI. The browser claims in the exports would be untested.
2. **A headless DOM shim in Node.** Fast. It uses Node's WebCrypto, so it tests nothing about
   browser engines.
3. **Accept the latest engines unpinned.** No upkeep. Engine updates would change results with
   no commit to explain them.

## Consequences

Every Playwright update must re-observe the engine versions and the declared limitations. The
runtime matrix records Playwright 1.64.0 (`docs/reference/runtime-matrix.md:8`) while
`interop/browser/package-lock.json:13` resolves 1.64.1; the engine versions under 1.64.1 were
not re-observed for this record.
