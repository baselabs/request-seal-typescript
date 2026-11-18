# 0011 — Test in pinned browser engines as declared lanes

## Context

The package exports WebCrypto-based signing, verification, JOSE and custody that run in
browsers as well as in server runtimes. Browser engines implement WebCrypto and `fetch`
independently, and a server-only test matrix says nothing about them.

## Decision

The browser CI lane uses the official Playwright Noble image pinned by digest,
with Chromium, Firefox, WebKit, and their OS packages preinstalled. The image
version matches the exact locked Playwright dependency in `interop/browser`;
an installed-version check refuses drift before running the harness against the built bundle.
The engines are Chromium 156.0.8078.4, Firefox 157.0, and WebKit 27.2; see the
[runtime matrix](../reference/runtime-matrix.md).
Their exact version/platform limitations use the shared strict runtime-limits table
([0006](0006-declared-runtime-limitations.md)).
Fetch verification returns `adapter/invalid_request` in every browser because its wire
behavior is outside the measured verification allowlist.
Each engine rejects the [planted failure](0009-planted-failure-runner-proof.md).

## Consequences

The browser workspace locks Playwright 1.64.1. Every dependency update requires checking its engine versions and declared limitations against the real browser harness.
