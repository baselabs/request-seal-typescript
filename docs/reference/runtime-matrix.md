**Status:** maintained · **Kind:** reference · **Updated:** October 10, 2026 · **Governed by:** exact CI pins, package engines, public standards, and executed runtime probes · **Review when:** runtime lanes, permissions, Playwright, or declared limitations change

# Runtime matrix

CI runs on Linux (`ubuntu-24.04`). Development supports macOS and Linux;
Windows developers use WSL2. The [README table](../../README.md#compatibility)
equals the CI lane set: Node 22.12.0, 24.21.0, and 26.11.1; Deno 2.5.6;
Bun 1.3.14; the denied-roots-only check on Deno 2.9.7; Chromium 156.0.8078.4, Firefox 157.0, and WebKit 27.2 from
Playwright 1.64.0. Releases call the same workflow, including `browsers`.
The Node 26 job remains named `Node 26`; all Node pins and installed-version
assertions use exact patch versions.

## Node floor and engines

The package floor remains `>=22.12.0`. `npm run check` runs source contracts,
self-checks, build, the shared corpus, and the package boundary check. The latter
runs built-module contracts without changing the source runner.

OBSERVED on macOS arm64, October 10, 2026: the Node 23.11.0 probe
`node -e 'const tls=require("node:tls"); console.log(process.version, tls.rootCertificates.length, tls.getCACertificates("system").length)'`
exited 0 and returned 150 bundled roots and 0 system roots. The previously
reported crash did not reproduce in this execution environment. Therefore
`engines.node` does not exclude 23 based on that report. Node 23 is outside the
CI lane set; its full suite is not asserted here. An absent or empty system
store refuses `cacerts: "os"` as `custody/unsupported_format` without falling
back to bundled roots. Denied system-store access has the distinct bounded
result below.

Fetch signing on Node majors below 24 refuses a target ending in an empty query
delimiter as `adapter/invalid_request`. The exact Node 22 and Node 24 contracts
run in `test/runtime-query.test.ts`; the browser suite exercises its equivalent
in all three engines.

## Native versions and permissions

Support statements identify exact CI releases: Deno 2.5.6 and Bun 1.3.14.
They do not imply every patch of either major passes. Additional versions
probed on October 10, 2026 were Deno 2.9.7 and Bun 1.4.3. Their suite failures
below prevent adding full-suite CI lanes or claiming full support. Deno 2.9.7
has a dedicated CI check without system permission for the denied-roots branch.
Installed binaries
can be selected per command without upgrading the developer's existing runtime.
Run the native test and corpus commands exactly as declared in
[ci.yml](../../.github/workflows/ci.yml).

OBSERVED using `deno run` on Deno 2.9.7:

- `tls.getCACertificates("system")` throws `NotCapable` without `--allow-sys=ca`.
  It returned 153 system certificates when granted that permission on macOS arm64.
  Source creation previously threw that exception; fetching a core-created
  source returned `discovery/invalid_options`. Both now return the existing
  bounded reason `discovery/transport_unavailable`, with `retryable: false`.
  `test/discovery-os-trust.test.ts` executes both denied entry points without
  the permission. No bundled or alternate
  root store is substituted. Only the real `Deno.errors.NotCapable` class maps
  to `transport_unavailable`.
  Other errors are rethrown into the existing bounded entry-point mappings:
  source creation uses `invalid_source`, the fetch pre-check uses
  `invalid_options`, and unrelated connect-time read failures retain the
  existing `connect_failed` result.
  A trust-store denial at connect time terminates the address retry loop with
  `transport_unavailable` intact.
- Explicit DNS via `Resolver.setServers()` additionally requires
  `--allow-sys=networkInterfaces`. Use `--allow-sys=ca,networkInterfaces` when
  both OS roots and an explicit resolver are needed. The exact older CI command
  on 2.9.7 produced 40 failures: 35 CA-permission checks, two Fetch verification
  checks outside the version allowlist, two configured-localhost DNS observations,
  and one explicit-resolver permission check. Without the DNS permission,
  the discovery operation returns `discovery/invalid_response`.
- With those permissions, `resolve4("localhost")` returns the local address
  without querying the configured real DNS publisher. For `directory.test`,
  one answer succeeds and 65 repeated answers produce `ETIMEOUT`, with
  `unexpected end of input reached` from the runtime parser. The unchanged
  resolver tests require observing configured-publisher queries and accepting
  duplicate answers before deduplication. Those checks fail on this release.
- Child permission allowlists resolve executable names when the command starts.
  A downloaded runtime must be selected in that command's PATH so the permitted
  `deno` child is the same binary as the parent.

OBSERVED in direct `node:tls` probes on macOS arm64: Node 24.21.0 and
Bun 1.3.14 return an empty system-store array; an invalid store name throws
`TypeError` with code `ERR_INVALID_ARG_VALUE`. Node 22.12.0 and Deno 2.5.6
have no `getCACertificates` function; calling it directly throws `TypeError`
without a code, while the adapter checks availability before calling it.
A Deno 2.9.7 `deno run` without system permission throws `NotCapable` without
a code for the real system-store read; its invalid-store argument instead
throws `TypeError` with `ERR_INVALID_ARG_VALUE`. Node and Bun did not throw
permission-denial errors in these probes. Unrelated errors retain the bounded
entry-point mappings rather than being labeled as permission denials.

OBSERVED using Bun 1.4.3 on macOS arm64:

- The shared corpus passes, including Wycheproof P-256 items 261 and 262, and
  vetted-socket discovery succeeds. The Bun 1.3.14 exceptions do not apply to it. Runtime-limited count assertions
  now key on 1.3.14 exactly, rather than every Bun version.
- An actual HTTPS request reaches `node:https`'s request listener, but its
  `secureConnection` socket emits zero request `data` events. The same probe on
  Node 24 emits one. Three unchanged tests whose real publisher writes raw
  chunk framing from that event reach `discovery/deadline_exceeded` instead of
  their expected success or `limit`. Their assertions remain intact.
- During a two-address TLS retry, the second server's connection event can arrive
  after the operation returns. The original immediate count fails; a diagnostic
  retaining the assertion observes both connections after 50 ms. No timing
  change was applied to the test helper.
- Under `bun test --isolate`, Bun 1.3.14 on Linux intermittently fails a test
  file with `EEXIST: file already exists, epoll_ctl` while re-creating process
  stdio for that file ([oven-sh/bun#37968](https://github.com/oven-sh/bun/issues/37968)).
  CI hit it twice on October 10 and 11, 2026. The Bun lane therefore runs without
  `--isolate`; the full suite passes that way (1,011 tests, 905 passed, 106 skipped,
  0 failed on macOS arm64).

The [Deno permission reference](https://docs.deno.com/runtime/reference/permissions/)
explains scoped system permissions. Additional probes are observations of these
operations, not full-version acceptance.

## Exact runtime limitations

The consumer policy in
[`runtime-limits.json`](../../tools/conformance/runtime-limits.json) preserves
published corpus verdicts and requires exact outcomes. Its entire schema is
validated before any release is selected. Unlisted divergence and stale
limitations fail rather than being skipped silently.

| Engine/version | Platform | Operation and exact library outcome |
| --- | --- | --- |
| Bun 1.3.14 | macOS arm64 | Published Wycheproof P-256 signatures 261 and 262 return `crypto/invalid_signature`; Linux is outside this exception. |
| Bun 1.3.14 | All configured platforms | Vetted existing TLS socket passed to HTTPS discovery returns `discovery/invalid_response`; the two discovery transport files declare this prerequisite and the real-peer limitation test executes it. |
| Deno 2.5.6 | All configured platforms | The same vetted-socket HTTPS discovery returns `discovery/invalid_response`; the real-peer limitation test executes it. |
| WebKit 27.2 | macOS arm64 | `subtle.sign("Ed25519", key, new Uint8Array())` produces a signature that verifies false; custody's empty-message key health check returns `custody/invalid_key`. |

OBSERVED with `npm test --prefix interop/browser`: Firefox 157.0 lacks the
`Request.body` accessor. Its Requests cannot carry a `ReadableStream`; the body
is already materialized by Request construction. When `body === undefined`,
the adapter reads `clone().arrayBuffer()` and rejects a result exceeding
`maxBytes`. This read allocates a complete copy before the length check;
maxBytes bounds accepted bytes, not the peak allocation. The streamed reader
in other runtimes checks the running byte count before retaining each chunk.
An undefined body is absent for the GET/HEAD guard, which still rejects a
positive declared content length. All three engines sign plain GET, bodyless
POST, POST with body, and `signedFetch`; they also reject oversized bodies.

OBSERVED in WebKit's real page: generated Ed25519 keys and both PKCS8 and JWK
imports verify their one-byte and 257-byte signatures, but their empty-message
signatures verify false. Import itself succeeds; changing import format does not
repair this engine defect. The page asserts all three message sizes and both
custody construction forms. It also verifies the independent empty-message
signature in [RFC 8032 test 1](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1).
The `darwin-arm64` declaration is retained; the first hosted Linux WebKit run
will decide Linux behavior. No Linux outcome is claimed here. Chromium and Firefox verify all three sizes.
The [WebCrypto Ed25519 contract](https://w3c.github.io/webcrypto/#ed25519-operations)
permits empty messages. Custody's rejection is retained.

Fetch verification remains restricted to the measured runtime allowlist,
currently `deno:2.5.6`. Browsers and unrecorded versions return
`adapter/invalid_request`; verified delivery refuses before consuming caller
bytes. Core test passage cannot expand this transport allowlist. See
[Fetch adapter evidence](adapters.md#fetch).

## Browser suite

From the repository root on Linux:

```sh
npm ci --ignore-scripts
npm ci --prefix interop/browser --ignore-scripts
cd interop/browser
npx playwright install --with-deps chromium firefox webkit
cd ../..
npm run build
npm run build --prefix interop/browser
npm test --prefix interop/browser
sh scripts/red-proof.sh npm run test:red --prefix interop/browser
```

On macOS, use `npx playwright install chromium firefox webkit` for installation.
`PLAYWRIGHT_BROWSERS_PATH` can select an existing browser cache. A diagnostic
can select one engine with
`npm test --prefix interop/browser -- --browser=firefox`; CI runs all three.

Playwright is an exact private-workspace devDependency with its own lockfile;
the published package keeps zero runtime dependencies. The browser build uses
native ESM and the existing TypeScript compiler. It selects portable core test
graphs and replaces only runner/assertion imports with the browser harness.
The exact list of portable test files is pinned and compared to discovered
candidates before compilation; an omitted or unexpected file fails the build.
The browser page reports loaded files and the runner checks the same list.
The browser Fetch checks replace the native empty-query contract. Generated files are ignored.

A test-owned `node:http` server on loopback and an ephemeral port serves the
page and built `dist/` modules. Contexts permit requests only to that server.
The page executes core contracts, byte/JSON codecs, eight JWS algorithms subject
to the exact Ed25519 custody limitation, all five JWE key-management algorithms
with both content ciphers, nested JOSE, and Fetch signing in every engine. It checks changed signatures/tags and refuses verification.

Each engine uses separate regular and planted-failure contexts. Console records
tie out with executed counts. Running browser versions must match the declared releases and README. Every
selected limitation must execute with its exact reason; an improvement, changed reason, or unlisted failure is red.
The planted assertion comes from the shared native planted-failure file and
must produce one failure with its intentional marker. `test:red` exits nonzero;
the proof wrapper succeeds only after observing all three engine failures.
