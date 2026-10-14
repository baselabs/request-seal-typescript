**Status:** maintained · **Kind:** reference · **Updated:** October 14, 2026 · **Governed by:** exact CI pins, package engines, public standards, and executed runtime probes · **Review when:** runtime lanes, permissions, Playwright, or declared limitations change

# Runtime matrix

CI runs on Linux (`ubuntu-24.04`). Development supports macOS and Linux;
Windows developers use WSL2. The table below equals the CI runtime lanes: Node 22.12.0, 24.21.0, and 26.11.1; Deno 2.5.6;
Bun 1.3.14; the denied-roots-only check on Deno 2.9.7; Chromium 156.0.8078.4, Firefox 157.0, and WebKit 27.2 from
Playwright 1.64.0. The separate `reciprocal` job runs on Node 24.21.0 with Erlang/OTP
29.0.3 and Elixir 1.20.3. Releases call the same workflow, including `browsers`.
The Node 26 job remains named `Node 26`; all Node pins and installed-version
assertions use exact patch versions.

## Tested runtime lanes

| Runtime lane | Version | Declared runtime limitations |
| --- | --- | --- |
| Node 22.12.0 | 22.12.0 | No `tls.getCACertificates`, so `cacerts: "os"` returns `discovery/transport_unavailable`. Empty-query Fetch signing returns `adapter/invalid_request`. Fetch verification returns `adapter/invalid_request` outside the measured allowlist. |
| Node 24.21.0 | 24.21.0 | Fetch verification returns `adapter/invalid_request` outside the measured allowlist. |
| Node 26.11.1 | 26.11.1 | Fetch verification returns `adapter/invalid_request` outside the measured allowlist. |
| Deno 2.5.6 | 2.5.6 | No `tls.getCACertificates`, so `cacerts: "os"` returns `discovery/transport_unavailable`. `test_file/discovery-node.test.ts` item 1: `discovery/invalid_response`. `test_file/discovery-fixes.test.ts` item 1: `discovery/invalid_response`. |
| Deno 2.9.7 | 2.9.7 | Denied OS roots check only; without `--allow-sys=ca`, source creation and fetch return `discovery/transport_unavailable`. Full-suite support is not asserted. |
| Bun 1.3.14 | 1.3.14 | `crypto/ecdsa_secp256r1_sha256_p1363_test` items 261, 262 on darwin-arm64: `crypto/invalid_signature`. `test_file/discovery-node.test.ts` item 1: `discovery/invalid_response`. `test_file/discovery-fixes.test.ts` item 1: `discovery/invalid_response`. Fetch verification returns `adapter/invalid_request` outside the measured allowlist. |
| Chromium | 156.0.8078.4 | Browser Fetch verification returns `adapter/invalid_request`. |
| Firefox | 157.0 | Browser Fetch verification returns `adapter/invalid_request`. |
| WebKit | 27.2 | `custody/ed25519_empty_message` item 1 on darwin-arm64: `custody/invalid_key`. `custody/ed25519_pkcs8_leading_zero_seed` item 1 on linux-x64: `custody/invalid_key`. Browser Fetch verification returns `adapter/invalid_request`. |

## Node floor and engines

The package floor remains `>=22.12.0`. `npm run check` runs, in order, `typecheck`,
`typecheck:web`, `build`, `test`, `self-checks`, `conformance`, and `pack:check`. The
package boundary check runs built-module contracts without changing the source runner.

OBSERVED on macOS arm64, October 10, 2026: the Node 23.11.0 probe
`node -e 'const tls=require("node:tls"); console.log(process.version, tls.rootCertificates.length, tls.getCACertificates("system").length)'`
exited 0 and returned 150 bundled roots and 0 system roots. The previously
reported crash did not reproduce in this execution environment. Therefore
`engines.node` does not exclude 23 based on that report. Node 23 is outside the
CI lane set; its full suite is not asserted here. An absent or empty system
store refuses `cacerts: "os"` as `discovery/transport_unavailable` without falling
back to bundled roots. Denied system-store access returns the same result, as
described below.

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

OBSERVED in direct `node:tls` probes on macOS arm64: Node 24.21.0, 26.11.1, and
Bun 1.3.14 return an empty system-store array, so `cacerts: "os"` returns
`discovery/transport_unavailable` there (custody `unsupported_format` before
October 14, 2026). Through the built `discovery-node` module on
October 11, 2026, all five native lane versions returned that result on macOS
arm64. An invalid store name throws `TypeError` with code
`ERR_INVALID_ARG_VALUE`. Node 22.12.0 and Deno 2.5.6 have no `getCACertificates` function; calling it directly throws `TypeError`
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
| WebKit 27.2 | Linux x64 | `importKey("pkcs8")` rejects an Ed25519 private key whose seed begins with `0x00`; `Custody.local` given that PKCS8 form returns `custody/invalid_key`. The JWK form of the same key is accepted. |

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

OBSERVED in WebKit's real page on macOS arm64: generated Ed25519 keys and both
PKCS8 and JWK imports verify their one-byte and 257-byte signatures, but their
empty-message signatures verify false. Import itself succeeds; changing import format does not
repair this engine defect. The page asserts all three message sizes and both
custody construction forms. It also verifies the independent empty-message
signature in [RFC 8032 test 1](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1).
The `darwin-arm64` declaration is retained. OBSERVED in CI run 38169787602
(commit ce16e5e, `ubuntu-24.04`): WebKit 27.2 on linux-x64 selected no limitation
and passed 62 of 62, so its empty-message signatures and RFC 8032 test 1 verify
on Linux. Chromium and Firefox verify all three sizes.

OBSERVED with Playwright 1.64.0 WebKit 27.2 on linux-x64, October 11, 2026:

- `importKey("pkcs8")` rejected 100 of 100 Ed25519 seeds beginning with `0x00`
  (`DataError`), including seeds beginning with `0x00 0x00`. Among 5,000 random
  keys, all 25 rejections had that leading byte. JWK import of every key succeeded.
- Through the built package, `Custody.local` returned `custody/invalid_key` for 50
  of 50 leading-zero seeds in PKCS8 form and accepted the same 50 keys as JWK.
  Callers on this engine can pass Ed25519 private keys as JWK.
- Ed25519 `generateKey` threw `OperationError` in 34 of 5,000 calls. CI run
  38173205551 failed once this way. The page therefore imports RFC 8032 test 1
  instead of generating Ed25519 keys, and the discovery test uses the RFC 8032
  test 2 public key.
- ECDSA P-256 and P-384 generated, exported, imported and verified 3,000 keys
  each without a failure, including 13 private keys per curve beginning with `0x00`.

The page executes the declared PKCS8 limitation with the seed `0x00` through
`0x1f`. Where PKCS8 import succeeds, it checks the exported public key against the
fixed value; the JWK custody form signs and verifies in every engine without the
empty-message limitation.
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
tie out with executed counts. Running browser versions must match the declared releases in the table above. Every
selected limitation must execute with its exact reason; an improvement, changed reason, or unlisted failure is red.
The planted assertion comes from the shared native planted-failure file and
must produce one failure with its intentional marker. `test:red` exits nonzero;
the proof wrapper succeeds only after observing all three engine failures.
