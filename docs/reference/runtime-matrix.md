# Runtime matrix

CI runs on Linux (`ubuntu-24.04`). Development supports macOS and Linux;
Windows developers use WSL2. The table below equals the CI runtime lanes: Node 22.12.0, 22.23.1, 24.21.0, and 26.11.1; Deno 2.5.6;
Bun 1.3.14; the denied-roots-only check on Deno 2.9.7; Chromium 156.0.8078.80, Firefox 157.0, and WebKit 27.2 from
Playwright 1.64.1. The separate `reciprocal` job runs on Node 24.21.0 with Erlang/OTP
29.0.3 and Elixir 1.20.3. The complete matrix, including `browsers`, qualifies
a release commit before it lands; `publish.yml` stages the archive from the default branch.
The Node 26 job remains named `Node 26`; all Node pins and installed-version
assertions use exact patch versions.

The browser job uses the official Playwright 1.64.1 Noble container pinned by
digest, with all three engines and their OS packages already installed. It
refuses an installed Playwright version that differs from the image. The job
sets `HOME=/root` for Firefox and uses `--init --ipc=host` for browser processes.
Node is still installed from `.tool-versions` and checked for an exact match.

## Tested runtime lanes

| Runtime lane | Version | Declared runtime limitations |
| --- | --- | --- |
| Node 22.12.0 | 22.12.0 | No `tls.getCACertificates`, so `cacerts: "os"` returns `discovery/transport_unavailable`. Empty-query Fetch signing returns `adapter/invalid_request`. Fetch verification returns `adapter/invalid_request` outside the measured allowlist. |
| Node 22.23.1 | 22.23.1 | Empty-query Fetch signing returns `adapter/invalid_request`. Fetch verification returns `adapter/invalid_request` outside the measured allowlist. |
| Node 24.21.0 | 24.21.0 | Fetch verification returns `adapter/invalid_request` outside the measured allowlist. |
| Node 26.11.1 | 26.11.1 | Fetch verification returns `adapter/invalid_request` outside the measured allowlist. |
| Deno 2.5.6 | 2.5.6 | No `tls.getCACertificates`, so `cacerts: "os"` returns `discovery/transport_unavailable`. `test_file/discovery-node.test.ts` item 1: `discovery/invalid_response`. `test_file/discovery-fixes.test.ts` item 1: `discovery/invalid_response`. |
| Deno 2.9.7 | 2.9.7 | Denied OS roots check only; without `--allow-sys=ca`, source creation and fetch return `discovery/transport_unavailable`. Full-suite support is not asserted. |
| Bun 1.3.14 | 1.3.14 | `crypto/ecdsa_secp256r1_sha256_p1363_test` items 261, 262 on darwin-arm64: `crypto/invalid_signature`. `test_file/discovery-node.test.ts` item 1: `discovery/invalid_response`. `test_file/discovery-fixes.test.ts` item 1: `discovery/invalid_response`. Fetch verification returns `adapter/invalid_request` outside the measured allowlist. |
| Chromium | 156.0.8078.80 | Browser Fetch verification returns `adapter/invalid_request`. |
| Firefox | 157.0 | Browser Fetch verification returns `adapter/invalid_request`. |
| WebKit | 27.2 | `custody/ed25519_empty_message` item 1 on darwin-arm64: `custody/invalid_key`. `custody/ed25519_pkcs8_leading_zero_seed` item 1 on linux-x64: `custody/invalid_key`. Browser Fetch verification returns `adapter/invalid_request`. |

## Node floor and engines

The package floor remains `>=22.12.0`. `npm run check` runs, in order, `typecheck`,
`typecheck:web`, `build`, `test`, `self-checks`, `conformance`, and `pack:check`. The
package boundary check runs built-module contracts without changing the source runner.

Fetch signing on Node majors below 24 refuses a target ending in an empty query
delimiter as `adapter/invalid_request`. The exact Node 22 and Node 24 contracts
run in `test/runtime-query.test.ts`; the browser suite exercises its equivalent
in all three engines.

## Native versions and permissions

Support statements identify exact CI releases: Deno 2.5.6 and Bun 1.3.14.
They do not imply every patch of either major passes. Additional versions
probed on October 10, 2026 were Deno 2.9.7 and Bun 1.4.3. Those probes do not
establish full-version support. Deno 2.9.7
has a dedicated CI check without system permission for the denied-roots branch.
Installed binaries
can be selected per command without upgrading the developer's existing runtime.
Run the native test and corpus commands exactly as declared in
[ci.yml](../../.github/workflows/ci.yml).

Missing, empty, or denied OS roots return `discovery/transport_unavailable`;
no bundled or alternate store is substituted. Deno 2.9.7 requires `--allow-sys=ca`
for OS roots and `--allow-sys=networkInterfaces` for an explicit DNS resolver.
Use `--allow-sys=ca,networkInterfaces` when both are needed. Without DNS permission,
discovery returns `discovery/invalid_response`.
Only the runtime's real `Deno.errors.NotCapable` store denial maps to
`transport_unavailable`, including at connect time, where address retries stop.
Other failures retain their bounded mappings: `invalid_source` at creation,
`invalid_options` at the fetch pre-check, and `connect_failed` for unrelated reads.
Child permission allowlists resolve executable names from PATH when the command starts.
Select the parent and permitted child runtime from the same PATH.

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

Firefox 157.0 has no `Request.body` accessor and materializes request bodies at
construction. The adapter uses `clone().arrayBuffer()` when the body is undefined;
maxBytes bounds accepted bytes, not the peak allocation. Streamed readers check
running byte counts before retaining chunks. The GET/HEAD guard rejects a positive
content length even with an undefined body. All browser lanes exercise Fetch signing
and oversized-body rejection.
WebKit 27.2 on macOS arm64 rejects Ed25519 custody's empty-message health check;
PKCS8 and JWK imports do not avoid that limitation. On Linux x64, WebKit rejects
PKCS8 Ed25519 seeds beginning with `0x00`; callers can use JWK for those keys.
The browser page checks both key forms, the fixed leading-zero seed, and the
independent empty-message signature in [RFC 8032 test 1](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1).
The [WebCrypto Ed25519 contract](https://w3c.github.io/webcrypto/#ed25519-operations)
permits empty messages. Limitations remain scoped to their exact engine and platform.
The harness uses published Ed25519 keys for repeatable custody and discovery checks.

Fetch verification remains restricted to the measured runtime allowlist,
currently `deno:2.5.6`. Browsers and unrecorded versions return
`adapter/invalid_request`; verified delivery refuses before consuming caller
bytes. Core test passage cannot expand this transport allowlist. See
[Fetch adapter evidence](adapters.md#fetch).

## Browser suite

The declared browser releases are the ones in the digest-pinned Playwright image
that the `browsers` job uses. A `npx playwright install` of the same Playwright
version can report a different build (Chromium 156.0.8078.4 rather than
156.0.8078.80), which the runner refuses before testing. Run the suite in that
image, from the repository root on any Docker host:

```sh
docker run --rm --init --ipc=host -e HOME=/root -v "$PWD:/src:ro" \
  mcr.microsoft.com/playwright:v1.64.1-noble@sha256:2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f \
  sh -euc '
    cp -R /src /work && cd /work
    npm ci --ignore-scripts
    npm ci --prefix interop/browser --ignore-scripts
    npm run build
    npm run build --prefix interop/browser
    npm test --prefix interop/browser
    sh scripts/red-proof.sh npm run test:red --prefix interop/browser
  '
```

The checkout is mounted read-only and copied inside the container, so the run
leaves nothing behind. CI additionally installs the `.tool-versions` Node in the
image; this command uses the image's own Node. CI qualifies `linux-x64`. On an
arm64 host Docker selects the image's arm64 variant, where limitations recorded
for `linux-x64` are not expected; add `--platform linux/amd64` to run the CI
architecture under emulation. A diagnostic can select one engine with
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
