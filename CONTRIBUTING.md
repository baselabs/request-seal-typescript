**Status:** maintained · **Kind:** guide · **Updated:** October 14, 2026 · **Governed by:** AGENTS.md and the shared conformance corpus · **Review when:** development commands or runtime requirements change

# Contributing

Use Node 22.12.0 or newer. Elixir must be on PATH for the replay peer URL check;
local tests print a skip reason when it is absent, and CI requires it. The OpenSSL tests need OpenSSL 3 or later as `openssl` on PATH (on macOS, Homebrew's `openssl@3` or newer; the system LibreSSL lacks `pkeyutl -rawin` Ed25519 signing), and the reciprocal tests also need its development headers, a C compiler, and pkg-config; the AES-GCM peer uses EVP because the `openssl enc` frontend rejects AEAD. Development supports macOS and Linux; Windows developers use WSL2. CI runs on Linux.

```sh
npm ci --ignore-scripts
npm run check
```

`npm run check` runs, in order: `typecheck`, `typecheck:web`, `build`, `test`, `self-checks`, `conformance`, and `pack:check`. CI also runs `npm run docs` and the migration claims test after `npm ci --prefix interop/migration --ignore-scripts`: `node --experimental-strip-types --no-warnings --test interop/migration/claims.test.ts`. Build the [API reference](https://baselabs.github.io/request-seal-typescript/) locally with `npm run docs` and open `site-dist/index.html`; warnings fail the build.

Write behavior tests before implementation and retain the failing and passing output. Use `node:test` and fast-check properties. Test actual cryptography and published vectors; no substitutes for an external peer. `npm run test:red` deliberately fails and verifies the runner's exit status.

Keep the core independent of Node modules and runtime dependencies. Generate error documentation with `node --experimental-strip-types --no-warnings scripts/render-parity.ts`. To refresh the pinned extraction, set `REQUEST_SEAL_REPO` to an Elixir reference checkout, then run `node --experimental-strip-types --no-warnings scripts/extract-elixir-reasons.ts 0a6568aa246326617f760e94e21b359285c6ddfc <output.json>`. Extraction reads pinned public source only through `git show` and requires Elixir with OTP 29 for AST parsing. It writes only the requested output. Compare it before explicitly replacing `test/fixtures/elixir-reasons-0a6568a.json`. Run `REQUEST_SEAL_REPO=<reference-repo> node --experimental-strip-types --no-warnings --test test/extract-elixir-reasons.ts` to check live extraction against the fixture.

The shared corpus in `conformance/` is pinned to RequestSeal `v0.4.0`, commit `b2392871933d99641a7cb2ca2726aefd20081dee`, index SHA-256 `f37435eca377666ab45c2b8f580287263145268e03d9224c76e324e4afaded6f`. Shared corpus updates preserve upstream bytes and expectations. With the GitHub CLI authenticated, reproduce that byte copy with:

```sh
node --experimental-strip-types --no-warnings scripts/vendor-corpus.ts v0.4.0
```

For a pin move, run the same command with the new tag and `--update-pin`. It verifies the release asset checksum, archive paths, inventory digests, release commit, and index digest, then replaces the corpus and updates `src/constants.ts` together. Review both in one change; never regenerate expectations.

`npm run conformance` runs the independently pinned smoke corpus and the released corpus with `--pending-ok`. Pending entries name the surface, optional item format, case IDs, case count, and asserted item count. Listed items tie out as executed plus not applicable plus runtime limited plus pending. A pending known-positive case stays explicitly unexecuted. The release workflow runs the released corpus without that flag, requiring every surface, every asserted item, and the known-positive case to execute successfully. Integrity failures and disagreements always fail, including with `--pending-ok`. Keep the corpus outside the npm tarball. Releases run the complete CI matrix before staging a provenance-bearing package; approval on npmjs.com completes publication.

The package uses ESM with declaration exports. Use a modern TypeScript module resolver (`nodenext` or `bundler`); `node10` resolution cannot resolve future subpath declaration exports.

## Runtime test compatibility

Observed on Bun 1.3.14 with the native CI lane and direct API probes:

| Unimplemented `node:test` API | Portable replacement |
| --- | --- |
| Imported `test()` called inside a running test | Register independent tests at module scope. |
| `TestContext.test()` (`t.test()`) | Register independent tests at module scope. |

The Bun lane uses a 30-second default test budget; explicit per-test bounds and
application Context deadlines remain separate. The Elixir URL check has a
30-second parent bound around its 25-second subprocess bound.

The native files already use top-level `test()` and `t.diagnostic()`; they do not
use `describe` or `mock`. The lane's 22 module errors followed a 5-second timeout
in a test executing the whole corpus twice. Bun retained the running-test state
and rejected later files' module-level registrations as nested tests. Give corpus tests an explicit 30-second timeout (the two CLI subprocesses each
have a 10-second bound), and the live vendoring test an
explicit 180-second timeout matching its two bounded subprocess commands.
The message-override, stale-pending, and override-container corpus checks use
30-second budgets for complete inventory reads and repeated corpus validation.
The private-byte tracker test has a 15-second timeout around its 10-second child
process bound. The parent-deadline test also has a 15-second timeout because it
waits for a 5-second application deadline. The red-proof test has a 60-second
timeout around four subprocesses, each bounded to 10 seconds. No unsupported
nested API is used in the native suite. Keep runtime-only skips
explicit, with their reason printed. Context deadline child processes bound
themselves with an unreferenced watchdog because Deno's `spawnSync` ignores
`timeout`; the throwing-unref check skips Deno, whose timer functions are captured
at load.

Conformance limitations live only in `tools/conformance/runtime-limits.json`.
The CLI and crypto tests select exact runtime versions and share the same
classification; never add a second test-side Bun exception. Optional `platforms`
entries apply only to their listed `${process.platform}-${process.arch}` names;
unscoped entries apply everywhere. Stale checks use the same platform selection. See the
[format contract](docs/reference/corpus-format.md#consumer-runtime-limitations).

Live vendoring verification runs unless `REQUEST_SEAL_OFFLINE` is set (any value),
with a printed skip reason. The check does not depend on `gh`. Offline tests use
only vendored bytes and loopback peers.

## Reciprocal exchange

The optional reciprocal check requires exactly Elixir 1.20.3 and Erlang/OTP 29
(the local and CI toolchain patch is 29.0.3), plus Hex, rebar3, OpenSSL, and an
existing PostgreSQL database. These Elixir requirements apply to the reciprocal
check, not the TypeScript package. The error extraction check separately needs
OTP 29 as described above. See [reciprocity](docs/reference/reciprocity.md) for
isolated workspace installation, the exact published peer, the exchange protocol,
and local commands. The CI check is named `reciprocal`; release verification runs
it through the same reusable workflow. Registry failures fail this check.
