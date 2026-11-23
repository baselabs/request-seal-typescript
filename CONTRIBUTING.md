# Contributing

Use Node 22.12.0 or newer and the npm version declared in `package.json` (11.19.0). Elixir must be on PATH for the replay peer URL check;
local tests print a skip reason when it is absent, and CI requires it. The OpenSSL tests need OpenSSL 3 or later as `openssl` on PATH (on macOS, Homebrew's `openssl@3` or newer; the system LibreSSL lacks `pkeyutl -rawin` Ed25519 signing), and the reciprocal tests also need its development headers, a C compiler, and pkg-config; the AES-GCM peer uses EVP because the `openssl enc` frontend rejects AEAD. Development supports macOS and Linux; Windows developers use WSL2. CI runs on Linux.

```sh
npm ci --ignore-scripts
npm ci --prefix interop --ignore-scripts
npm ci --prefix interop/adapters --ignore-scripts
npm run check
```

`npm run check` runs, in order: `typecheck`, `typecheck:web`, `build`, `test`, `self-checks`, `conformance`, and `pack:check`. CI also runs `npm run docs` and the migration claims test after `npm ci --prefix interop/migration --ignore-scripts`: `node --experimental-strip-types --no-warnings --test interop/migration/claims.test.ts`. Build the [API reference](https://baselabs.github.io/request-seal-typescript/) locally with `npm run docs` and open `site-dist/index.html`; warnings fail the build.

Keep the core independent of Node modules and runtime dependencies. Regenerate `docs/reference/error-parity.md` in place with `node --experimental-strip-types --no-warnings scripts/render-parity.ts`. To refresh the pinned extraction, set `REQUEST_SEAL_REPO` to an Elixir reference checkout, then run `node --experimental-strip-types --no-warnings scripts/extract-elixir-reasons.ts 511fed142044ccea28bdcbb317c091cb2c8a515d <output.json>`. Extraction reads pinned public source only through `git show` and requires Elixir with OTP 29 for AST parsing. It writes only the requested output. Compare it before explicitly replacing `test/fixtures/elixir-reasons-511fed1.json`. Run `REQUEST_SEAL_REPO=<reference-repo> node --experimental-strip-types --no-warnings --test test/extract-elixir-reasons.ts` to check live extraction against the fixture.

The shared corpus in `conformance/` is pinned to RequestSeal `v1.0.0`, commit `511fed142044ccea28bdcbb317c091cb2c8a515d`, index SHA-256 `34dcdcae8af03d45d7bf222d46cd368a683b365ae2f470756dd1d461c9ecd798`. Shared corpus updates preserve upstream bytes and expectations. With network access, reproduce that byte copy with:

```sh
node --experimental-strip-types --no-warnings scripts/vendor-corpus.ts v1.0.0
```

For a pin move, run the same command with the new tag and `--update-pin`. It verifies the release asset checksum, archive paths, inventory digests, release commit, and index digest, then replaces the corpus and updates `src/constants.ts` together. Review both in one change; never regenerate expectations.

`npm run conformance` runs the independently pinned smoke corpus and the released corpus under the same strict execution rules as CI. Every surface and item format must have an execution adapter. Executed plus not applicable plus runtime limited must equal listed, and the named known-positive case must match successfully. Unsupported surfaces, unsupported formats, integrity failures and disagreements fail the run. Keep the corpus outside the npm tarball. The complete CI matrix qualifies a `kci/**` commit before it lands on the default branch. CI reads every exact runtime lane from `.tool-versions` only through `scripts/toolchain.sh`, and npm from the root `package.json` `packageManager` through `scripts/package-manager.py`, checks installed versions, and uses frozen installs. The shared shell reader is carried byte-identical with mode 755 and called by path; never edit its copy or add a repository-owned parser. Its defaults and JSON lane outputs feed setup actions and runtime matrices. After setup, its `--installed` mode refuses differing Node, Elixir and OTP versions; Deno and Bun compare their installed versions explicitly against the reader's outputs because that mode does not cover them. `.tool-versions` names only tools that asdf and mise install: every listed Node version is a lane and the first is the primary; the first Deno version is the supported runtime and each later, newer one runs only the denied-OS-roots check. `asdf install` or `mise install` sets up the same toolchain locally. Setup actions do not restore or save workflow caches. CI checks this package from local source and packed output; the registry-install check runs only after publication and public read-back.

A release maintainer dispatches `publish.yml` from the default branch in environment `publish`, after owner approval. It refuses existing tags and missing package names, builds the library and docs, and stages only the inspected archive with provenance. After npmjs.com approval, a second dispatch on the same commit skips an identical public archive and reads its actual bytes back. Different bytes, deprecation, or recorded unpublication refuse the release. Pending stages cannot be inspected through npm's trusted publisher; duplicate staging fails closed until approval. The dependent consumer job requires completed read-back and verifies npm signatures. See the [release procedure](docs/releasing.md) and [consumer verification guide](SECURITY.md#verifying-a-release). Release files are published on the GitHub release for `v<version>`; workflows create neither a release nor a tag.

The publication workflow publishes new versions of existing npm packages only and
refuses a package name the registry has never had. A first publication is the owner's decision.

The package uses ESM with declaration exports. Use a modern TypeScript module resolver (`nodenext` or `bundler`); `node10` resolution cannot resolve the package's subpath declaration exports.

## Runtime test compatibility

The fixed public API inventory is `test/fixtures/public-api-inventory.json`.
Every Node qualification lane compares the built declarations at all typed package
exports with it, including resolved facade call signatures and merged type/value
names. Additions, removals and signature changes fail with a named diff. After an
intentional API change, regenerate it on the hosted qualification runner with
`node --experimental-strip-types --no-warnings scripts/public-api-inventory.ts --write`
after the build; review the inventory edit beside the source change. Tests never
rewrite the baseline. The `package.json` metadata subpath has no declared API.

Register independent `node:test` tests at module scope; Bun 1.3.14 does not support
nested imported `test()` calls or `TestContext.test()` (`t.test()`).
Keep runtime-only skips explicit and print their reasons.
Give subprocess tests explicit bounds within their parent test budget.
Context deadline children need an unreferenced watchdog because Deno's
`spawnSync` ignores `timeout`. The throwing-unref check skips Deno because
the library captures its timer functions at load.
Run one file with `node --experimental-strip-types --no-warnings --test test/<name>.test.ts`.

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
and local commands. The CI check is named `reciprocal`; it must pass before the
release commit lands. Registry failures fail this check.
