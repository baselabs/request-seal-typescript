**Status:** accepted · **Kind:** record · **Updated:** October 11, 2026 · **Governed by:** package.json exports, the pack check, and the release workflow · **Review when:** the package name, scope, or export map changes

# ADR 0001: Publish one package named @request-seal/core with subpath exports

- Status: Accepted
- Date: October 11, 2026

## Context

The TypeScript implementation of RequestSeal began as an npm package named `request-seal` and was renamed to the scoped `@request-seal/core`, owned by the `request-seal` npm organization. The Elixir implementation is the Hex package `request_seal`; both share a conformance corpus and an error vocabulary.

The package has one dependency-free core and several capabilities that need Node: a streaming SHA-2 hasher, HTTPS key discovery, Node HTTP capture, SSH agent custody, and a PostgreSQL replay store. It also has a Fetch adapter that must run on Deno and Bun. The core must stay importable where Node modules do not exist.

## Decision

Publish one package, `@request-seal/core`. The package root holds the portable core. Capabilities with a different runtime requirement are subpath exports of the same package:

| Subpath | Capability |
| --- | --- |
| `@request-seal/core/node-hasher` | Streaming SHA-2 over `node:crypto` |
| `@request-seal/core/discovery-node` | HTTPS key discovery on Node |
| `@request-seal/core/node-http` | Node HTTP capture, verification, and clients |
| `@request-seal/core/fetch` | Fetch signing, delivery, and measured-runtime verification |
| `@request-seal/core/custody-ssh-agent` | OpenSSH agent custody |
| `@request-seal/core/replay-postgres` | Replay store over a caller-owned query function |

Every import in the code, tests, and documentation uses the scoped name. The package declares `"sideEffects": false`, so importing the root never loads a subpath. Releases are tagged, verified by the full battery, and staged through the repository's trusted publisher with provenance; a human approval on npmjs.com makes a version live.

## Strongest alternatives

1. **Keep the unscoped name `request-seal`.** It is shorter, and it needs no organization. It puts sibling packages, a trusted-publisher binding, and ownership in one flat namespace with no boundary, and the rename is already complete.
2. **One package per adapter**, such as `@request-seal/fetch` and `@request-seal/node-http`. Dependency graphs become exact, and a framework fix could ship alone. Every package then needs its own release, provenance, and version-skew policy for a core that is zero-dependency anyway, and a consumer must match versions across packages for a security library.
3. **A single root export with every capability.** One import path is simplest for consumers. Node-only code would enter the core's type surface and break its portability check, and importing the package on Deno or Bun would risk loading Node modules.

## Deciding evidence and deletion test

The export map in `package.json` separates the portable root from Node capabilities. `scripts/pack-check.ts` checks the scoped package name, allowed files, type declarations, and resolution of every exported subpath from an unpacked package. `test/package-name.test.ts` checks documented import specifiers. These checks describe the current package boundary; no deletion mutation is claimed here.

## Consequences

Renaming again would break every consumer and every example, so it needs a new decision. Adding a subpath is a public API change and needs the pack check, the type declarations, and the documentation. A subpath must keep working when the root is imported alone. Unscoped specifiers in documentation are rejected by a test.

## Acceptance

- `package.json` names the package `@request-seal/core`, sets `publishConfig.access` to `public`, and lists each export with types.
- `npm run pack:check` (`scripts/pack-check.ts`) asserts the name and tarball name, checks the allowed file list, and resolves and loads every export from an unpacked copy placed at `node_modules/@request-seal/core`.
- `test/package-name.test.ts` rejects unscoped imports and `npm install request-seal` in the README and reference documents.
- `.github/workflows/release.yml` runs the full check, the full corpus, and `npm stage publish --provenance` on a tag.
- `CHANGELOG.md` records the rename.
