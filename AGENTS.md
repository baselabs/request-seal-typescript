# RequestSeal contributor and agent contract

## Scope

This is a public, framework-independent TypeScript library for HTTP message signatures
and JOSE. Preserve wire bytes, explicit policies, caller-owned custody, and safe results.
Use public standards and published vectors to establish behavior. The shared corpus is
the semantic oracle; neither implementation may regenerate expected values.

Use WebCrypto for cryptographic primitives. The core imports no Node modules. Keep zero
runtime dependencies, ESM, strict TypeScript, and erasable syntax. No namespaces, enums,
or top-level await. New bounded reasons must land in both language implementations.

Do not add a server, database, mandatory fetch, global key store, implicit authorization,
or fail-open fallback. Do not copy private material, machine paths, personal information,
or internal work records into public source, package contents, or documentation.

## Workflow

Make the change, run the tests that cover it, commit with named paths, and push to `main`.
CI runs once on `main`; if it goes red, fix forward. CI runs `npm run check`; run the parts
that cover your change. Publishing to npm, deploying and pushes to mirrors need the owner's
approval. Update the CHANGELOG when behavior, a dependency or a contract changes.

## Verification

Every command must work on macOS and Linux; Windows developers use WSL2. CI runs on Linux
only. Validate workflow syntax and pin actions by commit SHA.
Write meaningful positive and rejection tests. Use actual cryptography and authorized
real peers. Do not introduce mocks, stubs, fake services, or generated examples presented
as external conformance.

Check the planted failure with `npm run test:red`; it must exit nonzero on every runtime.
Keep core results and errors free of stack
traces, callback diagnostics, key material, and caller bytes. Read own option keys once
into null-prototype snapshots; reject unknown keys. Branding uses private WeakSets.

## Documents and releases

README, CONTRIBUTING, SECURITY and `docs/` Markdown start with Status, Kind, Updated,
Governed by, and Review when metadata (`test/docs-contract.test.ts` checks it). The
changelog is a record. Public docs explain technical usage
and maintenance.

The package allowlist governs publication. Corpus data and repository tools stay outside
the tarball. Release tags run the full battery and stage with provenance through the
repository's trusted publisher; human approval on npmjs.com makes the version live.
