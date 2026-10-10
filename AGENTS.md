# RequestSeal contributor and agent contract

**Status:** maintained · **Kind:** contract · **Updated:** October 9, 2026 · **Governed by:** public standards and the shared conformance corpus · **Review when:** scope, tests, or package boundaries change

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

## Verification

Run `npm run check`. Every command must work on macOS and Linux; Windows developers use
WSL2. CI runs on Linux only. Validate workflow syntax and pin actions by commit SHA.
Write meaningful positive and rejection tests first. Use actual cryptography and authorized
real peers. Do not introduce mocks, stubs, fake services, or generated examples presented
as external conformance. A passing authored test is established only by its executed output.

Check the planted failure with `npm run test:red`; it must exit nonzero on every runtime.
Do not claim a check ran without its output. Keep core results and errors free of stack
traces, callback diagnostics, key material, and caller bytes. Read own option keys once
into null-prototype snapshots; reject unknown keys. Branding uses private WeakSets.

## Documents and releases

Use US English. Non-record Markdown starts with Status, Kind, Updated, Governed by,
and Review when metadata. The changelog is a record. Public docs explain technical usage
and maintenance. Keep this contract below 120 lines.

The package allowlist governs publication. Corpus data and repository tools stay outside
the tarball. Release tags run the full battery and stage with provenance through the
repository's trusted publisher; human approval on npmjs.com makes the version live.
