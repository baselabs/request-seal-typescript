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

## Publication

Publishing to npm, deploying, and pushes to mirrors need the owner's approval. Update the CHANGELOG when behavior, a dependency, or a contract changes.

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

Public documentation explains technical usage and maintenance.

The package allowlist governs publication. Corpus data and repository tools stay outside
the tarball. Qualification runs on `kci/**`; the release maintainers publish the inspected archive with provenance
through the repository's trusted publisher from the default branch.

## Build and test

Public-repository builds and tests run only in GitHub-hosted qualification on a `kci/`
ref; agents run no project code on a workstation or a build box. Qualification runs
`npm run check`, `npm run docs` and the planted-failure proof on each Node lane, plus
the Deno, Bun and browser lanes, and a change reaches the default branch only through
the landing tool. Pure Python source checks that compile
nothing may run with `python3 -I -B`. Only the landing command watches a run.

## CI/CD and releases

Releases, deployments, and publications are done by the release maintainers.
The project lands on the default branch with the landing tool and stops there.
The CI maintainers' requirements for every product apply.

Workflow changes go to the CI maintainers for review with repository, branch, and full commit
before landing. The default branch requires the exact `qualified` context, with
no bypass and no classic branch protection.

Every runtime lane comes only through the byte-identical, executable shared reader
`scripts/toolchain.sh`, called by path. Never edit its copy or add another parser of
`.tool-versions`, `version-file:` input, or workflow runtime pin. Setup actions use
its outputs; `scripts/toolchain.sh --installed` refuses differing Node, Elixir and OTP.
Deno, Bun and Python use explicit installed-version comparisons against the same outputs.
npm comes only from the root `packageManager` through `scripts/package-manager.py`;
every manifest declares the same npm. `.tool-versions` declares product runtimes
(Node, Deno, Bun, Elixir and Erlang) and the exact Python used by CI tooling.
Every job that invokes Python installs and checks that reader-selected version first,
including calls inside composite actions and the final qualification verdict.
Installs are frozen. Qualification uses no workflow
cache and never installs this package from npm. Both Elixir peer projects retain
locked fetching and both advisory feeds. Keep action SHAs and version comments exact.
Measure timeouts on cold green jobs, use the five-minute floor and 90-minute cap,
and replace `90 # no green run yet` after the first green run.

Publication and Pages are default-branch dispatches only. Agents never dispatch,
publish, deploy, tag, push mirrors, or handle registry keys. The release maintainers obtain owner
approval, dispatches, performs read-back and tagging, then creates the GitHub release
for `v<version>` from `release-assets`. The workflow stages only the inspected archive
with provenance; it reuses an identical public version, refuses different, deprecated,
unpublished, or tagged versions, and never creates a package name. Pending-stage
retries fail closed because npm OIDC tokens cannot inspect stages. The registry-install
job depends on upload and read-back, has the same actor gate, no environment, and no key.
See [the release procedure](docs/releasing.md) and [verification](SECURITY.md#verifying-a-release).
