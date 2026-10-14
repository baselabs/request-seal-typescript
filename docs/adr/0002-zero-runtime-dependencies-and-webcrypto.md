**Status:** accepted · **Kind:** record · **Updated:** October 14, 2026 · **Governed by:** AGENTS.md, WebCrypto, and the pack and web type checks · **Review when:** a dependency, a cryptographic primitive source, or a Node import in the core is proposed

# ADR 0002: Zero runtime dependencies and WebCrypto for every primitive

- Status: Accepted
- Date: October 11, 2026

## Context

RequestSeal sits at an authentication boundary and parses attacker-controlled bytes. Each dependency adds code that runs with that authority, adds a release stream to watch, and can change behavior between installs. The library targets Node, Deno, and Bun, which share WebCrypto but not much else. The Elixir implementation uses its platform's cryptography and a small number of audited libraries; the TypeScript implementation has a different platform.

## Decision

1. The package has no runtime `dependencies`. Development and documentation tooling are exact-pinned in `devDependencies`; none enters the runtime dependency graph. The TypeDoc bridge uses TypeScript 6.0.3 while the package compiler stays TypeScript 7.0.2.
2. Every cryptographic primitive is WebCrypto. The library implements no primitive. `src/crypto/subtle.ts` captures the `crypto.subtle` methods and `getRandomValues` when the module loads.
3. The core imports no Node module. Code that needs Node lives in four places, each behind its own subpath: `src/node_hasher.ts`, `src/discovery/node.ts`, `src/adapters/node-http/`, and `src/custody/ssh-agent/`.
4. Parsers for Structured Fields, JSON, DER, OpenSSH agent frames, HTTP body encodings, and compact JOSE are owned code with explicit bounds, tested against published vectors.
5. The code is ESM, strict TypeScript, and erasable syntax only: no enums, namespaces, or top-level `await` in the package, so Node can run the source with type stripping.

## Strongest alternatives

1. **Use established packages** for Structured Fields, JOSE, or HTTP signatures. Mature code and fewer owned parsers. Their input models (decoded header maps, no raw targets) lose the bytes a signature covers, their bounds are not ours, and each is another supply-chain edge. The migration tests show the cost for one such library.
2. **Call `node:crypto` directly.** More algorithms and streaming for free. It would remove Deno and Bun from the portable core and give up one boundary where the runtime, not the library, owns primitives.
3. **Bundle audited pure-JavaScript or WebAssembly primitives.** It would make behavior identical on every runtime, and it would close the runtime gaps in ADR 0006. It would also add code that handles key material, with its own timing and zeroing story, to a library whose design is to keep key material inside the runtime.
4. **Allow dependencies outside the core**, in adapters only. A smaller blast radius than alternative 1, but each adapter's consumers inherit the dependency, and the adapters then differ in how much they can be trusted.

## Deciding evidence and deletion test

In `scripts/pack-check.ts`, assertions require `dependencies` to be absent and the development dependency names to match the declared documentation and test tooling. `tsconfig.web.json` compiles the portable core against `lib: ["es2024", "dom"]` without Node types and excludes the four Node capability locations. `src/crypto/subtle.ts` captures methods at load; `test/support/jose-subtle-trace.ts` installs its boundary trace before importing the library. These are code and test assertions, not executed deletion mutations.

## Consequences

The library owns and must test its parsers, and it relies on property tests and the shared corpus for that. It also inherits each runtime's WebCrypto behavior, including defects (ADR 0006), and it adds no fallback. Types cost nothing at runtime: erasable syntax means the tested source and the shipped source behave alike.

## Acceptance

- `scripts/pack-check.ts` asserts `pkg.dependencies === undefined` and the exact development dependency names.
- `tsconfig.web.json` and `npm run typecheck:web` compile the portable core with no Node types.
- `src/crypto/subtle.ts` is the only module that reads `crypto.subtle`; `test/message.test.ts` and `test/crypto-fixes.test.ts` replace the global methods after load and check that results do not change.
- `test/crypto.test.ts`, `test/crypto-corpus.test.ts`, and `test/openssl.test.ts` check the primitives against published vectors and OpenSSL; `test/custody.test.ts` and `test/support/zeroing.ts` check key handling.
- `package-lock.json` is committed, and CI runs `npm audit --audit-level=high`.
