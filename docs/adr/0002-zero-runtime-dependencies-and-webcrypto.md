# 0002: Zero runtime dependencies and platform cryptography

## Decision

1. The package has no runtime `dependencies`. Development and documentation tooling are exact-pinned in `devDependencies`; none enters the runtime dependency graph. The TypeDoc bridge uses TypeScript 6.0.3 while the package compiler stays TypeScript 7.0.2.
2. Portable-core cryptographic primitives use WebCrypto; src/crypto/subtle.ts captures its methods and getRandomValues at load. The node-hasher subpath uses node:crypto createHash for streaming SHA-2. The package implements no cryptographic primitive itself.
3. The core imports no Node module. Code that needs Node lives in four places, each behind its own subpath: `src/node_hasher.ts`, `src/discovery/node.ts`, `src/adapters/node-http/`, and `src/custody/ssh-agent/`.
4. Parsers for Structured Fields, JSON, DER, OpenSSH agent frames, HTTP body encodings, and compact JOSE are owned code with explicit bounds, tested against published vectors.
5. The code is ESM, strict TypeScript, and erasable syntax only: no enums, namespaces, or top-level `await` in the package, so Node can run the source with type stripping.

## Consequences

The library owns and must test its parsers, and it relies on property tests and the shared corpus for that. It also inherits each runtime's WebCrypto behavior, including defects (ADR 0006), and it adds no fallback. Types cost nothing at runtime: erasable syntax means the tested source and the shipped source behave alike.
