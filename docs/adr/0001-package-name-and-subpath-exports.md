# 0001 — Publish one package named @request-seal/core with subpath exports

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

The root’s import graph excludes the Node-only subpaths, which are exposed through separate package exports. The package also declares sideEffects: false for bundlers. Release commits pass the full CI battery before landing. The owner dispatches `publish.yml` from the default branch in environment `publish` to stage the inspected archive through the trusted publisher with provenance; npm approval makes it live, and infra verifies publication before tagging.

## Consequences

Each subpath is a public API with declarations and documented runtime requirements. The portable root works independently of Node-only capabilities.
