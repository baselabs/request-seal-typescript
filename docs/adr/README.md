**Status:** maintained · **Kind:** index · **Updated:** October 11, 2026 · **Governed by:** the accepted decision records in this directory · **Review when:** a decision record is added, superseded, or withdrawn

# Architecture decisions

These records capture decisions that a maintainer must not undo by accident. Each one states the context, the decision, the strongest alternatives, the evidence and deletion test that justify keeping it, the consequences, and the code and tests that enforce it. The format matches the records in RequestSeal for Elixir, so the two projects can be read side by side.

| Record | Decision |
| --- | --- |
| [0001](0001-package-name-and-subpath-exports.md) | Publish one package named `@request-seal/core`, with subpath exports for runtime-specific capabilities. |
| [0002](0002-zero-runtime-dependencies-and-webcrypto.md) | No runtime dependencies. WebCrypto performs every primitive, and the core imports no Node module. |
| [0003](0003-trailing-options-object-for-max-bytes.md) | A trailing `{ maxBytes }` options object carries the per-call byte bound. |
| [0004](0004-context-deadline-timer-design.md) | A referenced timer exists only while a run is active. |
| [0005](0005-shared-corpus-and-separate-pins.md) | The shared corpus is the only oracle, with separate corpus and error-vocabulary pins. |
| [0006](0006-declared-runtime-limitations.md) | Declare runtime limitations exactly instead of weakening assertions. |
| [0007](0007-fail-closed-os-trust-in-discovery.md) | Discovery trusts the operating system store and fails closed when it is unavailable. |

To supersede a record, add a new one that names it, and change the old record's status line to `superseded` with a link. Do not edit an accepted decision in place to reverse it.
