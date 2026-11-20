# 0005 — The shared corpus is the only oracle, with separate corpus and error-vocabulary pins

## Context

Both implementations use independently published corpus bytes and expectations to agree on wire bytes, verification facts, and rejection reasons. Neither implementation generates the other's expected values.

## Decision

`CORPUS_PIN` in `src/constants.ts` pins the `v1.0.0` corpus release, commit, and index digest; `ELIXIR_ERROR_PIN` in `src/errors/parity.ts` independently pins the error-vocabulary source. Both name commit `511fed142044ccea28bdcbb317c091cb2c8a515d`.
Vendoring verifies release assets, archive paths, and every digest before updating the corpus and its pin together. The runner requires every surface and item to execute under one strict development and release gate: executed + not applicable + runtime limited equals listed, and the known-positive case matches. Integrity failures, unsupported surfaces or formats, and disagreements fail.
The vocabulary is extracted from pinned public source by `scripts/extract-elixir-reasons.ts`, rendered by `scripts/render-parity.ts`, and re-extracted in CI.

## Consequences

A corpus update is a reviewed data change with provenance, never a quiet edit in one codebase. A re-pinned corpus that is self-consistent passes the runner by design, so the cross-language seal is the pin itself plus review of pin changes. The error vocabulary can lead or lag the corpus, and the documentation says which.
