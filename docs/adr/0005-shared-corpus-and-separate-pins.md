**Status:** accepted · **Kind:** record · **Updated:** October 11, 2026 · **Governed by:** the shared conformance corpus format and the vendoring and extraction scripts · **Review when:** a pin moves, a corpus surface is added, or the error vocabulary changes

# ADR 0005: The shared corpus is the only oracle, with separate corpus and error-vocabulary pins

- Status: Accepted
- Date: October 11, 2026

## Context

This package and RequestSeal for Elixir must agree on wire bytes, verification facts, and rejection reasons. Two hand-written test suites agree only by accident. If one implementation generates the other's expected values, a defect in the generator becomes the expected output and every check confirms itself.

The two implementations release independently. The Elixir release `v0.4.1` changed the error vocabulary but changed no corpus bytes and published no corpus release assets, so the corpus tag and the error-vocabulary tag legitimately differ.

## Decision

1. **The shared corpus is the semantic oracle.** `conformance/` holds public source bytes, canonical case manifests, and an `index.json` with every file digest. This package vendors it from one upstream release tag. Neither implementation regenerates an expected value during a run.
2. **Two pins, two artifacts.** `CORPUS_PIN` in `src/constants.ts` names the corpus release tag, commit, and index SHA-256; it is `v0.4.0`. `ELIXIR_ERROR_PIN` in `src/errors/parity.ts` names the Elixir commit that the error vocabulary is extracted from; it is the commit behind `v0.4.1`. The pins move separately, each with its own reviewed commit, and each states why it differs from the other.
3. **Vendoring is verified.** `scripts/vendor-corpus.ts` downloads the release assets and checks the asset checksum, archive paths, inventory digests, release commit, and index digest before it replaces the corpus and updates the pin in one change.
4. **Consumption ties out.** The runner (`tools/conformance/cli.ts`) checks the index pin and every file digest, executes each case once, and requires `executed + not_applicable + runtime_limited + pending` to equal the listed items. A known-positive case must execute and match. `--pending-ok` is a development flag; the release workflow runs the corpus without it.
5. **The error vocabulary is generated, not typed.** `scripts/extract-elixir-reasons.ts` reads the pinned Elixir source through `git show`, and `scripts/render-parity.ts` renders `docs/reference/error-parity.md` from the same table. CI re-extracts from the pinned tag and compares.

## Strongest alternatives

1. **Generate the TypeScript fixtures from Elixir.** One source of truth. Any Elixir defect becomes the expected output, and reciprocal tests stop being independent.
2. **One pin for both artifacts.** Simpler to describe. It would force a corpus re-vendor with no byte change whenever the error vocabulary moves, or hide a real corpus change behind an error-vocabulary bump.
3. **Parallel fixture sets, one per language.** Each language is autonomous, with no oracle and a guarantee of drift.
4. **Only official positive vectors.** Independent and authoritative where they exist. They leave profiles, rejection reasons, adapters, and edge representations uncovered.

## Deciding evidence and deletion test

`src/constants.ts` and `src/errors/parity.ts` record separate pins. `test/conformance.test.ts` checks the pinned inventory, known-positive execution, and a changed index. `test/upstream-integrity.test.ts` checks copied source digests, and `test/parity-generation.test.ts` compares generated vocabulary documents. These checks support independent pins and preserved expectations; no corpus deletion or pin-collapse mutation is claimed.

## Consequences

A corpus update is a reviewed data change with provenance, never a quiet edit in one codebase. A re-pinned corpus that is self-consistent passes the runner by design, so the cross-language seal is the pin itself plus review of pin changes. The error vocabulary can lead or lag the corpus, and the documentation says which.

## Acceptance

- `src/constants.ts` (`CORPUS_PIN`) and `src/errors/parity.ts` (`ELIXIR_ERROR_PIN`) are the two pins.
- `test/conformance.test.ts` ties out inventory, index pin, and known-positive execution, and its tamper test shows a changed index is detected.
- `test/conformance-vendor.test.ts` covers pending permissions, changed expectations, symlink and name collisions, and live vendoring.
- `test/upstream-integrity.test.ts` checks every copied upstream byte against its checksums.
- `test/errors.test.ts`, `test/parity-generation.test.ts`, and `test/extract-elixir-reasons.ts` check the vocabulary, its generated documentation, and live extraction from the pinned tag.
- `npm run conformance` runs the smoke corpus and the released corpus; `.github/workflows/release.yml` requires the full corpus.
