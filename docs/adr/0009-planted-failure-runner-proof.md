<!-- Status: accepted · Kind: decision record · Updated: 2026-11-15 · Governed by: public API, compatibility contract, and cited decisions · Review when: the implementation or a governing decision changes -->

# 0009 — Prove every test lane rejects a planted failure
Status: Accepted

## Context

A test lane that exits zero proves nothing if its runner would also exit zero on a failing test.
Runner flags, a wrong glob, a swallowed exit code or a runtime that skips TypeScript files can
each turn a red suite green. This package runs on Node, Deno, Bun and three browser engines, each
with its own runner.

## Decision

1. `test/red/planted.test.ts` holds one test that always fails with the marker
   `Intentional red proof`. It is outside the `test/*.test.ts` glob of `npm test`.
2. `scripts/red-proof.sh` runs a lane's command on that file. It fails if the run passes, if
   the output lacks the marker, or if the output lacks a positive failing-test count, so a
   different failure cannot stand in for the planted one.
3. CI runs the proof for Node (`npm run test:red`, `.github/workflows/ci.yml:61-63`), Deno and
   Bun (`.github/workflows/ci.yml:110-117`) and every browser
   (`.github/workflows/ci.yml:170-171`) before or beside that lane's real tests.
4. `test/red-proof.test.ts` checks the script itself: the planted test is accepted as a proof,
   and a missing test file is not.

## Alternatives

1. **Trust the runner's exit code.** No extra step. A misconfigured lane stays green silently.
2. **Count executed tests.** Detects an empty run. It does not detect a runner that reports
   failures but exits zero.
3. **Mutation testing of the library.** Stronger evidence about the tests. It is slower by
   orders of magnitude and does not check the lane wiring this proof checks.

## Consequences

Every new lane needs its own proof step. The marker and the count patterns in
`scripts/red-proof.sh` must follow each runner's output format, so a runner upgrade that changes
its summary line fails the proof until the pattern is updated.
