# 0009 — Prove every test lane rejects a planted failure

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

## Consequences

The proof requires a nonzero exit, its intentional marker, and a positive failing-test count. Runner output changes must preserve those checks in `scripts/red-proof.sh`.
