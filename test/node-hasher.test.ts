import test from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { DigestState, digest } from "../src/index.ts";
test("the Node hasher computes real incremental SHA-2 through the core port", async () => {
  assert.equal(
    existsSync("src/node_hasher.ts"),
    true,
    "Node hasher entry point must exist",
  );
  const { createNodeHasher } = await import(
    new URL("../src/node_hasher.ts", import.meta.url).href
  );
  const r = createNodeHasher();
  assert.equal(r.ok, true);
  const state = await DigestState.create(
    "representation",
    ["sha-256", "sha-512"],
    r.value,
  );
  assert.equal(state.ok, true);
  if (!state.ok) return;
  const bytes = new TextEncoder().encode("real incremental hashes");
  assert.equal((await state.value.update(bytes)).ok, true);
  assert.deepEqual(
    await state.value.finish(),
    await digest(bytes, ["sha-256", "sha-512"]),
  );
});
