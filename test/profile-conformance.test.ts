import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runCorpus, surfaceRegistry, parsePendingAllowlist } from "../tools/conformance/loader.ts";

test("profile corpus: nine tagged cases execute through the registered surface", async () => {
  assert.equal(typeof surfaceRegistry().get("profile.name"), "function", "the profile corpus surface must execute");
  const pending = parsePendingAllowlist(readFileSync("tools/conformance/pending.json", "utf8"));
  assert.equal(pending.reduce((n, p) => n + p.items, 0), 2);
  const report = await runCorpus("conformance");
  assert.equal(report.known_positive_executed, true);
  assert.equal(report.executed + report.runtime_limited, 3000);
  assert.equal(report.runtime_limited, process.versions.bun === "1.3.14" && process.platform === "darwin" && process.arch === "arm64" ? 2 : 0);
  assert.deepEqual(report.pending, pending);
  assert.deepEqual(report.failures, [{id: "index", reason: "pending_surface"}]);
  assert.equal(report.ok, false);
});
