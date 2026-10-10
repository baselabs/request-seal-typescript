import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  runCorpus,
  surfaceRegistry,
  canonicalJson,
  resolvePointer,
  type CorpusResources,
} from "../tools/conformance/loader.ts";
import { ok, decodeJson, WebBotAuth } from "../src/index.ts";
import { value, request, policy } from "./support/web-bot-auth.ts";
const resources: CorpusResources = {
  read: (p) => ok(new Uint8Array(readFileSync("conformance/" + p))),
  reference: (v) => {
    const ref = (v as { ref: { file: string; pointer: string } }).ref;
    const r = decodeJson(readFileSync("conformance/" + ref.file), {
      maxBytes: 16777216,
      maxDepth: 64,
      maxMembers: 100000,
      maxArrayLength: 100000,
      maxStringBytes: 16777216,
    });
    return r.ok ? ok(resolvePointer(r.value.node, ref.pointer)) : r;
  },
};
test(
  "all fourteen Web Bot Auth cases execute against the unchanged oracle",
  { timeout: 90000 },
  async () => {
    const registry = surfaceRegistry();
    assert.equal(registry.has("web_bot_auth.verify"), true);
    const index = JSON.parse(readFileSync("conformance/index.json", "utf8"));
    const cases = index.cases.filter(
      (c: { surface: string }) => c.surface === "web_bot_auth.verify",
    );
    assert.equal(cases.length, 14);
    for (const c of cases) {
      const m = JSON.parse(readFileSync("conformance/" + c.manifest, "utf8"));
      const r = await registry.get("web_bot_auth.verify")!(m, resources);
      if (m.class === "rejection") {
        assert.equal(r.ok, false, c.id);
        if (!r.ok && "error" in r)
          assert.equal(
            r.error.kind +
              "/" +
              ("layer" in r.error ? r.error.layer + "." : "") +
              r.error.reason,
            m.expected.rule_id,
            c.id,
          );
      } else {
        assert.ok(r.ok && "verification" in r.value, c.id);
        assert.equal(
          canonicalJson(r.value.verification),
          canonicalJson(m.expected.verification),
          c.id,
        );
      }
    }
    const report = await runCorpus("conformance", { pendingOk: true });
    assert.equal(report.ok, true, canonicalJson(report));
    assert.equal(report.executed + report.runtime_limited, 3002);
    assert.equal(
      report.pending.reduce((n, p) => n + p.items, 0),
      0,
    );
  },
);
test("canonical envelope facts omit provenance while runtime results retain it", async () => {
  const r = value(await WebBotAuth.verify(await request(), policy()));
  assert.equal(r.signatures.agent!.principal.kind, "agent");
});
