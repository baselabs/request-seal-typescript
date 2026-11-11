import test from "node:test";
import assert from "node:assert/strict";
import * as Seal from "../src/index.ts";
import * as NodeHttp from "../src/adapters/node-http/index.ts";
test("public verification exposes per-label results without composite APIs, reasons, or telemetry", () => {
  for (const api of [Seal, NodeHttp])
    assert.deepEqual(Object.keys(api).filter(k => /quorum/i.test(k)), []);
  assert.equal(Seal.ERROR_PARITY.some(e => /quorum|negotiation_unfulfilled/.test(e.rule_id)), false);
  assert.deepEqual(Seal.Telemetry.events(), ["verify", "webBotAuthVerify", "replayClaim", "custodySign"]);
});
