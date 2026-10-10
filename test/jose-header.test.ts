import test from "node:test";
import assert from "node:assert/strict";
import * as API from "../src/index.ts";
import { ruleId } from "../src/errors/types.ts";
import type { Result } from "../src/result.ts";
const bytes = (s: string) => new TextEncoder().encode(s);
const value = <T>(r: Result<T>): T => {
  assert.equal(r.ok, true);
  if (!r.ok) throw Error("Rejected");
  return r.value;
};
test("compact framing preserves segments and stops at excess separators", async () => {
  assert.equal("JoseHeader" in API, false);
  const { JoseHeader } = await import("../src/jose/header.ts");
  assert.deepEqual(value(JoseHeader.compact("a.b.c", 3)), ["a", "b", "c"]);
  for (const [input, reason] of [
    ["a.b", "invalid_serialization"],
    [".".repeat(1048576), "invalid_serialization"],
    ["x".repeat(1048577), "limit"],
    [" {}", "unsupported_serialization"],
  ] as const) {
    const r = JoseHeader.compact(input, 3);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(ruleId(r.error), "jose/input." + reason);
  }
});
test("headers preserve order and reject duplicate members at every depth", async () => {
  assert.equal("JoseHeader" in API, false);
  const { JoseHeader } = await import("../src/jose/header.ts");
  const h = value(JoseHeader.json(bytes('{ "kid":"k", "alg":"RS256" }')));
  assert.deepEqual(h, [
    ["kid", "k"],
    ["alg", "RS256"],
  ]);
  assert.ok(Object.isFrozen(h));
  assert.ok(Object.isFrozen(h[0]));
  for (const [raw, reason] of [
    ['{"alg":"RS256","alg":"RS256"}', "duplicate_member"],
    ['{"alg":"RS256","x":{"a":1,"a":2}}', "duplicate_member"],
    ['{"alg":"RS256","crit":[]}', "unsupported_critical_header"],
    ['{"alg":"RS256","zip":null}', "compression_unsupported"],
    ['{"alg":"RS256","b64":false}', "unsupported_header"],
    ['{"alg":"RS256","jwk":{}}', "unsupported_header"],
    ['{"alg":"RS256","x":1.0}', "invalid_header"],
    ['{"alg":"RS256","x":1000000000000000}', "limit"],
    ['{"alg":"RS256","x":-1000000000000000}', "limit"],
    ['{"alg":"RS256","x":[[[[0]]]]}', "limit"],
    ['{"alg":null}', "invalid_header"],
    ['{"alg":"RS256"}\u2003', "invalid_header"],
  ] as const) {
    const r = JoseHeader.json(bytes(raw));
    assert.equal(r.ok, false, raw);
    if (!r.ok) assert.equal(r.error.reason, reason, raw);
  }
  for (const segment of ["e30=", "Zh", "+w", "/w"])
    assert.equal(JoseHeader.parse(segment).ok, false);
  const good = '{"alg":"RS256"}'.padEnd(16384);
  assert.equal(JoseHeader.json(bytes(good)).ok, true);
  assert.equal(JoseHeader.json(bytes(good + " ")).ok, false);
});
