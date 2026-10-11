import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
test("native and built lanes include the real Web Bot Auth discovery contracts", () => {
  const workflow = readFileSync(".github/workflows/ci.yml", "utf8");
  const commands = workflow.split("\n").map(line => line.trim());
  const deno = commands.find(line => line.startsWith("deno test --no-check "));
  const bun = commands.find(line => line.startsWith("bun test ") && !line.includes("test/red/"));
  assert.ok(deno);
  assert.ok(bun);
  for (const lane of [deno, bun])
    assert.ok(lane.includes("test/web-bot-auth-discovery.test.ts") || lane.includes("test/*.test.ts"));
  assert.ok(/--allow-net(=| |$)/.test(deno));
  assert.ok(deno.includes("--allow-run=deno,node,"));
  const built = readFileSync("scripts/test-built.ts", "utf8");
  assert.match(built, /'web-bot-auth-discovery'/);
});
test("deadline documentation distinguishes resolution and per-signature phases", () => {
  const doc = readFileSync("docs/reference/web-bot-auth.md", "utf8");
  assert.match(doc, /trust or discovery[^.]*agent_unresolved[^.]*timeout/s);
  assert.match(doc, /per-signature check[^.]*retryable[^.]*custody\/deadline_exceeded/s);
});
test("nested evidence documentation requires intersection with verified signatures", () => {
  const doc = readFileSync("docs/reference/web-bot-auth.md", "utf8");
  assert.match(doc, /evidence records coverage only/);
  assert.match(doc, /inner label[^.]*untagged or unverified/s);
  assert.match(doc, /intersect[^.]*evidence[^.]*signatures/s);
});
test("held-key documentation names eligible failures and non-bypassable failures", () => {
  const doc = readFileSync("docs/reference/web-bot-auth.md", "utf8");
  assert.match(doc, /after refused trust, an unsupported agent type, an unknown key,[\s\S]*an unavailable source, or a timeout/);
  assert.match(doc, /never after `revoked_key`, `source_mismatch`, or `not_an_origin`/);
  assert.match(doc, /expired Context prevents[^.]*callback/s);
});
test("origin documentation records host normalization and the corpus gap", () => {
  const doc = readFileSync("docs/reference/web-bot-auth.md", "utf8");
  for (const text of ["WHATWG URL", "https://[0:0::1]", "https://0x7f.1", "not_an_origin", "reference compares the host text", "TypeScript fails closed", "No corpus case covers"]) assert.ok(doc.includes(text), text);
  for (const text of ["three-key", "sign()", "WebBotAuth.sign", "KeyHandle and any callable", "reference requires a two-argument function", "No wire bytes change"]) assert.ok(doc.includes(text), text);
  assert.match(doc, /`agents` and `heldKeys` accept any callable, while the reference requires arity-one functions\.\s+Results are validated at invocation\./);
});
test("generic verification documentation describes profile and principal narrowing", () => {
  const doc = readFileSync("docs/reference/sign-and-verify.md", "utf8");
  for (const text of ["Verification.profile", "Verification.principal", "unions", "rfc9421", "web_bot_auth", "unattributed", "agent principal", "held-key principal", "narrow `principal` before use"]) assert.ok(doc.includes(text), text);
  assert.match(doc, /Every Verification prints and serializes to JSON as[^.]*`label`, `profile`, `replay`, and `authorization` only/s);
  assert.match(doc, /full facts call `serializeVerification\(\)`\./s);
  assert.doesNotMatch(doc, /verificationFacts/);
});
test("JOSE documentation describes callable signers and branded handles", () => {
  const doc = readFileSync("docs/reference/jose.md", "utf8");
  for (const text of ["branded KeyHandle", "any callable", "Function length does not determine validity", "algorithm_mismatch", "reference requires a two-argument function", "without changing wire bytes"]) assert.ok(doc.includes(text), text);
});
