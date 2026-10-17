import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as api from "../src/index.ts";
import { verifyLabel } from "../src/verify.ts";
import { faultClass, coreError } from "../src/errors/types.ts";
import { value, policy, quorum, input } from "./support/quorum.ts";

test("the fault class vocabulary is bounded to exception class names", () => {
  assert.equal(faultClass(new TypeError("secret message")), "TypeError");
  assert.equal(faultClass(new RangeError("x")), "RangeError");
  class CustomFault extends Error {}
  assert.equal(faultClass(new CustomFault()), "Error");
  assert.equal(faultClass("thrown string"), "throw");
  assert.equal(faultClass(null), "throw");
  assert.equal(faultClass(42), "throw");
  // The internal error carries the class name only, never message text.
  const error = coreError("internal", "internal", faultClass(new TypeError("secret message")));
  assert.equal(error.reason, "internal");
  assert.equal(error.layer, "internal");
  assert.equal(error.retryable, false);
  assert.equal(error.detail, "TypeError");
  assert.doesNotMatch(JSON.stringify(error), /secret message/);
});
test("a throwing extension pipeline step keeps its invalid_policy classification", async () => {
  const c = JSON.parse(await readFile("test/fixtures/upstream/multi_signature/rfc9421.json", "utf8"));
  const { message } = await import("../tools/conformance/wire.ts");
  const base = value(message(c.b2, {read: () => {throw Error("Unexpected reference");}} as never));
  const v = c.signatures.find((s: {label: string}) => s.label === "sig-b26")!;
  const ed25519 = value(await api.PublicKey.import(
    await readFile("test/fixtures/upstream/crypto/ed25519_public.pem", "utf8"), "pem"));
  const resolving = policy({algorithms: ["ed25519"], keyResolver: () => api.ok({algorithm: "ed25519", key: ed25519})});
  const m = value(api.Message.create({...base, fields: [...base.fields, ...[
    ["Signature-Input", v.signature_input],
    ["Signature", v.signature],
  ].map(([name, raw]) => value(api.FieldOccurrence.create({name, value: raw as string, section: "headers"})))]}));
  // The observer runs only on a successful verification, so the label must
  // first verify for real; its throwing step is then classified as policy.
  const r = await verifyLabel(m, resolving, {label: v.label}, () => {throw new Error("observer secret");}, undefined, {name: "rfc9421"} as never);
  assert.equal(r.ok, false);
  if (!r.ok) {
    assert.equal(r.error.kind, "core");
    if (r.error.kind === "core") {
      assert.equal(r.error.reason, "invalid_policy");
      assert.equal(r.error.layer, "input");
      assert.doesNotMatch(JSON.stringify(r.error), /observer secret/);
    }
  }
});
