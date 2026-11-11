import test from "node:test";
import assert from "node:assert/strict";
import { faultClass, coreError } from "../src/errors/types.ts";

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
