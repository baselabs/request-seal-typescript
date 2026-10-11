import test from "node:test";
import assert from "node:assert/strict";
import { Profile, type ProfileStamp } from "../src/index.ts";

// Compile-time constraints complement validation of unknown boundary input.
const valid: ProfileStamp<"revision" | "enabled"> = {name: ["example_pkg", "example"], revision: "one", enabled: true};
// @ts-expect-error Metadata cannot be a tuple.
const tuple: ProfileStamp<"revision"> = {name: ["example_pkg", "example"], revision: ["a", "b"]};
// @ts-expect-error Metadata cannot be an object.
const object: ProfileStamp<"revision"> = {name: ["example_pkg", "example"], revision: {value: "one"}};
// @ts-expect-error Name requires exactly two strings.
const short: ProfileStamp = {name: ["example_pkg"]};
// @ts-expect-error Name cannot contain a numeric kind.
const numeric: ProfileStamp = {name: ["example_pkg", 1]};
const unknownStamp: unknown = valid;

// These assignments check both typed and untrusted callers without making a call.
const typedBoundary: (m: unknown, p: unknown, l: unknown, i: unknown, s: unknown, stamp: typeof valid) => unknown = Profile.verifyLabel;
const unknownBoundary: (m: unknown, p: unknown, l: unknown, i: unknown, s: unknown, stamp: typeof unknownStamp) => unknown = Profile.verifyLabel;

test("profile type checks coexist with the runtime authority", () => {
  assert.equal(typedBoundary, unknownBoundary);
  assert.equal(valid.name.length, 2);
  assert.equal(Array.isArray(tuple.revision), true);
  assert.equal(typeof object.revision, "object");
  assert.equal(short.name.length, 1);
  assert.equal(typeof numeric.name[1], "number");
});
