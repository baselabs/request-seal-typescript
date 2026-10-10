import test from "node:test";
import assert from "node:assert/strict";
import { signRequest } from "../src/adapters/fetch/index.ts";
import { Custody, type Result } from "../src/index.ts";
function value<T>(r: Result<T>): T {
  if (!r.ok) assert.fail(JSON.stringify(r.error));
  return r.value;
}
test(
  "refuses Bun targets whose leading slashes change during delivery",
  { skip: !(globalThis as any).Bun },
  async () => {
    const key = value(
      await Custody.local("hmac-sha256", {
        hmac: crypto.getRandomValues(new Uint8Array(32)),
      }),
    );
    try {
      const r = await signRequest(
        new Request("http://127.0.0.1//%2F?"),
        {
          label: "sig",
          components: '("@request-target")',
          algorithm: "hmac-sha256",
          expiresIn: 60,
        },
        key,
      );
      assert.equal(r.ok, false);
      if (!r.ok) assert.equal(r.error.reason, "invalid_request");
    } finally {
      await key.release();
    }
  },
);
