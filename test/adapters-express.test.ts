import { nodeAdapterTest } from "./support/node-adapter-test.ts";
const test = nodeAdapterTest(import.meta.url);
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { createServer } from "node:http";
import { once } from "node:events";
import {
  captureBody,
  captureRequest,
  signedRequest,
  verifyRequest,
} from "../src/adapters/node-http/index.ts";
import { Custody, Policy, ok, type Result } from "../src/index.ts";
const require = createRequire(
  new URL("../interop/adapters/package.json", import.meta.url),
);
const express = require("express");
function value<T>(r: Result<T>): T {
  if (!r.ok) assert.fail(JSON.stringify(r.error));
  return r.value;
}
test("Express body-parser verify captures bytes before URL rewriting and authenticates the parsed body", async (t) => {
  t.diagnostic(
    `Express ${require("express/package.json").version}: express.json verify(req,res,buf) -> captureBody; verifyRequest after parser`,
  );
  const key = value(
    await Custody.local("hmac-sha256", {
      hmac: crypto.getRandomValues(new Uint8Array(32)),
    }),
  );
  const components = '("@method" "@request-target" "content-digest")';
  const p = value(
    Policy.create({
      algorithms: ["hmac-sha256"],
      components,
      keyResolver: () => ok({ algorithm: "hmac-sha256", key }),
      freshness: "not_evaluated",
      content: { kind: "content", algorithms: ["sha-256"], section: "headers" },
      replay: "not_required",
    }),
  );
  const app = express();
  app.use(
    express.json({
      inflate: false,
      verify(req: unknown, _res: unknown, buf: Buffer) {
        value(captureBody(req, buf));
      },
    }),
  );
  app.use(async (req: any, res: any) => {
    req.url = "/rewritten";
    const c = value(await captureRequest(req));
    assert.equal(c.message.rawTarget, "/a%2Fb?");
    const v = value(await verifyRequest(req, p, { label: "sig" }));
    assert.deepEqual(JSON.parse(Buffer.from(v.bytes).toString()), req.body);
    res.end("accepted");
  });
  const server = createServer(app);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  try {
    const response = value(
      await signedRequest(
        {
          url: `http://127.0.0.1:${addr.port}/a%2Fb?`,
          method: "POST",
          headers: [["Content-Type", "application/json"]],
          body: new TextEncoder().encode('{"hello":"world"}'),
        },
        {
          label: "sig",
          components,
          algorithm: "hmac-sha256",
          expiresIn: 60,
          digest: ["sha-256"],
        },
        key,
      ),
    );
    assert.equal(Buffer.from(response.bytes).toString(), "accepted");
  } finally {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
    await key.release();
  }
});
