import { nodeAdapterTest } from "./support/node-adapter-test.ts";
const test = nodeAdapterTest(import.meta.url);
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import {
  capture,
  captureRequest,
  signedRequest,
  verifyRequest,
} from "../src/adapters/node-http/index.ts";
import { Custody, Policy, ok, type Result } from "../src/index.ts";
const require = createRequire(
  new URL("../interop/adapters/package.json", import.meta.url),
);
const fastify = require("fastify");
function value<T>(r: Result<T>): T {
  if (!r.ok) assert.fail(JSON.stringify(r.error));
  return r.value;
}
test("Fastify parses a fully drained replay and authenticates the original bytes", async (t) => {
  t.diagnostic(
    `Fastify ${require("fastify/package.json").version}: capture(server) -> preParsing replay -> verifyRequest after parser`,
  );
  const key = value(
    await Custody.local("hmac-sha256", {
      hmac: crypto.getRandomValues(new Uint8Array(32)),
    }),
  );
  const components = '("@method" "@request-target" "content-digest")';
  let resolutions = 0;
  const policy = value(
    Policy.create({
      algorithms: ["hmac-sha256"],
      components,
      keyResolver: () => {
        resolutions++;
        return ok({ algorithm: "hmac-sha256", key });
      },
      freshness: "not_evaluated",
      content: { kind: "content", algorithms: ["sha-256"], section: "headers" },
      replay: "not_required",
    }),
  );
  const app = fastify({ logger: false });
  const registration = value(capture(app.server));
  let handled = 0;
  app.addHook("preParsing", async (request: any) => {
    const retained = value(await captureRequest(request.raw));
    const stream = value(retained.replay());
    Object.defineProperty(stream, "receivedEncodedLength", {
      value: retained.message.body.bytes!.length,
    });
    return stream;
  });
  app.post("/*", async (request: any, reply: any) => {
    const result = await verifyRequest(request.raw, policy, { label: "sig" });
    if (!result.ok)
      return reply.code(400).send({ reason: result.error.reason });
    const verified = result.value;
    assert.equal(verified.capture.message.rawTarget, "/a%2Fb?x=%20");
    assert.deepEqual(
      JSON.parse(Buffer.from(verified.bytes).toString()),
      request.body,
    );
    assert.equal(verified.capture.replay().ok, false);
    handled++;
    return { accepted: true };
  });
  try {
    await app.listen({ port: 0, host: "127.0.0.1" });
    const address = app.server.address();
    assert.ok(address && typeof address === "object");
    const response = value(
      await signedRequest(
        {
          url: `http://127.0.0.1:${address.port}/a%2Fb?x=%20`,
          method: "POST",
          headers: [["Content-Type", "application/json"]],
          body: new TextEncoder().encode('{"hello":"café 🌊"}'),
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
    assert.equal(response.status, 200, Buffer.from(response.bytes).toString());
    assert.deepEqual(JSON.parse(Buffer.from(response.bytes).toString()), {
      accepted: true,
    });
    assert.equal(handled, 1);
    const before = resolutions;
    const prefix = new TextEncoder().encode('{"hello":"');
    const suffix = new TextEncoder().encode('"}');
    const invalidUtf8 = new Uint8Array([...prefix, 255, ...suffix]);
    const accepted = value(
      await signedRequest(
        {
          url: `http://127.0.0.1:${address.port}/a%2Fb?x=%20`,
          method: "POST",
          headers: [["Content-Type", "application/json"]],
          body: invalidUtf8,
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
    // Fastify 5.12.7's parser decodes invalid UTF-8 leniently, so the drained
    // replay completes and the request authenticates over the exact original
    // bytes. The mid-stream parser_order rejection this case used to pin is
    // covered directly by the node-http adapter suite.
    assert.equal(accepted.status, 200);
    assert.ok(resolutions > before, "the request authenticated through the resolver");
    assert.equal(handled, 2, "both requests reached the handler");
  } finally {
    value(registration.close());
    await app.close();
    await key.release();
  }
});
