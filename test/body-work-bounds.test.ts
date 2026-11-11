import test from "node:test";
import assert from "node:assert/strict";
import * as Seal from "../src/index.ts";
import * as Fetch from "../src/adapters/fetch/index.ts";
import * as NodeHttp from "../src/adapters/node-http/index.ts";
import { createServer } from "node:http";
import { once } from "node:events";
import { rawRequest } from "./support/wire-server.ts";
import { nodeAdapterTest } from "./support/node-adapter-test.ts";
const networkTest = nodeAdapterTest(import.meta.url);
const value = <T>(r: Seal.Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return r.value; };
const spec = { label: "sig", algorithm: "hmac-sha256", components: '("@method")', expiresIn: 60 };
for (const empty of [true, false]) test(`retention stops ${empty ? "empty" : "tiny"} producers before a pull beyond 16,384`, async () => {
  const h = value(await Seal.Custody.local("hmac-sha256", { hmac: crypto.getRandomValues(new Uint8Array(32)) }));
  let pulls = 0, canceled = 0;
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (pulls >= 16384) throw new Error("pulled beyond the work ceiling");
      pulls++;
      controller.enqueue(empty ? new Uint8Array() : new Uint8Array([1]));
    },
    cancel() { canceled++; },
  }, { highWaterMark: 0 });
  try {
    const request = new Request("https://example.com/", { method: "POST", body: stream, duplex: "half" } as RequestInit);
    const result = await Fetch.signRequest(request, spec, h);
    assert.equal(!result.ok && result.error.reason, "limit");
    assert.equal(pulls, 16384);
    assert.equal(canceled, 1);
  } finally { await h.release(); }
});

test("retention discards empty chunks and cancels a stalled producer at its deadline", async () => {
  const h = value(await Seal.Custody.local("hmac-sha256", { hmac: crypto.getRandomValues(new Uint8Array(32)) }));
  try {
    let i = 0;
    const parts = [new Uint8Array(), new Uint8Array([1]), new Uint8Array(), new Uint8Array([2])];
    const stream = new ReadableStream<Uint8Array>({ pull(c) { if (i < parts.length) c.enqueue(parts[i++]!); else c.close(); } }, { highWaterMark: 0 });
    const request = new Request("https://example.com/", { method: "POST", body: stream, duplex: "half" } as RequestInit);
    const signed = value(await Fetch.signRequest(request, spec, h));
    assert.deepEqual(signed.message.body.bytes, new Uint8Array([1, 2]));
    await signed.request.body?.cancel();
    let canceled = 0;
    const blocked = new ReadableStream<Uint8Array>({ pull() {}, cancel() { canceled++; } }, { highWaterMark: 0 });
    const stalled = new Request("https://example.com/", { method: "POST", body: blocked, duplex: "half" } as RequestInit);
    const r = await Fetch.signRequest(stalled, spec, h, { context: value(Seal.withDeadline({ timeoutMs: 50 })) });
    assert.equal(r.ok, false);
    assert.equal(canceled, 1);
  } finally { await h.release(); }
});

networkTest("Node capture bounds tiny HTTP chunks independently of retained byte size", async () => {
  let complete!: (r: Seal.Result<NodeHttp.Capture>) => void;
  const captured = new Promise<Seal.Result<NodeHttp.Capture>>(resolve => { complete = resolve; });
  const server = createServer((req, res) => {
    void NodeHttp.captureRequest(req).then(r => { complete(r); res.end(); });
  });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const address = server.address(); assert.ok(address && typeof address === "object");
  try {
    await rawRequest(address.port, `POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n${"1\r\nx\r\n".repeat(16384)}0\r\n\r\n`).catch(() => {});
    const r = await captured;
    assert.equal(!r.ok && r.error.reason, "limit");
  } finally {
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
});
