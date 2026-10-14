import { nodeAdapterTest } from "./support/node-adapter-test.ts";
const test = nodeAdapterTest(import.meta.url);
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import * as adapter from "../src/adapters/node-http/index.ts";
import { Custody, ok, Policy } from "../src/index.ts";
function value<T>(
  r: { ok: true; value: T } | { ok: false; error: unknown },
): T {
  if (!r.ok) assert.fail(JSON.stringify(r.error));
  return r.value;
}
test("captures exact targets and replays retained bytes once before verification", async () => {
  assert.equal(
    typeof adapter.captureRequest,
    "function",
    "captureRequest must translate live incoming requests",
  );
  const key = value(
    await Custody.local("hmac-sha256", {
      hmac: crypto.getRandomValues(new Uint8Array(32)),
    }),
  );
  const policy = value(
    Policy.create({
      algorithms: ["hmac-sha256"],
      components: '("@method" "@request-target" "content-digest")',
      keyResolver: () => ok({ algorithm: "hmac-sha256", key }),
      freshness: "not_evaluated",
      content: { kind: "content", algorithms: ["sha-256"], section: "headers" },
      replay: "not_required",
    }),
  );
  const server = createServer(async (req, res) => {
    const c = value(await adapter.captureRequest(req));
    assert.equal(c.message.rawTarget, "/a%2Fb?");
    assert.equal(c.ingress.evidence, "observed");
    const stream = value(c.replay());
    const chunks: Buffer[] = [];
    for await (const chunk of stream) chunks.push(chunk);
    assert.equal(Buffer.concat(chunks).toString(), "hello");
    assert.equal(c.replay().ok, false);
    const verified = value(
      await adapter.verifyRequest(req, policy, { label: "sig" }),
    );
    assert.equal(Buffer.from(verified.bytes).toString(), "hello");
    assert.equal(adapter.verification(req).ok, true);
    res.end("accepted");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  try {
    const response = value(
      await adapter.signedRequest(
        {
          url: `http://127.0.0.1:${address.port}/a%2Fb?`,
          method: "POST",
          body: new TextEncoder().encode("hello"),
        },
        {
          label: "sig",
          components: '("@method" "@request-target" "content-digest")',
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

import fc from "fast-check";
import {
  signResponse,
  verifyResponse,
} from "../src/adapters/node-http/index.ts";
import { connect as h2Connect, createServer as h2Server } from "node:http2";
import { Message, sign } from "../src/index.ts";
import { rawRequest } from "./support/wire-server.ts";
test("rejects partial replay before key resolution and refuses a second verification", async () => {
  let resolutions = 0;
  const key = value(
    await Custody.local("hmac-sha256", {
      hmac: crypto.getRandomValues(new Uint8Array(32)),
    }),
  );
  const policy = value(
    Policy.create({
      algorithms: ["hmac-sha256"],
      components: '("@method")',
      keyResolver: () => {
        resolutions++;
        return ok({ algorithm: "hmac-sha256", key });
      },
      freshness: "not_evaluated",
      content: "not_required",
      replay: "not_required",
    }),
  );
  let outcome!: Promise<void>;
  const server = createServer((req, res) => {
    outcome = (async () => {
      const c = value(await adapter.captureRequest(req));
      const stream = value(c.replay());
      stream.read(2);
      const result = await adapter.verifyRequest(req, policy, { label: "sig" });
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.error.reason, "parser_order");
      assert.equal(resolutions, 0);
      stream.resume();
      await once(stream, "end");
      assert.equal(
        (await adapter.verifyRequest(req, policy, { label: "sig" })).ok,
        true,
      );
      const again = await adapter.verifyRequest(req, policy, { label: "sig" });
      assert.equal(again.ok, false);
      if (!again.ok) assert.equal(again.error.reason, "already_verified");
      res.end();
    })();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  try {
    value(
      await adapter.signedRequest(
        {
          url: `http://127.0.0.1:${address.port}/`,
          method: "POST",
          body: new TextEncoder().encode("hello"),
        },
        {
          label: "sig",
          components: '("@method")',
          algorithm: "hmac-sha256",
          expiresIn: 60,
        },
        key,
      ),
    );
    await outcome;
  } finally {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
    await key.release();
  }
});
test("captures HTTP/2 pseudo-headers, cookie crumbs, and trailers without inventing Host", async () => {
  const server = h2Server();
  let outcome!: Promise<void>;
  server.on("request", (req, res) => {
    outcome = (async () => {
      const c = value(await adapter.captureRequest(req));
      assert.equal(c.message.rawTarget, "/a%2Fb?");
      assert.equal(c.message.transport.httpVersion, "http2");
      assert.equal(c.ingress.evidence, "observed");
      assert.ok(
        !c.message.fields.some(
          (f) => f.name.startsWith(":") || f.name === "host",
        ),
      );
      assert.equal(
        Buffer.from(
          c.message.fields.find((f) => f.name === "cookie")!.value,
        ).toString(),
        "a=1; b=2",
      );
      assert.ok(Array.isArray(c.message.trailers));
      assert.equal(
        Buffer.from(
          c.message.trailers.find((f) => f.name === "x-trailer")!.value,
        ).toString(),
        "complete",
      );
      res.end("ok");
    })();
    void outcome.catch(() => res.end());
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  const client = h2Connect(`http://127.0.0.1:${addr.port}`);
  try {
    const req = client.request(
      {
        ":method": "POST",
        ":path": "/a%2Fb?",
        cookie: ["a=1", "b=2"],
      },
      { waitForTrailers: true },
    );
    req.on("wantTrailers", () => req.sendTrailers({ "x-trailer": "complete" }));
    req.resume();
    req.end("hello");
    await once(req, "end");
    await outcome;
  } finally {
    client.destroy();
    await new Promise<void>((r) => server.close(() => r()));
  }
});
test("signs buffered responses with final Date and length and associates the sent request", async () => {
  const key = value(
    await Custody.local("hmac-sha256", {
      hmac: crypto.getRandomValues(new Uint8Array(32)),
    }),
  );
  const components =
    '("@status" "@method";req "date" "content-length" "content-digest")';
  const policy = value(
    Policy.create({
      algorithms: ["hmac-sha256"],
      components,
      keyResolver: () => ok({ algorithm: "hmac-sha256", key }),
      freshness: "not_evaluated",
      content: { kind: "content", algorithms: ["sha-256"], section: "headers" },
      replay: "not_required",
    }),
  );
  const body = new TextEncoder().encode("signed response");
  let outcome!: Promise<void>;
  const server = createServer((req, res) => {
    outcome = (async () => {
      const c = value(await adapter.captureRequest(req));
      value(
        await signResponse(
          res,
          {
            label: "sig",
            components,
            algorithm: "hmac-sha256",
            expiresIn: 60,
            digest: ["sha-256"],
          },
          key,
          { body, request: c },
        ),
      );
      assert.equal(res.writableEnded, true);
    })();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  try {
    const r = value(
      await adapter.signedRequest(
        { url: `http://127.0.0.1:${addr.port}/` },
        {
          label: "sig",
          components: '("@method")',
          algorithm: "hmac-sha256",
          expiresIn: 60,
        },
        key,
      ),
    );
    const verified = value(
      await verifyResponse(r, r.request, policy, { label: "sig" }),
    );
    assert.deepEqual(verified.bytes, body);
    assert.equal(
      r.message.fields.find((f) => f.name.toLowerCase() === "content-length")
        ?.value.length,
      2,
    );
    await outcome;
    const wrong = value(
      await Message.request("PUT", `http://127.0.0.1:${addr.port}/`, [], null),
    );
    assert.equal(
      (await verifyResponse(r, wrong, policy, { label: "sig" })).ok,
      false,
    );
  } finally {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
    await key.release();
  }
});
test("preserves generated targets and covered bytes and ignores uncovered fields over real HTTP", async () => {
  const key = value(
    await Custody.local("hmac-sha256", {
      hmac: crypto.getRandomValues(new Uint8Array(32)),
    }),
  );
  const components =
    '("@method" "@request-target" "x-covered" "content-digest")';
  const policy = value(
    Policy.create({
      algorithms: ["hmac-sha256"],
      components,
      keyResolver: () => ok({ algorithm: "hmac-sha256", key }),
      freshness: "not_evaluated",
      content: { kind: "content", algorithms: ["sha-256"], section: "headers" },
      replay: "not_required",
    }),
  );
  const server = createServer(async (req, res) => {
    const c = await adapter.captureRequest(req);
    if (!c.ok) {
      res.statusCode = 400;
      res.end();
      return;
    }
    const v = await adapter.verifyRequest(req, policy, { label: "sig" });
    res.statusCode = v.ok ? 200 : 401;
    res.end();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  try {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.constantFrom("a", "b", "%2F", "%20", "~"), {
          minLength: 1,
          maxLength: 12,
        }),
        fc.uint8Array({ maxLength: 64 }),
        async (parts, body) => {
          const target = "/" + parts.join("") + "?x=%20";
          const url = `http://127.0.0.1:${addr.port}${target}`;
          const spec = {
            label: "sig",
            components,
            algorithm: "hmac-sha256",
            expiresIn: 60,
            digest: ["sha-256"],
          };
          const r = value(
            await adapter.signedRequest(
              {
                url,
                method: "POST",
                headers: [
                  ["x-covered", "yes"],
                  ["x-extra", "unused"],
                ],
                body,
              },
              spec,
              key,
            ),
          );
          assert.equal(r.status, 200);
          const m = value(
            await Message.request("POST", url, [["x-covered", "yes"]], body),
          );
          const signed = value(await sign(m, spec, key));
          const header = signed.fields
            .map(
              (f) =>
                `${f.name}: ${Buffer.from(f.value).toString("latin1")}\r\n`,
            )
            .join("");
          const wire =
            `POST ${target} HTTP/1.1\r\nHost: 127.0.0.1:${addr.port}\r\n${
              header.replace("x-covered: yes", "x-covered: changed")
            }Content-Length: ${body.length}\r\nConnection: close\r\n\r\n`;
          const result = await rawRequest(
            addr.port,
            wire + Buffer.from(body).toString("latin1"),
          );
          assert.ok(result.includes("401"));
        },
      ),
      { numRuns: 12 },
    );
  } finally {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
    await key.release();
  }
});

import { peer } from "./support/discovery-peer.ts";
import { X509Certificate } from "node:crypto";
test("captures observed TLS and verifies retained content over the local CA connection", async () => {
  const key = value(
    await Custody.local("hmac-sha256", {
      hmac: crypto.getRandomValues(new Uint8Array(32)),
    }),
  );
  const p = value(
    Policy.create({
      algorithms: ["hmac-sha256"],
      components: '("@method" "content-digest")',
      keyResolver: () => ok({ algorithm: "hmac-sha256", key }),
      freshness: "not_evaluated",
      content: { kind: "content", algorithms: ["sha-256"], section: "headers" },
      replay: "not_required",
    }),
  );
  let outcome!: Promise<void>;
  const tls = await peer((req, res) => {
    outcome = (async () => {
      const c = value(await adapter.captureRequest(req));
      assert.equal(c.ingress.tls, "tls");
      assert.ok(c.ingress.protocol?.startsWith("TLS"));
      assert.equal(c.message.scheme, "https");
      value(await adapter.verifyRequest(req, p, { label: "sig" }));
      res.end("tls verified");
    })();
  });
  try {
    const r = value(
      await adapter.signedRequest(
        {
          url: `https://127.0.0.1:${tls.port}/`,
          method: "POST",
          body: new TextEncoder().encode("hello"),
          ca: new TextEncoder().encode(new X509Certificate(tls.ca).toString()),
        },
        {
          label: "sig",
          components: '("@method" "content-digest")',
          algorithm: "hmac-sha256",
          expiresIn: 60,
          digest: ["sha-256"],
        },
        key,
      ),
    );
    assert.equal(Buffer.from(r.bytes).toString(), "tls verified");
    await outcome;
  } finally {
    await tls.close();
    await key.release();
  }
});
test("reconstructs forwarded origins only for explicit socket peers and retains ingress facts", async () => {
  const server = createServer();
  let expected = "untrusted_proxy";
  let outcome!: Promise<void>;
  server.on("request", (req, res) => {
    outcome = (async () => {
      const c = await adapter.captureRequest(req, {
        trustedProxies: {
          peers: expected === "untrusted_proxy" ? ["192.0.2.1"] : ["127.0.0.1"],
          field: "forwarded",
        },
      });
      if (expected === "untrusted_proxy") {
        assert.equal(c.ok, false);
        if (!c.ok) assert.equal(c.error.reason, "untrusted_proxy");
      } else {
        const capture = value(c);
        assert.equal(capture.ingress.authority, "ingress.test");
        assert.equal(capture.message.authority, "example.test");
        assert.equal(capture.message.scheme, "https");
      }
      res.end();
    })();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  try {
    for (const mode of ["untrusted_proxy", "accepted"]) {
      expected = mode;
      await rawRequest(
        addr.port,
        'GET / HTTP/1.1\r\nHost: ingress.test\r\nForwarded: proto=http;host="first.test", proto=https;host="EXAMPLE.TEST:443"\r\nConnection: close\r\n\r\n',
      );
      await outcome;
    }
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});
test("refuses retained body overflow, ambiguous header truncation, and streamed response signing", async () => {
  const server = createServer();
  server.maxHeadersCount = 2;
  let outcome!: Promise<void>;
  server.on("request", (req, res) => {
    outcome = (async () => {
      const c = await adapter.captureRequest(req);
      assert.equal(c.ok, false);
      if (!c.ok) assert.equal(c.error.reason, "limit");
      res.write("already streamed");
      const signed = await signResponse(
        res,
        {
          label: "sig",
          components: '("@status")',
          algorithm: "ed25519",
          expiresIn: 60,
        },
        null,
        { body: new Uint8Array() },
      );
      assert.equal(signed.ok, false);
      if (!signed.ok) assert.equal(signed.error.reason, "unsupported_delivery");
      res.end();
    })();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  try {
    await rawRequest(
      addr.port,
      "GET / HTTP/1.1\r\nHost: ingress.test\r\nX-One: one\r\nConnection: close\r\n\r\n",
    );
    await outcome;
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test("re-signs each retry and redirect and refuses unapproved cross-origin hops", async () => {
  const key = value(
    await Custody.local("hmac-sha256", {
      hmac: crypto.getRandomValues(new Uint8Array(32)),
    }),
  );
  const components = '("@method" "@authority" "@request-target")';
  const p = value(
    Policy.create({
      algorithms: ["hmac-sha256"],
      components,
      keyResolver: () => ok({ algorithm: "hmac-sha256", key }),
      freshness: "not_evaluated",
      content: "not_required",
      replay: "not_required",
    }),
  );
  const signatures: string[] = [];
  const clock = (() => {
    let now = Math.floor(Date.now() / 1000);
    return () => now++;
  })();
  let outcome!: Promise<void>;
  const second = createServer((req, res) => {
    outcome = (async () => {
      value(await adapter.captureRequest(req));
      value(await adapter.verifyRequest(req, p, { label: "sig" }));
      assert.equal(req.headers.authorization, undefined);
      signatures.push(String(req.headers["signature-input"]));
      res.end("finished");
    })();
  });
  second.listen(0, "127.0.0.1");
  await once(second, "listening");
  const b = second.address();
  assert.ok(b && typeof b === "object");
  const server = createServer((req, res) => {
    outcome = (async () => {
      value(await adapter.captureRequest(req));
      value(await adapter.verifyRequest(req, p, { label: "sig" }));
      signatures.push(String(req.headers["signature-input"]));
      if (signatures.length === 1) {
        res.statusCode = 503;
        res.end();
      } else {
        res.statusCode = 307;
        res.setHeader("location", `http://127.0.0.1:${b.port}/next`);
        res.end();
      }
    })();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const a = server.address();
  assert.ok(a && typeof a === "object");
  try {
    const spec = {
      label: "sig",
      components,
      algorithm: "hmac-sha256",
      expiresIn: 60,
    };
    const result = value(
      await adapter.signedRequest(
        {
          url: `http://127.0.0.1:${a.port}/`,
          headers: [["authorization", "sensitive"]],
          maxRetries: 1,
          maxRedirects: 1,
          allowedOrigins: [`http://127.0.0.1:${b.port}`],
          clock,
        },
        spec,
        key,
      ),
    );
    assert.equal(Buffer.from(result.bytes).toString(), "finished");
    assert.equal(new Set(signatures).size, 3);
    await outcome;
    const refused = await adapter.signedRequest(
      { url: `http://127.0.0.1:${a.port}/`, maxRedirects: 1 },
      spec,
      key,
    );
    assert.equal(refused.ok, false);
    if (!refused.ok) {
      assert.equal(refused.error.reason, "cross_origin_redirect");
    }
  } finally {
    server.closeAllConnections();
    second.closeAllConnections();
    await Promise.all([
      new Promise<void>((r) => server.close(() => r())),
      new Promise<void>((r) => second.close(() => r())),
    ]);
    await key.release();
  }
});
test("rejects capture overflow without retaining a partial body", async () => {
  let outcome!: Promise<void>;
  const server = createServer((req, res) => {
    outcome = (async () => {
      const r = await adapter.captureRequest(req, { maxBytes: 1 });
      assert.equal(r.ok, false);
      if (!r.ok) assert.equal(r.error.reason, "limit");
      res.end();
    })();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  try {
    await rawRequest(
      addr.port,
      "POST / HTTP/1.1\r\nHost: ingress.test\r\nContent-Length: 2\r\nConnection: close\r\n\r\nab",
    );
    await outcome;
  } finally {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  }
});

import { createSecureServer as h2SecureServer } from "node:http2";
test("captures TLS HTTP/2 with observed ALPN through the compatibility API", async () => {
  const tls = await peer((_req, res) => res.end());
  await tls.close();
  const server = h2SecureServer({
    allowHTTP1: true,
    key: Buffer.from(tls.tlsOptions.key),
    cert: Buffer.from(tls.tlsOptions.cert),
  });
  let outcome!: Promise<void>;
  server.on("request", (req, res) => {
    outcome = (async () => {
      const c = value(await adapter.captureRequest(req));
      assert.equal(c.ingress.alpn, "h2");
      assert.equal(c.ingress.tls, "tls");
      assert.equal(c.message.transport.httpVersion, "http2");
      res.end("secure h2");
    })();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  const client = h2Connect(`https://127.0.0.1:${addr.port}`, {
    servername: "localhost",
    ca: new X509Certificate(tls.ca).toString(),
  });
  try {
    const req = client.request({ ":method": "POST", ":path": "/encoded%2F?" });
    req.resume();
    req.end("hello");
    await once(req, "end");
    await outcome;
  } finally {
    client.destroy();
    await new Promise<void>((r) => server.close(() => r()));
    tls.tlsOptions.key.fill(0);
  }
});

test("rejects an invalid TLS trust option before sending signed bytes", async () => {
  const key = value(
    await Custody.local("hmac-sha256", {
      hmac: crypto.getRandomValues(new Uint8Array(32)),
    }),
  );
  const peer = await import("./support/wire-server.ts").then(({ wireServer }) =>
    wireServer(
      "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
  );
  try {
    const result = await adapter.signedRequest(
      { url: `http://127.0.0.1:${peer.port}/`, ca: "ignored" },
      {
        label: "sig",
        components: '("@method")',
        algorithm: "hmac-sha256",
        expiresIn: 60,
      },
      key,
    );
    assert.equal(
      result.ok,
      false,
      "a supplied CA must be validated rather than ignored",
    );
    if (!result.ok) assert.equal(result.error.reason, "invalid_options");
    assert.equal(peer.records.length, 0);
  } finally {
    await peer.close();
    await key.release();
  }
});

test("refuses capture at the configured header count boundary", async () => {
  let outcome: Promise<void> | undefined;
  const server = createServer((req, res) => {
    outcome = (async () => {
      const result = await adapter.captureRequest(req);
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.error.reason, "limit");
      res.end();
    })();
  });
  server.maxHeadersCount = 2;
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  try {
    await rawRequest(
      address.port,
      "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
    );
    await outcome;
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test("refuses Set-Cookie coverage while cookies are pending", async () => {
  const key = value(
    await Custody.local("hmac-sha256", {
      hmac: crypto.getRandomValues(new Uint8Array(32)),
    }),
  );
  let outcome: Promise<void> | undefined;
  const server = createServer((req, res) => {
    outcome = (async () => {
      res.setHeader("Set-Cookie", ["a=1", "b=2"]);
      const result = await adapter.signResponse(
        res,
        {
          label: "sig",
          components: '("@status" "set-cookie")',
          algorithm: "hmac-sha256",
          expiresIn: 60,
        },
        key,
        { body: new Uint8Array(), pendingCookies: true },
      );
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.error.reason, "unsupported_delivery");
      assert.equal(res.headersSent, false);
      res.end();
    })();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  try {
    await rawRequest(
      address.port,
      "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
    );
    await outcome;
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    await key.release();
  }
});

test("validates the capture Context before installing a listener", () => {
  const server = createServer();
  const before = server.listenerCount("request");
  const result = adapter.capture(server, { context: {} });
  assert.equal(result.ok, false, "invalid Context must reject registration");
  if (!result.ok) assert.equal(result.error.reason, "invalid_options");
  assert.equal(server.listenerCount("request"), before);
});

test("signs the method case that the Node client sends on the wire", async () => {
  const key = value(
    await Custody.local("hmac-sha256", {
      hmac: crypto.getRandomValues(new Uint8Array(32)),
    }),
  );
  const { wireServer } = await import("./support/wire-server.ts");
  const peer = await wireServer(
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
  );
  try {
    const response = value(
      await adapter.signedRequest(
        { url: `http://127.0.0.1:${peer.port}/`, method: "MiXeD" },
        {
          label: "sig",
          components: '("@method")',
          algorithm: "hmac-sha256",
          expiresIn: 60,
        },
        key,
      ),
    );
    const sentMethod = peer.records[0]!.toString().split(" ")[0];
    assert.equal(
      response.request.method,
      sentMethod,
      "the signature base method must equal the transmitted method",
    );
    assert.equal(sentMethod, "MIXED");
    const invalid = await adapter.signedRequest(
      { url: `http://127.0.0.1:${peer.port}/`, method: "ß" },
      {
        label: "sig",
        components: '("@method")',
        algorithm: "hmac-sha256",
        expiresIn: 60,
      },
      key,
    );
    assert.equal(
      invalid.ok,
      false,
      "invalid method bytes must not normalize into a valid method",
    );
    if (!invalid.ok) assert.equal(invalid.error.reason, "invalid_request");
  } finally {
    await peer.close();
    await key.release();
  }
});

test("snapshots trusted proxy options once before middleware can change them", async () => {
  const peers = ["127.0.0.1"];
  let reads = 0;
  let outcome: Promise<void> | undefined;
  const server = createServer((req, res) => {
    outcome = (async () => {
      const result = value(await adapter.captureRequest(req));
      assert.equal(result.origin.authority, "external.example");
      assert.equal(result.origin.scheme, "https");
      res.end();
    })();
    void outcome.catch(() => res.end());
  });
  const registration = value(
    adapter.capture(server, {
      trustedProxies: {
        get peers() {
          reads++;
          return peers;
        },
        field: "forwarded",
      },
    }),
  );
  try {
    assert.equal(reads, 1, "registration must read nested proxy options once");
    peers[0] = "198.51.100.1";
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    assert.ok(address && typeof address === "object");
    await rawRequest(
      address.port,
      "GET / HTTP/1.1\r\nHost: internal.example\r\nForwarded: proto=https;host=external.example\r\nConnection: close\r\n\r\n",
    );
    await outcome;
    assert.equal(reads, 1);
  } finally {
    value(registration.close());
    if (server.listening) {
      await new Promise<void>((r) => server.close(() => r()));
    }
  }
});

import { connect as netConnect } from "node:net";
import { withDeadline } from "../src/index.ts";
test("capture(server) refuses a shared Context and bounds each request with its own timeoutMs", { timeout: 15_000 }, async () => {
  // One Context is one absolute deadline; a server registration outlives it, so it is refused.
  const refusedServer = createServer();
  const refused = adapter.capture(refusedServer, { context: value(withDeadline({ timeoutMs: 1000 })) });
  assert.ok(!refused.ok && refused.error.kind === "adapter" && refused.error.reason === "invalid_options");
  assert.equal(refusedServer.listenerCount("request"), 0);
  for (const timeoutMs of [0, 300_001, 1.5, "100"]) {
    const bad = adapter.capture(createServer(), { timeoutMs });
    assert.ok(!bad.ok && bad.error.reason === "invalid_options", String(timeoutMs));
  }

  const outcomes: Promise<string>[] = [];
  const server = createServer((req, res) => {
    const outcome = adapter.captureRequest(req).then((r) => r.ok ? "captured" : `${r.error.kind}/${r.error.reason}`);
    outcomes.push(outcome);
    void outcome.then((o) => res.end(o));
  });
  const registration = value(adapter.capture(server, { timeoutMs: 150 }));
  try {
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const port = (server.address() as { port: number }).port;
    // Well after 150 ms from registration, a fresh request still gets its own full budget.
    await new Promise((r) => setTimeout(r, 300));
    await rawRequest(port, "GET / HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n");
    assert.equal(await outcomes[0], "captured");
    // A request whose body stalls past its own 150 ms budget ends at that deadline.
    const socket = netConnect(port, "127.0.0.1");
    await once(socket, "connect");
    socket.write("POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 10\r\n\r\nabc");
    while (outcomes.length < 2) await new Promise((r) => setTimeout(r, 10));
    assert.equal(await outcomes[1], "custody/deadline_exceeded");
    socket.destroy();
  } finally {
    value(registration.close());
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  }
});
