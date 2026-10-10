import { nodeAdapterTest } from "./support/node-adapter-test.ts";
const test = nodeAdapterTest(import.meta.url);
import assert from "node:assert/strict";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import {
  connect as h2Connect,
  createSecureServer,
  createServer as h2Server,
} from "node:http2";
import { connect, createServer as socketServer } from "node:net";
import { once } from "node:events";
import { createRequire } from "node:module";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as N from "../src/adapters/node-http/index.ts";
import * as api from "../src/index.ts";
import { createSshAgent } from "../src/custody/ssh-agent/index.ts";
import { rawRequest, wireServer } from "./support/wire-server.ts";
import { peer } from "./support/discovery-peer.ts";
import { X509Certificate } from "node:crypto";
import { quorum, signedPool } from "./support/quorum.ts";
function value<T>(r: api.Result<T>): T {
  if (!r.ok) assert.fail(JSON.stringify(r.error));
  return r.value;
}
function refused(r: api.Result<unknown>, reason: string) {
  assert.equal(r.ok, false);
  if (!r.ok) {
    assert.equal(r.error.reason, reason);
    return r.error;
  }
  assert.fail("accepted");
}
const spec = {
  label: "sig",
  algorithm: "hmac-sha256",
  components: '("@method")',
  expiresIn: 60,
};
const text = (s: string) => new TextEncoder().encode(s);
async function key() {
  return value(
    await api.Custody.local("hmac-sha256", {
      hmac: crypto.getRandomValues(new Uint8Array(32)),
    }),
  );
}
async function listen(server: Server) {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const a = server.address();
  assert.ok(a && typeof a === "object");
  return a.port;
}
async function close(server: Server) {
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
}

test("rejects server capture racing an Express body parser", async () => {
  const express = createRequire(
    new URL("../interop/adapters/package.json", import.meta.url),
  )("express");
  const app = express();
  let result: api.Result<N.Capture> | undefined;
  app.use(express.json());
  app.use(async (req: IncomingMessage, res: ServerResponse) => {
    result = await N.captureRequest(req);
    res.end();
  });
  const server = createServer(app);
  const registration = value(N.capture(server));
  const port = await listen(server);
  try {
    await rawRequest(
      port,
      'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 7\r\nConnection: close\r\n\r\n{"a":1}',
    );
    assert.ok(result);
    refused(result, "parser_order");
  } finally {
    value(registration.close());
    await close(server);
  }
});
test("rejects a supplied captured body shorter than Content-Length", async () => {
  let result: api.Result<N.Capture> | undefined;
  const server = createServer((req, res) => {
    result = N.captureBody(req, text("ab"));
    req.resume();
    res.end();
  });
  const port = await listen(server);
  try {
    await rawRequest(
      port,
      "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc",
    );
    assert.ok(result);
    refused(result, "body_unavailable");
  } finally {
    await close(server);
  }
});
for (const secure of [false, true]) {
  test(`derives HTTP/2 scheme from ${secure ? "TLS" : "cleartext"} and rejects conflicting pseudo-headers`, async () => {
    const cert = secure ? await peer((_req, res) => res.end()) : undefined;
    if (cert) await cert.close();
    const server = secure
      ? createSecureServer({
        key: Buffer.from(cert!.tlsOptions.key),
        cert: Buffer.from(cert!.tlsOptions.cert),
      })
      : h2Server();
    let result: api.Result<N.Capture> | undefined;
    server.on("request", (req, res) => {
      void N.captureRequest(req).then((r) => {
        result = r;
        res.end();
      });
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    const session = h2Connect(
      `${secure ? "https" : "http"}://127.0.0.1:${addr.port}`,
      secure
        ? {
          servername: "localhost",
          ca: new X509Certificate(cert!.ca).toString(),
        }
        : {},
    );
    try {
      for (
        const scheme of [
          secure ? "http" : "https",
          "ftp",
          secure ? "https" : "http",
        ]
      ) {
        const req = session.request({ ":scheme": scheme, ":path": "/" });
        req.resume();
        req.end();
        await once(req, "end");
        assert.ok(result);
        if (scheme === (secure ? "https" : "http")) {
          const c = value(result);
          assert.equal(c.ingress.scheme, scheme);
          assert.equal(c.ingress.tls, secure ? "tls" : "plain");
        } else refused(result, "invalid_request");
      }
    } finally {
      session.destroy();
      await new Promise<void>((r) => server.close(() => r()));
      cert?.tlsOptions.key.fill(0);
    }
  });
}
test("rejects HTTP/2 Host conflicting with authority and accepts normalized equality", async () => {
  const server = h2Server();
  let result: api.Result<N.Capture> | undefined;
  server.on("request", (req, res) => {
    void N.captureRequest(req).then((r) => {
      result = r;
      res.end();
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const a = server.address();
  assert.ok(a && typeof a === "object");
  const session = h2Connect(`http://127.0.0.1:${a.port}`);
  try {
    for (const host of ["evil.example", "GOOD.EXAMPLE:80"]) {
      const req = session.request({ ":authority": "good.example", host });
      req.resume();
      req.end();
      await once(req, "end");
      assert.ok(result);
      if (host === "evil.example") refused(result, "invalid_request");
      else value(result);
    }
  } finally {
    session.destroy();
    await new Promise<void>((r) => server.close(() => r()));
  }
});
test("reports the redirect refusal on the second Node attempt", async () => {
  const h = await key();
  let count = 0;
  const server = createServer((_req, res) => {
    if (++count === 1) res.statusCode = 503;
    else {
      res.statusCode = 307;
      res.setHeader("location", "http://127.0.0.1:1/");
    }
    res.end();
  });
  const port = await listen(server);
  try {
    const error = refused(
      await N.signedRequest(
        { url: `http://127.0.0.1:${port}/`, maxRetries: 1, maxRedirects: 1 },
        spec,
        h,
      ),
      "cross_origin_redirect",
    );
    assert.equal(error.kind, "adapter");
    if (error.kind === "adapter") assert.equal(error.attempt, 2);
  } finally {
    await close(server);
    await h.release();
  }
});
test("applies Node redirect method and body rules before re-signing", async () => {
  const h = await key();
  let status = 303;
  let seen: {
    method: string | undefined;
    body: string;
    type: unknown;
    length: unknown;
    fields: IncomingMessage["headers"];
  } | undefined;
  const second = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c);
    seen = {
      method: req.method,
      body: Buffer.concat(chunks).toString(),
      type: req.headers["content-type"],
      length: req.headers["content-length"],
      fields: req.headers,
    };
    res.end();
  });
  const b = await listen(second);
  const first = createServer((req, res) => {
    req.resume();
    res.statusCode = status;
    res.setHeader("location", `http://127.0.0.1:${b}/next`);
    res.end();
  });
  const a = await listen(first);
  try {
    for (
      const [code, method, expected] of [
        [303, "PUT", "GET"],
        [303, "HEAD", "HEAD"],
        [301, "POST", "GET"],
        [302, "POST", "GET"],
        [307, "POST", "POST"],
        [308, "POST", "POST"],
      ] as const
    ) {
      status = code;
      value(
        await N.signedRequest(
          {
            url: `http://127.0.0.1:${a}/`,
            method,
            body: method === "HEAD" ? new Uint8Array() : text("payload"),
            headers: [
              ["content-type", "text/plain"],
              ["content-encoding", "identity"],
              ["content-language", "en"],
              ["content-location", "/old"],
              ["content-digest", "sha-256=:AAAA:"],
            ],
            maxRedirects: 1,
            allowedOrigins: [`http://127.0.0.1:${b}`],
          },
          spec,
          h,
        ),
      );
      assert.ok(seen);
      assert.equal(seen.method, expected);
      assert.equal(seen.body, expected === "POST" ? "payload" : "");
      if (expected === "GET") {
        assert.equal(seen.type, undefined);
        assert.equal(seen.length, undefined);
        for (
          const name of [
            "content-encoding",
            "content-language",
            "content-location",
            "content-digest",
          ]
        ) assert.equal(seen.fields[name], undefined);
      }
    }
  } finally {
    await close(first);
    await close(second);
    await h.release();
  }
});
test("requires an absolute agent path and maps permission errors from a real socket", async (t) => {
  const pub = value(
    await api.PublicKey.import({
      kty: "OKP",
      crv: "Ed25519",
      x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    }),
  );
  refused(
    await createSshAgent("ed25519", "relative.sock", pub),
    "invalid_options",
  );
  const root = await mkdtemp(join(tmpdir(), "rsa-"));
  const path = join(root, "s");
  const server = socketServer((s) => s.destroy());
  server.listen(path);
  await once(server, "listening");
  try {
    if (process.getuid?.() === 0) {
      t.skip("Root bypasses POSIX socket permission checks");
      return;
    }
    await chmod(path, 0);
    const code = await new Promise<string>((r) => {
      const s = connect(path);
      s.once("error", (e: NodeJS.ErrnoException) => r(e.code!));
      s.once("connect", () => {
        s.destroy();
        r("connected");
      });
    });
    assert.equal(code, "EACCES");
    refused(await createSshAgent("ed25519", path, pub), "custodian_failure");
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    await rm(root, { recursive: true, force: true });
  }
});
test("matches trusted CIDRs and mapped peers and parses Forwarded tokens", async () => {
  let peers = ["127.0.0.0/8"];
  let forwarded = "proto=Https; host = external.example";
  let result: api.Result<N.Capture> | undefined;
  const server = createServer((req, res) => {
    void N.captureRequest(req, {
      trustedProxies: { peers, field: "forwarded" },
    }).then((r) => {
      result = r;
      res.end();
    });
  });
  const port = await listen(server);
  try {
    for (
      const network of [
        "127.0.0.0/8",
        "::ffff:127.0.0.1",
        "::ffff:127.0.0.0/104",
        "::/0",
      ]
    ) {
      peers = [network];
      await rawRequest(
        port,
        `GET / HTTP/1.1\r\nHost: internal.example\r\nForwarded: ${forwarded}\r\nConnection: close\r\n\r\n`,
      );
      assert.ok(result);
      assert.equal(value(result).origin.scheme, "https");
    }
    peers = ["127.0.0.0/8"];
    forwarded = "proto=https;host=external.example;for=bad:value";
    await rawRequest(
      port,
      `GET / HTTP/1.1\r\nHost: internal.example\r\nForwarded: ${forwarded}\r\nConnection: close\r\n\r\n`,
    );
    assert.ok(result);
    refused(result, "invalid_request");
  } finally {
    await close(server);
  }
});
test("uses one response clock, omits prohibited lengths, and ends with signed bytes", async () => {
  const h = await key();
  let status = 200;
  let signed: api.Result<api.Message> | undefined;
  let ended = false;
  const server = createServer((_req, res) => {
    void (async () => {
      res.statusCode = status;
      signed = await N.signResponse(
        res,
        { ...spec, components: '("@status" "date")' },
        h,
        {
          clock: () => 1000000000,
          body: status === 200 ? text("signed") : new Uint8Array(),
        },
      );
      ended = res.writableEnded;
      if (!ended) res.end(status === 200 ? "other!" : undefined);
    })();
  });
  const port = await listen(server);
  try {
    for (const code of [200, 204, 304]) {
      status = code;
      const response = await rawRequest(
        port,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
      );
      assert.ok(signed);
      value(signed);
      assert.match(response, /created=1000000000/);
      assert.match(response, /date: Sun, 09 Sep 2001 01:46:40 GMT/i);
      if (code === 200) {
        assert.equal(response.split("\r\n\r\n")[1], "signed");
        assert.equal(ended, true);
      } else assert.doesNotMatch(response, /content-length/i);
    }
  } finally {
    await close(server);
    await h.release();
  }
});
for (const reason of ["signing_failed", "invalid_options"] as const) {
  test(`restores response headers after ${reason} before the caller replies`, async () => {
    const h = await key();
    if (reason === "signing_failed") await h.release();
    const reply = "caller reply";
    let preset = false;
    let outcome: Promise<void> | undefined;
    const server = createServer((_req, res) => {
      outcome = (async () => {
        res.setHeader("x-caller", ["one", "two"]);
        if (preset) {
          res.setHeader("date", "Thu, 01 Jan 1970 00:00:00 GMT");
          res.setHeader("content-length", String(Buffer.byteLength(reply)));
        }
        const before = { ...res.getHeaders() };
        const result = await N.signResponse(
          res,
          { ...spec, components: '("@status")' },
          h,
          {
            body: text("signed"),
            clock: () => 1000000000,
            ...(reason === "invalid_options" ? { request: {} } : {}),
          },
        );
        refused(result, reason);
        assert.equal(res.headersSent, false);
        const after = { ...res.getHeaders() };
        res.end(reply);
        assert.deepEqual(after, before);
      })();
      void outcome.catch(() => {
        if (!res.writableEnded) res.end(reply);
      });
    });
    const port = await listen(server);
    try {
      for (const existing of [false, true]) {
        preset = existing;
        const response = await fetch(`http://127.0.0.1:${port}/`, {
          headers: { connection: "close" },
        });
        const delivered = await response.text();
        await outcome;
        assert.equal(delivered, reply);
        assert.equal(response.headers.has("signature"), false);
        assert.equal(response.headers.has("signature-input"), false);
        if (existing) {
          assert.equal(response.headers.get("content-length"), "12");
          assert.equal(response.headers.get("date"), "Thu, 01 Jan 1970 00:00:00 GMT");
        } else {
          assert.notEqual(response.headers.get("content-length"), "6");
          assert.notEqual(response.headers.get("date"), "Sun, 09 Sep 2001 01:46:40 GMT");
        }
      }
    } finally {
      await close(server);
      await h.release();
    }
  });
}
test("refuses CONNECT capture with invalid_request", async () => {
  let result: api.Result<N.Capture> | undefined;
  const server = createServer();
  server.on("connect", (req, socket) => {
    result = N.captureBody(req, new Uint8Array());
    socket.end("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
  });
  const port = await listen(server);
  try {
    await rawRequest(
      port,
      "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n",
    );
    assert.ok(result);
    refused(result, "invalid_request");
  } finally {
    await close(server);
  }
});
test("validates Node redirect options before sending and strips Location fragments", async () => {
  const h = await key();
  let requests = 0;
  let location = "http://[";
  const server = createServer((req, res) => {
    requests++;
    if (req.url === "/") {
      res.statusCode = 303;
      res.setHeader("location", location);
    }
    res.end();
  });
  const port = await listen(server);
  try {
    for (
      const options of [{ allowedOrigins: ["invalid"] }, {
        credentialHeaders: ["bad header"],
      }, { credentialHeaders: [1] }]
    ) {
      refused(
        await N.signedRequest(
          { url: `http://127.0.0.1:${port}/`, ...options },
          spec,
          h,
        ),
        "invalid_options",
      );
      assert.equal(requests, 0);
    }
    refused(
      await N.signedRequest(
        { url: `http://127.0.0.1:${port}/`, maxRedirects: 1 },
        spec,
        h,
      ),
      "invalid_request",
    );
    location = "/next#discard";
    value(
      await N.signedRequest(
        { url: `http://127.0.0.1:${port}/`, maxRedirects: 1 },
        spec,
        h,
      ),
    );
  } finally {
    await close(server);
    await h.release();
  }
});
test("records complete chunked request frames including trailers", async () => {
  const server = await wireServer(
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
  );
  const socket = connect(server.port, "127.0.0.1");
  socket.on("data", () => {});
  await once(socket, "connect");
  try {
    socket.write(
      "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
    );
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(server.records.length, 0);
    socket.write("3\r\nabc\r\n0\r\nX-End: yes\r\n\r\n");
    await once(socket, "close");
    assert.match(
      server.records[0]!.toString(),
      /abc\r\n0\r\nX-End: yes\r\n\r\n$/,
    );
  } finally {
    socket.destroy();
    await server.close();
  }
});
test("verifies a captured two-signature quorum once and rejects partial replay", async () => {
  const pool = await signedPool(2);
  const q = quorum([{
    id: "first",
    required: true,
    label: "s0",
    policy: pool.policy,
  }, { id: "second", required: true, label: "s1", policy: pool.policy }], {
    mode: "all",
    unit: "keys",
  });
  let partial = false;
  let outcome: Promise<void> | undefined;
  const server = createServer((req, res) => {
    outcome = (async () => {
      const c = value(await N.captureRequest(req));
      const verifyQuorum = (N as unknown as {
        verifyQuorum?: (
          req: unknown,
          q: unknown,
          o: unknown,
        ) => Promise<
          api.Result<{ bytes: Uint8Array; verification: unknown }>
        >;
      }).verifyQuorum;
      assert.equal(typeof verifyQuorum, "function");
      if (partial) {
        const stream = value(c.replay());
        stream.read(1);
        refused(await verifyQuorum!(req, q, {}), "parser_order");
        stream.resume();
        await once(stream, "end");
      }
      const result = value(await verifyQuorum!(req, q, {}));
      assert.deepEqual(result.bytes, text("hello"));
      assert.ok(result.verification);
      refused(
        await N.verifyRequest(req, pool.policy, { label: "s0" }),
        "already_verified",
      );
      refused(await verifyQuorum!(req, q, {}), "already_verified");
      res.end();
    })();
    void outcome.catch(() => res.end());
  });
  const port = await listen(server);
  try {
    const headers = pool.message.fields.map((f) =>
      `${f.name}: ${Buffer.from(f.value).toString()}\r\n`
    ).join("");
    for (const flag of [false, true]) {
      partial = flag;
      await rawRequest(
        port,
        `POST /a HTTP/1.1\r\nHost: localhost\r\n${headers}Content-Length: 5\r\nConnection: close\r\n\r\nhello`,
      );
      await outcome;
    }
  } finally {
    await close(server);
    await pool.release();
  }
});

test("refuses incomplete Content-Length on the real request stream", async () => {
  let outcome: Promise<api.Result<N.Capture>> | undefined;
  const server = createServer((req) => {
    outcome = N.captureRequest(req);
  });
  const port = await listen(server);
  const socket = connect(port, "127.0.0.1");
  socket.on("data", () => {});
  await once(socket, "connect");
  try {
    socket.end(
      "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nab",
    );
    await once(socket, "close");
    assert.ok(outcome);
    refused(await outcome, "body_unavailable");
  } finally {
    socket.destroy();
    await close(server);
  }
});

test("refuses default-port absolute targets and HTTP/2 without authority as documented", async () => {
  let result: api.Result<N.Capture> | undefined;
  const server = createServer((req, res) => {
    void N.captureRequest(req).then((r) => {
      result = r;
      res.end();
    });
  });
  const port = await listen(server);
  try {
    await rawRequest(
      port,
      "GET http://127.0.0.1:80/p HTTP/1.1\r\nHost: 127.0.0.1:80\r\nConnection: close\r\n\r\n",
    );
    assert.ok(result);
    refused(result, "invalid_request");
  } finally {
    await close(server);
  }
  const h2 = h2Server();
  h2.on("request", (req, res) => {
    void N.captureRequest(req).then((r) => {
      result = r;
      res.end();
    });
  });
  h2.listen(0, "127.0.0.1");
  await once(h2, "listening");
  const a = h2.address();
  assert.ok(a && typeof a === "object");
  const session = h2Connect(`http://127.0.0.1:${a.port}`);
  try {
    result = undefined;
    const req = session.request({ host: "localhost" });
    req.resume();
    req.end();
    await once(req, "end");
    assert.ok(result);
    refused(result, "invalid_request");
  } finally {
    session.destroy();
    await new Promise<void>((r) => h2.close(() => r()));
  }
});

for (const framing of ["chunked", "length"] as const) {
  test(`refuses concurrent body consumers with ${framing} framing even when all bytes match`, async () => {
    let outcome: Promise<api.Result<N.Capture>> | undefined;
    let consumed = "";
    const server = createServer((req, res) => {
      req.on("data", (part) => {
        consumed += part.toString();
      });
      outcome = N.captureRequest(req);
      void outcome.then(() => res.end());
    });
    const registration = value(N.capture(server));
    const port = await listen(server);
    try {
      await rawRequest(
        port,
        `POST / HTTP/1.1\r\nHost: localhost\r\n${
          framing === "chunked"
            ? "Transfer-Encoding: chunked"
            : "Content-Length: 7"
        }\r\nConnection: close\r\n\r\n${
          framing === "chunked" ? '7\r\n{"a":1}\r\n0\r\n\r\n' : '{"a":1}'
        }`,
      );
      assert.ok(outcome);
      refused(await outcome, "parser_order");
      assert.equal(consumed, '{"a":1}');
    } finally {
      value(registration.close());
      await close(server);
    }
  });
}
test("refuses a data consumer attached after the first captured chunk", async () => {
  let first!: () => void;
  const firstChunk = new Promise<void>((r) => {
    first = r;
  });
  let outcome: Promise<api.Result<N.Capture>> | undefined;
  let consumed = "";
  const server = createServer((req, res) => {
    // Observe native reads; no bytes or stream behavior are substituted.
    const nativeRead = req.read;
    req.read = function (size?: number) {
      const part = nativeRead.call(this, size);
      if (part && !consumed) {
        queueMicrotask(() => {
          req.on("data", (c) => {
            consumed += c.toString();
          });
          first();
        });
        req.read = nativeRead;
      }
      return part;
    };
    outcome = N.captureRequest(req);
    void outcome.then(() => res.end());
  });
  const port = await listen(server);
  const socket = connect(port, "127.0.0.1");
  socket.on("data", () => {});
  await once(socket, "connect");
  try {
    socket.write(
      "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nab\r\n",
    );
    await firstChunk;
    socket.write("2\r\ncd\r\n0\r\n\r\n");
    await once(socket, "close").catch((e) => {
      assert.equal(e.code, "ECONNRESET");
    });
    assert.ok(outcome);
    refused(await outcome, "parser_order");
    assert.ok(consumed === "" || consumed === "cd");
  } finally {
    socket.destroy();
    await close(server);
  }
});

test("matches IPv4 networks against actual dual-stack mapped peers", async (t) => {
  let peers = ["127.0.0.0/8"];
  let result: api.Result<N.Capture> | undefined;
  const server = createServer((req, res) => {
    void N.captureRequest(req, {
      trustedProxies: { peers, field: "forwarded" },
    }).then((r) => {
      result = r;
      res.end();
    });
  });
  try {
    server.listen(0, "::");
    await once(server, "listening");
  } catch (e) {
    if (
      ["EAFNOSUPPORT", "EADDRNOTAVAIL"].includes(
        (e as NodeJS.ErrnoException).code ?? "",
      )
    ) {
      t.skip("IPv6 dual-stack listener is unavailable");
      return;
    }
    throw e;
  }
  const a = server.address();
  assert.ok(a && typeof a === "object");
  try {
    for (const network of ["127.0.0.0/8", "10.0.0.0/8"]) {
      peers = [network];
      await rawRequest(
        a.port,
        "GET / HTTP/1.1\r\nHost: internal.example\r\nForwarded: proto=https;host=external.example\r\nConnection: close\r\n\r\n",
      );
      assert.ok(result);
      if (network.startsWith("127")) {
        const c = value(result);
        assert.match(c.ingress.remoteAddress!, /^::ffff:/);
        assert.equal(c.origin.scheme, "https");
      } else refused(result, "untrusted_proxy");
    }
  } finally {
    await close(server);
  }
});
for (const field of ["forwarded", "x-forwarded"] as const) {
  test(`rejects ambiguous ${field} origin declarations`, async () => {
    let result: api.Result<N.Capture> | undefined;
    const server = createServer((req, res) => {
      void N.captureRequest(req, {
        trustedProxies: { peers: ["127.0.0.0/8"], field },
      }).then((r) => {
        result = r;
        res.end();
      });
    });
    const port = await listen(server);
    try {
      await rawRequest(
        port,
        `GET / HTTP/1.1\r\nHost: internal.example\r\n${
          field === "forwarded"
            ? "Forwarded: proto=https;host=a.example;host=b.example"
            : "X-Forwarded-Proto: https,http\r\nX-Forwarded-Host: a.example"
        }\r\nConnection: close\r\n\r\n`,
      );
      assert.ok(result);
      refused(result, "invalid_request");
    } finally {
      await close(server);
    }
  });
}

test("matches broad IPv6 networks and IPv4 peers in both address directions", async (t) => {
  let peers = ["::/96"];
  let result: api.Result<N.Capture> | undefined;
  const server = createServer((req, res) => {
    void N.captureRequest(req, {
      trustedProxies: { peers, field: "forwarded" },
    }).then((r) => {
      result = r;
      res.end();
    });
  });
  const port = await listen(server);
  try {
    for (
      const [network, trusted] of [
        ["::/96", false],
        ["::/0", true],
        ["::ffff:0:0/96", true],
        ["2001:db8::/32", false],
        ["::ffff:10.0.0.0/104", false],
      ] as const
    ) {
      peers = [network];
      await rawRequest(
        port,
        "GET / HTTP/1.1\r\nHost: internal.example\r\nForwarded: proto=https;host=external.example\r\nConnection: close\r\n\r\n",
      );
      assert.ok(result);
      if (trusted) {
        assert.equal(value(result).ingress.remoteAddress, "127.0.0.1");
      } else refused(result, "untrusted_proxy");
    }
  } finally {
    await close(server);
  }
  const ipv6 = createServer((req, res) => {
    void N.captureRequest(req, {
      trustedProxies: { peers: ["0.0.0.0/0"], field: "forwarded" },
    }).then((r) => {
      result = r;
      res.end();
    });
  });
  try {
    ipv6.listen(0, "::1");
    await once(ipv6, "listening");
  } catch (e) {
    if (
      ["EAFNOSUPPORT", "EADDRNOTAVAIL"].includes(
        (e as NodeJS.ErrnoException).code ?? "",
      )
    ) {
      t.skip("IPv6 loopback is unavailable");
      return;
    }
    throw e;
  }
  const a = ipv6.address();
  assert.ok(a && typeof a === "object");
  const socket = connect(a.port, "::1");
  socket.on("data", () => {});
  await once(socket, "connect");
  try {
    socket.write(
      "GET / HTTP/1.1\r\nHost: internal.example\r\nForwarded: proto=https;host=external.example\r\nConnection: close\r\n\r\n",
    );
    await once(socket, "close");
    assert.ok(result);
    refused(result, "untrusted_proxy");
  } finally {
    socket.destroy();
    await close(ipv6);
  }
});

test("rejects a malformed earlier Forwarded element before using the final origin", async () => {
  let result: api.Result<N.Capture> | undefined;
  const server = createServer((req, res) => {
    void N.captureRequest(req, {
      trustedProxies: { peers: ["127.0.0.0/8"], field: "forwarded" },
    }).then((r) => {
      result = r;
      res.end();
    });
  });
  const port = await listen(server);
  try {
    for (
      const earlier of [
        "broken",
        "host=a.example;host=b.example",
        "for=bad:value",
      ]
    ) {
      await rawRequest(
        port,
        `GET / HTTP/1.1\r\nHost: internal.example\r\nForwarded: ${earlier},proto=https;host=external.example\r\nConnection: close\r\n\r\n`,
      );
      assert.ok(result);
      refused(result, "invalid_request");
    }
  } finally {
    await close(server);
  }
});

test("records verification rejection when a resolver throws", async () => {
  const h = await key();
  const policy = value(api.Policy.create({
    algorithms: ["hmac-sha256"],
    components: '("@method")',
    keyResolver() {
      throw new Error("private callback diagnostic");
    },
    freshness: "not_evaluated",
    content: "not_required",
    replay: "not_required",
  }));
  let outcome: Promise<void> | undefined;
  const server = createServer((req, res) => {
    outcome = (async () => {
      value(await N.captureRequest(req));
      const e = refused(
        await N.verifyRequest(req, policy, { label: "sig" }),
        "request_rejected",
      );
      assert.deepEqual(refused(N.verification(req), "request_rejected"), e);
      assert.doesNotMatch(JSON.stringify(e), /private callback diagnostic/);
      refused(
        await N.verifyRequest(req, policy, { label: "sig" }),
        "already_verified",
      );
    })();
    void outcome.finally(() => res.end()).catch(() => {});
  });
  const port = await listen(server);
  try {
    value(await N.signedRequest({ url: `http://127.0.0.1:${port}/` }, spec, h));
    await outcome;
  } finally {
    await close(server);
    await h.release();
  }
});

test("refuses signing informational responses without sending headers", async () => {
  const h = await key();
  let result: api.Result<api.Message> | undefined;
  const server = createServer((_req, res) => {
    res.statusCode = 103;
    void N.signResponse(res, { ...spec, components: '("@status")' }, h, {
      body: new Uint8Array(),
    }).then((r) => {
      result = r;
      if (!res.headersSent) {
        res.statusCode = 200;
        res.end();
      }
    });
  });
  const port = await listen(server);
  try {
    await rawRequest(
      port,
      "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert.ok(result);
    refused(result, "unsupported_delivery");
  } finally {
    await close(server);
    await h.release();
  }
});

test("refuses nonempty GET and HEAD client bodies before delivery", async () => {
  const h = await key();
  let delivered = 0;
  const server = createServer((req, res) => {
    delivered++;
    req.resume();
    res.end();
  });
  const port = await listen(server);
  try {
    for (const method of ["GET", "HEAD"]) {
      refused(
        await N.signedRequest(
          { url: `http://127.0.0.1:${port}/`, method, body: text("body") },
          spec,
          h,
        ),
        "invalid_options",
      );
    }
    assert.equal(delivered, 0);
  } finally {
    await close(server);
    await h.release();
  }
});

test("refuses response coverage of hop-by-hop fields", async () => {
  const h = await key();
  let name = "connection";
  let result: api.Result<api.Message> | undefined;
  let sent = false;
  const server = createServer((_req, res) => {
    res.setHeader(name, name === "content-length" ? "0" : "value");
    void N.signResponse(
      res,
      { ...spec, components: `("@status" "${name}")` },
      h,
      { body: new Uint8Array() },
    ).then((r) => {
      result = r;
      sent = res.headersSent;
      if (!res.writableEnded) {
        res.removeHeader(name);
        res.end();
      }
    });
  });
  const port = await listen(server);
  try {
    for (
      const field of [
        "connection",
        "transfer-encoding",
        "trailer",
        "keep-alive",
        "proxy-connection",
        "te",
        "upgrade",
      ]
    ) {
      name = field;
      await rawRequest(
        port,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
      );
      assert.ok(result);
      refused(result, "unsupported_component");
      assert.equal(sent, false);
    }
  } finally {
    await close(server);
    await h.release();
  }
});

test("validates quorum option values before reserving verification state", async () => {
  const pool = await signedPool(2);
  const q = quorum([{
    id: "one",
    required: true,
    label: "s0",
    policy: pool.policy,
  }], { mode: "all", unit: "keys" });
  let outcome: Promise<void> | undefined;
  const server = createServer((req, res) => {
    outcome = (async () => {
      value(await N.captureRequest(req));
      for (
        const options of [
          { context: null },
          { context: {} },
          { acceptSignature: null },
          { acceptSignature: [] },
          { unknown: true },
        ]
      ) {
        refused(await N.verifyQuorum(req, q, options), "invalid_options");
      }
      let reads = 0;
      refused(
        await N.verifyQuorum(req, q, {
          get context() {
            reads++;
            return null;
          },
        }),
        "invalid_options",
      );
      assert.equal(reads, 1);
      // Invalid options must not consume the shared verification attempt.
      value(await N.verifyRequest(req, pool.policy, { label: "s0" }));
    })();
    void outcome.finally(() => res.end()).catch(() => {});
  });
  const port = await listen(server);
  try {
    const fields = pool.message.fields.map((f) =>
      `${f.name}: ${Buffer.from(f.value).toString()}\r\n`
    ).join("");
    await rawRequest(
      port,
      `POST /a HTTP/1.1\r\nHost: localhost\r\n${fields}Content-Length: 5\r\nConnection: close\r\n\r\nhello`,
    );
    await outcome;
  } finally {
    await close(server);
    await pool.release();
  }
});

test("signs Node redirect and retry attempts with three distinct nonces", async () => {
  const h = await key();
  const nonces: string[] = [];
  const server = createServer((req, res) => {
    nonces.push(
      /;nonce="([^"]+)"/.exec(String(req.headers["signature-input"]))![1]!,
    );
    req.resume();
    if (nonces.length === 1) {
      res.statusCode = 307;
      res.setHeader("location", "/next");
    } else if (nonces.length === 2) res.statusCode = 503;
    res.end();
  });
  const port = await listen(server);
  try {
    value(
      await N.signedRequest(
        {
          url: `http://127.0.0.1:${port}/`,
          method: "POST",
          body: text("payload"),
          maxRedirects: 1,
          maxRetries: 1,
          nonce: new Uint8Array(32).fill(1),
        },
        spec,
        h,
      ),
    );
    assert.equal(nonces.length, 3);
    assert.equal(nonces[0], api.encodeBase64Url(new Uint8Array(32).fill(1)));
    assert.equal(new Set(nonces).size, 3);
  } finally {
    await close(server);
    await h.release();
  }
});

test("accepts a trusted HTTP/2 scheme declaration separately from observed transport", async () => {
  const server = h2Server();
  let trusted = true;
  let result: api.Result<N.Capture> | undefined;
  server.on("request", (req, res) => {
    void N.captureRequest(
      req,
      trusted
        ? { trustedProxies: { peers: ["127.0.0.0/8"], field: "forwarded" } }
        : {},
    ).then((r) => {
      result = r;
      res.end();
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const a = server.address();
  assert.ok(a && typeof a === "object");
  const session = h2Connect(`http://127.0.0.1:${a.port}`);
  try {
    for (
      const [isTrusted, scheme] of [[true, "https"], [true, "http"], [
        true,
        "ftp",
      ], [false, "https"]] as const
    ) {
      trusted = isTrusted;
      const req = session.request({
        ":scheme": scheme,
        ":authority": "internal.example",
        forwarded: "proto=https;host=external.example",
      });
      req.resume();
      req.end();
      await once(req, "end");
      assert.ok(result);
      if (scheme === "ftp" || !isTrusted) refused(result, "invalid_request");
      else {
        const c = value(result);
        assert.equal(c.ingress.scheme, "http");
        assert.equal(c.ingress.tls, "plain");
        assert.equal(c.ingress.declaredScheme, scheme);
        assert.equal(c.origin.scheme, "https");
        assert.equal(c.origin.source, "forwarded");
      }
    }
  } finally {
    session.destroy();
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test("signs final response length and date while permitting request-side hop fields", async () => {
  const h = await key();
  const body = text("response");
  const components = '("@status" "content-length" "date" "connection";req)';
  const policy = value(
    api.Policy.create({
      algorithms: ["hmac-sha256"],
      components,
      keyResolver: () => api.ok({ algorithm: "hmac-sha256", key: h }),
      freshness: "not_evaluated",
      content: "not_required",
      replay: "not_required",
    }),
  );
  let outcome: Promise<void> | undefined;
  const server = createServer((req, res) => {
    outcome = (async () => {
      const capture = value(await N.captureRequest(req));
      res.setHeader("content-length", "999");
      const signed = value(
        await N.signResponse(res, { ...spec, components }, h, {
          body,
          request: capture,
        }),
      );
      assert.equal(
        Buffer.from(
          signed.fields.find((f) => f.name === "content-length")!.value,
        ).toString(),
        "8",
      );
    })();
    void outcome.catch(() => res.end());
  });
  const port = await listen(server);
  try {
    const response = value(
      await N.signedRequest(
        {
          url: `http://127.0.0.1:${port}/`,
          headers: [["connection", "close"]],
        },
        spec,
        h,
      ),
    );
    await outcome;
    assert.deepEqual(
      value(
        await N.verifyResponse(response, response.request, policy, {
          label: "sig",
        }),
      ).bytes,
      body,
    );
  } finally {
    await close(server);
    await h.release();
  }
});

test("refuses a caller Host before Node client signing and delivery", async () => {
  const h = await key();
  let requests = 0;
  const server = createServer((req, res) => {
    requests++;
    req.resume();
    res.end();
  });
  const port = await listen(server);
  try {
    refused(
      await N.signedRequest(
        {
          url: `http://127.0.0.1:${port}/`,
          headers: [["Host", "other.example"]],
        },
        spec,
        h,
      ),
      "invalid_options",
    );
    assert.equal(requests, 0);
    value(await N.signedRequest({ url: `http://127.0.0.1:${port}/` }, spec, h));
    assert.equal(requests, 1);
  } finally {
    await close(server);
    await h.release();
  }
});

for (const field of ["forwarded", "x-forwarded"] as const) {
  test(`requires ${field} origin fields when trusted proxies are configured`, async () => {
    let result: api.Result<N.Capture> | undefined;
    const server = createServer((req, res) => {
      void N.captureRequest(req, {
        trustedProxies: { peers: ["127.0.0.0/8"], field },
      }).then((r) => {
        result = r;
        res.end();
      });
    });
    const port = await listen(server);
    try {
      await rawRequest(
        port,
        "GET / HTTP/1.1\r\nHost: internal.example\r\nConnection: close\r\n\r\n",
      );
      assert.ok(result);
      refused(result, "invalid_request");
      const forwarding = field === "forwarded"
        ? "Forwarded: proto=https;host=external.example"
        : "X-Forwarded-Proto: https\r\nX-Forwarded-Host: external.example";
      await rawRequest(
        port,
        `GET / HTTP/1.1\r\nHost: internal.example\r\n${forwarding}\r\nConnection: close\r\n\r\n`,
      );
      assert.ok(result);
      assert.equal(value(result).origin.source, "forwarded");
    } finally {
      await close(server);
    }
  });
}

test("Forwarded extension names accept underscore tokens and reject separators", async () => {
  let result: api.Result<N.Capture> | undefined;
  const server = createServer((req, res) => {
    void N.captureRequest(req, {
      trustedProxies: { peers: ["127.0.0.0/8"], field: "forwarded" },
    }).then((r) => {
      result = r;
      res.end();
    });
  });
  const port = await listen(server);
  try {
    for (const name of ["_", "x_ext", "bad/name", "bad(name)", "bad name"]) {
      await rawRequest(
        port,
        `GET / HTTP/1.1\r\nHost: internal.example\r\nForwarded: proto=https;host=external.example;${name}=value\r\nConnection: close\r\n\r\n`,
      );
      assert.ok(result);
      if (name === "_" || name === "x_ext") {
        assert.equal(value(result).origin.source, "forwarded");
      } else refused(result, "invalid_request");
    }
  } finally {
    await close(server);
  }
});

test("stores core invalid-option rejection after reserving single verification", async () => {
  const h = await key();
  const policy = value(
    api.Policy.create({
      algorithms: ["hmac-sha256"],
      components: '("@method")',
      keyResolver: () => api.ok({ algorithm: "hmac-sha256", key: h }),
      freshness: "not_evaluated",
      content: "not_required",
      replay: "not_required",
    }),
  );
  let outcome: Promise<void> | undefined;
  const server = createServer((req, res) => {
    outcome = (async () => {
      value(await N.captureRequest(req));
      for (
        const options of [{ label: "sig", context: null }, {
          label: "sig",
          unknown: true,
        }]
      ) {
        refused(await N.verifyRequest(req, policy, options), "invalid_options");
      }
      const e = refused(
        await N.verifyRequest(req, policy, { label: null }),
        "request_rejected",
      );
      if (e.kind === "adapter") {
        assert.equal(e.source?.reason, "invalid_options");
      }
      assert.deepEqual(refused(N.verification(req), "request_rejected"), e);
      refused(
        await N.verifyRequest(req, policy, { label: "sig" }),
        "already_verified",
      );
    })();
    void outcome.finally(() => res.end()).catch(() => {});
  });
  const port = await listen(server);
  try {
    value(await N.signedRequest({ url: `http://127.0.0.1:${port}/` }, spec, h));
    await outcome;
  } finally {
    await close(server);
    await h.release();
  }
});

test("stores a quorum resolver rejection without throwing out of core verification", async () => {
  const pool = await signedPool(1);
  const policy = value(
    api.Policy.create({
      algorithms: ["hmac-sha256"],
      components: '("@method")',
      keyResolver() {
        throw new Error("private quorum diagnostic");
      },
      freshness: "not_evaluated",
      content: "not_required",
      replay: "not_required",
    }),
  );
  const q = quorum([{ id: "one", required: true, label: "s0", policy }], {
    mode: "all",
    unit: "keys",
  });
  let outcome: Promise<void> | undefined;
  const server = createServer((req, res) => {
    outcome = (async () => {
      value(await N.captureRequest(req));
      const e = refused(await N.verifyQuorum(req, q), "request_rejected");
      assert.deepEqual(refused(N.verification(req), "request_rejected"), e);
      assert.doesNotMatch(JSON.stringify(e), /private quorum diagnostic/);
      refused(await N.verifyQuorum(req, q), "already_verified");
    })();
    void outcome.finally(() => res.end()).catch(() => {});
  });
  const port = await listen(server);
  try {
    const fields = pool.message.fields.map((f) =>
      `${f.name}: ${Buffer.from(f.value).toString()}\r\n`
    ).join("");
    await rawRequest(
      port,
      `POST /a HTTP/1.1\r\nHost: localhost\r\n${fields}Content-Length: 5\r\nConnection: close\r\n\r\nhello`,
    );
    await outcome;
  } finally {
    await close(server);
    await pool.release();
  }
});

test("counts HTTP/2 cookie separators in the aggregate field byte bound", async () => {
  const max = 1_048_576;
  const server = h2Server({
    maxSessionMemory: 128,
    maxHeaderListPairs: 128,
    settings: { maxHeaderListSize: max * 2, headerTableSize: max * 2 },
  });
  let result: api.Result<N.Capture> | undefined;
  server.on("request", (req, res) => {
    void N.captureRequest(req).then((r) => {
      result = r;
      res.end();
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const serverReady = new Promise<void>((resolve) =>
    server.once(
      "session",
      (session) => session.once("localSettings", () => resolve()),
    )
  );
  const session = h2Connect(`http://127.0.0.1:${address.port}`, {
    maxSendHeaderBlockLength: max * 2,
    maxDeflateDynamicTableSize: max * 2,
  });
  await serverReady;
  try {
    for (const remaining of [2, 1]) {
      const fields: Record<string, string | string[]> = {
        cookie: ["a=1", "b=2"],
      };
      let size = 2 * ("cookie".length + 3);
      const padding: string[] = [];
      for (let i = 0; i < 32; i++) {
        const length = Math.min(32768, max - remaining - size - "x-pad".length);
        padding.push("x".repeat(length));
        size += "x-pad".length + length;
      }
      fields["x-pad"] = padding;
      assert.equal(size, max - remaining);
      const stream = session.request({ ":path": "/", ...fields });
      stream.resume();
      stream.end();
      await once(stream, "end");
      assert.ok(result, "the real HTTP/2 request reached capture");
      if (remaining === 2) {
        assert.equal(
          Buffer.from(
            value(result).message.fields.find((f) => f.name === "cookie")!
              .value,
          ).toString(),
          "a=1; b=2",
        );
      } else refused(result, "limit");
    }
  } finally {
    session.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
