import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { once } from "node:events";
import * as F from "../src/adapters/fetch/index.ts";
import * as api from "../src/index.ts";
import { canVerify, runtime } from "../src/adapters/fetch/runtime.ts";
import { rawRequest, wireServer } from "./support/wire-server.ts";
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
  components: '("@method")',
  algorithm: "hmac-sha256",
  expiresIn: 60,
};
async function key() {
  return value(
    await api.Custody.local("hmac-sha256", {
      hmac: crypto.getRandomValues(new Uint8Array(32)),
    }),
  );
}
async function listen(s: ReturnType<typeof createServer>) {
  s.listen(0, "127.0.0.1");
  await once(s, "listening");
  const a = s.address();
  assert.ok(a && typeof a === "object");
  return a.port;
}
async function close(s: ReturnType<typeof createServer>) {
  s.closeAllConnections();
  await new Promise<void>((r) => s.close(() => r()));
}
test("refuses runtime-overridden sec-fetch-mode only on Node", async () => {
  const h = await key();
  const p = await wireServer(
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
  );
  try {
    const r = await F.signRequest(
      new Request(`http://127.0.0.1:${p.port}/`, {
        headers: { "sec-fetch-mode": "navigate" },
      }),
      { ...spec, components: '("@method" "sec-fetch-mode")' },
      h,
    );
    if (runtime.startsWith("node:")) refused(r, "unsupported_component");
    else {
      await fetch(value(r).request);
      assert.match(p.records[0]!.toString(), /sec-fetch-mode: navigate/i);
    }
  } finally {
    await p.close();
    await h.release();
  }
});
test("reports the redirect refusal on the second Fetch attempt", async () => {
  const h = await key();
  let count = 0;
  const s = createServer((_req, res) => {
    if (++count === 1) res.statusCode = 503;
    else {
      res.statusCode = 307;
      res.setHeader("location", "http://127.0.0.1:1/");
    }
    res.end();
  });
  const port = await listen(s);
  try {
    const e = refused(
      await F.signedFetch(
        `http://127.0.0.1:${port}/`,
        {},
        { spec, signer: h },
        { maxRetries: 1, maxRedirects: 1 },
      ),
      "cross_origin_redirect",
    );
    assert.equal(e.kind, "adapter");
    if (e.kind === "adapter") assert.equal(e.attempt, 2);
  } finally {
    await close(s);
    await h.release();
  }
});
test("applies Fetch redirect method and body rules before re-signing", async (t) => {
  const h = await key();
  let status = 303;
  let seen:
    | { method: unknown; body: string; type: unknown; length: unknown }
    | undefined;
  const b = await wireServer(
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
  );
  const bp = b.port;
  const a = createServer((req, res) => {
    req.resume();
    res.statusCode = status;
    res.setHeader("location", `http://127.0.0.1:${bp}/next`);
    res.end();
  });
  const ap = await listen(a);
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
      t.diagnostic(`redirect ${code} ${method}`);
      value(
        await F.signedFetch(
          `http://127.0.0.1:${ap}/`,
          {
            method,
            headers: {
              "content-type": "text/plain",
              "content-encoding": "identity",
              "content-language": "en",
              "content-location": "/old",
              "content-digest": "sha-256=:AAAA:",
            },
            ...(method === "HEAD" ? {} : { body: "payload" }),
          },
          { spec, signer: h },
          { maxRedirects: 1, allowedOrigins: [`http://127.0.0.1:${bp}`] },
        ),
      );
      const wire = b.records.at(-1)!.toString();
      const [head, body] = wire.split("\r\n\r\n");
      const field = (name: string) =>
        head!.split("\r\n").find((line) =>
          line.toLowerCase().startsWith(name + ":")
        )?.split(":").slice(1).join(":").trim();
      seen = {
        method: head!.split(" ")[0],
        body: body!,
        type: field("content-type"),
        length: field("content-length"),
      };
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
        ) assert.equal(field(name), undefined);
      }
    }
  } finally {
    await close(a);
    await b.close();
    await h.release();
  }
});
test("a planted Deno marker does not enable Node Fetch verification", () => {
  if (!runtime.startsWith("node:")) return;
  const path =
    new URL("../src/adapters/fetch/runtime.ts", import.meta.url).href;
  const source =
    `globalThis.Deno={version:{deno:'2.5.6'}};const m=await import(${
      JSON.stringify(path)
    });if(m.canVerify)throw Error('Node marker enabled verification');console.log(m.runtime)`;
  const child = spawnSync(process.execPath, [
    "--experimental-strip-types",
    "--no-warnings",
    "--input-type=module",
    "-e",
    source,
  ], { encoding: "utf8" });
  assert.equal(child.status, 0, child.stderr);
  assert.match(child.stdout, /node:/);
});
test("validates Fetch redirect options before sending and strips Location fragments", async () => {
  const h = await key();
  let requests = 0;
  let location = "http://[";
  const s = createServer((req, res) => {
    requests++;
    if (req.url === "/") {
      res.statusCode = 303;
      res.setHeader("location", location);
    }
    res.end();
  });
  const port = await listen(s);
  try {
    for (
      const opts of [{ allowedOrigins: ["invalid"] }, {
        credentialHeaders: ["bad header"],
      }, { credentialHeaders: [1] }]
    ) {
      refused(
        await F.signedFetch(`http://127.0.0.1:${port}/`, {}, {
          spec,
          signer: h,
        }, opts),
        "invalid_options",
      );
      assert.equal(requests, 0);
    }
    refused(
      await F.signedFetch(
        `http://127.0.0.1:${port}/`,
        {},
        { spec, signer: h },
        { maxRedirects: 1 },
      ),
      "invalid_request",
    );
    location = "/next#discard";
    value(
      await F.signedFetch(
        `http://127.0.0.1:${port}/`,
        {},
        { spec, signer: h },
        { maxRedirects: 1 },
      ),
    );
  } finally {
    await close(s);
    await h.release();
  }
});
test(
  "rejects inapplicable Fetch response representation and missing labels at the adapter",
  { skip: !canVerify },
  async () => {
    const h = await key();
    const p = value(api.Policy.create({
      algorithms: ["hmac-sha256"],
      components: '("@status")',
      keyResolver: () => api.ok({ algorithm: "hmac-sha256", key: h }),
      freshness: "not_evaluated",
      content: "not_required",
      replay: "not_required",
    }));
    try {
      const r = value(
        await F.signResponse(new Response("body"), {
          ...spec,
          components: '("@status")',
        }, h),
      );
      for (
        const options of [{ label: "sig", representation: new Uint8Array() }, {
          label: undefined,
        }]
      ) {
        const e = refused(
          await F.verifyResponse(r.response.clone(), p, options),
          "invalid_options",
        );
        assert.equal(e.kind, "adapter");
      }
      const req = new Request("http://localhost/");
      const e = refused(
        await F.verifyRequest(req, p, {
          scheme: "http",
          authority: "localhost",
        }),
        "invalid_options",
      );
      assert.equal(e.kind, "adapter");
    } finally {
      await h.release();
    }
  },
);
test("observes string-body Content-Type before signing", async () => {
  const h = await key();
  try {
    const request = new Request("http://127.0.0.1/", {
      method: "POST",
      body: "payload",
    });
    if (runtime.startsWith("bun:")) {
      assert.equal(request.headers.get("content-type"), null);
      refused(
        await F.signRequest(request, {
          ...spec,
          components: '("@method" "content-type")',
        }, h),
        "signing_failed",
      );
    } else {
      assert.equal(
        request.headers.get("content-type"),
        "text/plain;charset=UTF-8",
      );
      value(
        await F.signRequest(request, {
          ...spec,
          components: '("@method" "content-type")',
        }, h),
      );
    }
    const explicit = new Request("http://127.0.0.1/", {
      method: "POST",
      body: "payload",
      headers: { "content-type": "text/plain" },
    });
    value(
      await F.signRequest(explicit, {
        ...spec,
        components: '("@method" "content-type")',
      }, h),
    );
  } finally {
    await h.release();
  }
});

test("retains Fetch request settings across a method-changing redirect", async () => {
  const h = await key();
  const server = createServer((req, res) => {
    req.resume();
    if (req.url === "/start") {
      res.statusCode = 303;
      res.setHeader("location", "/finish");
    }
    res.end();
  });
  const port = await listen(server);
  try {
    // Compare with actual Request properties: runtimes expose different settings.
    const initial = new Request(`http://127.0.0.1:${port}/start`, {
      method: "POST",
      body: "payload",
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });
    const result = value(
      await F.signedFetch(initial, {}, { spec, signer: h }, {
        maxRedirects: 1,
      }),
    );
    assert.equal(result.request.request.credentials, initial.credentials);
    assert.equal(result.request.request.cache, initial.cache);
    assert.equal(result.request.request.referrerPolicy, initial.referrerPolicy);
  } finally {
    await close(server);
    await h.release();
  }
});
test(
  "refuses Node empty-query targets whose delimiter changes during delivery",
  {
    skip: !(runtime.startsWith("node:") &&
      Number(runtime.slice(5).split(".")[0]) < 24),
  },
  async () => {
    const h = await key();
    try {
      refused(
        await F.signRequest(
          new Request("http://127.0.0.1/empty?#fragment"),
          spec,
          h,
        ),
        "invalid_request",
      );
    } finally {
      await h.release();
    }
  },
);

test("signs redirect and retry attempts with three distinct nonces", async () => {
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
      await F.signedFetch(
        `http://127.0.0.1:${port}/`,
        { method: "POST", body: "payload" },
        { spec, signer: h },
        { maxRedirects: 1, maxRetries: 1, nonce: new Uint8Array(32).fill(1) },
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

test("cancels unused rebuilt Request streams before the next attempt", async () => {
  const h = await key();
  let attempts = 0;
  const server = createServer((req, res) => {
    req.resume();
    if (++attempts === 1) {
      res.statusCode = 307;
      res.setHeader("location", "/next");
    } else if (attempts === 2) res.statusCode = 503;
    res.end();
  });
  const port = await listen(server);
  // Instrument actual Request bodies and native cancellation; no stream is replaced.
  const getter = Object.getOwnPropertyDescriptor(Request.prototype, "body")!;
  const NativeRequest = Request;
  const nativeCancel = ReadableStream.prototype.cancel;
  const observed = new Set<Request>();
  const canceled = new Set<ReadableStream>();
  let cancels = 0;
  globalThis.Request = new Proxy(NativeRequest, {
    construct(target, args) {
      const request = Reflect.construct(target, args) as Request;
      // Observe bodies created from final URLs, including every library rebuild.
      // Native fetch may internally construct additional copies from a Request.
      if (typeof args[0] === "string" || args[0] instanceof URL) {
        observed.add(request);
      }
      return request;
    },
  });
  ReadableStream.prototype.cancel = function (reason?: unknown) {
    canceled.add(this);
    cancels++;
    return nativeCancel.call(this, reason);
  };
  try {
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new TextEncoder().encode("payload"));
        c.close();
      },
    });
    const input = new Request(
      `http://127.0.0.1:${port}/`,
      { method: "POST", body, duplex: "half" } as RequestInit,
    );
    value(
      await F.signedFetch(input, {}, { spec, signer: h }, {
        maxRedirects: 1,
        maxRetries: 1,
      }),
    );
    assert.equal(attempts, 3);
    assert.ok(cancels > 0, "unused redirect Request body must be canceled");
    for (const request of observed) {
      const stream = getter.get!.call(request) as ReadableStream | null;
      assert.ok(
        !stream || request.bodyUsed || canceled.has(stream),
        "every observed Request body is consumed or canceled",
      );
    }
  } finally {
    globalThis.Request = NativeRequest;
    ReadableStream.prototype.cancel = nativeCancel;
    await close(server);
    await h.release();
  }
});

test("a ten-hop Fetch chain shares one caller context and aborts promptly", async () => {
  const h = await key();
  const controller = new AbortController();
  const parent = value(api.withDeadline({ timeoutMs: 5000 }));
  let hops = 0;
  const server = createServer((req, res) => {
    req.resume();
    if (++hops <= 10) {
      res.statusCode = 307;
      res.setHeader("location", `/hop/${hops}`);
      res.end();
    } else controller.abort();
  });
  const port = await listen(server);
  // Observe registrations on the actual parent signal; retain native event delivery.
  const add = AbortSignal.prototype.addEventListener;
  const descriptor = Object.getOwnPropertyDescriptor(
    AbortSignal.prototype,
    "addEventListener",
  );
  let composed = 0;
  AbortSignal.prototype.addEventListener = function (
    ...args: Parameters<typeof add>
  ) {
    if (
      this === parent.signal && args[0] === "abort"
    ) composed++;
    return add.apply(this, args);
  };
  try {
    const start = performance.now();
    refused(
      await F.signedFetch(
        `http://127.0.0.1:${port}/`,
        { signal: controller.signal },
        { spec, signer: h },
        { context: parent, maxRedirects: 10 },
      ),
      "deadline_exceeded",
    );
    assert.equal(hops, 11);
    assert.ok(performance.now() - start < 2000);
    assert.ok(
      composed > 0,
      "the parent signal has an observed composition edge",
    );
    assert.ok(
      composed <= 1,
      `one caller/context composition; observed ${composed}`,
    );
  } finally {
    if (descriptor) {
      Object.defineProperty(
        AbortSignal.prototype,
        "addEventListener",
        descriptor,
      );
    } else {delete (AbortSignal.prototype as Partial<AbortSignal>)
        .addEventListener;}
    await close(server);
    await h.release();
  }
});

test("a null init signal follows native Request replacement semantics", async () => {
  const h = await key();
  const p = await wireServer(
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
  );
  try {
    const controller = new AbortController();
    controller.abort();
    const source = new Request(`http://127.0.0.1:${p.port}/`, {
      signal: controller.signal,
    });
    assert.equal(source.signal.aborted, true);
    const nativeAborted = new Request(source, { signal: null }).signal.aborted;
    const result = await F.signedFetch(source, { signal: null }, {
      spec,
      signer: h,
    });
    if (nativeAborted) {
      refused(result, "deadline_exceeded");
      assert.equal(p.records.length, 0);
    } else {
      const r = value(result);
      assert.equal(r.response.status, 200);
      assert.equal(p.records.length, 1);
      await r.response.arrayBuffer();
    }
  } finally {
    await p.close();
    await h.release();
  }
});

test("response signing can cover captured request fields with req", async () => {
  const h = await key();
  try {
    const request = value(
      await api.Message.request("POST", "http://127.0.0.1/", [
        ["host", "127.0.0.1"],
        ["content-length", "7"],
        ["accept-encoding", "identity"],
        ["connection", "close"],
        ["sec-fetch-mode", "navigate"],
      ], "payload"),
    );
    const components =
      '("@status" "content-length";req "accept-encoding";req "connection";req "sec-fetch-mode";req)';
    const r = value(
      await F.signResponse(
        new Response("response"),
        { ...spec, components },
        h,
        { request },
      ),
    );
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
    value(await api.verify(r.message, policy, { label: "sig" }));
    assert.equal(await r.response.text(), "response");
  } finally {
    await h.release();
  }
});

test("invalid related request options report the operation stage", async () => {
  const h = await key();
  try {
    const e = refused(
      await F.signResponse(
        new Response("response"),
        { ...spec, components: '("@status")' },
        h,
        { request: {} },
      ),
      "invalid_options",
    );
    assert.equal(e.kind, "adapter");
    if (e.kind === "adapter") assert.equal(e.stage, "sign");
  } finally {
    await h.release();
  }
});

test("refuses caller compression preferences before signed Fetch delivery", async () => {
  const h = await key();
  const p = await wireServer(
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
  );
  try {
    for (const encoding of ["gzip", "br", "identity, gzip"]) {
      refused(
        await F.signedFetch(`http://127.0.0.1:${p.port}/`, {
          headers: { "accept-encoding": encoding },
        }, { spec, signer: h }),
        "invalid_options",
      );
    }
    assert.equal(p.records.length, 0);
    const r = value(
      await F.signedFetch(`http://127.0.0.1:${p.port}/`, {
        headers: { "accept-encoding": "identity" },
      }, { spec, signer: h }),
    );
    await r.response.arrayBuffer();
    assert.equal(p.records.length, 1);
    assert.match(p.records[0]!.toString(), /accept-encoding: identity/i);
  } finally {
    await p.close();
    await h.release();
  }
});

test("refuses a caller Host before Fetch signing and delivery", async () => {
  const h = await key();
  const p = await wireServer(
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
  );
  try {
    refused(
      await F.signedFetch(`http://127.0.0.1:${p.port}/`, {
        headers: { host: "other.example" },
      }, { spec, signer: h }),
      "invalid_options",
    );
    assert.equal(p.records.length, 0);
    const r = value(
      await F.signedFetch(`http://127.0.0.1:${p.port}/`, {}, {
        spec,
        signer: h,
      }),
    );
    await r.response.arrayBuffer();
    assert.match(
      p.records[0]!.toString(),
      new RegExp(`host: 127\\.0\\.0\\.1:${p.port}`, "i"),
    );
  } finally {
    await p.close();
    await h.release();
  }
});

test("native fetch settles signed Request bodies on early rejection", {
  skip: !runtime.startsWith("node:"),
}, async () => {
  const h = await key();
  const p = await wireServer(
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
  );
  const NativeRequest = Request;
  const signed: Request[] = [];
  globalThis.Request = new Proxy(NativeRequest, {
    construct(target, args) {
      const request = Reflect.construct(target, args) as Request;
      if (request.headers.has("signature-input")) signed.push(request);
      return request;
    },
  });
  try {
    refused(
      await F.signedFetch(`http://127.0.0.1:${p.port}/`, {
        method: "POST",
        body: "payload",
        headers: { expect: "100-continue" },
      }, { spec, signer: h }),
      "invalid_request",
    );
    assert.ok(signed.length > 0, "native signed Requests were observed");
    for (const request of signed) {
      assert.ok(request.bodyUsed, "native fetch settled the signed body");
      const reader = request.body!.getReader();
      assert.equal((await reader.read()).done, true);
      reader.releaseLock();
    }
    assert.equal(p.records.length, 0);
  } finally {
    globalThis.Request = NativeRequest;
    await p.close();
    await h.release();
  }
});

for (const operation of ["sign", "verify"] as const) {
  test(`${operation} refuses nonempty native GET and HEAD request bodies`, {
    skip: !canVerify,
  }, async () => {
    const deno = (globalThis as any).Deno;
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
    const server = deno.serve(
      { hostname: "127.0.0.1", port: 0, onListen() {} },
      async (request: Request) => {
        outcome = (async () => {
          assert.equal(request.headers.get("content-length"), "7");
          assert.ok(["GET", "HEAD"].includes(request.method));
          const r = operation === "sign"
            ? await F.signRequest(request, spec, h)
            : await F.verifyRequest(request, policy, {
              label: "sig",
              scheme: "http",
              authority: "127.0.0.1",
            });
          refused(r, "invalid_request");
        })();
        await outcome.catch(() => {});
        return new Response("observed");
      },
    );
    try {
      for (const method of ["GET", "HEAD"]) {
        const signed = value(
          await api.sign(
            value(
              await api.Message.request(
                method,
                "http://127.0.0.1/",
                [],
                "payload",
              ),
            ),
            spec,
            h,
          ),
        );
        const fields = operation === "verify"
          ? signed.fields.map((f) =>
            `${f.name}: ${String.fromCharCode(...f.value)}\r\n`
          ).join("")
          : "";
        await rawRequest(
          server.addr.port,
          `${method} / HTTP/1.1\r\nHost: 127.0.0.1\r\n${fields}Content-Length: 7\r\nConnection: close\r\n\r\npayload`,
        );
        await outcome;
      }
    } finally {
      await server.shutdown();
      await h.release();
    }
  });
}

test('ineligible verified delivery with init preserves the caller Request body', {skip: canVerify}, async () => {
  const owner = await key();
  try {
    for (const init of [{headers: {'x-caller': 'present'}}, {referrerPolicy: 'no-referrer'}]) {
      const request = new Request('http://127.0.0.1/', {method: 'POST', body: new Uint8Array([1, 2, 3])});
      const result = await F.signedFetch(request, init, {spec, signer: owner}, {verify: {policy: {}, label: 'sig'}});
      refused(result, 'invalid_request');
      assert.equal(request.bodyUsed, false, 'Refusal must precede Request construction');
      assert.deepEqual(new Uint8Array(await request.arrayBuffer()), new Uint8Array([1, 2, 3]));
    }
  } finally {await owner.release();}
});
test("a Request that hides its body stream cannot bypass the bounded signing reader", {skip: typeof Object.getOwnPropertyDescriptor(Request.prototype, "body")?.get !== "function"}, async () => {
  const h = await key();
  let pulled = 0;
  const chunk = new Uint8Array(64 * 1024);
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (pulled >= 5 * 1024 * 1024) return controller.close();
      pulled += chunk.length;
      controller.enqueue(chunk);
    },
  });
  try {
    const request = new Request("http://127.0.0.1:9/", {method: "POST", body: stream, duplex: "half"} as RequestInit);
    Object.defineProperty(request, "body", {get: () => undefined});
    const r = await F.signRequest(request, spec, h, {maxBytes: 1024});
    assert.equal(r.ok, false);
    assert.ok(pulled < 1024 * 1024, `the signing reader pulled ${pulled} bytes past a 1 KiB bound`);
  } finally {
    await h.release();
  }
});
