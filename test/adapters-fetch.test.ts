import test from "node:test";
import assert from "node:assert/strict";
import * as adapter from "../src/adapters/fetch/index.ts";
import { Custody, Policy, ok, verify, type Result } from "../src/index.ts";
import { wireServer } from "./support/wire-server.ts";
function value<T>(
  r: { ok: true; value: T } | { ok: false; error: unknown },
): T {
  if (!r.ok) assert.fail(JSON.stringify(r.error));
  return r.value;
}
test("signs the finalized Fetch bytes and refuses runtime-owned fields", async () => {
  assert.equal(
    typeof adapter.signRequest,
    "function",
    "signRequest must translate finalized Fetch requests",
  );
  const key = value(
    await Custody.local("hmac-sha256", {
      hmac: crypto.getRandomValues(new Uint8Array(32)),
    }),
  );
  try {
    const request = new Request("https://example.test/a%2Fb?x=+&x=%20#f", {
      method: "POST",
      body: "hello",
    });
    const signed = value(
      await adapter.signRequest(
        request,
        {
          label: "sig",
          components: '("@method" "@authority" "content-digest")',
          algorithm: "hmac-sha256",
          expiresIn: 60,
          digest: ["sha-256"],
        },
        key,
      ),
    );
    assert.equal(signed.message.rawTarget, "/a%2Fb?x=+&x=%20");
    assert.equal(signed.request.url.includes("#"), false);
    const p = value(
      Policy.create({
        algorithms: ["hmac-sha256"],
        components: '("@method" "@authority" "content-digest")',
        keyResolver: () => ok({ algorithm: "hmac-sha256", key }),
        freshness: "not_evaluated",
        content: {
          kind: "content",
          algorithms: ["sha-256"],
          section: "headers",
        },
        replay: "not_required",
      }),
    );
    assert.equal((await verify(signed.message, p, { label: "sig" })).ok, true);
    assert.equal(await signed.request.text(), "hello");
    const bad = await adapter.signRequest(
      new Request("https://example.test/"),
      {
        label: "sig",
        components: '("content-length")',
        algorithm: "hmac-sha256",
        expiresIn: 60,
      },
      key,
    );
    assert.equal(bad.ok, false);
    if (!bad.ok) assert.equal(bad.error.reason, "unsupported_component");
  } finally {
    await key.release();
  }
});
test("refuses unproven Fetch verification before resolving keys", async (t) => {
  const deno = (globalThis as any).Deno;
  if (deno) {
    t.skip("Deno has a separately exercised verification lane");
    return;
  }
  let calls = 0;
  const p = value(
    Policy.create({
      algorithms: ["ed25519"],
      components: '("@method")',
      keyResolver: () => {
        calls++;
        return ok(null);
      },
      freshness: "not_evaluated",
      content: "not_required",
      replay: "not_required",
    }),
  );
  const r = await adapter.verifyRequest(
    new Request("https://example.test/"),
    p,
    { label: "sig", scheme: "https", authority: "example.test" },
  );
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.error.reason, "invalid_request");
  assert.equal(calls, 0);
});
test("sends signed Fetch exchanges to a raw wire listener", async () => {
  const key = value(
    await Custody.local("hmac-sha256", {
      hmac: crypto.getRandomValues(new Uint8Array(32)),
    }),
  );
  const peer = await wireServer(
    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
  );
  try {
    const r = value(
      await adapter.signedFetch(
        `http://127.0.0.1:${peer.port}/a%2Fb`,
        { method: "POST", body: "hello" },
        {
          spec: {
            label: "sig",
            components: '("@method" "content-digest")',
            algorithm: "hmac-sha256",
            expiresIn: 60,
            digest: ["sha-256"],
          },
          signer: key,
        },
      ),
    );
    assert.equal(await r.response.text(), "ok");
    const wire = peer.records[0]!.toString();
    assert.ok(/accept-encoding: identity/i.test(wire));
    assert.ok(/signature-input:/i.test(wire));
    assert.ok(wire.endsWith("hello"));
  } finally {
    await peer.close();
    await key.release();
  }
});

import fc from "fast-check";
import { Message } from "../src/index.ts";
import { gzipSync } from "node:zlib";
test("generated Fetch targets, fields, and bodies verify from the bytes sent on the wire", async () => {
  const key = value(
    await Custody.local("hmac-sha256", {
      hmac: crypto.getRandomValues(new Uint8Array(32)),
    }),
  );
  const components = '("@method" "x-covered" "content-digest")';
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
  try {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.constantFrom("a", "%2F", "%20", "~"), {
          minLength: 1,
          maxLength: 8,
        }),
        fc.uint8Array({ maxLength: 48 }),
        async (parts, body) => {
          const peer = await wireServer(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
          );
          try {
            value(
              await adapter.signedFetch(
                `http://127.0.0.1:${peer.port}/${parts.join("")}`,
                {
                  method: "POST",
                  body,
                  headers: { "x-covered": "yes", "x-uncovered": "extra" },
                },
                {
                  spec: {
                    label: "sig",
                    components,
                    algorithm: "hmac-sha256",
                    expiresIn: 60,
                    digest: ["sha-256"],
                  },
                  signer: key,
                },
              ),
            );
            const wire = peer.records[0]!,
              end = wire.indexOf("\r\n\r\n"),
              lines = wire.subarray(0, end).toString("latin1").split("\r\n"),
              start = lines.shift()!.split(" "),
              fields = lines.map((l) => {
                const pos = l.indexOf(":");
                return [l.slice(0, pos), l.slice(pos + 1).trim()];
              });
            const m = value(
              await Message.request(
                start[0],
                `http://127.0.0.1:${peer.port}${start[1]}`,
                fields,
                wire.subarray(end + 4),
              ),
            );
            assert.equal((await verify(m, p, { label: "sig" })).ok, true);
            const changed = value(
              Message.create({
                ...m,
                fields: m.fields.map((f) =>
                  f.name.toLowerCase() === "x-covered"
                    ? { ...f, value: "tampered" }
                    : f,
                ),
              }),
            );
            assert.equal(
              (await verify(changed, p, { label: "sig" })).ok,
              false,
            );
          } finally {
            await peer.close();
          }
        },
      ),
      { numRuns: 8 },
    );
  } finally {
    await key.release();
  }
});
test("records gzip decoding and refuses required response content when wire identity is lost", async (t) => {
  const body = gzipSync("encoded bytes");
  const peer = await wireServer(
    Buffer.concat([
      Buffer.from(
        `HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`,
      ),
      body,
    ]),
  );
  try {
    const res = await fetch(`http://127.0.0.1:${peer.port}/`);
    t.diagnostic(
      JSON.stringify({
        encoding: res.headers.get("content-encoding"),
        length: res.headers.get("content-length"),
      }),
    );
    const p = value(
      Policy.create({
        algorithms: ["ed25519"],
        components: '("content-digest")',
        keyResolver: () => ok(null),
        freshness: "not_evaluated",
        content: {
          kind: "content",
          algorithms: ["sha-256"],
          section: "headers",
        },
        replay: "not_required",
      }),
    );
    const r = await adapter.verifyResponse(res, p, { label: "sig" });
    assert.equal(r.ok, false);
    if (!r.ok)
      assert.equal(
        r.error.reason,
        (globalThis as any).Deno ? "body_unavailable" : "invalid_request",
      );
    assert.equal(await res.text(), "encoded bytes");
  } finally {
    await peer.close();
  }
});
test(
  "Deno verifies an actual incoming Fetch request and returns exactly the retained body",
  { skip: !(globalThis as any).Deno },
  async (t) => {
    const deno = (globalThis as any).Deno;
    if (!deno) return;
    const key = value(
      await Custody.local("hmac-sha256", {
        hmac: crypto.getRandomValues(new Uint8Array(32)),
      }),
    );
    let called = 0;
    const components =
      '("@method" "@authority" "@scheme" "@query-param";name="x" "x-covered" "content-digest")';
    const p = value(
      Policy.create({
        algorithms: ["hmac-sha256"],
        components,
        keyResolver: () => {
          called++;
          return ok({ algorithm: "hmac-sha256", key });
        },
        freshness: "not_evaluated",
        content: {
          kind: "content",
          algorithms: ["sha-256"],
          section: "headers",
        },
        replay: "not_required",
      }),
    );
    const responseComponents = '("@status" "@method";req "set-cookie")';
    let responseKeys = 0;
    const responsePolicy = value(
      Policy.create({
        algorithms: ["hmac-sha256"],
        components: responseComponents,
        keyResolver: () => {
          responseKeys++;
          return ok({ algorithm: "hmac-sha256", key });
        },
        freshness: "not_evaluated",
        content: "not_required",
        replay: "not_required",
      }),
    );
    let outcome: Result<adapter.VerifiedRequest> | undefined;
    const server = deno.serve(
      { hostname: "127.0.0.1", port: 0, onListen() {} },
      async (req: Request) => {
        outcome = await adapter.verifyRequest(req, p, {
          label: "sig",
          scheme: "http",
          authority: `127.0.0.1:${server.addr.port}`,
        });
        if (!outcome.ok)
          return new Response(JSON.stringify(outcome), { status: 401 });
        assert.equal(await outcome.value.request.text(), "hello");
        assert.equal(new TextDecoder().decode(outcome.value.bytes), "hello");
        return value(
          await adapter.signResponse(
            new Response("accepted", {
              headers: [
                ["set-cookie", "a=1"],
                ["set-cookie", "b=2"],
              ],
            }),
            {
              label: "response",
              components: responseComponents,
              algorithm: "hmac-sha256",
              expiresIn: 60,
            },
            key,
            { request: outcome.value.message },
          ),
        ).response;
      },
    );
    try {
      const r = value(
        await adapter.signedFetch(
          `http://127.0.0.1:${server.addr.port}/a?x=%20`,
          { method: "POST", body: "hello", headers: { "x-covered": "yes" } },
          {
            spec: {
              label: "sig",
              components,
              algorithm: "hmac-sha256",
              expiresIn: 60,
              digest: ["sha-256"],
            },
            signer: key,
          },
          { verify: { policy: responsePolicy, label: "response" } },
        ),
      );
      assert.equal(r.response.status, 200, await r.response.text());
      assert.deepEqual(r.response.headers.getSetCookie(), ["a=1", "b=2"]);
      assert.equal(responseKeys, 1);
      assert.equal(called, 1);
      assert.equal(outcome?.ok, true);
    } finally {
      await server.shutdown();
      await key.release();
    }
  },
);

test("cancels Fetch signing and sending through the Request signal", async () => {
  const key = value(
    await Custody.local("hmac-sha256", {
      hmac: crypto.getRandomValues(new Uint8Array(32)),
    }),
  );
  const peer = await wireServer(
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
  );
  const controller = new AbortController();
  controller.abort();
  const spec = {
    label: "sig",
    components: '("@method")',
    algorithm: "hmac-sha256",
    expiresIn: 60,
  };
  try {
    const request = new Request(`http://127.0.0.1:${peer.port}/`, {
      signal: controller.signal,
    });
    const signed = await adapter.signRequest(request, spec, key);
    assert.equal(signed.ok, false, "an aborted Request must cancel signing");
    if (!signed.ok) assert.equal(signed.error.reason, "deadline_exceeded");
    for (const [input, init] of [
      [request, {}],
      [request.url, { signal: controller.signal }],
    ] as const) {
      const sent = await adapter.signedFetch(input, init, {
        spec,
        signer: key,
      });
      assert.equal(
        sent.ok,
        false,
        "an aborted Request or init signal must cancel sending",
      );
      if (!sent.ok) assert.equal(sent.error.reason, "deadline_exceeded");
    }
    assert.equal(peer.records.length, 0);
  } finally {
    await peer.close();
    await key.release();
  }
});

test("generated Fetch response signatures preserve cookies and detect covered byte changes", async () => {
  const key = value(
    await Custody.local("hmac-sha256", {
      hmac: crypto.getRandomValues(new Uint8Array(32)),
    }),
  );
  const components = '("@status" "set-cookie" "content-digest")';
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
  try {
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ maxLength: 48 }), async (body) => {
        const source = new Response(body, {
          status: 201,
          headers: [
            ["set-cookie", "a=1"],
            ["set-cookie", "b=2"],
          ],
        });
        const signed = value(
          await adapter.signResponse(
            source,
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
        assert.deepEqual(signed.response.headers.getSetCookie(), [
          "a=1",
          "b=2",
        ]);
        assert.deepEqual(
          new Uint8Array(await signed.response.arrayBuffer()),
          body,
        );
        assert.equal(
          (await verify(signed.message, policy, { label: "sig" })).ok,
          true,
        );
        const extra = value(
          Message.create({
            ...signed.message,
            fields: [
              ...signed.message.fields,
              { name: "x-uncovered", value: "extra", section: "headers" },
            ],
          }),
        );
        assert.equal((await verify(extra, policy, { label: "sig" })).ok, true);
        const changed = value(
          Message.create({
            ...signed.message,
            body: { state: "retained", bytes: new Uint8Array([...body, 1]) },
          }),
        );
        assert.equal(
          (await verify(changed, policy, { label: "sig" })).ok,
          false,
        );
      }),
      { numRuns: 8 },
    );
  } finally {
    await key.release();
  }
});
