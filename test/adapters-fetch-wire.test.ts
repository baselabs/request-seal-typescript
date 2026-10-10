import test from "node:test";
import assert from "node:assert/strict";
import { rawRequest, wireServer } from "./support/wire-server.ts";
import { readFileSync } from "node:fs";
import {
  canVerify,
  FETCH_SIGNING_REFUSALS,
  FETCH_VERIFICATION_RUNTIMES,
  runtime,
} from "../src/adapters/fetch/runtime.ts";
import { verifyRequest, verifyResponse } from "../src/adapters/fetch/index.ts";
const evidence = JSON.parse(
  readFileSync(
    new URL("./fixtures/adapters-fetch-wire.json", import.meta.url),
    "utf8",
  ),
);
const version = runtime.replace(/^node:/, "Node ").replace(/^deno:/, "Deno ")
  .replace(/^bun:/, "Bun ");
const targetCases = ["//%2F?", "/empty?", "/a%2Fb?x=%2f%20+"];
// Eligibility is derived from wire facts, never from the fixture's decision flag.
function eligible(o: any): boolean {
  return o.duplicate === "a, b" && o.whitespace === true &&
    o.setCookie.length === 2 && o.method === "MiXeD" &&
    o.requestDuplicates === "a, b" && o.target === "/a%2Fb?x=+&x=%20" &&
    o.incoming?.method === "MiXeD" && o.incoming?.duplicate === "a, b" &&
    o.incoming?.target === "/a%2Fb?x=+&x=%20" &&
    JSON.stringify(o.incoming?.standardMixedCaseMethods) ===
      JSON.stringify(["gEt", "pOsT"]) &&
    targetCases.every((target) => o.unusualTargets?.[target] === target);
}
async function refusesUnrecorded() {
  assert.equal(canVerify, false, "unrecorded runtimes fail closed");
  let reads = 0;
  const options = {
    get label() {
      reads++;
      throw new Error("options read");
    },
  };
  for (
    const result of [
      await verifyRequest(new Request("http://127.0.0.1/"), null, options),
      await verifyResponse(new Response("unread"), null, options),
    ]
  ) {
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.error.reason, "invalid_request");
  }
  assert.equal(reads, 0);
}
async function outbound() {
  const peer = await wireServer(
    "HTTP/1.1 200 OK\r\nX-Duplicate: a \t\r\nX-Duplicate:\tb  \r\nCookie: a=1\r\nCookie: b=2\r\nSet-Cookie: a=1; Expires=Wed, 21 Oct 2030 07:28:00 GMT\r\nSet-Cookie: b=2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
  );
  try {
    const request = new Request(
      `http://127.0.0.1:${peer.port}/x/../a%2Fb?x=+&x=%20#fragment`,
      {
        method: "MiXeD",
        headers: [
          ["x-duplicate", " a \t"],
          ["x-duplicate", "\tb  "],
          ["cookie", "a=1"],
          ["cookie", "b=2"],
          ["sec-fetch-mode", "navigate"],
          ["accept-encoding", "identity"],
        ],
      },
    );
    const response = await fetch(request);
    await response.arrayBuffer();
    const overriddenFields = ["sec-fetch-mode", "accept-encoding"].filter(
      (name) => {
        const line = peer.records[0]!.toString().split("\r\n").find((line) =>
          line.toLowerCase().startsWith(name + ":")
        );
        return line?.slice(line.indexOf(":") + 1).trim() !==
          request.headers.get(name);
      },
    );
    return {
      overriddenFields,
      duplicate: response.headers.get("x-duplicate"),
      whitespace: response.headers.get("x-duplicate") === "a, b",
      cookie: response.headers.get("cookie"),
      setCookie: response.headers.getSetCookie(),
      method: peer.records[0]!.toString().split(" ")[0],
      target: peer.records[0]!.toString().split(" ")[1],
      requestDuplicates: request.headers.get("x-duplicate"),
      requestCookies: request.headers.get("cookie"),
    };
  } finally {
    await peer.close();
  }
}
async function targets() {
  const unusualTargets: Record<string, string> = Object.create(null);
  for (const target of targetCases) {
    const peer = await wireServer(
      "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    try {
      const response = await fetch(`http://127.0.0.1:${peer.port}${target}`);
      await response.arrayBuffer();
      unusualTargets[target] = peer.records[0]!.toString().split(" ")[1]!;
    } finally {
      await peer.close();
    }
  }
  return { ...unusualTargets };
}
async function nativeIncoming() {
  const deno = (globalThis as any).Deno, bun = (globalThis as any).Bun;
  if (!deno && !bun) return null;
  let seen: any;
  const handle = (req: Request) => {
    seen = {
      method: req.method,
      url: req.url,
      duplicate: req.headers.get("x-duplicate"),
      cookie: req.headers.get("cookie"),
    };
    return new Response("accepted");
  };
  const server = deno
    ? deno.serve({ hostname: "127.0.0.1", port: 0, onListen() {} }, handle)
    : bun.serve({ hostname: "127.0.0.1", port: 0, fetch: handle });
  const port = deno ? server.addr.port : server.port;
  try {
    const result = await rawRequest(
      port,
      "MiXeD /a%2Fb?x=+&x=%20 HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Duplicate: a \t\r\nX-Duplicate:\tb  \r\nCookie: a=1\r\nCookie: b=2\r\nConnection: close\r\n\r\n",
    );
    if (deno) {
      assert.ok(result.includes("accepted"));
      assert.equal(seen.method, "MiXeD");
    } else {
      assert.equal(result, "");
      assert.equal(seen, undefined);
    }
    const incoming = seen
      ? {
        method: seen.method,
        duplicate: seen.duplicate,
        cookie: seen.cookie,
        target: new URL(seen.url).pathname + new URL(seen.url).search,
        standardMixedCaseMethods: [] as string[],
      }
      : { unusualMethod: "connection closed without a response" };
    for (const method of ["gEt", "pOsT"]) {
      seen = undefined;
      const reply = await rawRequest(
        port,
        `${method} /empty? HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`,
      );
      if (deno) {
        assert.ok(reply.includes("accepted"));
        assert.equal(seen.method, method);
        incoming.standardMixedCaseMethods!.push(seen.method);
        assert.ok(seen.url.endsWith("/empty?"));
      } else {
        assert.equal(reply, "");
        assert.equal(seen, undefined);
      }
    }
    if (deno) {
      for (const target of targetCases) {
        await rawRequest(
          port,
          `GET ${target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`,
        );
        assert.ok(seen.url.endsWith(target));
      }
    }
    return incoming;
  } finally {
    if (deno) await server.shutdown();
    else server.stop(true);
  }
}

test("derives runtime eligibility from every required wire observation", () => {
  const allowed: string[] = [];
  for (
    const [name, o] of Object.entries(evidence.observations) as [string, any][]
  ) {
    const measured = eligible(o);
    const family = name.toLowerCase().split(" ")[0] as "node" | "deno" | "bun";
    assert.deepEqual(
      o.overriddenFields.filter((f: string) =>
        !FETCH_SIGNING_REFUSALS.common.includes(f)
      ),
      FETCH_SIGNING_REFUSALS[family],
    );
    assert.equal(o.allowVerification, measured, `${name} fixture eligibility`);
    if (measured) allowed.push(name.toLowerCase().replace(" ", ":"));
  }
  assert.deepEqual(FETCH_VERIFICATION_RUNTIMES, allowed);
});
test("records runtime views of duplicate occurrences and exact request bytes", async (t) => {
  const observation = await outbound();
  t.diagnostic(JSON.stringify({ runtime: version, ...observation }));
  const expected = evidence.observations[version];
  if (expected) {
    for (const [name, value] of Object.entries(observation)) {
      assert.deepEqual(value, expected[name], `recorded ${name}`);
    }
  } else await refusesUnrecorded();
  assert.equal(observation.setCookie.length, 2);
  assert.ok(observation.target?.includes("a%2Fb?"));
});
test("records native incoming Fetch request views on runtimes with a Fetch server", async (t) => {
  // Each test owns its observations and can run alone.
  const observation = {
    ...await outbound(),
    incoming: await nativeIncoming(),
    unusualTargets: await targets(),
  };
  const measured = eligible(observation);
  t.diagnostic(
    JSON.stringify({
      runtime: version,
      ...observation,
      allowVerification: measured,
    }),
  );
  const expected = evidence.observations[version];
  if (expected) {
    assert.deepEqual({ ...observation, allowVerification: measured }, expected);
    assert.equal(canVerify, measured);
  } else await refusesUnrecorded();
});
