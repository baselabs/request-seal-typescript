import test, { type TestContext } from "node:test";
import assert from "node:assert/strict";
import { createServer, request, type IncomingMessage } from "node:http";
import { once } from "node:events";
import { createPrivateKey, createHash, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import {execFileWithEnvSync as execFileSync} from "./support/child-env.ts";
import { fileURLToPath } from "node:url";
import * as Seal from "../src/index.ts";
import * as N from "../src/adapters/node-http/index.ts";
import { peer } from "./support/discovery-peer.ts";
import { custody, now, policy, value } from "./support/web-bot-auth.ts";

type BotVerifier = (
  req: unknown,
  policy: unknown,
  options?: unknown,
) => Promise<Seal.Result<Readonly<{
  capture: N.Capture;
  verification: Seal.WebBotAuthVerification;
  bytes: Uint8Array;
}>>>;
function verifier(): BotVerifier {
  const fn = (N as unknown as { verifyWebBotAuth?: BotVerifier }).verifyWebBotAuth;
  assert.equal(typeof fn, "function", "node-http must export verifyWebBotAuth");
  return fn!;
}
function transportTest(name: string, check: (t: TestContext) => Promise<void>) {
  test(name, async (t) => {
    if (process.versions.deno || process.versions.bun) {
      // The configured discovery-node source uses Node's TLS transport.
      const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const env = { ...process.env };
      delete env.NODE_TEST_CONTEXT;
      const output = execFileSync("node", [
        "--unhandled-rejections=strict", "--experimental-strip-types", "--no-warnings",
        "--test", "--test-reporter=tap", `--test-name-pattern=^${escaped}$`,
        fileURLToPath(import.meta.url),
      ], { encoding: "utf8", timeout: 30000, env });
      assert.match(output, /^# pass 1$/m);
      assert.match(output, /^# fail 0$/m);
      t.diagnostic(`Node HTTP/TLS subprocess:\n${output}`);
      return;
    }
    await check(t);
  });
}
function rejected(r: Seal.Result<unknown>, expected: string, source?: string) {
  assert.equal(r.ok, false);
  if (r.ok) assert.fail("expected rejection");
  const error = r.error;
  assert.equal(error.kind, "adapter");
  if (error.kind !== "adapter") assert.fail("expected adapter error");
  assert.equal(error.adapter, "node-http");
  assert.equal(error.stage, "verify");
  assert.equal(error.attempt, 0);
  assert.equal(error.reason, expected);
  if (source) {
    assert.equal(error.source?.kind, "core");
    assert.equal(error.source?.reason, source);
  } else assert.equal(error.source, null);
  assert.equal(error.retryable, false);
  assert.equal(Object.hasOwn(error, "stack"), false);
  assert.equal(JSON.stringify(error).includes("127.0.0.1"), false);
  return error;
}
async function exchange(
  signed: boolean,
  check: (
    req: IncomingMessage,
    p: Seal.WebBotAuthPolicy,
    directory: Awaited<ReturnType<typeof peer>>,
  ) => Promise<void>,
) {
  const handle = await custody();
  const key = value(await handle.publicKey()), kid = value(await key.thumbprint());
  const signingKey = createPrivateKey(readFileSync("conformance/sources/rfc9421/keys/ed25519_private.pem"));
  const body = JSON.stringify({ keys: [value(key.jwk())] });
  const directory = await peer((_req, res) => {
    const digest = `sha-256=:${createHash("sha256").update(body).digest("base64")}:`;
    const input = `("@authority";req "content-digest");created=${now};expires=${now + 120};keyid="${kid}";tag="http-message-signatures-directory"`;
    const base = `"@authority";req: 127.0.0.1:${directory.port}\n"content-digest": ${digest}\n"@signature-params": ${input}`;
    res.writeHead(200, {
      "content-type": "application/http-message-signatures-directory+json",
      "content-digest": digest,
      "signature-input": `directory=${input}`,
      signature: `directory=:${sign(null, Buffer.from(base), signingKey).toString("base64")}:`,
      "cache-control": "max-age=120",
    });
    res.end(body);
  });
  const { Discovery, DiscoverySource } = await import("../src/discovery/node.ts");
  const location = `https://127.0.0.1:${directory.port}`;
  const source = value(DiscoverySource.create({
    type: "directory", location, cacerts: [directory.ca],
    permittedAddresses: ["127.0.0.1"], requireSignedDirectory: true,
  }));
  const cache = value(Seal.createCache({ clock: () => now, fetch: Discovery.fetch }));
  const p = policy({
    algorithms: ["ed25519"], cache,
    agents: (a: Seal.AgentRequest) => Seal.ok(a.location === location ? source : null),
    components: '("@method" "@path" "content-digest")',
    content: { kind: "content", algorithms: ["sha-256"], section: "headers" },
  });
  let outcome: Promise<void> | undefined;
  const server = createServer((req, res) => {
    outcome = (async () => {
      value(await N.captureRequest(req));
      await check(req, p, directory);
    })();
    void outcome.finally(() => res.end()).catch(() => {});
  });
  try {
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const bytes = new TextEncoder().encode('{"a":1}');
    const digest = `sha-256=:${createHash("sha256").update(bytes).digest("base64")}:`;
    let message = value(await Seal.Message.request(
      "POST", `http://127.0.0.1:${address.port}/a%2Fb?x=1`,
      [["content-digest", digest]], bytes,
    ));
    if (signed) message = value(await Seal.WebBotAuth.sign(message, {
      label: "agent", key, algorithm: "ed25519",
      agent: { location, type: "directory" }, created: now, expires: now + 60,
      nonce: null, components: '("@method" "@path" "content-digest")',
    }, handle));
    await new Promise<void>((done, fail) => {
      const outgoing = request({
        host: "127.0.0.1", port: address.port, method: "POST", path: "/a%2Fb?x=1",
        headers: ["Host", `127.0.0.1:${address.port}`, "Content-Length", String(bytes.length),
          ...message.fields.flatMap(f => [f.name, Buffer.from(f.value).toString("latin1")])],
        agent: false,
      }, res => { res.resume(); res.once("end", done); });
      outgoing.once("error", fail);
      outgoing.end(bytes);
    });
    assert.ok(outcome, "real HTTP listener executed");
    await outcome;
  } finally {
    server.closeAllConnections();
    await new Promise<void>(done => server.close(() => done()));
    cache.close(); await directory.close(); await handle.release();
  }
}

transportTest("Node Web Bot Auth verifies captured bytes against a real signed TLS directory", async () => {
  const verify = verifier();
  await exchange(true, async (req, p, directory) => {
    const result = value(await verify(req, p));
    assert.equal(result.capture.message.rawTarget, "/a%2Fb?x=1");
    assert.equal(result.verification.profile.name, "web_bot_auth");
    const principal = result.verification.signatures.agent!.principal;
    assert.equal(principal.kind, "agent");
    if (principal.kind === "agent") assert.equal(principal.provenance.proof, "signed");
    assert.equal(value(N.verification(req)), result.verification);
    assert.equal(Buffer.from(result.bytes).toString(), '{"a":1}');
    result.bytes.fill(0);
    assert.equal(Buffer.from(result.bytes).toString(), '{"a":1}');
    assert.equal(Object.isFrozen(result), true);
    assert.equal(Object.isFrozen(result.capture), true);
    assert.equal(directory.requests, 1);
  });
});
transportTest("Node Web Bot Auth stores the bounded unsigned request rejection", async () => {
  const verify = verifier();
  await exchange(false, async (req, p, directory) => {
    const result = await verify(req, p);
    rejected(result, "request_rejected", "missing_signature_input");
    assert.equal(N.verification(req), result);
    assert.equal(directory.requests, 0);
    rejected(await verify(req, p), "already_verified");
  });
});
transportTest("Node Web Bot Auth rejects an untrusted agent before directory access", async () => {
  const verify = verifier();
  await exchange(true, async (req, p, directory) => {
    // Prove the real directory and its counter before measuring denied access.
    const { Discovery } = await import("../src/discovery/node.ts");
    value(await Discovery.fetch(value(Seal.DiscoverySource.create({
      type: "directory", location: `https://127.0.0.1:${directory.port}`,
      cacerts: [directory.ca], permittedAddresses: ["127.0.0.1"],
    })), { clock: () => now }));
    const before = directory.requests;
    const untrusted = policy({
      algorithms: p.algorithms, cache: p.cache, agents: () => Seal.ok(null),
      components: '("@method" "@path" "content-digest")', content: p.content,
    });
    const result = await verify(req, untrusted);
    rejected(result, "request_rejected", "agent_unresolved");
    assert.equal(N.verification(req), result);
    assert.equal(directory.requests, before);
  });
});
transportTest("Node Web Bot Auth shares its single attempt with generic and quorum verification", async () => {
  const verify = verifier();
  await exchange(true, async (req, p) => {
    const first = verify(req, p);
    rejected(await verify(req, p), "already_verified");
    rejected(await N.verifyRequest(req, null, { label: "agent" }), "already_verified");
    rejected(await N.verifyQuorum(req, null), "already_verified");
    const accepted = value(await first);
    assert.equal(value(N.verification(req)), accepted.verification);
    rejected(await verify(req, p), "already_verified");
    assert.equal(value(N.verification(req)), accepted.verification);
  });
});
transportTest("Node Web Bot Auth validates options once before reserving the attempt", async () => {
  const verify = verifier();
  await exchange(true, async (req, p) => {
    for (const options of [null, [], { unknown: 1 }, { [Symbol("unknown")]: 1 },
      { context: null }, { timeoutMs: 0 }, { timeoutMs: 300001 }, { timeoutMs: 1.5 },
      { timeoutMs: undefined }, Object.defineProperty({}, "context", { get() { throw new Error("caller diagnostic"); } })]) {
      rejected(await verify(req, p, options), "invalid_options");
    }
    let contextReads = 0, timeoutReads = 0;
    const context = value(Seal.withDeadline({ timeoutMs: 5000 }));
    const accepted = value(await verify(req, p, {
      get context() { contextReads++; return contextReads === 1 ? context : null; },
      get timeoutMs() { timeoutReads++; return timeoutReads === 1 ? 5000 : 0; },
    }));
    assert.equal(contextReads, 1); assert.equal(timeoutReads, 1);
    assert.equal(value(N.verification(req)), accepted.verification);
  });
});
transportTest("Node Web Bot Auth honors replay stream drain before reserving the attempt", async () => {
  const verify = verifier();
  await exchange(true, async (req, p) => {
    const captured = value(await N.captureRequest(req));
    const stream = value(captured.replay());
    stream.read(1);
    rejected(await verify(req, p), "parser_order");
    stream.resume(); await once(stream, "end");
    value(await verify(req, p));
  });
});
transportTest("Node Web Bot Auth cannot reuse an attempt reserved by generic verification", async () => {
  const verify = verifier();
  await exchange(true, async (req, p) => {
    const first = await N.verifyRequest(req, null, { label: "agent" });
    rejected(first, "request_rejected", "invalid_policy");
    rejected(await verify(req, p), "already_verified");
    assert.equal(N.verification(req), first);
  });
});
transportTest("README Node Web Bot Auth example executes against captured HTTP and signed TLS discovery", async () => {
  verifier();
  const readme = readFileSync("README.md", "utf8");
  const fence = [...readme.matchAll(/```ts\n([\s\S]*?)```/g)]
    .map(m => m[1]!).find(code => /async function authenticateBot\b/.test(code));
  assert.ok(fence, "README includes executable authenticateBot example");
  const code = fence.replace('import {captureRequest, verifyWebBotAuth} from "@request-seal/core/node-http";',
    'const {captureRequest, verifyWebBotAuth} = adapter;');
  assert.notEqual(code, fence, 'README Node Web Bot Auth import must be replaced');
  const execute = new Function("adapter", "req", "policy",
    `return (async () => { ${code}\nreturn authenticateBot(req, policy); })();`) as
    (adapter: typeof N, req: IncomingMessage, policy: Seal.WebBotAuthPolicy) => ReturnType<BotVerifier>;
  await exchange(true, async (req, p, directory) => {
    const accepted = value(await execute(N, req, p));
    assert.equal(value(N.verification(req)), accepted.verification);
    assert.equal(accepted.verification.profile.name, "web_bot_auth");
    assert.equal(Buffer.from(accepted.bytes).toString(), '{"a":1}');
    assert.equal(directory.requests, 1);
  });
});
