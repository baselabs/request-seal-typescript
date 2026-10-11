import test, { type TestContext } from "node:test";
import assert from "node:assert/strict";
import {
  createPrivateKey,
  createHash,
  sign,
  generateKeyPairSync,
} from "node:crypto";
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { peer } from "./support/discovery-peer.ts";
import {
  value,
  now,
  directory,
  custody,
  policy,
  rejection,
  published,
} from "./support/web-bot-auth.ts";
import * as Seal from "../src/index.ts";
function transportTest(name: string, check: (t: TestContext) => Promise<void>) {
  test(name, async (t) => {
    if (process.versions.deno || process.versions.bun) {
      // The discovery-node transport's supported substrate is Node. Native
      // lanes run its real TLS contracts in Node and the core contract locally.
      const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const output = execFileSync("node", [
        "--unhandled-rejections=strict", "--experimental-strip-types", "--no-warnings",
        "--test", "--test-reporter=tap", `--test-name-pattern=^${escapedName}$`, fileURLToPath(import.meta.url),
      ], {encoding: "utf8", timeout: 30000});
      assert.match(output, new RegExp(`^ok \\d+ - ${escapedName}$`, "m"));
      assert.match(output, /^# pass 1$/m);
      assert.match(output, /^# fail 0$/m);
      t.diagnostic(`Node transport subprocess:\n${output}`);
      return;
    }
    await check(t);
  });
}
function response(
  authority: string,
  body: string,
  key: ReturnType<typeof createPrivateKey>,
  kid: string,
  time: number,
) {
  const digest = `sha-256=:${createHash("sha256").update(body).digest("base64")}:`;
  const input = `("@authority";req "content-digest");created=${time};expires=${time + 120};keyid="${kid}";tag="http-message-signatures-directory"`;
  const base = `"@authority";req: ${authority}\n"content-digest": ${digest}\n"@signature-params": ${input}`;
  return {
    body,
    headers: {
      "content-type": "application/http-message-signatures-directory+json",
      "content-digest": digest,
      "signature-input": `directory=${input}`,
      signature: `directory=:${sign(null, Buffer.from(base), key).toString("base64")}:`,
      "cache-control": "max-age=120",
    },
  };
}
transportTest("agent fields, trust sources, redirects, and CIMD links cannot connect to another origin", async (t) => {
  const h = await custody(), key = value(await h.publicKey()), kid = value(await key.thumbprint());
  const signingKey = createPrivateKey(readFileSync("conformance/sources/rfc9421/keys/ed25519_private.pem"));
  const {Discovery, DiscoverySource} = await import("../src/discovery/node.ts");
  let mode: "directory" | "redirect" | "cimd" | "delayed" = "directory";
  const heldResponses: (() => void)[] = [];
  const other = await peer((_req, res) => {
    const r = response(`127.0.0.1:${other.port}`, directory.body, signingKey, kid, now);
    res.writeHead(200, r.headers); res.end(r.body);
  });
  const server = await peer((_req, res) => {
    if (mode === "redirect") {res.writeHead(302, {location: `https://127.0.0.1:${other.port}/.well-known/http-message-signatures-directory`}); res.end(); return;}
    if (mode === "cimd") {res.writeHead(200, {"content-type": "application/json"}); res.end(JSON.stringify({client_id: `https://127.0.0.1:${server.port}/client`, jwks_uri: `https://127.0.0.1:${other.port}/jwks`})); return;}
    const r = response(`127.0.0.1:${server.port}`, directory.body, signingKey, kid, now);
    if (mode === "delayed") {heldResponses.push(() => {res.writeHead(200, r.headers); res.end(r.body);}); return;}
    res.writeHead(200, r.headers); res.end(r.body);
  });
  const location = `https://127.0.0.1:${server.port}`, otherLocation = `https://127.0.0.1:${other.port}`;
  const source = (at: string, extra = {}) => value(DiscoverySource.create({type: "directory", location: at, cacerts: [server.ca, other.ca], permittedAddresses: ["127.0.0.1"], ...extra}));
  const configured = source(location), otherSource = source(otherLocation);
  const cache = value(Seal.createCache({clock: () => now, fetch: Discovery.fetch}));
  const signAs = async (at: string, type = "directory") => value(await Seal.WebBotAuth.sign(value(await Seal.Message.request("GET", "https://example.com/resource", [], "")), {label: "agent", key, algorithm: "ed25519", agent: {location: at, type}, created: now, expires: now + 60, nonce: null}, (a: Seal.SigningAlgorithm, b: Uint8Array, c = value(Seal.withDeadline())) => h.sign(a, b, c)));
  try {
    // Positive controls prove both real peers and their connection counters work.
    value(await Discovery.fetch(otherSource, {clock: () => now}));
    assert.ok(other.connections > 0); assert.ok(other.requests > 0);
    const p = policy({cache, agents: (a: Seal.AgentRequest) => a.location === location ? Seal.ok(configured) : Seal.ok(null)});
    const signed = await signAs(location);
    value(await Seal.WebBotAuth.verify(signed, p));
    assert.ok(server.connections > 0); assert.ok(server.requests > 0);
    const connections = other.connections, requests = other.requests;
    const confined = (name: string) => {
      assert.equal(other.connections - connections, 0, name);
      assert.equal(other.requests - requests, 0, name);
      t.diagnostic(`${name}: other peer connections=0, requests=0`);
    };
    rejection(await Seal.WebBotAuth.verify(await signAs(otherLocation), p), "agent_unresolved", "untrusted_agent");
    confined("agent names another origin");
    rejection(await Seal.WebBotAuth.verify(signed, policy({cache, agents: (_a: unknown) => Seal.ok(otherSource)})), "agent_unresolved", "source_mismatch");
    confined("trust returns another source");
    mode = "redirect"; value(cache.invalidate(configured));
    rejection(await Seal.WebBotAuth.verify(signed, p), "agent_unresolved", "source_unavailable");
    confined("configured directory redirects");
    mode = "cimd";
    const cimdLocation = `${location}/client`, cimdSource = value(DiscoverySource.create({type: "cimd", location: cimdLocation, cacerts: [server.ca, other.ca], permittedAddresses: ["127.0.0.1"]}));
    rejection(await Seal.WebBotAuth.verify(await signAs(cimdLocation, "cimd"), policy({cache, agents: (_a: unknown) => Seal.ok(cimdSource)})), "agent_unresolved", "source_unavailable");
    confined("CIMD links another origin");
    // A source's shorter timeout leaves the envelope Context live for held keys.
    mode = "delayed";
    // Allow real TLS setup while keeping the source deadline below the envelope's.
    const timedSource = source(location, {timeoutMs: 1000});
    const timedCache = value(Seal.createCache({clock: () => now, fetch: Discovery.fetch}));
    let heldCalls = 0;
    try {
      const timeoutPolicy = policy({cache: timedCache, agents: (_a: unknown) => Seal.ok(timedSource)});
      rejection(await Seal.WebBotAuth.verify(signed, timeoutPolicy, {timeoutMs: 5000}), "agent_unresolved", "timeout");
      // Invalidate the negative-cache observation before exercising live fallback.
      value(timedCache.invalidate(timedSource));
      const fallback = value(await Seal.WebBotAuth.verify(signed, policy({cache: timedCache, agents: (_a: unknown) => Seal.ok(timedSource), unresolved: {heldKeys: (_a: unknown) => {heldCalls++; return Seal.ok({algorithm: "ed25519", key});}}}), {timeoutMs: 5000}));
      assert.equal(heldResponses.length, 2, "both timeouts reach the real directory peer");
      assert.equal(heldCalls, 1);
      assert.equal(fallback.signatures.agent!.principal.kind, "key");
      t.diagnostic("source timeout with live envelope Context: held-key calls=1, accepted");
    } finally {timedCache.close();}
  } finally {for (const release of heldResponses) release(); cache.close(); await server.close(); await other.close(); await h.release();}
});
transportTest("real signed TLS directories prove possession, rotate keys, remove keys, and preserve source binding", async (t) => {
  const h = await custody(),
    key = value(await h.publicKey()),
    kid = value(await key.thumbprint());
  const signingKey = createPrivateKey(
    readFileSync("conformance/sources/rfc9421/keys/ed25519_private.pem"),
  );
  let current: ReturnType<typeof response>;
  let holdResponse = false;
  const heldResponses: (() => void)[] = [];
  const server = await peer((_req, res) => {
    const reply = () => {
      res.writeHead(200, current.headers);
      res.end(current.body);
    };
    if (holdResponse) heldResponses.push(reply);
    else reply();
  });
  const location = `https://127.0.0.1:${server.port}`,
    authority = `127.0.0.1:${server.port}`;
  const { Discovery, DiscoverySource } =
    await import("../src/discovery/node.ts");
  const source = value(
    DiscoverySource.create({
      type: "directory",
      location,
      cacerts: [server.ca],
      permittedAddresses: ["127.0.0.1"],
    }),
  );
  const cache = value(
    Seal.createCache({ clock: () => now, fetch: Discovery.fetch }),
  );
  try {
    current = response(authority, directory.body, signingKey, kid, now);
    const set = value(await Discovery.fetch(source, { clock: () => now }));
    assert.equal(set.proof, "signed");
    assert.equal(Object.keys(set.keys).length, 2);
    const signer = (
      a: Seal.SigningAlgorithm,
      b: Uint8Array,
      c = value(Seal.withDeadline()),
    ) => h.sign(a, b, c);
    const unsigned = value(
      await Seal.Message.request("GET", "https://example.com/resource", [], ""),
    );
    const signed = value(
      await Seal.WebBotAuth.sign(
        unsigned,
        {
          label: "agent",
          agent: { location, type: "directory" },
          key,
          algorithm: "ed25519",
          created: now,
          expires: now + 60,
          nonce: "tls-nonce",
        },
        signer,
      ),
    );
    const p = policy({
      cache,
      agents: (a: Seal.AgentRequest) =>
        a.location === location ? Seal.ok(source) : Seal.ok(null),
    });
    const r = value(await Seal.WebBotAuth.verify(signed, p));
    const principal = r.signatures.agent!.principal;
    assert.equal(principal.kind, "agent");
    if (principal.kind === "agent") {
      assert.equal(principal.provenance.proof, "signed");
      assert.equal(principal.identifier, source.location);
      assert.equal(principal.origin, location);
    }
    t.diagnostic(
      `signed directory: proof=signed, valid request=accepted, TLS requests=${server.requests}`,
    );
    const pair = generateKeyPairSync("ed25519"),
      jwk = pair.publicKey.export({ format: "jwk" }),
      nextKey = value(await Seal.PublicKey.import(jwk)),
      nextId = value(await nextKey.thumbprint());
    current = response(
      authority,
      JSON.stringify({ keys: [jwk] }),
      pair.privateKey,
      nextId,
      now,
    );
    value(await cache.refresh(source));
    rejection(
      await Seal.WebBotAuth.verify(signed, p),
      "agent_unresolved",
      "unknown_key",
    );
    const nextHandle = value(
      await Seal.Custody.local(
        "ed25519",
        pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
      ),
    );
    try {
      const nextSigner = (
        a: Seal.SigningAlgorithm,
        b: Uint8Array,
        c = value(Seal.withDeadline()),
      ) => nextHandle.sign(a, b, c);
      const rotated = value(
        await Seal.WebBotAuth.sign(
          unsigned,
          {
            label: "agent",
            agent: { location, type: "directory" },
            key: nextKey,
            algorithm: "ed25519",
            created: now,
            expires: now + 60,
            nonce: "rotated",
          },
          nextSigner,
        ),
      );
      value(await Seal.WebBotAuth.verify(rotated, p));
      value(cache.remove(source, nextId));
      rejection(
        await Seal.WebBotAuth.verify(rotated, p),
        "agent_unresolved",
        "revoked_key",
      );
      value(cache.invalidate(source));
      rejection(
        await Seal.WebBotAuth.verify(rotated, p),
        "agent_unresolved",
        "revoked_key",
      );
      t.diagnostic(
        "rotation: old key=unknown_key, new key=accepted; removal: revoked_key before and after invalidation",
      );
      const revoked = value(
        DiscoverySource.create({
          type: "directory",
          location,
          cacerts: [server.ca],
          permittedAddresses: ["127.0.0.1"],
          revoked: [nextId],
        }),
      );
      rejection(
        await Seal.WebBotAuth.verify(
          rotated,
          policy({ agents: (_a: unknown) => Seal.ok(revoked), cache }),
        ),
        "agent_unresolved",
        "revoked_key",
      );
    } finally {
      await nextHandle.release();
    }
    // Return a fresh real directory snapshot under another source. Trust alone cannot bind it.
    const other = value(
      await Seal.Discovery.resolver.fromSnapshot(
        {
          type: "directory",
          location: "https://other.example",
          requireSignedDirectory: false,
        },
        new TextEncoder().encode(directory.body),
        now,
        [
          [
            "content-type",
            "application/http-message-signatures-directory+json",
          ],
        ],
      ),
    );
    rejection(
      await Seal.WebBotAuth.verify(
        signed,
        policy({ agents: (_a: unknown) => Seal.ok(other) }),
      ),
      "agent_unresolved",
      "source_mismatch",
    );
    current = response(authority, directory.body, signingKey, kid, now);
    current.headers.signature = "directory=:AAAA:";
    value(cache.invalidate(source));
    rejection(
      await Seal.WebBotAuth.verify(signed, p),
      "agent_unresolved",
      "source_unavailable",
    );
    current = response(authority, directory.body, signingKey, kid, now);
    holdResponse = true;
    const timedSource = value(DiscoverySource.create({
      type: "directory", location, cacerts: [server.ca],
      permittedAddresses: ["127.0.0.1"], timeoutMs: 300,
    }));
    const timedCache = value(
      Seal.createCache({ clock: () => now, fetch: Discovery.fetch }),
    );
    try {
      rejection(
        await Seal.WebBotAuth.verify(signed, policy({
          cache: timedCache, agents: (_a: unknown) => Seal.ok(timedSource),
        }), { timeoutMs: 5000 }),
        "agent_unresolved",
        "timeout",
      );
      assert.equal(heldResponses.length, 1, "timeout reaches the real directory peer");
    } finally { timedCache.close(); }
    t.diagnostic(
      "invalid possession proof=source_unavailable; delayed real TLS discovery=timeout; source mismatch=rejected",
    );
  } finally {
    for (const release of heldResponses) release();
    cache.close();
    await server.close();
    await h.release();
  }
});
test("OpenSSL protocol signatures verify from published bases without using library signing", async (t) => {
  const root = mkdtempSync(resolve("test/.tmp-wba-openssl-"));
  try {
    const v = published.find((v) => v.section === "E.2.1")!;
    writeFileSync(join(root, "base"), v.base);
    const signature = execFileSync(
      "openssl",
      [
        "pkeyutl",
        "-sign",
        "-rawin",
        "-inkey",
        resolve("conformance/sources/rfc9421/keys/ed25519_private.pem"),
        "-in",
        join(root, "base"),
      ],
      { timeout: 10000 },
    );
    assert.equal(
      `sig2=:${signature.toString("base64")}:`,
      v.fields.find(([n]) => n === "Signature")![1],
    );
    const p = await import("./support/web-bot-auth.ts");
    const m = value(
      await Seal.Message.request(
        "GET",
        "https://example.com/resource",
        v.fields,
        "",
      ),
    );
    const set = value(
      await p.trust({
        type: "directory",
        location: "https://signature-agent.test",
        identifier: "",
      }),
    );
    const key = Object.values(set.keys).find(
      (k) => k.algorithm === "ed25519",
    )!.key;
    value(
      await Seal.verify(
        m,
        value(
          Seal.Policy.create({
            algorithms: ["ed25519"],
            components: "()",
            keyResolver: async () => Seal.ok({ algorithm: "ed25519", key }),
            freshness: "not_evaluated",
            content: "not_required",
            replay: "not_required",
            fieldSchemas: (
              await import("../src/web-bot-auth/support.ts")
            ).schemas({}),
          }),
        ),
        { label: "sig2" },
      ),
    );
    rejection(
      await Seal.WebBotAuth.verify(m, policy()),
      "agent_unresolved",
      "missing_member",
    );
    t.diagnostic(
      "OpenSSL exact protocol-00 E.2.1 bytes=equal; generic crypto=valid; profile=missing_member (published mismatch retained)",
    );
    const independent = p.requests.find((v) => v.name === "directory")!;
    writeFileSync(join(root, "base"), independent.base);
    const acceptedSignature = execFileSync(
      "openssl",
      [
        "pkeyutl",
        "-sign",
        "-rawin",
        "-inkey",
        resolve("conformance/sources/rfc9421/keys/ed25519_private.pem"),
        "-in",
        join(root, "base"),
      ],
      { timeout: 10000 },
    );
    assert.equal(
      `agent=:${acceptedSignature.toString("base64")}:`,
      independent.fields.find(([name]) => name === "Signature")![1],
    );
    const accepted = value(
      await Seal.Message.request(
        "GET",
        independent.target,
        independent.fields.map(([name, wire]) => [
          name,
          name === "Signature"
            ? `agent=:${acceptedSignature.toString("base64")}:`
            : wire,
        ]),
        "",
      ),
    );
    value(await Seal.WebBotAuth.verify(accepted, policy()));
    t.diagnostic(
      "OpenSSL conforming protocol-00 request: independent base bytes=equal, Web Bot Auth=accepted",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
