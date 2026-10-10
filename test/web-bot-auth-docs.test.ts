import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  generateKeyPairSync,
  createHash,
  sign,
} from "node:crypto";
import * as Seal from "../src/index.ts";
import { value } from "./support/web-bot-auth.ts";
test("native and built lanes include the real Web Bot Auth discovery contracts", () => {
  const workflow = readFileSync(".github/workflows/ci.yml", "utf8");
  const commands = workflow.split("\n").map(line => line.trim());
  const deno = commands.find(line => line.startsWith("deno test --no-check "));
  const bun = commands.find(line => line.startsWith("bun test ") && !line.includes("test/red/"));
  assert.ok(deno);
  assert.ok(bun);
  for (const lane of [deno, bun])
    assert.ok(lane.includes("test/web-bot-auth-discovery.test.ts") || lane.includes("test/*.test.ts"));
  assert.ok(/--allow-net(=| |$)/.test(deno));
  assert.ok(deno.includes("--allow-run=deno,node,"));
  const built = readFileSync("scripts/test-built.ts", "utf8");
  assert.match(built, /'web-bot-auth-discovery'/);
});
test("deadline documentation distinguishes resolution and per-signature phases", () => {
  const doc = readFileSync("docs/reference/web-bot-auth.md", "utf8");
  assert.match(doc, /trust or discovery[^.]*agent_unresolved[^.]*timeout/s);
  assert.match(doc, /per-signature check[^.]*retryable[^.]*custody\/deadline_exceeded/s);
});
test("nested evidence documentation requires intersection with verified signatures", () => {
  const doc = readFileSync("docs/reference/web-bot-auth.md", "utf8");
  assert.match(doc, /evidence records coverage only/);
  assert.match(doc, /inner label[^.]*untagged or unverified/s);
  assert.match(doc, /intersect[^.]*evidence[^.]*signatures/s);
});
test("held-key documentation names eligible failures and non-bypassable failures", () => {
  const doc = readFileSync("docs/reference/web-bot-auth.md", "utf8");
  assert.match(doc, /after refused trust, an unsupported agent type, an unknown key,[\s\S]*an unavailable source, or a timeout/);
  assert.match(doc, /never after `revoked_key`, `source_mismatch`, or `not_an_origin`/);
  assert.match(doc, /expired Context prevents[^.]*callback/s);
});
test("origin documentation records host normalization and the corpus gap", () => {
  const doc = readFileSync("docs/reference/web-bot-auth.md", "utf8");
  for (const text of ["WHATWG URL", "https://[0:0::1]", "https://0x7f.1", "not_an_origin", "reference compares the host text", "TypeScript fails closed", "No corpus case covers"]) assert.ok(doc.includes(text), text);
  for (const text of ["three-key", "sign()", "WebBotAuth.sign", "KeyHandle and any callable", "reference requires a two-argument function", "No wire bytes change"]) assert.ok(doc.includes(text), text);
  assert.match(doc, /`agents` and `heldKeys` accept any callable, while the reference requires arity-one functions\.\s+Results are validated at invocation\./);
});
test("generic verification documentation describes profile and principal narrowing", () => {
  const doc = readFileSync("docs/reference/sign-and-verify.md", "utf8");
  for (const text of ["Verification.profile", "Verification.principal", "unions", "rfc9421", "web_bot_auth", "unattributed", "agent principal", "held-key principal", "narrow `principal` before use"]) assert.ok(doc.includes(text), text);
  assert.match(doc, /Every Verification prints and serializes to JSON as[^.]*`label`, `profile`, `replay`, and `authorization` only/s);
  assert.match(doc, /full facts call `serializeVerification\(\)`\./s);
  assert.doesNotMatch(doc, /verificationFacts/);
});
test("JOSE documentation describes callable signers and branded handles", () => {
  const doc = readFileSync("docs/reference/jose.md", "utf8");
  for (const text of ["branded KeyHandle", "any callable", "Function length does not determine validity", "algorithm_mismatch", "reference requires a two-argument function", "without changing wire bytes"]) assert.ok(doc.includes(text), text);
});
test("README Web Bot Auth quick start executes with real cryptography and a signed snapshot", async () => {
  const now = Math.floor(Date.now() / 1000),
    pair = generateKeyPairSync("ed25519"),
    key = value(
      await Seal.PublicKey.import(pair.publicKey.export({ format: "jwk" })),
    ),
    kid = value(await key.thumbprint());
  const body = JSON.stringify({ keys: [value(key.jwk())] }),
    digest = `sha-256=:${createHash("sha256").update(body).digest("base64")}:`;
  const params = `("@authority";req "content-digest");created=${now};expires=${now + 60};keyid="${kid}";tag="http-message-signatures-directory"`;
  const base = `"@authority";req: agent.example\n"content-digest": ${digest}\n"@signature-params": ${params}`;
  const keySet = value(
    await Seal.Discovery.resolver.fromSnapshot(
      { type: "directory", location: "https://agent.example" },
      new TextEncoder().encode(body),
      now,
      [
        ["content-type", "application/http-message-signatures-directory+json"],
        ["content-digest", digest],
        ["signature-input", `directory=${params}`],
        [
          "signature",
          `directory=:${sign(null, Buffer.from(base), pair.privateKey).toString("base64")}:`,
        ],
      ],
    ),
  );
  const handle = value(
    await Seal.Custody.local(
      "ed25519",
      pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
    ),
  );
  try {
    const signer = (
      a: Seal.SigningAlgorithm,
      b: Uint8Array,
      c = value(Seal.withDeadline()),
    ) => handle.sign(a, b, c);
    const message = value(
      await Seal.WebBotAuth.sign(
        value(
          await Seal.Message.request("GET", "https://example.com/a", [], ""),
        ),
        {
          label: "agent",
          key,
          algorithm: "ed25519",
          agent: { location: "https://agent.example", type: "directory" },
          created: now,
          expires: now + 60,
          nonce: null,
        },
        signer,
      ),
    );
    const readme = readFileSync("README.md", "utf8")
      .split("## Web Bot Auth")[1]!
      .split("## JOSE")[0]!;
    const original = /```ts\n([\s\S]*?)\n```/.exec(readme)![1]!;
    const replaced = original.replace(
        'import { WebBotAuth, ok, type AgentRequest } from "@request-seal/core";',
        "const { WebBotAuth, ok } = await import(moduleUrl);",
      );
    assert.notEqual(replaced, original, 'README Web Bot Auth import must be replaced');
    const fence = replaced.replace(": AgentRequest", "");
    const execute = new Function(
      "moduleUrl",
      "keySet",
      "message",
      "now",
      `return (async () => { ${fence}\nreturn authenticated; })();`,
    ) as (
      url: string,
      set: Seal.KeySet,
      message: Seal.Message,
      now: number,
    ) => Promise<Seal.Result<Seal.WebBotAuthVerification>>;
    const verified = value(
      await execute(
        new URL("../src/index.ts", import.meta.url).href,
        keySet,
        message,
        now,
      ),
    );
    assert.equal(verified.signatures.agent!.principal.kind, "agent");
  } finally {
    await handle.release();
  }
});
