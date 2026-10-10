import { nodeAdapterTest } from "./support/node-adapter-test.ts";
const test = nodeAdapterTest(import.meta.url);
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { createServer } from "node:http";
import { once } from "node:events";
import {spawn} from "node:child_process";
import {execFileWithEnvSync as execFileSync, spawnWithEnvSync as spawnSync} from "./support/child-env.ts";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  Custody,
  encodeBase64Url,
  ok,
  Policy,
  PublicKey,
  type Result,
} from "../src/index.ts";
import { signedRequest } from "../src/adapters/node-http/index.ts";
function value<T>(r: Result<T>): T {
  if (!r.ok) assert.fail(JSON.stringify(r.error));
  return r.value;
}
test("executes every README TypeScript fence with real inputs and parses verified JSON", async () => {
  const readme = await readFile("README.md", "utf8");
  const fences = [...readme.matchAll(/```(?:ts|typescript)\n([\s\S]*?)```/g)]
    .map((m) => m[1]!);
  assert.ok(
    fences.length > 0,
    "README contains executable TypeScript examples",
  );
  const AsyncFunction = Object.getPrototypeOf(async () => {})
    .constructor as new (
      ...s: string[]
    ) => (...a: unknown[]) => Promise<unknown>;
  const root = await mkdtemp(join(tmpdir(), "rsdoc-"));
  const socket = join(root, "s");
  const agent = spawn("ssh-agent", ["-D", "-a", socket], { stdio: "ignore" });
  let server: ReturnType<typeof createServer> | undefined;
  const h = value(
    await Custody.local("hmac-sha256", {
      hmac: crypto.getRandomValues(new Uint8Array(32)),
    }),
  );
  try {
    for (let i = 0;; i++) {
      try {
        await stat(socket);
        break;
      } catch {
        assert.ok(i < 500, "agent socket must appear within five seconds");
        await new Promise((r) => setTimeout(r, 10));
      }
    }
    for (
      const [cmd, args] of [["ssh-keygen", [
        "-q",
        "-t",
        "ed25519",
        "-N",
        "",
        "-f",
        join(root, "key"),
      ]], ["ssh-add", [join(root, "key")]]] as [string, string[]][]
    ) {
      const p = spawnSync(cmd, args, {
        env: { ...process.env, SSH_AUTH_SOCK: socket },
        encoding: "utf8",
      });
      assert.equal(p.status, 0, p.stderr);
    }
    const blob = Buffer.from(
      (await readFile(join(root, "key.pub"), "utf8")).split(" ")[1]!,
      "base64",
    );
    const offset = 4 + blob.readUInt32BE(0);
    const pub = value(
      await PublicKey.import({
        kty: "OKP",
        crv: "Ed25519",
        x: encodeBase64Url(blob.subarray(offset + 4)),
      }),
    );
    const source = (f: string) => {
      const code = f.replace(
        /import\s+\{([^}]+)\}\s+from\s+"(@request-seal\/core[^" ]*)";/g,
        (_m, bindings: string, name: string) =>
          `const {${bindings}} = await import(${
            JSON.stringify(
              new URL(
                name === "@request-seal/core"
                  ? "../src/index.ts"
                  : name.endsWith("node-http")
                  ? "../src/adapters/node-http/index.ts"
                  : name.endsWith("fetch")
                  ? "../src/adapters/fetch/index.ts"
                  : "../src/custody/ssh-agent/index.ts",
                import.meta.url,
              ).href,
            )
          });`,
      );
      assert.notEqual(code, f, 'README fence import must be replaced');
      assert.doesNotMatch(code, /from\s+["']@request-seal\/core/, 'Every scoped fence import must be replaced');
      return code;
    };

    const policy = value(Policy.create({
      algorithms: ["hmac-sha256"],
      components: '("@method" "content-digest")',
      keyResolver: () => ok({ algorithm: "hmac-sha256", key: h }),
      freshness: "not_evaluated",
      content: { kind: "content", algorithms: ["sha-256"], section: "headers" },
      replay: "not_required",
    }));
    const spec = {
      label: "sig",
      components: '("@method" "content-digest")',
      algorithm: "hmac-sha256",
      expiresIn: 60,
      digest: ["sha-256"],
    };
    server = createServer();
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const a = server.address();
    assert.ok(a && typeof a === "object");
    for (const fence of fences) {
      const code = source(fence);
      server.removeAllListeners("request");
      if (/async function authenticate\b/.test(fence)) {
        let outcome: Promise<void> | undefined;
        server.on("request", (req, res) => {
          outcome = (async () => {
            value(
              await new AsyncFunction(
                "req",
                "policy",
                code + "\nreturn authenticate(req,policy);",
              )(req, policy) as Result<unknown>,
            );
            assert.deepEqual((req as typeof req & { body: unknown }).body, {
              a: 1,
            });
          })();
          void outcome.finally(() => res.end()).catch(() => {});
        });
        value(
          await signedRequest(
            {
              url: `http://127.0.0.1:${a.port}/`,
              method: "POST",
              body: new TextEncoder().encode('{"a":1}'),
            },
            spec,
            h,
          ),
        );
        await outcome;
      } else if (/async function send\b/.test(fence)) {
        server.on("request", (req, res) => {
          req.resume();
          res.end();
        });
        value(
          await new AsyncFunction(
            "url",
            "spec",
            "signer",
            code + "\nreturn send(url,spec,signer);",
          )(`http://127.0.0.1:${a.port}/`, spec, h) as Result<unknown>,
        );
      } else if (/async function bindAgent\b/.test(fence)) {
        const bound = value(
          await new AsyncFunction(
            "socketPath",
            "publicKey",
            code + "\nreturn bindAgent(socketPath,publicKey);",
          )(socket, pub) as Result<{ release: () => Promise<unknown> }>,
        );
        await bound.release();
      } else if (/WebBotAuth\.verify\(message|async function authenticateBot\b/.test(fence)) {
        // This fence needs its signed directory and typed agent inputs. Its
        // dedicated contract executes the exact README fence with real keys.
        const env = { ...process.env };
        delete env.NODE_TEST_CONTEXT;
        const botAdapter = /async function authenticateBot\b/.test(fence);
        const output = execFileSync("node", [
          "--experimental-strip-types", "--no-warnings", "--test",
          "--test-reporter=tap", botAdapter
            ? "--test-name-pattern=^README Node Web Bot Auth example"
            : "--test-name-pattern=^README Web Bot Auth quick start",
          botAdapter ? "test/adapters-node-web-bot-auth.test.ts" : "test/web-bot-auth-docs.test.ts",
        ], { encoding: "utf8", timeout: 30000, env });
        assert.match(output, /^# pass 1$/m);
        assert.match(output, /^# fail 0$/m);
      } else {
        await new AsyncFunction(code)();
      }
    }
  } finally {
    if (server) {
      server.closeAllConnections();
      await new Promise<void>((r) => server!.close(() => r()));
    }
    agent.kill("SIGTERM");
    await once(agent, "exit");
    await rm(root, { recursive: true, force: true });
    await h.release();
  }
});
