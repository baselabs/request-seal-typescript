import test from "node:test";
import { nodeAdapterTest } from "./support/node-adapter-test.ts";
const socketTest = nodeAdapterTest(import.meta.url);
import assert from "node:assert/strict";
import {spawn} from "node:child_process";
import {spawnWithEnvSync as spawnSync} from "./support/child-env.ts";
import { mkdtemp, readFile, writeFile, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createServer } from "node:net";
import { once } from "node:events";
import * as adapter from "../src/custody/ssh-agent/index.ts";
import {
  PublicKey,
  Crypto,
  withDeadline,
  encodeBase64Url,
  type SigningAlgorithm,
  type Result,
} from "../src/index.ts";
import { sequence, integer } from "../src/custody/der.ts";
import { unsigned } from "../src/crypto/primitive.ts";
function value<T>(r: Result<T>): T {
  if (!r.ok) assert.fail(JSON.stringify(r.error));
  return r.value;
}
async function publicFile(path: string): Promise<PublicKey> {
  const line = await readFile(path + ".pub", "utf8");
  const blob = Buffer.from(line.split(" ")[1]!, "base64");
  let pos = 0;
  const string = () => {
    const size = blob.readUInt32BE(pos);
    pos += 4;
    const out = blob.subarray(pos, pos + size);
    pos += size;
    return out;
  };
  const type = string().toString();
  let jwk: unknown;
  if (type === "ssh-ed25519")
    jwk = { kty: "OKP", crv: "Ed25519", x: encodeBase64Url(string()) };
  else if (type === "ssh-rsa") {
    const magnitude = (v: Uint8Array) => (v[0] === 0 ? v.subarray(1) : v);
    const e = string(),
      n = string();
    jwk = {
      kty: "RSA",
      e: encodeBase64Url(magnitude(e)),
      n: encodeBase64Url(magnitude(n)),
    };
  } else {
    const curve = string().toString(),
      point = string(),
      width = (point.length - 1) / 2;
    jwk = {
      kty: "EC",
      crv: curve === "nistp256" ? "P-256" : "P-384",
      x: encodeBase64Url(point.subarray(1, 1 + width)),
      y: encodeBase64Url(point.subarray(1 + width)),
    };
  }
  return value(await PublicKey.import(jwk));
}
test(
  "binds exact agent keys and verifies each signature with OpenSSL",
  { timeout: 30000 },
  async (t) => {
    assert.equal(
      typeof adapter.createSshAgent,
      "function",
      "createSshAgent must bind a real OpenSSH agent",
    );
    const root = await mkdtemp(join(tmpdir(), "rsa-")),
      socket = join(root, "socket");
    const processAgent = spawn("ssh-agent", ["-D", "-a", socket], {
      stdio: "ignore",
    });
    const command = (program: string, args: string[]) => {
      const r = spawnSync(program, args, {
        env: { ...process.env, SSH_AUTH_SOCK: socket },
        encoding: "utf8",
        timeout: 10000,
      });
      t.diagnostic(
        `${program} ${args.map((a) => (a.startsWith(root) ? a.replace(root, "<keys>") : a)).join(" ")} => exit ${r.status} ${r.stdout.toString().trim()}`,
      );
      assert.equal(r.status, 0, r.stderr.toString());
    };
    try {
      for (let i = 0; ; i++) {
        try {
          await stat(socket);
          break;
        } catch {
          assert.ok(i < 100, "agent creates its socket");
          await new Promise((r) => setTimeout(r, 10));
        }
      }
      const data = new TextEncoder().encode("agent signature cross-check");
      await writeFile(join(root, "data"), data);
      // Load a different key first so selection and removal cannot pass against an empty agent.
      const other = join(root, "other-ed25519");
      command("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", other]);
      command("ssh-add", [other]);
      for (const [type, bits, algorithm, jws] of [
        ["ed25519", null, "ed25519", "EdDSA"],
        ["ecdsa", "256", "ecdsa-p256-sha256", "ES256"],
        ["ecdsa", "384", "ecdsa-p384-sha384", "ES384"],
        ["rsa", "2048", "rsa-v1_5-sha256", "RS256"],
      ] as const) {
        const path = join(root, type + (bits ?? ""));
        command("ssh-keygen", [
          "-q",
          "-t",
          type,
          ...(bits ? ["-b", bits] : []),
          "-N",
          "",
          "-f",
          path,
        ]);
        command("ssh-add", [path]);
        const pub = await publicFile(path);
        await writeFile(join(root, "public.pem"), value(pub.pem()));
        for (const selection of [algorithm, { jws }] as SigningAlgorithm[]) {
          const handle = value(
            await adapter.createSshAgent(selection, socket, pub),
          );
          const context = value(withDeadline());
          const signature = value(await handle.sign(selection, data, context));
          assert.equal(
            (await Crypto.verify(selection, pub, signature, data)).ok,
            true,
          );
          assert.equal(
            (
              await Crypto.verify(
                selection,
                pub,
                signature,
                new Uint8Array([1]),
              )
            ).ok,
            false,
          );
          const sig =
            type === "ecdsa"
              ? sequence(
                  integer(
                    unsigned(signature.subarray(0, signature.length / 2)),
                  ),
                  integer(unsigned(signature.subarray(signature.length / 2))),
                )
              : signature;
          await writeFile(join(root, "signature"), sig);
          command(
            "openssl",
            type === "ed25519"
              ? [
                  "pkeyutl",
                  "-verify",
                  "-pubin",
                  "-inkey",
                  join(root, "public.pem"),
                  "-rawin",
                  "-in",
                  join(root, "data"),
                  "-sigfile",
                  join(root, "signature"),
                ]
              : [
                  "dgst",
                  bits === "384" ? "-sha384" : "-sha256",
                  "-verify",
                  join(root, "public.pem"),
                  "-signature",
                  join(root, "signature"),
                  join(root, "data"),
                ],
          );
          await handle.release();
        }
        const handle = value(
          await adapter.createSshAgent(algorithm, socket, pub),
        );
        command("ssh-add", ["-d", path]);
        const removed = await handle.sign(
          algorithm,
          data,
          value(withDeadline()),
        );
        assert.equal(removed.ok, false);
        if (!removed.ok) assert.equal(removed.error.reason, "key_not_found");
        await handle.release();
      }
      const wrong = join(root, "absent");
      command("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", wrong]);
      const rejected = await adapter.createSshAgent(
        "ed25519",
        socket,
        await publicFile(wrong),
      );
      assert.equal(rejected.ok, false);
      if (!rejected.ok)
        assert.equal(rejected.error.reason, "custodian_rejected");
    } finally {
      processAgent.kill("SIGTERM");
      await once(processAgent, "exit");
      await rm(root, { recursive: true, force: true });
    }
  },
);
socketTest("bounds malformed agent frames and deadline sockets", async () => {
  const root = await mkdtemp(join(tmpdir(), "rsf-")),
    socket = join(root, "socket");
  const pub = value(
    await PublicKey.import({
      kty: "OKP",
      crv: "Ed25519",
      x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    }),
  );
  const server = createServer((s) =>
    s.once("data", () => s.end(Buffer.from([0, 16, 0, 1]))),
  );
  server.listen(socket);
  await once(server, "listening");
  try {
    const r = await adapter.createSshAgent("ed25519", socket, pub);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.error.reason, "custodian_protocol");
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    await rm(root, { recursive: true, force: true });
  }
  const unavailable = await adapter.createSshAgent("ed25519", socket, pub);
  assert.equal(unavailable.ok, false);
  if (!unavailable.ok)
    assert.equal(unavailable.error.reason, "custodian_unavailable");
});

socketTest("cancels a pending agent exchange and closes the owned socket", async () => {
  const root = await mkdtemp(join(tmpdir(), "rsd-")),
    socket = join(root, "socket");
  const pub = value(
    await PublicKey.import({
      kty: "OKP",
      crv: "Ed25519",
      x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    }),
  );
  const controller = new AbortController();
  let closed: Promise<unknown> | undefined;
  const server = createServer((s) => {
    closed = once(s, "close");
    s.once("data", () => controller.abort());
  });
  server.listen(socket);
  await once(server, "listening");
  try {
    const r = await adapter.createSshAgent("ed25519", socket, pub, {
      context: value(withDeadline({signal: controller.signal})),
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.error.reason, "deadline_exceeded");
    assert.ok(closed, "the faulty peer must accept the socket before cancellation");
    await closed;
    closed = undefined;
    const timed = await adapter.createSshAgent("ed25519", socket, pub, {timeoutMs: 1000});
    assert.equal(timed.ok, false);
    if (!timed.ok) assert.equal(timed.error.reason, "deadline_exceeded");
    assert.ok(closed, "the faulty peer must accept the socket before the deadline");
    await closed;
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    await rm(root, { recursive: true, force: true });
  }
});

socketTest('forwards selected byte bounds to a real agent and reports its observed refusal', {timeout: 30000}, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rsbytes-')), socket = join(root, 'socket');
  const agent = spawn('ssh-agent', ['-D', '-a', socket], {stdio: 'ignore'});
  let handle: import('../src/index.ts').KeyHandle | undefined;
  try {
    for (let i = 0; ; i++) {
      try {await stat(socket); break;} catch {assert.ok(i < 100); await new Promise(r => setTimeout(r, 10));}
    }
    const run = (program: string, args: string[]) => {
      const r = spawnSync(program, args, {encoding: 'utf8', env: {...process.env, SSH_AUTH_SOCK: socket}, timeout: 10000});
      assert.equal(r.status, 0, r.stderr.toString()); return r;
    };
    const version = run('ssh', ['-V']); t.diagnostic((version.stdout.toString() + version.stderr.toString()).trim());
    const path = join(root, 'ed25519'); run('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', path]); run('ssh-add', [path]);
    const pub = await publicFile(path); handle = value(await adapter.createSshAgent('ed25519', socket, pub));
    const sign = (size: number) => (handle!.sign as (a: unknown, d: unknown, c: import('../src/context.ts').Context, o?: unknown) => Promise<Result<Uint8Array<ArrayBuffer>>>)('ed25519', new Uint8Array(size), value(withDeadline()), {maxBytes: 16_777_216});
    value(await sign(262_000));
    let accepted = 262_000, refused = 524_288;
    const first = await sign(refused); assert.equal(first.ok, false); if (!first.ok) assert.equal(first.error.reason, 'custodian_protocol');
    while (refused - accepted > 1) {
      const size = Math.floor((accepted + refused) / 2), r = await sign(size);
      if (r.ok) accepted = size;
      else {assert.equal(r.error.reason, 'custodian_protocol'); refused = size;}
    }
    value(await sign(accepted));
    const over = await sign(refused); assert.equal(over.ok, false); if (!over.ok) assert.equal(over.error.reason, 'custodian_protocol');
    t.diagnostic(`Observed Ed25519 payload: ${accepted} accepted; ${refused} refused as custodian_protocol. This is a machine observation, not a portable byte-count assertion.`);
    for (const size of [1_048_577, 16_777_216]) {
      const r = await sign(size); assert.equal(r.ok, false); if (!r.ok) assert.equal(r.error.reason, 'custodian_protocol');
    }
  } finally {
    if (handle) await handle.release(); agent.kill('SIGTERM'); await once(agent, 'exit'); await rm(root, {recursive: true, force: true});
  }
});

socketTest('direct agent callbacks bound input before released state and verify at the ceiling', async () => {
  const {Custody} = await import('../src/index.ts');
  const {AgentPort} = await import('../src/custody/ssh-agent/port.ts');
  const {resolveAlgorithm} = await import('../src/crypto/algorithm.ts');
  const local = value(await Custody.local('ed25519', await readFile('test/fixtures/upstream/crypto/ed25519_private.pem', 'utf8')));
  try {
    const port = new AgentPort('/unused', value(await local.publicKey()), value(resolveAlgorithm('ed25519')));
    const sign = Crypto.sign as (a: unknown, k: unknown, d: unknown, o?: unknown) => Promise<Result<Uint8Array<ArrayBuffer>>>;
    const data = new Uint8Array(16_777_216), sig = value(await sign('ed25519', local, data, {maxBytes: 16_777_216}));
    value(await port.verify('ed25519', sig, data, value(withDeadline())));
    await port.release();
    for (const input of [new Uint8Array(16_777_217), 'not binary', null]) {
      for (const r of [await port.sign('unknown', input, value(withDeadline())), await port.verify('unknown', sig, input, value(withDeadline()))]) {
        assert.equal(r.ok, false); if (!r.ok) {assert.equal(r.error.kind, 'custody'); assert.equal(r.error.reason, 'invalid_data');}
      }
    }
  } finally {await local.release();}
});
