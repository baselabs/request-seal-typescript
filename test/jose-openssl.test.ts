import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import {
  Custody,
  JWE,
  KeyManagement,
  withDeadline,
  ok,
  encodeBase64Url,
  decodeBase64Url,
  type Context,
  type JoseProtectedHeader,
} from "../src/index.ts";
import { writePem } from "../src/custody/der.ts";
import { value } from "./support/jose-oaep.ts";
function decode(s: string | undefined) {
  return value(decodeBase64Url(s));
}
test("OpenSSL reciprocates OAEP, GCM key wrapping and direct GCM in both directions", async (t) => {
  const root = await mkdtemp("test/.tmp-jose-openssl-");
  const command = (tool: string, args: string[], expected = 0) => {
    const shellPeer = "Deno" in globalThis && tool.endsWith("/gcm-peer");
    const r = spawnSync(
      shellPeer ? "sh" : tool,
      shellPeer
        ? ["-c", 'exec "$@"', "request-seal-openssl-gcm", tool, ...args]
        : args,
      {
        encoding: "utf8",
        timeout: 20000,
        maxBuffer: 1048576,
      },
    );
    t.diagnostic("COMMAND: " + tool + " " + args.join(" "));
    assert.equal(r.error, undefined, String(r.error));
    t.diagnostic(
      "RESULT: exit=" +
        r.status +
        " " +
        r.stdout.trim() +
        " " +
        r.stderr.trim(),
    );
    assert.equal(r.status, expected, r.stderr);
    return r.stdout;
  };
  try {
    command("openssl", ["version"]);
    // The enc frontend refuses AEAD. EVP supplies the independent GCM operation.
    command("openssl", ["enc", "-aes-256-gcm", "-in", "/dev/null"], 1);
    const flags = command("pkg-config", ["--cflags", "--libs", "openssl"])
      .trim()
      .split(/\s+/);
    const peer = join(root, "gcm-peer");
    command("cc", [
      "-std=c11",
      "-Wall",
      "-Wextra",
      "-Werror",
      "test/support/openssl-gcm.c",
      "-o",
      peer,
      ...flags,
    ]);
    const put = async (name: string, bytes: Uint8Array | string) =>
      writeFile(join(root, name), bytes, { mode: 0o600 });
    const plaintext = crypto.getRandomValues(new Uint8Array(93));
    await put("plain", plaintext);
    for (const algorithm of ["RSA-OAEP", "RSA-OAEP-256"] as const) {
      const hash = algorithm === "RSA-OAEP" ? "sha1" : "sha256";
      const pair = await crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: algorithm === "RSA-OAEP" ? "SHA-1" : "SHA-256",
        },
        true,
        ["encrypt", "decrypt"],
      );
      const der = new Uint8Array(
        await crypto.subtle.exportKey("pkcs8", pair.privateKey),
      );
      const pem = value(writePem("PRIVATE KEY", der));
      der.fill(0);
      const owner = value(await Custody.local({ jwe: algorithm }, pem));
      try {
        await put("private.pem", pem);
        await put("public.pem", value(value(await owner.publicKey()).pem()));
        const options = [
          "-pkeyopt",
          "rsa_padding_mode:oaep",
          "-pkeyopt",
          "rsa_oaep_md:" + hash,
          "-pkeyopt",
          "rsa_mgf1_md:" + hash,
        ];
        const cek = crypto.getRandomValues(new Uint8Array(32));
        await put("cek", cek);
        command("openssl", [
          "pkeyutl",
          "-encrypt",
          "-pubin",
          "-inkey",
          join(root, "public.pem"),
          "-in",
          join(root, "cek"),
          "-out",
          join(root, "wrapped"),
          ...options,
        ]);
        const content = value(
          await owner.unwrap(
            { jwe: algorithm },
            await readFile(join(root, "wrapped")),
            value(withDeadline()),
            { length: 256 },
          ),
        );
        const iv = crypto.getRandomValues(new Uint8Array(12));
        await put("iv", iv);
        await put("aad", new Uint8Array());
        command(peer, [
          "encrypt",
          join(root, "cek"),
          join(root, "iv"),
          join(root, "aad"),
          join(root, "plain"),
          join(root, "sealed"),
        ]);
        assert.deepEqual(
          value(
            await content.decrypt(
              await readFile(join(root, "sealed")),
              { iv },
              value(withDeadline()),
            ),
          ),
          plaintext,
        );
        await content.release();
        const token = value(
            await JWE.encrypt(
              [
                ["alg", algorithm],
                ["enc", "A256GCM"],
              ],
              plaintext,
              owner,
            ),
          ),
          parts = token.split(".");
        await put("wrapped", decode(parts[1]));
        command("openssl", [
          "pkeyutl",
          "-decrypt",
          "-inkey",
          join(root, "private.pem"),
          "-in",
          join(root, "wrapped"),
          "-out",
          join(root, "cek"),
          ...options,
        ]);
        await put("iv", decode(parts[2]));
        await put("aad", parts[0]!);
        await put(
          "sealed",
          Buffer.concat([decode(parts[3]), decode(parts[4])]),
        );
        command(peer, [
          "decrypt",
          join(root, "cek"),
          join(root, "iv"),
          join(root, "aad"),
          join(root, "sealed"),
          join(root, "recovered"),
        ]);
        assert.deepEqual(
          new Uint8Array(await readFile(join(root, "recovered"))),
          plaintext,
        );
        if (algorithm === "RSA-OAEP-256") {
          await put("cek", cek);
          const wrong = [...options];
          wrong[wrong.length - 1] = "rsa_mgf1_md:sha1";
          command("openssl", [
            "pkeyutl",
            "-encrypt",
            "-pubin",
            "-inkey",
            join(root, "public.pem"),
            "-in",
            join(root, "cek"),
            "-out",
            join(root, "wrapped"),
            ...wrong,
          ]);
          assert.equal(
            (
              await owner.unwrap(
                { jwe: algorithm },
                await readFile(join(root, "wrapped")),
                value(withDeadline()),
              )
            ).ok,
            false,
          );
        }
      } finally {
        await owner.release();
      }
    }
    for (const algorithm of ["A128GCMKW", "A256GCMKW"]) {
      const kek = crypto.getRandomValues(new Uint8Array(algorithm === "A128GCMKW" ? 16 : 32));
      const owner = value(await KeyManagement.local(algorithm, kek));
      await put("kek", kek);
      try {
        for (const length of [16, 32]) {
          const enc = length === 16 ? "A128GCM" : "A256GCM";
          // Library wrap and content encryption -> independent EVP unwrap and decrypt.
          const fresh = value(await JWE.encrypt([["alg", algorithm], ["enc", enc]], plaintext,
            (a: string, cek: Uint8Array) => owner.wrap(a, cek)));
          const parts = fresh.split(".");
          const h = JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8"));
          await put("wrap-iv", decode(h.iv)); await put("empty-aad", new Uint8Array());
          await put("wrapped", Buffer.concat([decode(parts[1]), decode(h.tag)]));
          command(peer, ["decrypt", join(root, "kek"), join(root, "wrap-iv"), join(root, "empty-aad"), join(root, "wrapped"), join(root, "cek")]);
          await put("iv", decode(parts[2])); await put("aad", parts[0]!);
          await put("sealed", Buffer.concat([decode(parts[3]), decode(parts[4])]));
          command(peer, ["decrypt", join(root, "cek"), join(root, "iv"), join(root, "aad"), join(root, "sealed"), join(root, "recovered")]);
          assert.deepEqual(new Uint8Array(await readFile(join(root, "recovered"))), plaintext);

          // Independent EVP wrap and content encryption -> library unwrap and decrypt.
          const cek = crypto.getRandomValues(new Uint8Array(length)), wrapIv = crypto.getRandomValues(new Uint8Array(12)), iv = crypto.getRandomValues(new Uint8Array(12));
          await put("cek", cek); await put("wrap-iv", wrapIv);
          command(peer, ["encrypt", join(root, "kek"), join(root, "wrap-iv"), join(root, "empty-aad"), join(root, "cek"), join(root, "wrapped")]);
          const wrapped = await readFile(join(root, "wrapped"));
          const protectedPart = encodeBase64Url(new TextEncoder().encode(JSON.stringify({alg: algorithm, enc, iv: encodeBase64Url(wrapIv), tag: encodeBase64Url(wrapped.subarray(-16))})));
          await put("iv", iv); await put("aad", protectedPart);
          command(peer, ["encrypt", join(root, "cek"), join(root, "iv"), join(root, "aad"), join(root, "plain"), join(root, "sealed")]);
          const sealed = await readFile(join(root, "sealed"));
          const token = [protectedPart, encodeBase64Url(wrapped.subarray(0, -16)), encodeBase64Url(iv), encodeBase64Url(sealed.subarray(0, -16)), encodeBase64Url(sealed.subarray(-16))].join(".");
          const policy = {algorithms: [algorithm], encryption: [enc], max_plaintext: 1048576, timeout: 5000,
            key_resolver: () => ok({algorithm, unwrap: (ek: unknown, header: JoseProtectedHeader, c: Context) => owner.unwrap(ek, header, c)})};
          assert.deepEqual(value(await JWE.decrypt(token, policy)).plaintext, plaintext);
          cek.fill(0);
          t.diagnostic(algorithm + "/" + enc + " EVP exchange: both directions; key wrapping uses empty AAD");
        }
      } finally {kek.fill(0); await owner.release();}
    }
    for (const length of [16, 32]) {
      const enc = length === 16 ? "A128GCM" : "A256GCM",
        cek = crypto.getRandomValues(new Uint8Array(length)),
        iv = crypto.getRandomValues(new Uint8Array(12));
      const h = encodeBase64Url(
        new TextEncoder().encode(JSON.stringify({ alg: "dir", enc })),
      );
      await put("cek", cek);
      await put("iv", iv);
      await put("aad", h);
      command(peer, [
        "encrypt",
        join(root, "cek"),
        join(root, "iv"),
        join(root, "aad"),
        join(root, "plain"),
        join(root, "sealed"),
      ]);
      const sealed = await readFile(join(root, "sealed")),
        token = [
          h,
          "",
          encodeBase64Url(iv),
          encodeBase64Url(sealed.subarray(0, -16)),
          encodeBase64Url(sealed.subarray(-16)),
        ].join(".");
      const owner = value(await KeyManagement.local("dir", cek));
      const policy = {
        algorithms: ["dir"],
        encryption: [enc],
        max_plaintext: 1048576,
        timeout: 5000,
        key_resolver: () =>
          ok({
            algorithm: "dir",
            unwrap: (ek: unknown, header: JoseProtectedHeader, c: Context) =>
              owner.unwrap(ek, header, c),
          }),
      };
      try {
        assert.deepEqual(
          value(await JWE.decrypt(token, policy)).plaintext,
          plaintext,
        );
      } finally {
        await owner.release();
      }
      const fresh = value(
        await JWE.encrypt(
          [
            ["alg", "dir"],
            ["enc", enc],
          ],
          plaintext,
          async (_: string, generated: Uint8Array) => {
            await put("cek", generated);
            return ok({ encrypted_key: new Uint8Array(), header: [] });
          },
        ),
      );
      const parts = fresh.split(".");
      await put("iv", decode(parts[2]));
      await put("aad", parts[0]!);
      await put("sealed", Buffer.concat([decode(parts[3]), decode(parts[4])]));
      command(peer, [
        "decrypt",
        join(root, "cek"),
        join(root, "iv"),
        join(root, "aad"),
        join(root, "sealed"),
        join(root, "recovered"),
      ]);
      assert.deepEqual(
        new Uint8Array(await readFile(join(root, "recovered"))),
        plaintext,
      );
      const bad = await readFile(join(root, "sealed"));
      bad[bad.length - 1]! ^= 1;
      await put("sealed", bad);
      command(
        peer,
        [
          "decrypt",
          join(root, "cek"),
          join(root, "iv"),
          join(root, "aad"),
          join(root, "sealed"),
          join(root, "recovered"),
        ],
        1,
      );
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("OpenSSL coverage names the wrapped-key and content-cipher exchanges exactly", async () => {
  const changelog = await readFile('CHANGELOG.md', 'utf8');
  assert.match(changelog, /RSA-OAEP \(SHA-1 and SHA-256\), A128GCMKW and A256GCMKW \(empty AAD\), and direct A128GCM and A256GCM/);
});
