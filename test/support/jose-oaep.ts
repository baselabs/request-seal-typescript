import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import {
  JWE,
  Custody,
  ok,
  encodeBase64Url,
  decodeBase64Url,
  type Result,
} from "../../src/index.ts";
import { writePem } from "../../src/custody/der.ts";
export function value<T>(r: Result<T>): T {
  if (!r.ok) throw Error("Rejected: " + r.error.kind + "/" + r.error.reason);
  return r.value;
}
export async function oaepCases(
  algorithm: "RSA-OAEP" | "RSA-OAEP-256",
  diagnostic: (s: string) => void = () => {},
): Promise<{
  policy: unknown;
  cases: Record<string, string>;
  release: () => Promise<void>;
}> {
  const root = await mkdtemp("test/.tmp-oaep-");
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
  const privateDer = new Uint8Array(
    await crypto.subtle.exportKey("pkcs8", pair.privateKey),
  );
  const material = value(writePem("PRIVATE KEY", privateDer));
  privateDer.fill(0);
  const h = value(await Custody.local({ jwe: algorithm }, material));
  const command = (args: string[]) => {
    const r = spawnSync("openssl", args, { encoding: "utf8", timeout: 10000 });
    diagnostic("COMMAND: openssl " + args.join(" "));
    diagnostic(
      "RESULT: exit=" +
        r.status +
        " " +
        r.stdout.trim() +
        " " +
        r.stderr.trim(),
    );
    if (r.status !== 0) throw Error("OpenSSL failed");
  };
  try {
    await writeFile(join(root, "private.pem"), material, { mode: 0o600 });
    await writeFile(
      join(root, "public.pem"),
      value(value(await h.publicKey()).pem()),
      { mode: 0o600 },
    );
    const valid = value(
      await JWE.encrypt(
        [
          ["alg", algorithm],
          ["enc", "A256GCM"],
        ],
        new TextEncoder().encode("authenticated plaintext"),
        h,
      ),
    );
    const parts = valid.split(".");
    await writeFile(join(root, "wrapped"), value(decodeBase64Url(parts[1])), {
      mode: 0o600,
    });
    command([
      "pkeyutl",
      "-decrypt",
      "-inkey",
      join(root, "private.pem"),
      "-in",
      join(root, "wrapped"),
      "-out",
      join(root, "encoded"),
      "-pkeyopt",
      "rsa_padding_mode:none",
    ]);
    const encoded = await readFile(join(root, "encoded"));
    if (encoded.length !== 256 || encoded[0] !== 0)
      throw Error("Invalid positive OAEP block");
    const cases: Record<string, string> = { valid };
    for (const [name, index] of [
      ["leading_zero", 0],
      ["masked_seed", 1],
      ["masked_data_block", algorithm === "RSA-OAEP" ? 21 : 33],
    ] as const) {
      const corrupt = new Uint8Array(encoded);
      corrupt[index]! ^= 1;
      await writeFile(join(root, "encoded"), corrupt, { mode: 0o600 });
      command([
        "pkeyutl",
        "-encrypt",
        "-pubin",
        "-inkey",
        join(root, "public.pem"),
        "-in",
        join(root, "encoded"),
        "-out",
        join(root, "wrapped"),
        "-pkeyopt",
        "rsa_padding_mode:none",
      ]);
      const changed = [...parts];
      changed[1] = encodeBase64Url(await readFile(join(root, "wrapped")));
      cases[name] = changed.join(".");
    }
    const tag = value(decodeBase64Url(parts[4]));
    tag[0]! ^= 1;
    const bad = [...parts];
    bad[4] = encodeBase64Url(tag);
    cases.tag = bad.join(".");
    const policy = {
      algorithms: [algorithm],
      encryption: ["A256GCM"],
      max_plaintext: 1048576,
      timeout: 5000,
      key_resolver: () => ok({ algorithm, key: h }),
    };
    return {
      policy,
      cases,
      release: async () => {
        await h.release();
        await rm(root, { recursive: true, force: true });
      },
    };
  } catch (e) {
    await h.release();
    await rm(root, { recursive: true, force: true });
    throw e;
  }
}
