import { oaepCases } from "../test/support/jose-oaep.ts";
import { Custody, Crypto, JWE, type Result } from "../src/index.ts";
import * as subtle from "../src/crypto/subtle.ts";
function value<T>(r: Result<T>): T {
  if (!r.ok) throw new Error("Measurement failed");
  return r.value;
}
function quantile(a: number[], q: number): number {
  return a[Math.min(a.length - 1, Math.floor(q * a.length))]!;
}
function ks(a: number[], b: number[]): number {
  let i = 0,
    j = 0,
    d = 0;
  while (i < a.length || j < b.length) {
    const x = Math.min(a[i] ?? Infinity, b[j] ?? Infinity);
    while (i < a.length && a[i]! <= x) i++;
    while (j < b.length && b[j]! <= x) j++;
    d = Math.max(d, Math.abs(i / a.length - j / b.length));
  }
  return d;
}
class Primitive {
  #key: CryptoKey;
  constructor(key: CryptoKey) {
    this.#key = key;
  }
  static async create(secret: Uint8Array): Promise<Primitive> {
    return new Primitive(
      await subtle.importKey(
        "raw",
        new Uint8Array(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["verify"],
      ),
    );
  }
  async verify(signature: Uint8Array, data: Uint8Array): Promise<boolean> {
    return (
      (await subtle.verify(
        "HMAC",
        this.#key,
        new Uint8Array(signature),
        new Uint8Array(data),
      )) === true
    );
  }
}
async function measure(
  verify: (positive: boolean) => Promise<boolean>,
): Promise<unknown> {
  const valid: number[] = [],
    invalid: number[] = [];
  for (let i = 0; i < 1100; i++)
    for (const positive of i % 2 ? [true, false] : [false, true]) {
      const start = performance.now();
      const r = await verify(positive);
      const elapsed = performance.now() - start;
      if (r !== positive) throw new Error("Measurement verification failed");
      if (i >= 100) (positive ? valid : invalid).push(elapsed);
    }
  valid.sort((a, b) => a - b);
  invalid.sort((a, b) => a - b);
  return {
    valid: { p50: quantile(valid, 0.5), p99: quantile(valid, 0.99) },
    invalid: { p50: quantile(invalid, 0.5), p99: quantile(invalid, 0.99) },
    ks: ks(valid, invalid),
  };
}
async function measureOaep(): Promise<unknown> {
  const output: Record<string, unknown> = Object.create(null);
  for (const algorithm of ["RSA-OAEP", "RSA-OAEP-256"] as const) {
    const vector = await oaepCases(algorithm);
    const names = ["leading_zero", "masked_seed", "masked_data_block", "tag"];
    const samples: Record<string, number[]> = Object.fromEntries(
      names.map((n) => [n, []]),
    );
    try {
      if (!(await JWE.decrypt(vector.cases.valid, vector.policy)).ok)
        throw Error("OAEP positive failed");
      for (let round = 0; round < 1100; round++) {
        for (let n = 0; n < names.length; n++) {
          const name = names[(n + round) % names.length]!;
          const start = performance.now();
          const result = await JWE.decrypt(vector.cases[name], vector.policy);
          const elapsed = performance.now() - start;
          if (
            result.ok ||
            JSON.stringify(result.error) !==
              '{"kind":"jose","reason":"decryption_failed","layer":"crypto","correlation":null,"retryable":false}'
          )
            throw Error("Nonuniform failure");
          if (round >= 100) samples[name]!.push(elapsed);
        }
      }
      for (const values of Object.values(samples)) values.sort((a, b) => a - b);
      const populations = Object.fromEntries(
        names.map((name) => [
          name,
          {
            p50: quantile(samples[name]!, 0.5),
            p99: quantile(samples[name]!, 0.99),
            ks_vs_tag: ks(samples[name]!, samples.tag!),
          },
        ]),
      );
      const pairwise = names.flatMap((left, i) => names.slice(i + 1).map(right => {
        const distance = ks(samples[left]!, samples[right]!);
        const threshold = 1.36 * Math.sqrt(1 / samples[left]!.length + 1 / samples[right]!.length);
        return {left, right, ks: distance, ks_threshold: threshold, exceeds: distance > threshold};
      }));
      output[algorithm] = {populations, pairwise};
    } finally {
      await vector.release();
    }
  }
  return output;
}
async function main(): Promise<void> {
  const secret = new TextEncoder().encode(
    "Measurement-only HMAC test key, never operational",
  );
  const primitive = await Primitive.create(secret);
  const handle = value(await Custody.local("hmac-sha256", { hmac: secret }));
  secret.fill(0);
  const message = new TextEncoder().encode(
    "Equal-length HMAC verification timing",
  );
  const signature = value(await Crypto.sign("hmac-sha256", handle, message));
  const bad = new Uint8Array(signature);
  bad[0]! ^= 1;
  try {
    console.log(
      JSON.stringify({
        runtime: process.versions.deno
          ? "Deno " + process.versions.deno
          : process.versions.bun
            ? "Bun " + process.versions.bun
            : "Node " + process.versions.node,
        samples: 1000,
        significance: {alpha: 0.05, ks_threshold: 1.36 * Math.sqrt(2 / 1000), adjustment: "none; exploratory pairwise comparisons"},
        units: "milliseconds",
        oaep_uniform_failure: await measureOaep(),
        primitive: await measure((positive) =>
          primitive.verify(positive ? signature : bad, message),
        ),
        boundary: await measure(
          async (positive) =>
            (
              await Crypto.verify(
                "hmac-sha256",
                handle,
                positive ? signature : bad,
                message,
              )
            ).ok,
        ),
      }),
    );
  } finally {
    value(await handle.release());
  }
}
main().catch(() => {
  console.error("Measurement failed");
  process.exitCode = 1;
});
