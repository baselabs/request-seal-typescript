import { dictionaries } from '../src/signature-fields.ts';
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import fc from "fast-check";
import * as api from "../src/index.ts";
import { ok } from "../src/result.ts";
const A = api as any;
function value(r: any): any {
  assert.equal(r.ok, true, JSON.stringify(r));
  return r.value;
}
async function handle(alg: string, secret?: Uint8Array) {
  if (alg === "ecdsa-p384-sha384") {
    const jwk = JSON.parse(
      await readFile("test/fixtures/upstream/crypto/rfc6979.json", "utf8"),
    );
    const bytes = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
    return value(
      await api.Custody.local(alg, {
        kty: "EC",
        crv: "P-384",
        x: api.encodeBase64Url(bytes(jwk.Ux)),
        y: api.encodeBase64Url(bytes(jwk.Uy)),
        d: api.encodeBase64Url(bytes(jwk.x)),
      }),
    );
  }
  const names: Record<string, string> = {
    "rsa-pss-sha512": "rsa_pss",
    "rsa-v1_5-sha256": "rsa",
    "ecdsa-p256-sha256": "p256",
    "ecdsa-p384-sha384": "p384",
    ed25519: "ed25519",
  };
  return value(
    await api.Custody.local(
      alg,
      alg === "hmac-sha256"
        ? { hmac: secret ?? crypto.getRandomValues(new Uint8Array(32)) }
        : await readFile(
            `test/fixtures/upstream/crypto/${names[alg]}_private.pem`,
            "utf8",
          ),
    ),
  );
}
async function verificationKey(alg: string, secret: Uint8Array) {
  // HMAC uses a separately imported secret handle; asymmetric keys use published public material.
  if (alg === "hmac-sha256") return value(await api.Custody.local(alg, {hmac: secret}));
  if (alg === "ecdsa-p384-sha384") {
    const vector = JSON.parse(await readFile("test/fixtures/upstream/crypto/rfc6979.json", "utf8"));
    const bytes = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
    return value(await api.PublicKey.import({kty: "EC", crv: "P-384", x: api.encodeBase64Url(bytes(vector.Ux)), y: api.encodeBase64Url(bytes(vector.Uy))}, "jwk"));
  }
  const names: Record<string, string> = {"rsa-pss-sha512": "rsa_pss", "rsa-v1_5-sha256": "rsa", "ecdsa-p256-sha256": "p256", ed25519: "ed25519"};
  return value(await api.PublicKey.import(await readFile(`test/fixtures/upstream/crypto/${names[alg]}_public.pem`, "utf8"), "pem"));
}
function signing(h: any) {
  return (algorithm: api.SigningAlgorithm, base: Uint8Array, context = value(api.withDeadline())) => h.sign(algorithm, base, context);
}
function policy(alg: string, h: any, extra: any = {}) {
  return value(
    A.Policy.create({
      algorithms: [alg],
      components: '("@method")',
      keyResolver: async () => ok({ algorithm: alg, key: h }),
      freshness: "not_evaluated",
      content: "not_required",
      replay: "not_required",
      ...extra,
    }),
  );
}
for (const [name, signatureInput, maxAge, skew, expectedEnd] of [
  ["expiration overflow", '("@method");created=253402300798;expires=253402300799;nonce="end"', null, 1, null],
  ["max age overflow", '("@method");created=253402300798;nonce="end"', 1, 0, null],
  ["maximum expiration", '("@method");created=253402300798;expires=253402300799;nonce="end"', null, 0, 253402300799],
  ["maximum age retention", '("@method");created=253402300797;nonce="end"', 1, 0, 253402300799],
] as const) test("replay retention bounds: " + name, async () => {
  const h = await handle("ed25519");
  try {
    let commitments = 0, claims = 0, sweeps = 0;
    const entries = new Map<string, number>();
    const store = {
      async claim(c: any) {
        claims++;
        const key = api.encodeBase64Url(c.namespace) + ":" + api.encodeBase64Url(c.key);
        if (entries.has(key)) return ok("already_claimed");
        entries.set(key, c.retainUntil);
        return ok("claimed");
      },
      async sweep(now: number) {
        sweeps++;
        let removed = 0;
        for (const [key, end] of entries) if (end <= now) { entries.delete(key); removed++; }
        return ok(removed);
      },
    };
    const p = policy("ed25519", h, {
      freshness: {clock: () => 253402300798, maxAge, skew, requireExpires: maxAge === null},
      replay: {
        identifier: "nonce", namespace: new Uint8Array([1]), timeoutMs: 5000, store,
        commitment: async (facts: any) => {
          commitments++;
          return ok(new TextEncoder().encode(facts.identifier));
        },
      },
    });
    const m = value(await api.Message.request("GET", "https://example.com/", [], ""));
    const signed = value(await A.sign(m, {
      label: "s", signatureInput, algorithm: "ed25519",
    }, signing(h)));
    const r = await A.verify(signed, p, {label: "s"});
    // Check effects first so the rejection cannot hide an attempted store operation.
    assert.equal(commitments, expectedEnd === null ? 0 : 1);
    assert.equal(claims, expectedEnd === null ? 0 : 1);
    assert.equal(sweeps, 0);
    assert.equal(entries.size, expectedEnd === null ? 0 : 1);
    if (expectedEnd === null) {
      assert.equal(r.ok, false);
      assert.equal(r.error.kind, "core");
      assert.equal(r.error.layer, "replay");
      assert.equal(r.error.reason, "retention_exceeded");
    } else assert.equal(value(r).replay.retainUntil, expectedEnd);
  } finally { await h.release(); }
});
test("all HTTP algorithms sign random messages and reject covered mutations", {timeout: 30_000}, async () => {
  assert.equal(typeof A.sign, "function");
  assert.equal(typeof A.verify, "function");
  for (const alg of value(api.Crypto.algorithms())) {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const h = await handle(alg, secret);
    let publicKey: any;
    try {
      publicKey = await verificationKey(alg, secret);
      assert.notEqual(publicKey, h);
      if (alg !== "hmac-sha256") assert.equal(api.isPublicKey(publicKey), true);
      await fc.assert(
        fc.asyncProperty(
          fc.stringMatching(/^[a-z*][a-z0-9_.*-]{0,24}$/),
          fc.uint8Array({ maxLength: 40 }),
          fc.boolean(),
          fc.constantFrom("explicit", "six-key"),
          async (label, bytes, cover, form) => {
            const m = value(
              await api.Message.request(
                "POST",
                "https://example.com/a",
                [["x-covered", bytes.length.toString()]],
                bytes,
              ),
            );
            const components = cover
              ? '("@method" "x-covered")'
              : '("@method")';
            const spec = form === "explicit"
              ? {label, signatureInput: components, algorithm: alg}
              : {label, components, algorithm: alg, parameters: {
                  created: true, expiresIn: 60, nonce: "random", alg: true, keyid: "property", tag: null,
                }, digest: null, fieldSchemas: {}};
            const signed = value(
              await A.sign(
                m,
                spec,
                form === "explicit" ? signing(h) : h,
                form === "six-key" ? {clock: () => 10} : {},
              ),
            );
            const generated = dictionaries(signed, 16);
            assert.ok(generated[0].has(label)); assert.ok(generated[1].has(label));
            const p = policy(alg, publicKey);
            const verified = value(await A.verify(signed, p, { label }));
            assert.equal(A.isVerification(verified), true);
            assert.equal(Object.isFrozen(verified.signature), true);
            assert.equal(A.isVerification({ ...verified }), false);
            const changed = value(
              api.Message.create({ ...signed, method: "PUT" }),
            );
            assert.equal(
              (await A.verify(changed, p, { label })).error.reason,
              "invalid_signature",
            );
            const added = value(
              api.FieldOccurrence.create({
                name: "x-uncovered",
                value: "new",
                section: "headers",
              }),
            );
            assert.equal(
              (
                await A.verify(
                  value(
                    api.Message.create({
                      ...signed,
                      fields: [...signed.fields, added],
                    }),
                  ),
                  p,
                  { label },
                )
              ).ok,
              true,
            );
            if (form === "six-key") {
              const nonce = verified.signature.parameters.find(([key]: any) => key === "nonce")[1].value;
              assert.equal(value(api.decodeBase64Url(nonce)).length, api.SIGNING_NONCE_BYTES);
            }
            if (cover) {
              const mutatedField = value(api.FieldOccurrence.create({name: "x-covered", value: "mutated", section: "headers"}));
              const mutated = value(api.Message.create({...signed, fields: signed.fields.map((f: any) => f.name === "x-covered" ? mutatedField : f)}));
              assert.equal((await A.verify(mutated, p, {label})).error.reason, "invalid_signature");
              const dropped = value(
                api.Message.create({
                  ...signed,
                  fields: signed.fields.filter(
                    (f: any) => f.name !== "x-covered",
                  ),
                }),
              );
              assert.equal(
                (await A.verify(dropped, p, { label })).error.reason,
                "signature_base_failed",
              );
            }
            assert.equal(
              (
                await A.sign(
                  signed,
                  { label, signatureInput: components, algorithm: alg },
                  signing(h),
                )
              ).error.reason,
              "label_in_use",
            );
          },
        ),
        { numRuns: 48 },
      );
    } finally {
      if (api.isKeyHandle(publicKey)) await publicKey.release();
      await h.release();
      secret.fill(0);
    }
  }
});
test("freshness checks preserve exclusive expiry and inclusive max age with bounded clocks", async () => {
  assert.equal(typeof A.sign, "function");
  const h = await handle("ed25519");
  try {
    const m = value(
      await api.Message.request("GET", "https://example.com/", [], ""),
    );
    const signed = value(
      await A.sign(
        m,
        {
          label: "s",
          signatureInput: '("@method");created=10;expires=20',
          algorithm: "ed25519",
        },
        signing(h),
      ),
    );
    for (const [now, age, skew, reason] of [
      [-1, 10, 0, "invalid_clock"],
      [0, 10, 0, "created_in_future"],
      [20, 10, 0, "expired"],
      [21, 5, 0, "expired"],
      [253402300800, 10, 0, "invalid_clock"],
    ] as const) {
      const p = policy("ed25519", h, {
        freshness: {
          clock: () => now,
          maxAge: age,
          skew,
          requireExpires: true,
        },
      });
      assert.equal(
        (await A.verify(signed, p, { label: "s" })).error.reason,
        reason,
      );
    }
    const p = policy("ed25519", h, {
      freshness: { clock: () => 20, maxAge: 10, skew: 1, requireExpires: true },
    });
    assert.equal((await A.verify(signed, p, { label: "s" })).ok, true);
  } finally {
    await h.release();
  }
});
test("content integrity requires complete signed digest coverage and exact body bytes", async () => {
  assert.equal(typeof A.sign, "function");
  const h = await handle("ed25519");
  try {
    const m = value(
      await api.Message.request("POST", "https://example.com/", [], "body"),
    );
    const p = policy("ed25519", h, {
      content: {
        kind: "content",
        algorithms: ["sha-256", "sha-512"],
        section: "headers",
      },
    });
    const base = {
      label: "s",
      algorithm: "ed25519",
      components: '("@method" "content-digest")',
      expiresIn: 60,
      digest: ["sha-256", "sha-512"],
    };
    const signed = value(
      await A.sign(m, base, h, {
        clock: () => 10,
        nonce: crypto.getRandomValues(new Uint8Array(32)),
      }),
    );
    const v = value(await A.verify(signed, p, { label: "s" }));
    assert.equal(v.content.kind, "content-digest");
    assert.deepEqual(v.content.checked, ["sha-256", "sha-512"]);
    const body = value(api.Body.create({ state: "retained", bytes: "evil" }));
    const changed = value(api.Message.create({ ...signed, body }));
    assert.equal(
      (await A.verify(changed, p, { label: "s" })).error.reason,
      "digest_mismatch",
    );
    const bodyUnavailable = value(api.Body.create({ state: "unavailable" }));
    assert.equal(
      (
        await A.verify(
          value(api.Message.create({ ...signed, body: bodyUnavailable })),
          p,
          { label: "s" },
        )
      ).error.reason,
      "body_unavailable",
    );
    const uncovered = value(
      await A.sign(
        m,
        { label: "s", signatureInput: '("@method")', algorithm: "ed25519" },
        signing(h),
      ),
    );
    assert.equal(
      (await A.verify(uncovered, p, { label: "s" })).error.reason,
      "digest_not_covered",
    );
    const restrictive = policy("ed25519", h, {
      content: { kind: "content", algorithms: ["sha-256"], section: "headers" },
    });
    assert.equal(
      (await A.verify(signed, restrictive, { label: "s" })).error.reason,
      "digest_unsupported",
    );
  } finally {
    await h.release();
  }
});
test("freshness rejects missing timestamps and excessive age", async () => {
  assert.equal(typeof A.sign, "function");
  const h = await handle("ed25519");
  try {
    const m = value(
      await api.Message.request("GET", "https://example.com/", [], ""),
    );
    for (const [input, extra, reason] of [
      ['("@method")', { maxAge: 60, requireExpires: false }, "missing_created"],
      [
        '("@method");created=0',
        { maxAge: null, requireExpires: true },
        "missing_expires",
      ],
      [
        '("@method");created=0',
        { maxAge: 59, requireExpires: false },
        "too_old",
      ],
    ] as const) {
      const signed = value(
        await A.sign(
          m,
          { label: "s", signatureInput: input, algorithm: "ed25519" },
          signing(h),
        ),
      );
      const p = policy("ed25519", h, {
        freshness: { clock: () => 60, skew: 0, ...extra },
      });
      assert.equal(
        (await A.verify(signed, p, { label: "s" })).error.reason,
        reason,
      );
    }
  } finally {
    await h.release();
  }
});
test("resolver and verifier faults return bounded errors without callback diagnostics", async () => {
  assert.equal(typeof A.sign, "function");
  const h = await handle("ed25519");
  try {
    const m = value(
        await api.Message.request("GET", "https://example.com/", [], ""),
      ),
      signed = value(
        await A.sign(
          m,
          { label: "s", signatureInput: '("@method")', algorithm: "ed25519" },
          signing(h),
        ),
      );
    for (const [resolver, reason] of [
      [
        async () => {
          throw new Error("DIAGNOSTIC-CANARY");
        },
        "key_resolver_failed",
      ],
      [async () => ok(null), "unknown_key"],
      [
        async () =>
          ok({
            algorithm: "ed25519",
            verify: () => {
              throw new Error("DIAGNOSTIC-CANARY");
            },
          }),
        "verifier_failed",
      ],
    ] as const) {
      const r = await A.verify(
        signed,
        policy("ed25519", h, { keyResolver: resolver }),
        { label: "s" },
      );
      assert.equal(r.error.reason, reason);
      assert.equal(JSON.stringify(r).includes("DIAGNOSTIC-CANARY"), false);
    }
  } finally {
    await h.release();
  }
});
test("replay makes one atomic claim last and excludes labels from commitment facts", async () => {
  assert.equal(typeof A.sign, "function");
  const h = await handle("ed25519");
  try {
    const entries = new Map<string, number>();
    let calls = 0,
      commits = 0;
    const store = {
      async claim(c: any) {
        calls++;
        const key =
          api.encodeBase64Url(c.namespace) + ":" + api.encodeBase64Url(c.key);
        if (entries.has(key)) return ok("already_claimed");
        entries.set(key, c.retainUntil);
        return ok("claimed");
      },
      async sweep(now: number) {
        let n = 0;
        for (const [key, end] of entries)
          if (end <= now) {
            entries.delete(key);
            n++;
          }
        return ok(n);
      },
    };
    const p = policy("ed25519", h, {
      freshness: {
        clock: () => 100,
        maxAge: 60,
        skew: 0,
        requireExpires: true,
      },
      replay: {
        identifier: "nonce",
        namespace: new Uint8Array([0, 255]),
        timeoutMs: 5000,
        store,
        commitment: async (facts: any) => {
          commits++;
          assert.equal(Object.hasOwn(facts, "label"), false);
          assert.deepEqual(Object.keys(facts), [
            "identifier",
            "algorithm",
            "keyid",
            "tag",
            "created",
            "expires",
            "profile",
          ]);
          return ok(new TextEncoder().encode(facts.identifier));
        },
      },
    });
    const m = value(
      await api.Message.request("GET", "https://example.com/", [], ""),
    );
    const signed = value(
      await A.sign(
        m,
        {
          label: "s",
          signatureInput: '("@method");created=100;expires=160;nonce="once"',
          algorithm: "ed25519",
        },
        signing(h),
      ),
    );
    assert.equal(
      (
        await A.verify(
          value(api.Message.create({ ...signed, method: "PUT" })),
          p,
          { label: "s" },
        )
      ).error.reason,
      "invalid_signature",
    );
    assert.equal(calls, 0);
    assert.equal(commits, 0);
    const v = value(await A.verify(signed, p, { label: "s" }));
    assert.equal(v.replay.retainUntil, 160);
    assert.equal(calls, 1);
    assert.equal(commits, 1);
    assert.equal(
      (await A.verify(signed, p, { label: "s" })).error.reason,
      "replayed",
    );
    assert.equal(calls, 2);
  } finally {
    await h.release();
  }
});
test("canonical verification serialization preserves layer order and wire parameter order", async () => {
  assert.equal(typeof A.sign, "function");
  const h = await handle("ed25519");
  try {
    const m = value(
        await api.Message.request("GET", "https://example.com/", [], ""),
      ),
      signed = value(
        await A.sign(
          m,
          {
            label: "s",
            signatureInput: '("@method");keyid="k";created=0',
            algorithm: "ed25519",
          },
          signing(h),
        ),
      );
    const v = value(
      await A.verify(signed, policy("ed25519", h), { label: "s" }),
    );
    assert.equal(
      new TextDecoder().decode(value(A.serializeVerification(v))),
      '{"label":"s","signature":{"algorithm":"ed25519","covered":[["@method",[]]],"parameters":[["keyid","k"],["created",{"int":"0"}]],"keyid":"k","crypto":"valid"},"profile":{"name":"rfc9421"},"content":"not_required","freshness":"not_evaluated","replay":"not_required","principal":"unattributed","authorization":"not_evaluated"}',
    );
    assert.equal(
      A.serializeVerification({ ...v }).error.reason,
      "invalid_verification",
    );
  } finally {
    await h.release();
  }
});
test("signing clocks reject thrown or undefined values instead of substituting system time", async () => {
  assert.equal(typeof A.sign, "function");
  const h = await handle("ed25519");
  try {
    const m = value(
      await api.Message.request("GET", "https://example.com/", [], ""),
    );
    for (const clock of [
      () => undefined,
      () => {
        throw new Error("CLOCK-CANARY");
      },
    ]) {
      const r = await A.sign(
        m,
        {
          label: "s",
          algorithm: "ed25519",
          components: '("@method")',
          expiresIn: 60,
        },
        h,
        { clock },
      );
      assert.equal(r.ok, false, "Undefined and throwing clocks must reject");
      assert.equal(r.error.reason, "invalid_options");
    }
  } finally {
    await h.release();
  }
});
test("caller deadlines contain real signer and resolver work and callback faults", async () => {
  assert.equal(typeof A.sign, "function");
  const h = await handle("ed25519");
  try {
    const m = value(
      await api.Message.request("GET", "https://example.com/", [], ""),
    );
    const spec = {
      label: "s",
      signatureInput: '("@method")',
      algorithm: "ed25519",
    };
    const slowSigner = async (
      algorithm: string,
      base: Uint8Array,
      context: api.Context = value(api.withDeadline()),
    ) => {
      await new Promise((resolve) => setTimeout(resolve, 30));
      return h.sign(algorithm, base, context);
    };
    const c = value(api.withDeadline({ timeoutMs: 5 }));
    assert.equal(
      (await A.sign(m, spec, slowSigner, { context: c })).error.reason,
      "signer_failed",
    );
    const signed = value(await A.sign(m, spec, signing(h)));
    const p = policy("ed25519", h, {
      keyResolver: async () => {
        await new Promise((resolve) => setTimeout(resolve, 30));
        return ok({ algorithm: "ed25519", key: h });
      },
    });
    const next = value(api.withDeadline({ timeoutMs: 5 }));
    assert.equal(
      (await A.verify(signed, p, { label: "s", context: next })).error.reason,
      "deadline_exceeded",
    );
  } finally {
    await new Promise((resolve) => setTimeout(resolve, 35));
    await h.release();
  }
});
test("extension metadata preserves exact decimal and byte tags in immutable verification facts", async () => {
  const h = await handle("ed25519");
  try {
    const m = value(
      await api.Message.request("GET", "https://example.com/", [], ""),
    );
    const signed = value(
      await A.sign(
        m,
        {
          label: "s",
          signatureInput: '("@method");x=1.25;y=:AQI=:',
          algorithm: "ed25519",
        },
        signing(h),
      ),
    );
    const checked = await A.verify(signed, policy("ed25519", h), {
      label: "s",
    });
    assert.equal(
      checked.ok,
      true,
      "Valid extension metadata must produce a Verification",
    );
    const v = checked.value,
      before = value(A.serializeVerification(v));
    assert.deepEqual(
      JSON.parse(new TextDecoder().decode(before)).signature.parameters,
      [
        ["x", { dec: "1.25" }],
        ["y", { b64: "AQI" }],
      ],
    );
    v.signature.parameters[1][1].value.fill(0);
    assert.deepEqual(value(A.serializeVerification(v)), before);
  } finally {
    await h.release();
  }
});
test("verification cannot outlive its context during real incremental content work", async () => {
  const h = await handle("ed25519");
  try {
    const m = value(
      await api.Message.request("GET", "https://example.com/", [], "body"),
    );
    const signed = value(
      await A.sign(
        m,
        {
          label: "s",
          algorithm: "ed25519",
          components: '("@method" "content-digest")',
          expiresIn: 60,
          digest: ["sha-256"],
        },
        h,
      ),
    );
    const { createHash } = await import("node:crypto");
    let finishAfter = 0;
    let contentStarted = false;
    const hasher = {
      create(algorithm: string) {
        const hash = createHash(algorithm === "sha-256" ? "sha256" : "sha512");
        return {
          update(chunk: Uint8Array) {
            hash.update(chunk);
          },
          async finish() {
            if (finishAfter > 0) {
              contentStarted = true;
              await new Promise((resolve) => setTimeout(resolve, Math.max(0, finishAfter - performance.now())));
            }
            return new Uint8Array(hash.digest());
          },
        };
      },
    };
    const state = value(
      await A.DigestState.create("content", ["sha-256"], hasher),
    );
    value(await state.update(new TextEncoder().encode("body")));
    const p = policy("ed25519", h, {
        content: {
          kind: "content",
          algorithms: ["sha-256"],
          section: "headers",
        },
      }),
      context = value(api.withDeadline({ timeoutMs: 1000 }));
    // Hold actual hashing through the deadline after the content stage begins.
    finishAfter = context.deadline + 30;
    const r = await A.verify(signed, p, {
      label: "s",
      context,
      digestState: state,
    });
    assert.equal(
      r.ok,
      false,
      "Required content work must remain inside the caller deadline",
    );
    assert.equal(contentStarted, true, "This probe must expire during content, not before it");
    assert.equal(r.error.reason, "deadline_exceeded");
  } finally {
    await new Promise((resolve) => setTimeout(resolve, 35));
    await h.release();
  }
});
