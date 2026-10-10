import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { inspect } from "node:util";
import fc from "fast-check";
import * as api from "../src/index.ts";
import { message } from "../tools/conformance/wire.ts";
const A = api as any;
const value = (r: any): any => {
  assert.equal(r.ok, true, JSON.stringify(r));
  return r.value;
};
const reason = (r: any, s: string) => {
  assert.equal(r.ok, false);
  assert.equal(r.error.reason, s);
};
async function keys() {
  const handles: api.KeyHandle[] = [];
  const pub: Record<string, any> = {};
  for (const [id, name] of [
    ["rsa-pss-sha512", "rsa_pss"],
    ["ed25519", "ed25519"],
  ])
    pub[id!] = value(
      await api.PublicKey.import(
        await readFile(
          `test/fixtures/upstream/crypto/${name}_public.pem`,
          "utf8",
        ),
        "pem",
      ),
    );
  const secret = value(
    api.decodeBase64(
      (await readFile("test/fixtures/upstream/crypto/hmac.txt", "utf8")).trim(),
    ),
  );
  const h = value(
    await api.Custody.local("hmac-sha256", {
      hmac: secret,
      identity: "shared-key",
    }),
  );
  handles.push(h);
  pub["hmac-sha256"] = h;
  return { pub, handles };
}
function p(pub: Record<string, any>, extra = {}) {
  return value(
    api.Policy.create({
      algorithms: ["rsa-pss-sha512", "ed25519", "hmac-sha256"],
      components: "()",
      keyResolver: ({ keyid }: any) => {
        const alg =
          keyid === "test-key-ed25519"
            ? "ed25519"
            : keyid === "test-shared-secret"
              ? "hmac-sha256"
              : "rsa-pss-sha512";
        return api.ok({ algorithm: alg, key: pub[alg] });
      },
      freshness: "not_evaluated",
      content: "not_required",
      replay: "not_required",
      ...extra,
    }),
  );
}
function q(slots: any[], extra = {}) {
  return value(
    A.Quorum.create({
      mode: "all",
      unit: "keys",
      slots,
      unexpected: "ignore",
      invalid: "ignore",
      ...extra,
    }),
  );
}
async function corpus() {
  return JSON.parse(
    await readFile(
      "test/fixtures/upstream/multi_signature/rfc9421.json",
      "utf8",
    ),
  );
}
function m(input: any) {
  return value(
    message(input, {
      read: () => {
        throw Error("Unexpected reference");
      },
    } as any),
  );
}
async function signed(labels: string[]) {
  const c = await corpus();
  const base = m(c.b2);
  const vectors = c.signatures;
  return value(
    api.Message.create({
      ...base,
      fields: [
        ...base.fields,
        ...labels.flatMap((l) => {
          const v = vectors.find((v: any) => v.label === l);
          return [
            ["Signature-Input", v.signature_input],
            ["Signature", v.signature],
          ].map(([name, value]) => valueField(name, value));
        }),
      ],
    }),
  );
}
function valueField(name: any, raw: any) {
  return value(
    api.FieldOccurrence.create({ name, value: raw, section: "headers" }),
  );
}
test("published independent signatures count keys, principals and roles with retained facts", async () => {
  assert.equal(
    typeof A.verifyQuorum,
    "function",
    "verifyQuorum must be exported",
  );
  const k = await keys();
  try {
    const policy = p(k.pub),
      slots = [
        {
          id: "rsa",
          policy,
          required: true,
          label: "sig-b21",
          principal: "one",
          role: "agent",
        },
        {
          id: "hmac",
          policy,
          required: true,
          label: "sig-b25",
          principal: "two",
          role: "consumer",
        },
        {
          id: "ed",
          policy,
          required: true,
          label: "sig-b26",
          principal: "one",
          role: "agent",
        },
      ];
    const msg = await signed(["sig-b21", "sig-b25", "sig-b26"]);
    for (const extra of [
      { unit: "keys", n: 3 },
      { unit: "principals", n: 2 },
      { unit: "roles", sharedPrincipal: true, n: 2 },
      { unit: "roles", sharedPrincipal: false, n: 2 },
    ]) {
      const { n, ...unit } = extra;
      const result = value(
        await A.verifyQuorum(
          msg,
          q(slots, { ...unit, mode: { threshold: n } }),
          {},
        ),
      );
      assert.equal(result.count, n);
      assert.deepEqual(result.satisfied, ["rsa", "hmac", "ed"]);
      assert.equal(result.principal, "unattributed");
      assert.equal(A.isQuorumVerification(result), true);
      assert.equal(api.isVerification(result), false);
      assert.equal(A.isQuorumVerification({ ...result }), false);
      assert.equal(Object.isFrozen(result.signatures), true);
      assert.equal(api.isVerification(result.signatures["sig-b26"]), true);
      assert.equal(inspect(result).includes("sig-b26"), false);
      assert.equal(inspect(result).includes("satisfied"), true);
      const facts = JSON.parse(
        new TextDecoder().decode(value(api.serializeVerification(result))),
      );
      assert.deepEqual(facts.count, { int: String(n) });
      assert.equal(facts.signatures["sig-b26"].label, "sig-b26");
      reason(
        await A.verifyQuorum(
          msg,
          q(slots, { ...unit, mode: { threshold: n + 1 } }),
          {},
        ),
        "quorum_not_met",
      );
    }
  } finally {
    for (const h of k.handles) await h.release();
  }
});
test("aliases cannot fill two slots and partial coverage never combines", async () => {
  assert.equal(
    typeof A.verifyQuorum,
    "function",
    "verifyQuorum must be exported",
  );
  const k = await keys();
  try {
    const policy = p(k.pub),
      msg = await signed(["sig-b21", "sig-b22", "sig-b23"]);
    for (const unit of ["keys", "principals", "roles"])
      reason(
        await A.verifyQuorum(
          msg,
          q(
            [
              {
                id: "a",
                policy,
                required: true,
                label: "sig-b21",
                principal: "a",
                role: "a",
              },
              {
                id: "b",
                policy,
                required: true,
                label: "sig-b22",
                principal: "b",
                role: "b",
              },
            ],
            { unit, ...(unit === "roles" ? { sharedPrincipal: true } : {}) },
          ),
          {},
        ),
        "quorum_not_met",
      );
    const complete = p(k.pub, { components: '("@method" "content-digest")' });
    reason(
      await A.verifyQuorum(
        await signed(["sig-b21", "sig-b22"]),
        q([{ id: "complete", policy: complete, required: true }]),
        {},
      ),
      "quorum_not_met",
    );
    assert.equal(
      value(
        await A.verifyQuorum(
          msg,
          q([{ id: "complete", policy: complete, required: true }]),
          {},
        ),
      ).qualifying[0].label,
      "sig-b23",
    );
  } finally {
    for (const h of k.handles) await h.release();
  }
});
test("optional additions, removal and wire permutations preserve required assignment rules", async () => {
  assert.equal(
    typeof A.verifyQuorum,
    "function",
    "verifyQuorum must be exported",
  );
  const k = await keys();
  try {
    const policy = p(k.pub),
      slots = [
        { id: "rsa", policy, required: true, label: "sig-b23" },
        { id: "hmac", policy, required: true, label: "sig-b25" },
      ];
    for (const mode of ["any", { threshold: 2 }]) {
      const quorum = q(slots, { mode });
      const baseline = value(
        await A.verifyQuorum(await signed(["sig-b23", "sig-b25"]), quorum, {}),
      );
      await fc.assert(
        fc.asyncProperty(
          fc.shuffledSubarray(["sig-b26", "sig-b23", "sig-b25"], {
            minLength: 3,
            maxLength: 3,
          }),
          async (labels) => {
            const result = value(
              await A.verifyQuorum(await signed(labels), quorum, {}),
            );
            assert.deepEqual(result.qualifying, baseline.qualifying);
          },
        ),
        { numRuns: 24 },
      );
      reason(
        await A.verifyQuorum(await signed(["sig-b26"]), quorum, {}),
        "quorum_not_met",
      );
    }
    reason(
      await A.verifyQuorum(
        await signed(["sig-b26", "sig-b23", "sig-b25"]),
        q(slots, { mode: "any", unexpected: "reject" }),
        {},
      ),
      "unexpected_signature",
    );
    const broken = value(
      api.Message.create({ ...(await signed(["sig-b23"])), method: "PATCH" }),
    );
    reason(
      await A.verifyQuorum(
        broken,
        q([{ id: "one", policy, required: true }], { invalid: "reject" }),
        {},
      ),
      "nonqualifying_signature",
    );
    const base = await signed(["sig-b26"]);
    reason(
      await A.verifyQuorum(
        value(
          api.Message.create({
            ...base,
            fields: [...base.fields, base.fields.at(-1)],
          }),
        ),
        q([{ id: "one", policy, required: true }]),
        {},
      ),
      "duplicate_label",
    );
  } finally {
    for (const h of k.handles) await h.release();
  }
});
test("published proxy signatures preserve mixed validity and trusted optional-slot rejection", async () => {
  const publicKeys: Record<string, api.PublicKey> = {};
  for (const [algorithm, name] of [
    ["ecdsa-p256-sha256", "p256"],
    ["rsa-v1_5-sha256", "rsa"],
  ])
    publicKeys[algorithm!] = value(
      await api.PublicKey.import(
        await readFile(
          `test/fixtures/upstream/crypto/${name}_public.pem`,
          "utf8",
        ),
        "pem",
      ),
    );
  const policy = value(
    api.Policy.create({
      algorithms: ["ecdsa-p256-sha256", "rsa-v1_5-sha256"],
      components: "()",
      freshness: "not_evaluated",
      content: "not_required",
      replay: "not_required",
      keyResolver: ({ keyid }: { keyid: string | null }) => {
        const algorithm =
          keyid === "test-key-ecc-p256"
            ? "ecdsa-p256-sha256"
            : "rsa-v1_5-sha256";
        return api.ok({ algorithm, key: publicKeys[algorithm]! });
      },
    }),
  );
  const msg = m((await corpus()).proxy),
    slots = [
      { id: "client", label: "sig1", required: false, policy },
      { id: "proxy", label: "proxy_sig", required: true, policy },
    ];
  const result = value(
    await A.verifyQuorum(msg, q(slots, { mode: "any" }), {}),
  );
  assert.deepEqual(result.satisfied, ["proxy"]);
  assert.deepEqual(result.nonqualifying, [
    {
      label: "sig1",
      slot: "client",
      reason: "invalid_signature",
      layer: "crypto",
    },
  ]);
  reason(
    await A.verifyQuorum(msg, q(slots, { mode: "any", invalid: "reject" }), {}),
    "nonqualifying_signature",
  );
  reason(
    await A.verifyQuorum(
      msg,
      q(slots.map((s) => ({ ...s, required: true }))),
      {},
    ),
    "quorum_not_met",
  );
  const denied = value(
    api.Policy.create({ ...policy, keyResolver: () => api.ok(null) }),
  );
  const trusted = value(
    await A.verifyQuorum(
      msg,
      q([{ ...slots[0], policy: denied }, slots[1]], { mode: "any" }),
      {},
    ),
  );
  assert.equal(trusted.count, 1);
  assert.equal(trusted.nonqualifying[0].reason, "unknown_key");
});


test('quorum signature limit governs parsed inputs independently of slot limits', async () => {
  const {signedPool, quorum} = await import('./support/quorum.ts');
  const pool = await signedPool(17);
  try {
    const q = quorum(Array.from({length: 4}, (_, i) => ({id: `slot${i}`, policy: pool.policy, required: true})), {maxSignatures: 32, invalid: 'reject'});
    const r = value(await api.verifyQuorum(pool.message, q, {}));
    assert.equal(r.count, 4); assert.equal(pool.calls(), 68);
  } finally { await pool.release(); }
});

test('maximum quorum verification completes within the default context', {timeout: 15_000}, async (t) => {
  const {signedPool, quorum} = await import('./support/quorum.ts');
  const pool = await signedPool(64);
  try {
    const p = value(api.Policy.create({...pool.policy, maxSignatures: 64}));
    const q = quorum(Array.from({length: 16}, (_, i) => ({id: `slot${i}`, policy: p, required: true})), {maxSignatures: 64, invalid: 'reject'});
    const start = performance.now();
    const r = value(await api.verifyQuorum(pool.message, q, {}));
    const ms = performance.now() - start;
    t.diagnostic(`VERIFY_MAX signatures=64 slots=16 attempts=${pool.calls()} ms=${ms.toFixed(1)}`);
    assert.equal(r.count, 16); assert.equal(pool.calls(), 1024); assert.ok(ms < 4000);
  } finally { await pool.release(); }
});

test('nonqualifying facts and last rejection follow configured slot order', async () => {
  const {signedPool, quorum, policy} = await import('./support/quorum.ts');
  const pool = await signedPool(1);
  try {
    const slots = [
      {id: 'z', required: false, policy: policy({components: '("@authority")'})},
      {id: 'b', required: false, policy: pool.policy},
      {id: 'a', required: false, policy: policy({algorithms: ['ed25519']})},
    ];
    const r = value(await api.verifyQuorum(pool.message, quorum(slots), {}));
    assert.deepEqual(r.nonqualifying.map((f: any) => f.slot), ['z', 'a']);
    assert.deepEqual(r.satisfied, ['b']);
    const denied = await api.verifyQuorum(pool.message, quorum([slots[0], slots[2]], {invalid: 'reject'}), {});
    assert.equal(denied.ok, false);
    if (!denied.ok) { assert.equal(denied.error.reason, 'nonqualifying_signature'); assert.equal(denied.error.detail, 'algorithm_not_permitted'); }
  } finally { await pool.release(); }
});

test('asymmetric handle identities must match the canonical public key', async () => {
  const {quorum, policy} = await import('./support/quorum.ts');
  const priv = await readFile('test/fixtures/upstream/crypto/ed25519_private.pem', 'utf8');
  const pub = value(await api.PublicKey.import(await readFile('test/fixtures/upstream/crypto/ed25519_public.pem', 'utf8'), 'pem'));
  const handle = value(await api.Custody.local('ed25519', priv));
  try {
    const base = value(await api.Message.request('POST', 'https://example.com/a', [], ''));
    const first = value(await api.sign(base, {label: 's1', signatureInput: '("@method");keyid="handle"', algorithm: 'ed25519'}, (algorithm: api.SigningAlgorithm, data: Uint8Array, context = value(api.withDeadline())) => handle.sign(algorithm, data, context)));
    const msg = value(await api.sign(first, {label: 's2', signatureInput: '("@method");keyid="public"', algorithm: 'ed25519'}, (algorithm: api.SigningAlgorithm, data: Uint8Array, context = value(api.withDeadline())) => handle.sign(algorithm, data, context)));
    const wrong = value(api.KeyIdentity.symmetric('not-this-key'));
    const p = policy({algorithms: ['ed25519'], keyResolver: ({keyid}: {keyid: string}) => api.ok({algorithm: 'ed25519', key: keyid === 'handle' ? handle : pub, ...(keyid === 'handle' ? {identity: wrong} : {})})});
    const slots = [{id: 'a', policy: p, required: false}, {id: 'b', policy: p, required: false}];
    const r = await api.verifyQuorum(msg, quorum(slots, {mode: {threshold: 2}, invalid: 'reject'}), {});
    assert.equal(r.ok, false);
    if (!r.ok) { assert.equal(r.error.reason, 'nonqualifying_signature'); assert.equal(r.error.detail, 'key_resolver_failed'); }
    const canonical = value(await handle.identity(value(api.withDeadline())));
    for (const supplied of [undefined, canonical]) {
      const good = policy({algorithms: ['ed25519'], keyResolver: ({keyid}: {keyid: string}) => api.ok({algorithm: 'ed25519', key: keyid === 'handle' ? handle : pub, ...(supplied ? {identity: supplied} : {})})});
      const one = value(await api.verifyQuorum(msg, quorum(slots.map(s => ({...s, policy: good}))), {}));
      assert.equal(one.count, 1);
    }
  } finally { await handle.release(); }
});

test('composite JSON redacts labels while explicit fact serialization retains them', async () => {
  const {signedPool, quorum} = await import('./support/quorum.ts');
  const pool = await signedPool(1);
  try {
    const r = value(await api.verifyQuorum(pool.message, quorum([{id: 'only', policy: pool.policy, required: true}]), {}));
    const json = JSON.parse(JSON.stringify(r));
    assert.deepEqual(Object.keys(json), ['profile', 'mode', 'unit', 'required', 'satisfied', 'count', 'replay', 'principal', 'authorization']);
    assert.equal(json.count, 1); assert.deepEqual(json.satisfied, ['only']);
    assert.equal(JSON.stringify(json).includes('s0'), false);
    const facts = JSON.parse(new TextDecoder().decode(value(api.serializeVerification(r))));
    assert.equal(facts.qualifying[0].label, 's0');
  } finally { await pool.release(); }
});

test('per-label base cache reuses builds and separates field schemas', async () => {
  const {signedPool} = await import('./support/quorum.ts');
  const {dictionaries} = await import('../src/signature-fields.ts');
  const {verifyCandidate} = await import('../src/verify.ts');
  const pool = await signedPool(1);
  try {
    const [inputs, signatures] = dictionaries(pool.message, 64);
    const baseCache = new Map();
    const parsed = {input: inputs.get('s0')!, signature: signatures.get('s0') as api.Item, baseCache};
    for (let i = 0; i < 16; i++) value(await verifyCandidate(pool.message, pool.policy, {label: 's0'}, parsed));
    assert.equal(baseCache.size, 1);
    const first = [...baseCache.values()][0];
    value(await verifyCandidate(pool.message, pool.policy, {label: 's0'}, parsed));
    assert.equal([...baseCache.values()][0], first);
    const p = value(api.Policy.create({...pool.policy, fieldSchemas: {'x-field': {revision: 'rfc8941', type: 'item', itemTypes: ['string'], parameterTypes: [], innerLists: false}}}));
    value(await verifyCandidate(pool.message, p, {label: 's0'}, parsed));
    assert.equal(baseCache.size, 2);
  } finally { await pool.release(); }
});
