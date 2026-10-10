import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { signatureSchema } from "../src/signature-fields.ts";
import * as api from "../src/index.ts";
import {custodyError} from "../src/errors/types.ts";
const A = api as any;
const value = (r: any): any => {
  assert.equal(r.ok, true, JSON.stringify(r));
  return r.value;
};
const fieldSchemas = {
  "signature-input": { ...signatureSchema, type: "dictionary" },
  signature: {
    ...signatureSchema,
    type: "dictionary",
    itemTypes: ["bytes"],
    innerLists: false,
  },
};
const reason = (r: any, s: string) => {
  assert.equal(r.ok, false);
  assert.equal(r.error.reason, s);
};
async function handle(name = "ed25519", algorithm = "ed25519") {
  return value(
    await api.Custody.local(
      algorithm,
      await readFile(
        `test/fixtures/upstream/crypto/${name}_private.pem`,
        "utf8",
      ),
    ),
  );
}
function policy(key: any, algorithm = "ed25519", extra = {}) {
  return value(
    api.Policy.create({
      algorithms: [algorithm],
      components: "()",
      keyResolver: () => api.ok({ algorithm, key }),
      freshness: "not_evaluated",
      content: "not_required",
      replay: "not_required",
      fieldSchemas,
      ...extra,
    }),
  );
}
function quorum(slots: any[], extra = {}) {
  return value(
    A.Quorum.create({
      slots,
      mode: "all",
      unit: "keys",
      unexpected: "ignore",
      invalid: "ignore",
      ...extra,
    }),
  );
}
async function add(
  m: any,
  h: any,
  label: string,
  input: string,
  algorithm = "ed25519",
) {
  return value(
    await api.sign(
      m,
      { label, signatureInput: input, algorithm },
      (a: api.SigningAlgorithm, b: Uint8Array, c = value(api.withDeadline())) =>
        h.sign(a, b, c),
      { fieldSchemas },
    ),
  );
}
test("nested and same-parameter bindings evaluate actual assigned labels and parameter values", async () => {
  assert.equal(
    typeof A.verifyQuorum,
    "function",
    "verifyQuorum must be exported",
  );
  const first = await handle(),
    second = await handle("rsa_pss", "rsa-pss-sha512");
  try {
    const unsigned = value(
        await api.Message.request("GET", "https://example.com/", [], ""),
      ),
      inner = await add(unsigned, first, "inner", '("@method");nonce="same"'),
      outer = await add(
        inner,
        second,
        "outer",
        '("signature-input";key="inner" "signature";key="inner");nonce="same"',
        "rsa-pss-sha512",
      );
    const slots = [
      { id: "inner", required: true, label: "inner", policy: policy(first) },
      {
        id: "outer",
        required: true,
        label: "outer",
        policy: policy(second, "rsa-pss-sha512"),
      },
    ];
    const bindings = [
      { kind: "nested", outer: "outer", inner: "inner" },
      { kind: "same_parameter", name: "nonce", slots: ["inner", "outer"] },
    ];
    assert.equal(
      value(await A.verifyQuorum(outer, quorum(slots, { bindings }), {}))
        .bindings.length,
      2,
    );
    for (const input of [
      '("signature-input";key="inner");nonce="same"',
      '("signature-input";key="inner" "signature";key="inner");nonce="different"',
    ])
      reason(
        await A.verifyQuorum(
          await add(inner, second, "outer", input, "rsa-pss-sha512"),
          quorum(slots, { bindings }),
          {},
        ),
        "binding_unsatisfied",
      );
    const missing = quorum(
      [
        ...slots,
        {
          id: "optional",
          required: false,
          label: "absent",
          policy: policy(first),
        },
      ],
      { bindings: [{ kind: "nested", outer: "outer", inner: "optional" }] },
    );
    reason(await A.verifyQuorum(outer, missing, {}), "binding_unsatisfied");
    reason(
      await A.verifyQuorum(inner, quorum(slots, { bindings }), {}),
      "quorum_not_met",
    );
  } finally {
    await first.release();
    await second.release();
  }
});
test("negotiation searches the verified eligible pool even when a challenge is unassigned", async () => {
  assert.equal(
    typeof A.verifyQuorum,
    "function",
    "verifyQuorum must be exported",
  );
  const h = await handle();
  try {
    const unsigned = value(
      await api.Message.request("GET", "https://example.com/", [], ""),
    );
    let m = await add(unsigned, h, "a", '("@method");nonce="fresh";created=10');
    m = await add(m, h, "challenge", '("@method");nonce="fresh";created=10');
    const q = quorum([
      { id: "fixed", policy: policy(h), required: true, label: "a" },
      {
        id: "optional",
        policy: policy(h),
        required: false,
        label: "challenge",
      },
    ]);
    const requests = value(
      A.AcceptSignature.parse('challenge=("@method");created;nonce="fresh"', {
        target: "request",
      }),
    );
    const result = value(
      await A.verifyQuorum(m, q, { acceptSignature: requests }),
    );
    assert.equal(result.negotiation, "fulfilled");
    assert.deepEqual(Object.keys(result.signatures), ["a"]);
    for (const wire of [
      'challenge=("@path");nonce="fresh"',
      'challenge=("@method");expires;nonce="fresh"',
      'challenge=("@method");nonce="other"',
      'absent=("@method")',
    ])
      reason(
        await A.verifyQuorum(m, q, {
          acceptSignature: value(
            A.AcceptSignature.parse(wire, { target: "request" }),
          ),
        }),
        "negotiation_unfulfilled",
      );
    reason(
      await A.verifyQuorum(m, q, { acceptSignature: [...requests] }),
      "invalid_accept_signature",
    );
    const sig = m.fields.find(
      (f: any) =>
        f.name.toLowerCase() === "signature" &&
        new TextDecoder().decode(f.value).startsWith("challenge="),
    );
    const bytes = new TextDecoder().decode(sig.value);
    const changed = bytes.replace(
      /=:(.)/,
      (_: string, c: string) => "=:" + (c === "A" ? "B" : "A"),
    );
    const bad = value(
      api.Message.create({
        ...m,
        fields: m.fields.map((f: any) =>
          f === sig
            ? value(
                api.FieldOccurrence.create({
                  name: f.name,
                  value: changed,
                  section: "headers",
                }),
              )
            : f,
        ),
      }),
    );
    reason(
      await A.verifyQuorum(bad, q, { acceptSignature: requests }),
      "negotiation_unfulfilled",
    );
  } finally {
    await h.release();
  }
});
test("HMAC aliases and imports obey trusted equivalence and unknown pool capacity", async () => {
  assert.equal(
    typeof A.verifyQuorum,
    "function",
    "verifyQuorum must be exported",
  );
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const handles: any[] = [];
  try {
    for (const [name, identity] of [
      ["one", "shared"],
      ["alias", "shared"],
      ["distinct", "other"],
      ["unknown", null],
    ]) {
      const h = value(
        await api.Custody.local("hmac-sha256", {
          hmac: secret,
          ...(identity ? { identity } : {}),
        }),
      );
      handles.push(h);
    }
    const imported = value(
      await api.Custody.local(
        { jws: "HS256" },
        { kty: "oct", k: api.encodeBase64Url(secret) },
        { format: "jwk", equivalence: "shared" },
      ),
    );
    handles.push(imported);
    assert.equal(
      value(
        api.KeyIdentity.same(
          value(await handles[0].identity()),
          value(await imported.identity()),
        ),
      ),
      true,
    );
    const unsigned = value(
      await api.Message.request("GET", "https://example.com/", [], ""),
    );
    const m = await add(
      await add(
        unsigned,
        handles[0],
        "one",
        '("@method");keyid="first"',
        "hmac-sha256",
      ),
      handles[1],
      "two",
      '("@method");keyid="alias"',
      "hmac-sha256",
    );
    const first = {
      id: "one",
      label: "one",
      required: true,
      policy: policy(handles[0], "hmac-sha256"),
    };
    reason(
      await A.verifyQuorum(
        m,
        quorum([
          first,
          {
            id: "two",
            label: "two",
            required: true,
            policy: policy(handles[1], "hmac-sha256"),
          },
        ]),
        {},
      ),
      "quorum_not_met",
    );
    assert.equal(
      value(
        await A.verifyQuorum(
          m,
          quorum([
            first,
            {
              id: "two",
              label: "two",
              required: true,
              policy: policy(handles[2], "hmac-sha256"),
            },
          ]),
          {},
        ),
      ).count,
      2,
    );
    reason(
      await A.verifyQuorum(
        m,
        quorum([
          first,
          {
            id: "two",
            label: "two",
            required: true,
            policy: policy(handles[3], "hmac-sha256"),
          },
        ]),
        {},
      ),
      "ambiguous_key_identity",
    );
    const optional = {
      id: "two",
      label: "two",
      required: false,
      policy: policy(handles[3], "hmac-sha256"),
    };
    assert.equal(
      value(
        await A.verifyQuorum(m, quorum([first, optional], { mode: "any" }), {}),
      ).count,
      1,
    );
    const unknowns = [
      { ...first, policy: policy(handles[3], "hmac-sha256"), principal: "p1" },
      { ...optional, principal: "p2" },
    ];
    assert.equal(
      value(
        await A.verifyQuorum(
          m,
          quorum(unknowns, { unit: "principals", mode: "any" }),
          {},
        ),
      ).count,
      1,
    );
    // One verified label bridges the known class into the shared unknown pool.
    const bridge = [
      { ...first, principal: "known" },
      { ...optional, principal: "unknown" },
      {
        id: "bridge",
        required: false,
        label: "one",
        principal: "bridge",
        policy: policy(handles[3], "hmac-sha256"),
      },
    ];
    assert.equal(
      value(
        await A.verifyQuorum(
          m,
          quorum(bridge, { unit: "principals", mode: "any" }),
          {},
        ),
      ).count,
      1,
    );
    reason(
      await A.verifyQuorum(
        m,
        quorum(
          [
            { ...first, principal: "same", role: "agent" },
            {
              id: "two",
              label: "two",
              required: true,
              policy: policy(handles[2], "hmac-sha256"),
              principal: "same",
              role: "consumer",
            },
          ],
          { unit: "roles", sharedPrincipal: false },
        ),
        {},
      ),
      "quorum_not_met",
    );
  } finally {
    for (const h of handles) await h.release();
    secret.fill(0);
  }
});
test("retained content, caller deadlines and unsupported composite options fail closed", async () => {
  assert.equal(
    typeof A.verifyQuorum,
    "function",
    "verifyQuorum must be exported",
  );
  const h = await handle();
  try {
    const unsigned = value(
      await api.Message.request("POST", "https://example.com/", [], "body"),
    );
    const signed = value(
      await api.sign(
        unsigned,
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
    const p = policy(h, "ed25519", {
        content: {
          kind: "content",
          algorithms: ["sha-256"],
          section: "headers",
        },
      }),
      q = quorum([{ id: "one", policy: p, required: true }], {
        invalid: "reject",
      });
    assert.equal(
      value(await A.verifyQuorum(signed, q, {})).signatures.s.content.bytes,
      4,
    );
    const unavailable = value(api.Body.create({ state: "unavailable" }));
    reason(
      await A.verifyQuorum(
        value(api.Message.create({ ...signed, body: unavailable })),
        q,
        {},
      ),
      "nonqualifying_signature",
    );
    reason(
      await A.verifyQuorum(
        value(
          api.Message.create({
            ...signed,
            body: value(api.Body.create({ state: "retained", bytes: "evil" })),
          }),
        ),
        q,
        {},
      ),
      "nonqualifying_signature",
    );
    for (const options of [
      { digestState: {} },
      { representation: signed.body },
      { profile: {} },
      { label: "s" },
    ])
      reason(await A.verifyQuorum(signed, q, options), "invalid_options");
    const controller = new AbortController();
    controller.abort();
    reason(
      await A.verifyQuorum(signed, q, {
        context: value(api.withDeadline({ signal: controller.signal })),
      }),
      "deadline_exceeded",
    );
    let reads = 0;
    value(
      await A.verifyQuorum(signed, q, {
        get context() {
          reads++;
          return value(api.withDeadline());
        },
      }),
    );
    assert.equal(reads, 1);
    reason(await A.verifyQuorum(signed, { ...q }, {}), "invalid_quorum");
  } finally {
    await h.release();
  }
});

for (const behavior of ['fails', 'hangs'] as const) test(`single-label verification skips a custodian identity that ${behavior}`, async () => {
  const local = await handle();
  let calls = 0;
  const custodian = {
    sign: (a: unknown, d: unknown, c: api.Context) => local.sign(a, d, c),
    verify: (a: unknown, s: unknown, d: unknown, c: api.Context) => local.verify(a, s, d, c),
    publicKey: (c?: api.Context) => local.publicKey(c),
    identity: async (_c?: api.Context): Promise<api.Result<api.KeyIdentity>> => {
      calls++;
      if (behavior === 'hangs') return new Promise(() => {});
      return api.err(custodyError('unsupported_operation'));
    },
    unwrap: (a: unknown, w: unknown, c: api.Context, o?: unknown) => local.unwrap(a, w, c, o),
    release: () => local.release(),
  };
  const h = value(api.createKeyHandle('ed25519', custodian));
  try {
    const base = value(await api.Message.request('POST', 'https://example.com/', [], ''));
    const signed = value(await api.sign(base, {label: 's', algorithm: 'ed25519', components: '("@method")', expiresIn: 60}, local));
    const p = policy(h, 'ed25519');
    value(await api.verify(signed, p, {label: 's'}));
    assert.equal(calls, 0);
    const r = await api.verifyQuorum(signed, quorum([{id: 'one', policy: p, required: true}], {invalid: 'reject'}), {context: value(api.withDeadline({timeoutMs: behavior === 'hangs' ? 500 : 5000}))});
    assert.equal(r.ok, false);
    if (!r.ok) {
      assert.equal(r.error.reason, behavior === 'hangs' ? 'deadline_exceeded' : 'nonqualifying_signature');
      if (behavior === 'fails' && r.error.kind === 'core') assert.equal(r.error.detail, 'key_resolver_failed');
    }
    assert.equal(calls, 1);
    const supplied = policy(h, 'ed25519', {keyResolver: () => api.ok({algorithm: 'ed25519', key: h, identity: value(api.KeyIdentity.symmetric('claimed'))})});
    const checked = await api.verify(signed, supplied, {label: 's', context: value(api.withDeadline({timeoutMs: behavior === 'hangs' ? 500 : 5000}))});
    assert.equal(checked.ok, false);
    if (!checked.ok) assert.equal(checked.error.reason, behavior === 'hangs' ? 'deadline_exceeded' : 'key_resolver_failed');
    assert.equal(calls, 2);
  } finally { await h.release(); }
});
