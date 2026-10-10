import test from "node:test";
import assert from "node:assert/strict";
import { inspect } from "node:util";
import { verificationFacts } from "../src/verification.ts";
import { schemas } from "../src/web-bot-auth/support.ts";
import * as Seal from "../src/index.ts";
import fc from "fast-check";
import {
  value,
  now,
  request,
  published,
  policy,
  rewrite,
  agentField,
  rejection,
  trust,
  custody,
} from "./support/web-bot-auth.ts";
import { dictionaries } from "../src/signature-fields.ts";
async function signedMember(wire: string, extra: [string, string][] = [], components = '("@authority" "signature-agent";key="agent")') {
  const h = await custody();
  try {
    const key = value(await h.publicKey()), kid = value(await key.thumbprint());
    const m = value(await Seal.Message.request("GET", "https://example.com/resource", [["Signature-Agent", wire], ...extra], ""));
    return value(await Seal.sign(m, {
      label: "agent", algorithm: "ed25519",
      signatureInput: `${components};created=${now};expires=${now + 60};keyid="${kid}";nonce="inspection-nonce";tag="web-bot-auth"`,
    }, (a: Seal.SigningAlgorithm, b: Uint8Array, c = value(Seal.withDeadline())) => h.sign(a, b, c), {fieldSchemas: schemas({})}));
  } finally { await h.release(); }
}
for (const member of ["signature-input", "signature", "both"] as const)
test(`nested ${member} coverage preserves member-specific evidence and completeness`, async () => {
  const extra: [string, string][] = [
    ["Signature-Input", 'inner=("@method");keyid="unverified"'],
    ["Signature", "inner=:AAAA:"],
  ];
  const selected = member === "both"
    ? '"signature-input";key="inner" "signature";key="inner"'
    : `"${member}";key="inner"`;
  const m = await signedMember('agent="https://signature-agent.test"', extra,
    `("@authority" "signature-agent";key="agent" "@method" ${selected})`);
  if (member === "signature") {
    rejection(await Seal.WebBotAuth.verify(m, policy()), "nested_coverage_incomplete");
    return;
  }
  const verified = value(await Seal.WebBotAuth.verify(m, policy()));
  assert.deepEqual(verified.evidence.agent, member === "both" ? ["inner"] : []);
  assert.deepEqual(verified.ignored, ["inner"]);
  assert.deepEqual(Object.keys(verified.signatures), ["agent"]);
  if (member === "signature-input") {
    // Metadata coverage alone makes no claim about the ignored signature bytes.
    const changed = rewrite(m, (name, wire) => name === "signature"
      ? wire.replace("inner=:AAAA:", "inner=:BBBB:") : wire);
    assert.deepEqual(value(await Seal.WebBotAuth.verify(changed, policy())).evidence.agent, []);
  } else {
    const incomplete = await signedMember('agent="https://signature-agent.test"', extra,
      `("@authority" "signature-agent";key="agent" ${selected})`);
    rejection(await Seal.WebBotAuth.verify(incomplete, policy()), "nested_coverage_incomplete");
  }
});
test("signing lifetime accepts one second and one day and rejects outside those edges", async () => {
  const h = await custody();
  try {
    const key = value(await h.publicKey());
    const unsigned = value(await Seal.Message.request("GET", "https://example.com/resource", [], ""));
    const spec = {label: "agent", key, algorithm: "ed25519", agent: {location: "https://signature-agent.test", type: "directory"}, created: now, nonce: null};
    let calls = 0;
    const signer = (a: Seal.SigningAlgorithm, b: Uint8Array, c: Seal.Context) => {
      calls++;
      return h.sign(a, b, c);
    };
    for (const lifetime of [1, 86400]) {
      const m = value(await Seal.WebBotAuth.sign(unsigned, {...spec, expires: now + lifetime}, signer));
      value(await Seal.WebBotAuth.verify(m, policy({maxLifetime: 604800})));
    }
    assert.equal(calls, 2);
    for (const lifetime of [0, 86401, 604800])
      rejection(await Seal.WebBotAuth.sign(unsigned, {...spec, expires: now + lifetime}, signer), "invalid_options");
    assert.equal(calls, 2, "invalid lifetime never reaches signing custody");
  } finally { await h.release(); }
});
test("advancing clocks retain independent profile, key, and generic freshness samples", async () => {
  const m = await request();
  let reads = 0;
  const verified = value(await Seal.WebBotAuth.verify(m, policy({
    freshness: {clock: () => now + ++reads, maxAge: null, skew: 0},
  })));
  assert.equal(reads, 3);
  const freshness = verified.signatures.agent!.freshness;
  assert.notEqual(freshness, "not_evaluated");
  if (freshness !== "not_evaluated") assert.equal(freshness.now, now + 3);
  reads = 0;
  rejection(await Seal.WebBotAuth.verify(m, policy({
    freshness: {clock: () => now + 3597 + ++reads, maxAge: null, skew: 0},
  })), "expired");
  assert.equal(reads, 3, "generic sample reaches exclusive expiry after earlier samples accept");
  reads = 0;
  rejection(await Seal.WebBotAuth.verify(m, policy({
    freshness: {clock: () => now + 7198 + ++reads, maxAge: null, skew: 7200},
  })), "agent_unresolved", "unknown_key");
  assert.equal(reads, 2, "key lookup uses its own sample at the snapshot expiration");
});
test("nested coverage includes an ignored unverified inner label without attributing it", async () => {
  const m = await signedMember('agent="https://signature-agent.test"', [
    ["Signature-Input", 'inner=("@method");keyid="unverified"'],
    ["Signature", "inner=:AAAA:"],
  ], '("@authority" "signature-agent";key="agent" "@method" "signature-input";key="inner" "signature";key="inner")');
  const v = value(await Seal.WebBotAuth.verify(m, policy()));
  assert.deepEqual(v.evidence.agent, ["inner"]);
  assert.deepEqual(v.ignored, ["inner"]);
  assert.deepEqual(Object.keys(v.signatures), ["agent"]);
  assert.equal(Object.hasOwn(v.signatures, "inner"), false);
});
test("directory host normalization rejects noncanonical IPv6 and IPv4 before trust", async () => {
  let calls = 0;
  const p = policy({agents: (a: Seal.AgentRequest) => { calls++; return trust(a); }});
  value(await Seal.WebBotAuth.verify(await request(), p));
  assert.equal(calls, 1);
  for (const host of ["https://[0:0::1]", "https://0x7f.1"])
    rejection(await Seal.WebBotAuth.verify(agentField(await request(), `agent="${host}"`), p), "agent_unresolved", "not_an_origin");
  assert.equal(calls, 1);
});
test("per-signature deadline returns retryable custody failure after successful resolution", async () => {
  const context = value(Seal.withDeadline({timeoutMs: 500}));
  let clocks = 0, trusts = 0;
  const r = await Seal.WebBotAuth.verify(await request(), policy({
    agents: (a: Seal.AgentRequest) => { trusts++; return trust(a); },
    freshness: {clock: () => {
      if (++clocks === 3) {
        // Expire the real absolute deadline inside the generic freshness check.
        while (Seal.remainingMs(context) > 0) { /* bounded by the Context */ }
      }
      return now;
    }, maxAge: null, skew: 0},
  }), {context});
  assert.equal(trusts, 1);
  assert.equal(clocks, 3);
  assert.equal(r.ok, false);
  if (!r.ok) {
    assert.equal(r.error.kind, "custody");
    assert.equal(r.error.reason, "deadline_exceeded");
    assert.equal(r.error.retryable, true);
  }
});
test("held-key fallback runs for eligible resolution failures and never bypasses binding or revocation", async () => {
  const m = await request(), h = await custody();
  try {
    const key = value(await h.publicKey()), kid = value(await key.thumbprint());
    const source = (extra = {}) => value(Seal.DiscoverySource.create({type: "directory", location: "https://signature-agent.test", ...extra}));
    const empty = value(await Seal.Discovery.resolver.fromSnapshot(source({requireSignedDirectory: false}), new TextEncoder().encode('{"keys":[]}'), now, [["content-type", "application/http-message-signatures-directory+json"]]));
    const cases: [string, Seal.Message, Seal.AgentTrust, boolean][] = [
      ["untrusted_agent", m, (_a) => Seal.ok(null), true],
      ["unsupported_type", await signedMember('agent="https://signature-agent.test";type=unknown'), trust, true],
      ["unknown_key", m, (_a) => Seal.ok(empty), true],
      ["source_unavailable", m, (_a) => Seal.ok(source()), true],
      ["revoked_key", m, (_a) => Seal.ok(source({revoked: [kid]})), false],
      ["source_mismatch", m, (_a) => Seal.DiscoverySource.create({type: "directory", location: "https://other.example"}), false],
      ["not_an_origin", agentField(m, 'agent="https://signature-agent.test/"'), trust, false],
    ];
    for (const [detail, message, agents, allowed] of cases) {
      let calls = 0;
      const r = await Seal.WebBotAuth.verify(message, policy({agents, unresolved: {heldKeys: (_a: unknown) => {calls++; return Seal.ok({algorithm: "ed25519", key});}}}));
      assert.equal(calls, allowed ? 1 : 0, detail);
      if (allowed) assert.equal(value(r).signatures.agent!.principal.kind, "key");
      else rejection(r, "agent_unresolved", detail);
    }
    let calls = 0;
    let releaseTrust!: () => void;
    const heldTrust = new Promise<void>(resolve => {releaseTrust = resolve;});
    const trustWork: Promise<Awaited<ReturnType<typeof trust>>>[] = [];
    try {
      rejection(await Seal.WebBotAuth.verify(m, policy({agents: (a: Seal.AgentRequest) => {
        const work = heldTrust.then(() => trust(a));
        trustWork.push(work);
        return work;
      }, unresolved: {heldKeys: (_a: unknown) => {calls++; return Seal.ok({algorithm: "ed25519", key});}}}), {timeoutMs: 1000}), "agent_unresolved", "timeout");
      assert.equal(trustWork.length, 1, "timeout reaches the trust callback");
      assert.equal(calls, 0, "expired shared Context blocks held-key invocation");
    } finally {releaseTrust(); await Promise.all(trustWork);}
  } finally {await h.release();}
});
for (const form of ["bound zero-arity", "optional third parameter", "key handle"] as const)
test(`signing accepts a ${form} signer through both public pipelines`, async () => {
  const h = await custody();
  try {
    const key = value(await h.publicKey());
    const bound = ((...args: [Seal.SigningAlgorithm, Uint8Array, Seal.Context]) => h.sign(...args)).bind(null);
    const optional = (a: Seal.SigningAlgorithm, b: Uint8Array, c?: Seal.Context) => h.sign(a, b, c!);
    assert.equal(bound.length, 0);
    assert.equal(optional.length, 3);
    const signer = form === "key handle" ? h : form === "bound zero-arity" ? bound : optional;
    const m = value(await Seal.Message.request("GET", "https://example.com/resource", [], ""));
    const signed = value(await Seal.WebBotAuth.sign(m, {label: "agent", key, algorithm: "ed25519", agent: {location: "https://signature-agent.test", type: "directory"}, created: now, expires: now + 60, nonce: null}, signer));
    value(await Seal.WebBotAuth.verify(signed, policy()));
    const generic = value(await Seal.sign(m, {label: "single", algorithm: "ed25519", signatureInput: '("@method")'}, signer));
    value(await Seal.verify(generic, value(Seal.Policy.create({algorithms: ["ed25519"], components: "()", keyResolver: () => Seal.ok({algorithm: "ed25519", key}), freshness: "not_evaluated", content: "not_required", replay: "not_required"})), {label: "single"}));
  } finally {await h.release();}
});
test("trust and held-key callbacks accept callable shapes and reject malformed Results at invocation", async () => {
  const h = await custody();
  try {
    const key = value(await h.publicKey());
    const boundTrust = trust.bind(null, {type: "directory", location: "https://signature-agent.test", identifier: ""});
    const optionalTrust = (a: Seal.AgentRequest, _context?: Seal.Context, _extra?: unknown) => trust(a);
    const boundHeld = ((_a: unknown) => Seal.ok({algorithm: "ed25519", key})).bind(null, null);
    const optionalHeld = (_a: unknown, _context?: Seal.Context, _extra?: unknown) => Seal.ok({algorithm: "ed25519", key});
    assert.equal(boundTrust.length, 0); assert.equal(boundHeld.length, 0);
    assert.equal(optionalTrust.length, 3); assert.equal(optionalHeld.length, 3);
    for (const agents of [boundTrust, optionalTrust]) value(await Seal.WebBotAuth.verify(await request(), policy({agents})));
    for (const heldKeys of [boundHeld, optionalHeld])
      assert.equal(value(await Seal.WebBotAuth.verify(await request(), policy({agents: (_a: unknown) => Seal.ok(null), unresolved: {heldKeys}}))).signatures.agent!.principal.kind, "key");
    rejection(await Seal.WebBotAuth.verify(await request(), policy({agents: () => undefined})), "agent_unresolved", "untrusted_agent");
    rejection(await Seal.WebBotAuth.verify(await request("held-key"), policy({unresolved: {heldKeys: () => undefined}})), "agent_unresolved", "unknown_key");
    const bad = await Seal.WebBotAuth.sign(value(await Seal.Message.request("GET", "https://example.com", [], "")), {label: "agent", key, algorithm: "ed25519", agent: {location: "https://signature-agent.test", type: "directory"}, created: now, expires: now + 60, nonce: null}, () => undefined);
    rejection(bad, "signer_failed");
  } finally {await h.release();}
});
test("individual verification inspection exposes only safe facts while explicit serialization retains metadata", async () => {
  const envelope = value(await Seal.WebBotAuth.verify(await request(), policy()));
  const v = envelope.signatures.agent!;
  assert.equal(v.principal.kind, "agent");
  const sensitive = [v.principal.identifier, v.signature.keyid!,
    String(v.signature.parameters.find(([k]) => k === "nonce")![1].value)];
  const canonical = new TextDecoder().decode(value(Seal.serializeVerification(v)));
  const facts = JSON.stringify(value(verificationFacts(v)));
  for (const needle of sensitive) {
    assert.ok(needle.length > 0);
    // Positive control: the scan detects the retained caller-visible metadata.
    assert.ok(JSON.stringify({ ...v }).includes(needle));
    for (const printed of [JSON.stringify(v), inspect(v)])
      assert.equal(printed.includes(needle), false);
  }
  for (const needle of [v.signature.keyid!, sensitive[2]!]) {
    assert.ok(canonical.includes(needle));
    assert.ok(facts.includes(needle));
  }
  const safe = {label: v.label, profile: v.profile, replay: v.replay, authorization: v.authorization};
  assert.deepEqual(JSON.parse(JSON.stringify(v)), safe);
  for (const symbol of [Symbol.for("nodejs.util.inspect.custom"), Symbol.for("Deno.customInspect")]) {
    const hook = (v as unknown as Record<symbol, () => unknown>)[symbol]!;
    assert.deepEqual(hook(), safe);
  }
});
test("protocol verification produces independent source-bound signature facts and nested evidence", async () => {
  assert.equal(typeof Seal.WebBotAuth.verify, "function");
  for (const name of [
    "directory",
    "jwks_uri",
    "cimd",
    "target-uri",
    "rsa",
    "content",
    "nested",
  ]) {
    const p =
      name === "content"
        ? policy({
            content: {
              kind: "content",
              algorithms: ["sha-256"],
              section: "headers",
            },
          })
        : policy();
    const r = value(await Seal.WebBotAuth.verify(await request(name), p));
    assert.ok(Seal.isWebBotAuthVerification(r));
    assert.equal(Seal.isVerification(r), false);
    assert.equal(Seal.isWebBotAuthVerification({ ...r }), false);
    assert.ok(Object.isFrozen(r.signatures));
    for (const v of Object.values(r.signatures)) {
      assert.equal(v.signature.crypto, "valid");
      assert.equal(v.profile.name, "web_bot_auth");
      assert.equal(v.principal.kind, "agent");
      assert.equal(v.authorization, "not_evaluated");
      assert.ok(Seal.isVerification(v));
    }
    if (name === "nested") assert.deepEqual(r.evidence.browser, ["agent"]);
  }
});
test("protocol fields and selected-label requirements reject with bounded reasons before trust", async () => {
  const m = await request();
  for (const [wire, reason, detail] of [
    [
      '"https://signature-agent.test"',
      "invalid_signature_agent",
      "legacy_string",
    ],
    [
      'agent="https://signature-agent.test", agent="https://signature-agent.test"',
      "invalid_signature_agent",
      "duplicate_member",
    ],
    ["agent=?1", "invalid_signature_agent", "invalid_dictionary"],
    [
      'agent="http://signature-agent.test"',
      "invalid_signature_agent",
      "invalid_member",
    ],
    [
      'agent="https://signature-agent.test";type="directory"',
      "invalid_signature_agent",
      "invalid_member",
    ],
    [
      'other="https://signature-agent.test"',
      "agent_unresolved",
      "missing_member",
    ],
    [
      'agent="https://signature-agent.test/path"',
      "agent_unresolved",
      "not_an_origin",
    ],
    [
      'agent="https://signature-agent.test/"',
      "agent_unresolved",
      "not_an_origin",
    ],
    [
      'agent="https://signature-agent.test";type=unknown',
      "agent_unresolved",
      "unsupported_type",
    ],
  ])
    rejection(
      await Seal.WebBotAuth.verify(agentField(m, wire!), policy()),
      reason!,
      detail!,
    );
  for (const [name, reason] of [
    ["created", "missing_created"],
    ["expires", "missing_expires"],
    ["keyid", "invalid_keyid"],
    ["tag", "no_web_bot_auth_signature"],
  ])
    rejection(
      await Seal.WebBotAuth.verify(
        rewrite(m, (n, w) =>
          n === "signature-input"
            ? w.replace(new RegExp(`;${name}=(?:"[^"]*"|[0-9]+)`), "")
            : w,
        ),
        policy(),
      ),
      reason!,
    );
  rejection(
    await Seal.WebBotAuth.verify(m, policy({ testKeys: "reject" })),
    "test_key_rejected",
  );
  rejection(
    await Seal.WebBotAuth.verify(m, policy({ maxLifetime: 1 })),
    "lifetime_exceeded",
  );
  rejection(
    await Seal.WebBotAuth.verify(await request("nested-incomplete"), policy()),
    "nested_coverage_incomplete",
  );
  for (const replacement of ['"@path"', '"@authority";req'])
    rejection(
      await Seal.WebBotAuth.verify(
        rewrite(m, (n, w) =>
          n === "signature-input" ? w.replace('"@authority"', replacement) : w,
        ),
        policy(),
      ),
      "missing_required_component",
    );
  for (const v of published.filter((v) =>
    ["E.1.1", "E.2.1"].includes(v.section),
  ))
    rejection(
      await Seal.WebBotAuth.verify(
        value(
          await Seal.Message.request(
            "GET",
            "https://example.com/resource",
            v.fields,
            "",
          ),
        ),
        policy(),
      ),
      "agent_unresolved",
      "missing_member",
    );
});
test("source association cannot be replaced by aliases or unsafe held-key fallback", async () => {
  const m = await request();
  rejection(
    await Seal.WebBotAuth.verify(
      m,
      policy({ agents: (_a: unknown) => Seal.ok(null) }),
    ),
    "agent_unresolved",
    "untrusted_agent",
  );
  rejection(
    await Seal.WebBotAuth.verify(
      m,
      policy({
        agents: (a: Seal.AgentRequest) =>
          trust({ ...a, location: "https://other.example" }),
      }),
    ),
    "agent_unresolved",
    "source_mismatch",
  );
  rejection(
    await Seal.WebBotAuth.verify(
      m,
      policy({
        agents: (a: Seal.AgentRequest) =>
          Seal.DiscoverySource.create({ type: a.type, location: a.location }),
      }),
    ),
    "agent_unresolved",
    "source_unavailable",
  );
  const held = await request("held-key");
  const set = value(
    await trust({
      type: "directory",
      location: "https://signature-agent.test",
      identifier: "",
    }),
  );
  const key = Object.values(set.keys).find(
    (k) => k.algorithm === "ed25519",
  )!.key;
  let calls = 0;
  const p = policy({
    unresolved: {
      heldKeys: (_a: unknown) => {
        calls++;
        return Seal.ok({ algorithm: "ed25519", key });
      },
    },
  });
  const r = value(await Seal.WebBotAuth.verify(held, p));
  assert.deepEqual(r.signatures.agent!.principal, {
    kind: "key",
    thumbprint: value(await key.thumbprint()),
  });
  for (const wire of ["", 'other="https://signature-agent.test"'])
    rejection(
      await Seal.WebBotAuth.verify(agentField(held, wire), p),
      "agent_unresolved",
      "missing_member",
    );
  assert.equal(calls, 1);
});
test("trust deadlines share the caller Context and never record a late principal", async () => {
  const m = await request();
  let releaseTrust!: () => void;
  const heldTrust = new Promise<void>(resolve => {releaseTrust = resolve;});
  const trustWork: Promise<Awaited<ReturnType<typeof trust>>>[] = [];
  try {
    rejection(
      await Seal.WebBotAuth.verify(
        m,
        policy({
          agents: (a: Seal.AgentRequest) => {
            const work = heldTrust.then(() => trust(a));
            trustWork.push(work);
            return work;
          },
        }),
        { timeoutMs: 1000 },
      ),
      "agent_unresolved",
      "timeout",
    );
    assert.equal(trustWork.length, 1, "timeout reaches the trust callback");
  } finally {releaseTrust(); await Promise.all(trustWork);}
  const c = value(Seal.withDeadline({ timeoutMs: 300 }));
  await new Promise((r) => setTimeout(r, Seal.remainingMs(c) + 1));
  rejection(
    await Seal.WebBotAuth.verify(m, policy(), { context: c }),
    "agent_unresolved",
    "timeout",
  );
});
test("freshness bounds and signed coverage preserve inclusive age and exclusive expiry", async () => {
  const m = await request();
  await fc.assert(
    fc.asyncProperty(fc.integer({ min: 1, max: 1000 }), async (age) => {
      value(
        await Seal.WebBotAuth.verify(
          m,
          policy({
            freshness: { clock: () => now + age, maxAge: age, skew: 0 },
          }),
        ),
      );
      rejection(
        await Seal.WebBotAuth.verify(
          m,
          policy({
            freshness: { clock: () => now + age + 1, maxAge: age, skew: 0 },
          }),
        ),
        "too_old",
      );
    }),
    { numRuns: 25 },
  );
  rejection(
    await Seal.WebBotAuth.verify(
      m,
      policy({ freshness: { clock: () => now + 3600, maxAge: null, skew: 0 } }),
    ),
    "expired",
  );
});
test("signing retains protocol parameter order and reproduces independently recorded bytes", async () => {
  assert.equal(typeof Seal.WebBotAuth.sign, "function");
  const h = await custody();
  try {
    const m = await request();
    const input = dictionaries(m, 16)[0].get("agent")!;
    const params = Object.fromEntries(
      input.parameters.map(([k, v]) => [k, v.value]),
    );
    const key = value(await h.publicKey());
    const unsigned = value(
      Seal.Message.create({
        ...m,
        fields: m.fields.filter(
          (f) =>
            !["signature", "signature-input"].includes(f.name.toLowerCase()),
        ),
      }),
    );
    const spec = {
      label: "agent",
      agent: { location: "https://signature-agent.test", type: "directory" },
      key,
      algorithm: "ed25519",
      created: now,
      expires: now + 3600,
      nonce: params.nonce,
    };
    const signer = (
      a: Seal.SigningAlgorithm,
      b: Uint8Array,
      context = value(Seal.withDeadline()),
    ) => h.sign(a, b, context);
    const signed = value(await Seal.WebBotAuth.sign(unsigned, spec, signer));
    assert.deepEqual(signed.fields.at(-1)!.value, m.fields.at(-1)!.value);
    value(await Seal.WebBotAuth.verify(signed, policy()));
    for (const changed of [
      { expires: now },
      { nonce: "" },
      { algorithm: "hmac-sha256" },
      { unknown: true },
    ])
      rejection(
        await Seal.WebBotAuth.sign(unsigned, { ...spec, ...changed }, signer),
        "invalid_options",
      );
    rejection(
      await Seal.WebBotAuth.sign(
        await request("inner"),
        {
          ...spec,
          label: "browser",
          agent: { location: "https://browser.example", type: "directory" },
          components: '("signature-input";key="agent" "signature";key="agent")',
        },
        signer,
      ),
      "nested_coverage_incomplete",
    );
  } finally {
    await h.release();
  }
});
test("held-key refusals are unknown keys and cannot expose or attribute callback data", async () => {
  const m = await request("held-key");
  rejection(
    await Seal.WebBotAuth.verify(
      m,
      policy({ unresolved: { heldKeys: (_a: unknown) => Seal.ok(null) } }),
    ),
    "agent_unresolved",
    "unknown_key",
  );
  rejection(
    await Seal.WebBotAuth.verify(
      m,
      policy({
        unresolved: { heldKeys: (_a: unknown) => Seal.err(awaitError()) },
      }),
    ),
    "agent_unresolved",
    "unknown_key",
  );
});
function awaitError() {
  return (
    Seal.withDeadline({ timeoutMs: 0 }) as {
      ok: false;
      error: Seal.RequestSealError;
    }
  ).error;
}
test("untagged labels stay explicit under ignore and reject policies", async () => {
  const m = await request();
  const unrelated = rewrite(m, (n, w) =>
    n === "signature-input" ? w.replace("web-bot-auth", "other") : w,
  );
  rejection(
    await Seal.WebBotAuth.verify(unrelated, policy()),
    "no_web_bot_auth_signature",
  );
  rejection(
    await Seal.WebBotAuth.verify(unrelated, policy({ untagged: "reject" })),
    "unexpected_signature",
  );
  const h = await custody();
  try {
    const signer = (
      a: Seal.SigningAlgorithm,
      b: Uint8Array,
      c = value(Seal.withDeadline()),
    ) => h.sign(a, b, c);
    const extra = value(
      await Seal.sign(
        m,
        {
          label: "extra",
          signatureInput: '("@authority");tag="other"',
          algorithm: "ed25519",
        },
        signer,
      ),
    );
    const r = value(await Seal.WebBotAuth.verify(extra, policy()));
    assert.deepEqual(r.ignored, ["extra"]);
    rejection(
      await Seal.WebBotAuth.verify(extra, policy({ untagged: "reject" })),
      "unexpected_signature",
    );
  } finally {
    await h.release();
  }
});
test("explicit JOSE algorithm choices retain discovery source binding without an HTTP alg stamp", async () => {
  const h = value(
    await Seal.Custody.local(
      { jws: "EdDSA" },
      (await import("node:fs")).readFileSync(
        "conformance/sources/rfc9421/keys/ed25519_private.pem",
        "utf8",
      ),
    ),
  );
  try {
    const key = value(await h.publicKey()),
      source = value(
        Seal.DiscoverySource.create({
          type: "jwks_uri",
          location: "https://agent.example/keys",
        }),
      );
    const set = value(
      await Seal.Discovery.resolver.fromSnapshot(
        source,
        new TextEncoder().encode(JSON.stringify({ keys: [value(key.jwk())] })),
        now,
        [["content-type", "application/json"]],
      ),
    );
    const signer = (
      a: Seal.SigningAlgorithm,
      b: Uint8Array,
      c = value(Seal.withDeadline()),
    ) => h.sign(a, b, c);
    const m = value(
      await Seal.WebBotAuth.sign(
        value(
          await Seal.Message.request("GET", "https://example.com/a", [], ""),
        ),
        {
          label: "agent",
          key,
          algorithm: { jws: "EdDSA" },
          agent: { location: source.location, type: "jwks_uri" },
          created: now,
          expires: now + 60,
          nonce: null,
        },
        signer,
      ),
    );
    const r = value(
      await Seal.WebBotAuth.verify(
        m,
        policy({
          algorithms: [{ jws: "EdDSA" }],
          agents: (_a: unknown) => Seal.ok(set),
        }),
      ),
    );
    assert.deepEqual(r.signatures.agent!.signature.algorithm, { jws: "EdDSA" });
    assert.equal(
      r.signatures.agent!.signature.parameters.some(([k]) => k === "alg"),
      false,
    );
  } finally {
    await h.release();
  }
});
test("agent dictionaries enforce the protocol string-item schema before member validation", async () => {
  const m = await request();
  for (const wire of [
    "agent=?1",
    "agent=token",
    'agent=("https://signature-agent.test")',
  ])
    rejection(
      await Seal.WebBotAuth.verify(agentField(m, wire), policy()),
      "invalid_signature_agent",
      "invalid_dictionary",
    );
});

test("directory-assigned aliases cannot attribute the actual signing key or invoke held fallback", async () => {
  const original = await request();
  const [inputs] = dictionaries(original, 16),
    wireId = Object.fromEntries(
      inputs.get("agent")!.parameters.map(([k, v]) => [k, v.value]),
    ).keyid;
  const rsa = value(
    await Seal.Custody.local(
      "rsa-pss-sha512",
      (await import("node:fs")).readFileSync(
        "conformance/sources/rfc9421/keys/rsa_private.pem",
        "utf8",
      ),
    ),
  );
  try {
    const key = value(await rsa.publicKey()),
      source = value(
        Seal.DiscoverySource.create({
          type: "jwks_uri",
          location: "https://agent.example/keys",
          keyId: "directory",
        }),
      );
    const set = value(
      await Seal.Discovery.resolver.fromSnapshot(
        source,
        new TextEncoder().encode(
          JSON.stringify({ keys: [{ ...value(key.jwk()), kid: wireId }] }),
        ),
        now,
        [["content-type", "application/json"]],
      ),
    );
    const changed = agentField(
      rewrite(original, (n, w) =>
        n === "signature-input"
          ? w.replace('alg="ed25519"', 'alg="rsa-pss-sha512"')
          : w,
      ),
      'agent="https://agent.example/keys";type=jwks_uri',
    );
    const input = dictionaries(changed, 16)[0].get("agent")!;
    const unsigned = value(
      Seal.Message.create({
        ...changed,
        fields: changed.fields.filter(
          (f) =>
            !["signature", "signature-input"].includes(f.name.toLowerCase()),
        ),
      }),
    );
    const signer = (
      a: Seal.SigningAlgorithm,
      b: Uint8Array,
      c = value(Seal.withDeadline()),
    ) => rsa.sign(a, b, c);
    const schema = (await import("../src/web-bot-auth/support.ts")).schemas({});
    const signed = value(
      await Seal.sign(
        unsigned,
        { label: "agent", signatureInput: input, algorithm: "rsa-pss-sha512" },
        signer,
        { fieldSchemas: schema },
      ),
    );
    const generic = value(
      Seal.Policy.create({
        algorithms: ["rsa-pss-sha512"],
        components: "()",
        keyResolver: async () => Seal.ok({ algorithm: "rsa-pss-sha512", key }),
        freshness: "not_evaluated",
        content: "not_required",
        replay: "not_required",
        fieldSchemas: schema,
      }),
    );
    value(await Seal.verify(signed, generic, { label: "agent" }));
    let heldCalls = 0;
    rejection(
      await Seal.WebBotAuth.verify(
        signed,
        policy({
          agents: (_a: unknown) => Seal.ok(set),
          unresolved: {
            heldKeys: (_a: unknown) => {
              heldCalls++;
              return Seal.ok({ algorithm: "rsa-pss-sha512", key });
            },
          },
        }),
      ),
      "agent_unresolved",
      "source_mismatch",
    );
    assert.equal(heldCalls, 0);
  } finally {
    await rsa.release();
  }
});
test("sign then verify preserves randomized labels and nonce facts under real public keys", async () => {
  const h = await custody();
  try {
    const key = value(await h.publicKey()),
      base = value(
        await Seal.Message.request("GET", "https://example.com/a", [], ""),
      );
    const signer = (
      a: Seal.SigningAlgorithm,
      b: Uint8Array,
      c = value(Seal.withDeadline()),
    ) => h.sign(a, b, c);
    await fc.assert(
      fc.asyncProperty(
        fc.stringMatching(/^[a-z][a-z0-9]{0,8}$/),
        fc.stringMatching(/^[a-zA-Z0-9]{1,32}$/),
        async (label, nonce) => {
          const m = value(
            await Seal.WebBotAuth.sign(
              base,
              {
                label,
                key,
                algorithm: "ed25519",
                agent: {
                  location: "https://signature-agent.test",
                  type: "directory",
                },
                created: now,
                expires: now + 60,
                nonce,
              },
              signer,
            ),
          );
          const r = value(await Seal.WebBotAuth.verify(m, policy()));
          assert.deepEqual(Object.keys(r.signatures), [label]);
          assert.equal(
            Object.fromEntries(
              r.signatures[label]!.signature.parameters.map(([k, v]) => [
                k,
                v.value,
              ]),
            ).nonce,
            nonce,
          );
        },
      ),
      { numRuns: 25 },
    );
  } finally {
    await h.release();
  }
});

test("architecture vectors retain valid cryptography while their oversized profile lifetimes reject", async () => {
  const vectors = JSON.parse(
    (await import("node:fs")).readFileSync(
      "conformance/sources/web-bot-auth/web_bot_auth_architecture_v2.json",
      "utf8",
    ),
  );
  for (const index of [0, 2]) {
    const v = vectors[index],
      algorithm = index === 0 ? "rsa-pss-sha512" : "ed25519";
    const publicJwk =
      index === 0
        ? { kty: "RSA", n: v.key.n, e: v.key.e }
        : { kty: "OKP", crv: v.key.crv, x: v.key.x };
    const key = value(await Seal.PublicKey.import(publicJwk));
    const m = value(
      await Seal.Message.request(
        "GET",
        v.target_url,
        [
          ["Signature-Input", v.signature_input],
          ["Signature", v.signature],
        ],
        "",
      ),
    );
    const generic = value(
      Seal.Policy.create({
        algorithms: [algorithm],
        components: "()",
        keyResolver: async () => Seal.ok({ algorithm, key }),
        freshness: "not_evaluated",
        content: "not_required",
        replay: "not_required",
      }),
    );
    value(await Seal.verify(m, generic, { label: v.label }));
    rejection(
      await Seal.WebBotAuth.verify(
        m,
        policy({
          unresolved: {
            heldKeys: (_a: unknown) => Seal.ok({ algorithm, key }),
          },
        }),
      ),
      "lifetime_exceeded",
    );
    rejection(
      await Seal.WebBotAuth.verify(
        agentField(m, `${v.label}="https://signature-agent.test"`),
        policy(),
      ),
      "missing_required_component",
    );
  }
});
