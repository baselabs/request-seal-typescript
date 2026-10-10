import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import * as api from "../src/index.ts";
import { coreError, cryptoError, custodyError } from "../src/errors/types.ts";
import { ok, err } from "../src/result.ts";
import {resolvePointer} from "../tools/conformance/loader.ts";
import { verificationFacts } from "../src/verification.ts";
import { signSurface } from "../tools/conformance/sign-surfaces.ts";
const A = api as any;
const text = (s: string) => new TextEncoder().encode(s);
function signing(h: any) {
  return (algorithm: api.SigningAlgorithm, base: Uint8Array, context = value(api.withDeadline())) => h.sign(algorithm, base, context);
}
function value(r: any): any { assert.equal(r.ok, true, JSON.stringify(r)); return r.value; }
function reason(r: any, name: string, layer?: string) {
  assert.equal(r.ok, false);
  assert.equal(r.error.reason, name);
  if (layer) { assert.equal(r.error.kind, "core"); assert.equal(r.error.layer, layer); assert.equal(r.error.retryable, false); }
}
async function setup() {
  const h = value(await api.Custody.local("ed25519", readFileSync("test/fixtures/upstream/crypto/ed25519_private.pem", "utf8")));
  const pub = value(await api.PublicKey.import(readFileSync("test/fixtures/upstream/crypto/ed25519_public.pem", "utf8"), "pem"));
  const m = value(await api.Message.request("POST", "https://example.com/", [], "abc"));
  const spec = {label: "s", algorithm: "ed25519", signatureInput: '("@method");created=10;expires=70;nonce="once"'};
  const signed = value(await api.sign(m, spec, signing(h)));
  const policy = (extra: any = {}) => value(api.Policy.create({algorithms: ["ed25519"], components: '("@method")', keyResolver: () => ok({algorithm: "ed25519", key: pub}), freshness: "not_evaluated", content: "not_required", replay: "not_required", ...extra}));
  return {h, pub, m, spec, signed, policy};
}
const fresh = {clock: () => 20, maxAge: 60, skew: 0, requireExpires: true};
// A real process-local atomic store. Fault injection delays acknowledgment only;
// an already inserted claim remains present after cancellation.
function store(identity = "memory") {
  const entries = new Map<string, number>();
  let delay = false, calls = 0;
  return {entries, setDelay: () => {delay = true;}, get calls() {return calls;}, port: {
    identity,
    async claim(c: any) {
      calls++;
      const key = api.encodeBase64Url(c.namespace) + ":" + api.encodeBase64Url(c.key);
      if (entries.has(key)) return ok("already_claimed");
      entries.set(key, c.retainUntil);
      if (delay) await new Promise(() => {});
      return ok("claimed");
    },
    sweep(now: number) { let removed = 0; for (const [k, end] of entries) if (end <= now) { entries.delete(k); removed++; } return ok(removed); },
  }};
}
function replay(port: any) { return {identifier: "nonce", namespace: text("tenant"), commitment: (facts: any) => ok(text(facts.identifier)), store: port, timeoutMs: 1000}; }
function hashing() {
  let delay = false;
  return {setDelay: () => {delay = true;}, port: {create(a: string) {
    const h = createHash(a === "sha-256" ? "sha256" : "sha512");
    return {update(c: Uint8Array) {h.update(c);}, async finish() {if (delay) await new Promise(() => {}); return new Uint8Array(h.digest());}};
  }}};
}
test("replay deadline is nonretryable store_timeout after a committed claim", async () => {
  const x = await setup();
  const s = store(); const {identity, ...port} = s.port;
  try {
    const p = x.policy({freshness: fresh, replay: replay(port)});
    s.setDelay();
    reason(await api.verify(x.signed, p, {label: "s", context: value(api.withDeadline({timeoutMs: 50}))}), "store_timeout", "replay");
    assert.equal(s.entries.size, 1); assert.equal(s.calls, 1);
  } finally {await x.h.release();}
});
test("replay timer expires after a committed claim without consuming the crypto budget", async () => {
  const x = await setup(); const s = store(); const {identity, ...port} = s.port;
  try {
    const p = x.policy({freshness: fresh, replay: {...replay(port), timeoutMs: 50}});
    s.setDelay();
    reason(await api.verify(x.signed, p, {label: "s"}), "store_timeout", "replay");
    assert.equal(s.entries.size, 1); assert.equal(s.calls, 1);
  } finally {await x.h.release();}
});
test("content deadline preserves deadline_exceeded during real digest-state finish", async () => {
  const x = await setup(); const hs = hashing();
  try {
    const signed = value(await api.sign(x.m, {label: "s", algorithm: "ed25519", components: '("@method" "content-digest")', expiresIn: 60, digest: ["sha-256"]}, x.h, {clock: () => 10}));
    const state = value(await api.DigestState.create("content", ["sha-256"], hs.port)); value(await state.update(text("abc"))); hs.setDelay();
    const p = x.policy({content: {kind: "content", algorithms: ["sha-256"], section: "headers"}});
    reason(await api.verify(signed, p, {label: "s", digestState: state, context: value(api.withDeadline({timeoutMs: 50}))}), "deadline_exceeded");
  } finally {await x.h.release();}
});
test("resolver errors cannot inject a replay reason", async () => {
  const x = await setup();
  try {
    for (const error of [coreError("replayed", "replay"), cryptoError("invalid_signature"), custodyError("deadline_exceeded"), null, "fault"]) {
      reason(await api.verify(x.signed, x.policy({keyResolver: () => ({ok: false, error})}), {label: "s"}), "key_resolver_failed", "key");
    }
    reason(await api.verify(x.signed, x.policy({keyResolver: () => ok(null)}), {label: "s"}), "unknown_key", "key");
  } finally {await x.h.release();}
});
test("verifier validates exact result discriminants and negative shapes", async () => {
  const x = await setup();
  try {
    for (const [result, expected] of [[true, "verifier_failed"], [{}, "verifier_failed"], [{ok: 1, value: true}, "verifier_failed"], [{ok: false}, "verifier_failed"], [{ok: undefined, error: "no"}, "verifier_failed"], [{ok: true, value: true, extra: 1}, "verifier_failed"], [{ok: false, error: "no", value: true}, "verifier_failed"], [{ok: true, value: false}, "invalid_signature"], [{ok: false, error: null}, "invalid_signature"], [{ok: false, error: coreError("replayed", "replay")}, "invalid_signature"]] as const) {
      reason(await api.verify(x.signed, x.policy({keyResolver: () => ok({algorithm: "ed25519", verify: () => result})}), {label: "s"}), expected, "crypto");
    }
    value(await api.verify(x.signed, x.policy({keyResolver: () => ok({algorithm: "ed25519", verify: (a: any, b: any, s: any) => api.Crypto.verify(a, x.pub, s, b)})}), {label: "s"}));
  } finally {await x.h.release();}
});
test("reserved options precede unknown option rejection and are read once", async () => {
  for (const key of ["profile", "principal"]) {
    let reads = 0;
    reason(await api.verify(null, null, {label: "s", unknown: 1, get [key]() {reads++; return null;}}), "invalid_profile", "input");
    assert.equal(reads, 1);
    reason(await api.verify(null, null, {label: "s", [Symbol("unknown")]: 1, [key]: null}), "invalid_profile", "input");
  }
});
test("signing clock faults and non-integers always map to invalid_options", async () => {
  const x = await setup();
  try {
    for (const clock of [() => {throw coreError("replayed", "replay");}, () => 1.5, () => NaN, () => undefined])
      reason(await api.sign(x.m, {label: "s", algorithm: "ed25519", components: '("@method")', expiresIn: 60}, x.h, {clock}), "invalid_options", "input");
  } finally {await x.h.release();}
});
const orderRows = [
  ["components before signer type", "unsupported_component"],
  ["message before generated label", "invalid_message"],
  ["fieldSchemas before body", "invalid_options"],
  ["signingTimeout before body", "invalid_options"],
  ["digest list before body", "invalid_options"],
  ["generated signer before occupied label", "signer_failed"],
  ["explicit dictionaries before input parse", "label_in_use"],
  ["explicit spec count before message", "invalid_options"],
  ["explicit fieldSchemas before message", "invalid_options"],
] as const;
for (const [name, expected] of orderRows) test("sign validation order: " + name, async () => {
  const x = await setup();
  try {
    const generated = {label: "s", algorithm: "ed25519", components: '("@method")', expiresIn: 60};
    const unavailable = value(api.Message.create({...x.m, body: value(api.Body.create({state: "unavailable"}))}));
    const covered = {...generated, components: '("content-digest")'};
    let r;
    switch (name) {
      case "components before signer type": r = await api.sign(x.m, {...generated, components: '("host")'}, null); break;
      case "message before generated label": r = await api.sign(null, {...generated, label: "BAD"}, x.h); break;
      case "fieldSchemas before body": r = await api.sign(unavailable, {...covered, fieldSchemas: null}, x.h); break;
      case "signingTimeout before body": r = await api.sign(unavailable, covered, x.h, {signingTimeout: 0}); break;
      case "digest list before body": r = await api.sign(unavailable, {...covered, digest: ["md5"]}, x.h); break;
      case "generated signer before occupied label": r = await api.sign(x.signed, generated, () => err(cryptoError("invalid_signature")), {clock: () => 10}); break;
      case "explicit dictionaries before input parse": r = await api.sign(x.signed, {...x.spec, signatureInput: "bad"}, signing(x.h)); break;
      case "explicit spec count before message": r = await api.sign(null, {...x.spec, digest: null}, x.h); break;
      case "explicit fieldSchemas before message": r = await api.sign(null, x.spec, x.h, {fieldSchemas: null}); break;
    }
    reason(r, expected);
  } finally {await x.h.release();}
});
test("inner lists use last parameters while received dictionaries reject duplicates", async () => {
  const x = await setup();
  try {
    const p = x.policy({components: '("@method";req;req)'});
    assert.equal(p.components.value[0].parameters.length, 1);
    const signed = value(await api.sign(x.m, {...x.spec, signatureInput: '("@method");created=1;created=2'}, signing(x.h)));
    const v = value(await api.verify(signed, x.policy(), {label: "s"}));
    assert.deepEqual(v.signature.parameters, [["created", {kind: "integer", value: 2}]]);
    for (const [name, wire] of [["Signature-Input", 's=("@method");created=1;created=2'], ["Signature", "s=:AQ==:;x=1;x=2"]]) {
      const field = value(api.FieldOccurrence.create({name, value: wire, section: "headers"}));
      const bad = value(api.Message.create({...signed, fields: [...signed.fields.filter((f: any) => f.name.toLowerCase() !== name!.toLowerCase()), field]}));
      reason(await api.verify(bad, x.policy(), {label: "s"}), "duplicate_parameter", "fields");
    }
  } finally {await x.h.release();}
});
test("real last-chunk-only hashing fails the known-answer self-test", async () => {
  const hasher = {create(a: string) {
    let last = new Uint8Array();
    return {update(c: Uint8Array) {last = new Uint8Array(c);}, finish() {return new Uint8Array(createHash(a === "sha-256" ? "sha256" : "sha512").update(last).digest());}};
  }};
  reason(await api.DigestState.create("content", ["sha-256"], hasher), "invalid_state");
});
test("canonical facts retain decimal source text", async () => {
  const x = await setup();
  try {
    const signed = value(await api.sign(x.m, {...x.spec, signatureInput: '("@method");x=1.5;y=-0.0'}, signing(x.h)));
    // Wire parameters, not a regenerated expected decimal, govern the facts.
    const raw = value(api.FieldOccurrence.create({name: "Signature-Input", value: 's=("@method");x=01.500;y=-0.00', section: "headers"}));
    const received = value(api.Message.create({...signed, fields: signed.fields.map((f: any) => f.name === "Signature-Input" ? raw : f)}));
    const v = value(await api.verify(received, x.policy(), {label: "s"}));
    assert.deepEqual(JSON.parse(new TextDecoder().decode(value(api.serializeVerification(v)))).signature.parameters, [["x", {dec: "01.500"}], ["y", {dec: "-0.00"}]]);
  } finally {await x.h.release();}
});
test("verify-only signing reads and verifies the imported public artifact", async () => {
  const m = JSON.parse(readFileSync("conformance/cases/verify/rfc9421-sig-b21.json", "utf8"));
  const b = value(api.decodeBase64Url(m.inputs.append_fields[0][1].b64));
  const wire = new TextDecoder().decode(b); const reads: string[] = [];
  const resources: any = {
    read(path: string) {reads.push(path); return ok(new Uint8Array(readFileSync("conformance/" + path)));},
    reference(v: any) {const ref = v.ref; const j = value(api.decodeJson(new Uint8Array(readFileSync("conformance/" + ref.file)), {maxBytes: 16_777_216, maxDepth: 64, maxMembers: 100000, maxArrayLength: 100000, maxStringBytes: 16_777_216})); return ok(resolvePointer(j.node, ref.pointer));},
  };
  const r = await signSurface({...m, surface: "sign", class: "verify_only", inputs: {message: m.inputs.message, spec: {label: m.inputs.label, signature_input: wire.slice(wire.indexOf("=") + 1), algorithm: m.policy.key_resolver.key}, key: m.policy.key_resolver.key}, expected: {valid: true}}, resources);
  value(r);
  assert.ok(reads.some(path => path.endsWith("rsa_pss_public.pem")), "Must read the public key file independently");
});
test("HMAC rejects a public key at resolution", async () => {
  const x = await setup();
  try {reason(await api.verify(x.signed, x.policy({algorithms: ["hmac-sha256"], keyResolver: () => ok({algorithm: "hmac-sha256", key: x.pub})}), {label: "s"}), "key_resolver_failed", "key");}
  finally {await x.h.release();}
});
test("Content-Length compares raw bytes including a leading BOM", async () => {
  const x = await setup();
  try {
    const f = value(api.FieldOccurrence.create({name: "Content-Length", value: new Uint8Array([239,187,191,51]), section: "headers"}));
    reason(await api.sign(value(api.Message.create({...x.m, fields: [f]})), {label: "s", algorithm: "ed25519", components: '("content-length")', expiresIn: 60}, x.h), "invalid_request", "input");
  } finally {await x.h.release();}
});
test("already-aborted signals keep the clock resolver crypto and signer mappings", async () => {
  const x = await setup(); const controller = new AbortController(); controller.abort();
  const context = () => value(api.withDeadline({signal: controller.signal}));
  try {
    reason(await api.sign(x.m, x.spec, signing(x.h), {context: context()}), "signer_failed", "crypto");
    reason(await api.sign(x.m, {label: "s", algorithm: "ed25519", components: '("@method")', expiresIn: 60}, x.h, {context: context(), clock: () => {assert.fail("Canceled clock ran");}}), "deadline_exceeded");
    for (const freshness of ["not_evaluated", fresh]) {
      const r = await api.verify(x.signed, x.policy({freshness}), {label: "s", context: context()}); reason(r, "deadline_exceeded"); assert.equal(!r.ok && r.error.kind, "custody");
    }
    const live = new AbortController();
    reason(await api.verify(x.signed, x.policy({keyResolver: () => ok({algorithm: "ed25519", verify: async (a: any, b: any, sig: any) => {live.abort(); return api.Crypto.verify(a, x.pub, sig, b);}})}), {label: "s", context: value(api.withDeadline({signal: live.signal}))}), "deadline_exceeded");
  } finally {await x.h.release();}
});
test("every reference JWS selection is accepted; RS256 signs and verifies through the registry", async () => {
  const x = await setup();
  const algorithm = {jws: "RS256"} as const;
  const h = value(await api.Custody.local(algorithm, readFileSync("test/fixtures/upstream/crypto/rsa_private.pem", "utf8")));
  const pub = value(await api.PublicKey.import(readFileSync("test/fixtures/upstream/crypto/rsa_public.pem", "utf8"), "pem"));
  try {
    let reads = 0;
    x.policy({algorithms: [{get jws() {reads++; return "RS256";}}]});
    assert.equal(reads, 1);
    for (const jws of ["RS256", "PS256", "PS384", "PS512", "HS256", "ES256", "ES384", "EdDSA"]) x.policy({algorithms: [{jws}]});
    reason(api.Policy.create({algorithms: [{jws: "none"}], components: "()", keyResolver: () => ok(null), freshness: "not_evaluated", content: "not_required", replay: "not_required"}), "invalid_policy");
    const p = x.policy({algorithms: [algorithm], keyResolver: () => ok({algorithm: {jws: "RS256"}, key: pub})});
    for (const spec of [{label: "s", algorithm, signatureInput: '("@method")'}, {label: "s", algorithm, components: '("@method")', expiresIn: 60}]) {
      const signed = value(await A.sign(x.m, spec, Object.hasOwn(spec, "components") ? h : signing(h), Object.hasOwn(spec, "components") ? {clock: () => 10} : {}));
      value(await api.verify(signed, p, {label: "s"}));
    }
    reason(await A.sign(x.m, {label: "s", algorithm, signatureInput: '("@method");alg="RS256"'}, signing(h)), "algorithm_mismatch", "input");
  } finally {await h.release(); await x.h.release();}
});
test("replay receipt and canonical content/freshness/replay facts match the format contract", async () => {
  const x = await setup(); const s = store();
  try {
    const field = new TextDecoder().decode(value(await api.digest(text("abc"), ["sha-256"]))) + ", unknown=:AQ==:";
    const f = value(api.FieldOccurrence.create({name: "content-digest", value: field, section: "headers"}));
    const m = value(api.Message.create({...x.m, fields: [f]}));
    const signed = value(await api.sign(m, {...x.spec, signatureInput: '("@method" "content-digest");created=10;expires=70;nonce="once"'}, signing(x.h)));
    const v = value(await api.verify(signed, x.policy({freshness: fresh, content: {kind: "content", algorithms: ["sha-256"], section: "headers"}, replay: replay(s.port)}), {label: "s"}));
    assert.deepEqual(v.replay, {store: "memory", retainUntil: 70});
    assert.equal(Object.isFrozen(v.replay), true);
    assert.equal(new TextDecoder().decode(value(api.serializeVerification(v))), '{"label":"s","signature":{"algorithm":"ed25519","covered":[["@method",[]],["content-digest",[]]],"parameters":[["created",{"int":"10"}],["expires",{"int":"70"}],["nonce","once"]],"keyid":null,"crypto":"valid"},"profile":{"name":"rfc9421"},"content":{"kind":"content-digest","checked":["sha-256"],"bytes":{"int":"3"},"unsupported":["unknown"]},"freshness":{"now":{"int":"20"},"created":{"int":"10"},"expires":{"int":"70"},"max_age":{"int":"60"},"skew":{"int":"0"}},"replay":{"store":"store","retain_until":{"int":"70"}},"principal":"unattributed","authorization":"not_evaluated"}');
  } finally {await x.h.release();}
});

test("callable deadlines retain signer_failed while handle failures preserve custody sources", async () => {
  const x = await setup();
  const generated = {label: "s", algorithm: "ed25519", components: '("@method")', expiresIn: 60};
  try {
    const pending = new Set<Promise<unknown>>();
    const slow = (algorithm: api.SigningAlgorithm, base: Uint8Array, context = value(api.withDeadline())) => {
      const work = new Promise(resolve => setTimeout(resolve, 40)).then(() => x.h.sign(algorithm, base, context));
      pending.add(work);
      return work as Promise<api.Result<Uint8Array>>;
    };
    try { reason(await api.sign(x.m, generated, slow, {clock: () => 10, signingTimeout: 5}), "signer_failed", "crypto"); }
    finally {await Promise.all(pending);}
    for (const spec of [x.spec, generated]) {
      for (const error of [custodyError("deadline_exceeded"), custodyError("custodian_failure")]) {
        for (const mode of ["return", "throw"] as const) {
          const signer = (_algorithm: api.SigningAlgorithm, _base: Uint8Array) => {if (mode === "throw") throw error; return err(error);};
          reason(await api.sign(x.m, spec, signer), "signer_failed", "crypto");
        }
      }
    }
    const controller = new AbortController(); controller.abort();
    reason(await api.sign(x.m, x.spec, signing(x.h), {context: value(api.withDeadline({signal: controller.signal}))}), "signer_failed", "crypto");
    await x.h.release();
    reason(await api.sign(x.m, generated, x.h), "signing_failed", "crypto");
  } finally {await x.h.release();}
});

for (const required of [false, true]) test(required
  ? "deadline before required content work stays retryable"
  : "unrequired content never reports a digest failure at the crypto deadline boundary", async () => {
  const x = await setup();
  try {
    const hs = hashing();
    let finishes = 0;
    const port = {create(a: string) {
      const session = hs.port.create(a);
      return {update: session.update, finish() {finishes++; return session.finish();}};
    }};
    const signed = value(await api.sign(x.m, {label: "s", algorithm: "ed25519", components: '("@method" "content-digest")', expiresIn: 60, digest: ["sha-256"]}, x.h, {clock: () => 10}));
    let deadlines = 0;
    let contentFinishes = 0;
    const tally: Record<string, number> = {};
    for (let i = 0; i < 100; i++) {
      // A finished state caches EOF; each probe needs a fresh session to observe work.
      const state = value(await api.DigestState.create("content", ["sha-256"], port)); value(await state.update(text("abc")));
      const margin = [0.002, 0.005, 0.01, 0.02, 0.05][i % 5]!;
      const p = x.policy({
        content: required ? {kind: "content", algorithms: ["sha-256"], section: "headers"} : "not_required",
        keyResolver: () => ok({algorithm: "ed25519", verify: async (a: any, b: any, sig: any, ctx: api.Context) => {
          const r = await api.Crypto.verify(a, x.pub, sig, b);
          while (ctx.deadline - performance.now() > margin) {}
          return r;
        }}),
      });
      const before = finishes;
      const r = await api.verify(signed, p, {label: "s", ...(required ? {digestState: state} : {}), context: value(api.withDeadline({timeoutMs: 15}))});
      contentFinishes += finishes - before;
      const name = r.ok ? "valid" : r.error.reason; tally[name] = (tally[name] ?? 0) + 1;
      if (r.ok) {assert.equal(r.value.content === "not_required", !required); continue;}
      assert.notEqual(r.error.reason, "digest_unsupported", JSON.stringify({margin, tally}));
      assert.equal(r.error.kind, "custody"); assert.equal(r.error.reason, "deadline_exceeded"); assert.equal(r.error.retryable, true); deadlines++;
    }
    console.log(JSON.stringify({required, tally, finishes: contentFinishes}));
    assert.ok(deadlines > 0, "Must exercise expired deadlines with no content work begun");
    if (!required) assert.equal(contentFinishes, 0);
  } finally {await x.h.release();}
});

for (const [name, spec] of [
  ["missing expiry", {label: "s", algorithm: "ed25519", components: '("@method")'}],
  ["fractional expiry", {label: "s", algorithm: "ed25519", components: '("@method")', expiresIn: 1.5}],
  ["nested and flat parameters", {label: "s", algorithm: "ed25519", components: '("@method")', parameters: {expiresIn: 60}, created: true}],
  ["missing label", {algorithm: "ed25519", components: '("@method")', expiresIn: 60}],
  ["missing algorithm", {label: "s", components: '("@method")', expiresIn: 60}],
  ["missing components", {label: "s", algorithm: "ed25519", expiresIn: 60}],
  ["unknown parameter key", {label: "s", algorithm: "ed25519", components: '("@method")', parameters: {expiresIn: 60, unknown: true}}],
] as const) test("generated spec " + name + " rejects before a null message", async () => {
  reason(await api.sign(null, spec, null), "invalid_options", "input");
});

test("explicit and generated signing accept handles and validate callable Results", async () => {
  const x = await setup();
  try {
    const bound = ((...args: [api.SigningAlgorithm, Uint8Array, api.Context]) => x.h.sign(...args)).bind(null);
    const optional = (a: api.SigningAlgorithm, b: Uint8Array, c?: api.Context) => x.h.sign(a, b, c);
    for (const signer of [x.h, bound, optional, signing(x.h)]) {
      value(await api.verify(value(await api.sign(x.m, x.spec, signer)), x.policy(), {label: "s"}));
    }
    for (const signer of [() => undefined, () => ok("invalid bytes")])
      reason(await api.sign(x.m, x.spec, signer), "signer_failed", "crypto");
    const generated = {label: "s", algorithm: "ed25519", components: '("@method")', parameters: {created: true, expiresIn: 60, nonce: null, alg: true, keyid: null, tag: null}, digest: null, fieldSchemas: {}};
    value(await api.verify(value(await api.sign(x.m, generated, x.h, {clock: () => 10})), x.policy(), {label: "s"}));
  } finally {await x.h.release();}
});

test("canonical JWS facts use a pair and normalize the replay store label", async () => {
  const x = await setup();
  const algorithm = {jws: "RS256"} as const;
  const h = value(await api.Custody.local(algorithm, readFileSync("test/fixtures/upstream/crypto/rsa_private.pem", "utf8")));
  const pub = value(await api.PublicKey.import(readFileSync("test/fixtures/upstream/crypto/rsa_public.pem", "utf8"), "pem"));
  try {
    const signed = value(await api.sign(x.m, {label: "s", algorithm, components: '("@method")', expiresIn: 60}, h, {clock: () => 10}));
    const s = store("memory");
    const v = value(await api.verify(signed, x.policy({algorithms: [algorithm], keyResolver: () => ok({algorithm, key: pub}), freshness: fresh, replay: replay(s.port)}), {label: "s"}));
    assert.deepEqual(v.replay, {store: "memory", retainUntil: 70});
    const facts = value(verificationFacts(v));
    assert.deepEqual(facts.signature.algorithm, ["jws", "RS256"]);
    assert.deepEqual(facts.replay, {store: "store", retain_until: {int: "70"}});
    const serialized = JSON.parse(new TextDecoder().decode(value(api.serializeVerification(v))));
    assert.deepEqual(serialized.signature.algorithm, ["jws", "RS256"]);
    assert.deepEqual(serialized.replay, {store: "store", retain_until: {int: "70"}});
  } finally {await h.release(); await x.h.release();}
});

test("canonical replay facts compare retention independently of adapter labels", async () => {
  const x = await setup();
  try {
    for (const identity of ["caller", "memory", "ets"]) {
      const s = store(identity);
      const v = value(await api.verify(x.signed, x.policy({freshness: fresh, replay: replay(s.port)}), {label: "s"}));
      assert.deepEqual(v.replay, {store: identity, retainUntil: 70});
      assert.deepEqual((value(verificationFacts(v)) as any).replay, {store: "store", retain_until: {int: "70"}});
      assert.deepEqual(JSON.parse(new TextDecoder().decode(value(api.serializeVerification(v)))).replay, {store: "store", retain_until: {int: "70"}});
    }
  } finally {await x.h.release();}
});
