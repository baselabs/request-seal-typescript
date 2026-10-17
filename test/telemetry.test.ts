import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import * as api from "../src/index.ts";
const value = <T>(r: api.Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return (r as { value: T }).value; };

test("verify emits a bounded stop event and detach stops delivery", async () => {
  assert.equal(typeof api.Telemetry, "object", "Telemetry is exported");
  assert.deepEqual([...api.Telemetry.events()], ["verify", "verifyQuorum", "webBotAuthVerify", "replayClaim", "custodySign"]);
  const seen: api.TelemetryEvent[] = [];
  const handle = value(api.Telemetry.attach((event: api.TelemetryEvent) => seen.push(event)));
  const h = value(await api.Custody.local("ed25519", execFileSync("openssl", ["genpkey", "-algorithm", "ed25519"], { encoding: "utf8" })));
  try {
    const message = value(await api.Message.request("POST", "https://partner.example/x", [], "body"));
    const signed = value(await api.sign(message, {label: "sig", algorithm: "ed25519", signatureInput: '("@method")'}, (a: api.SigningAlgorithm, d: Uint8Array, c = value(api.withDeadline())) => h.sign(a, d, c)));
    const pub = value(await h.publicKey());
    const policy = value(api.Policy.create({algorithms: ["ed25519"], components: '("@method")', keyResolver: () => api.ok({algorithm: "ed25519", key: pub}), freshness: "not_evaluated", content: "not_required", replay: "not_required"}));
    value(await api.verify(signed, policy, {label: "sig"}));
    const verifyEvents = () => seen.filter((e) => e.event === "verify");
    assert.equal(verifyEvents().length, 1, "exactly one verify event, nothing per label");
    const event = verifyEvents()[0]! as Record<string, unknown>;
    assert.equal(event.event, "verify");
    assert.equal(event.outcome, "ok");
    assert.equal(event.reason, null);
    assert.equal(event.layer, null);
    assert.equal(event.detail, null);
    assert.ok(typeof event.durationMs === "number" && event.durationMs >= 0);
    // The payload is a frozen, closed shape: no label, key ID, URL, or bytes.
    assert.ok(Object.isFrozen(event));
    assert.deepEqual(Object.keys(event).sort(), ["detail", "durationMs", "event", "layer", "outcome", "reason"]);
    assert.doesNotMatch(JSON.stringify(event), /partner\.example|"sig"|sig=/);
    // A rejection reports the parity rule id exactly as the caller receives it.
    const bad = await api.verify(signed, policy, {label: "nope"});
    assert.equal(bad.ok, false);
    assert.equal(verifyEvents().length, 2);
    const failed = verifyEvents()[1]! as Record<string, unknown>;
    assert.equal(failed.outcome, "error");
    assert.equal(failed.reason, "core/fields.unknown_label");
    assert.equal(failed.layer, "fields");
    // Detach stops delivery and is idempotent.
    handle.detach();
    handle.detach();
    await api.verify(signed, policy, {label: "sig"});
    assert.equal(verifyEvents().length, 2);
  } finally {
    handle.detach();
    await h.release();
  }
});
test("verifyQuorum, Web Bot Auth, replay claims, and custody signing all report", async () => {
  const seen: api.TelemetryEvent[] = [];
  const handle = value(api.Telemetry.attach((event: api.TelemetryEvent) => seen.push(event)));
  try {
    // Quorum: an invalid definition reports the bounded reason.
    const quorum = await api.verifyQuorum({}, {invalid: true}, {});
    assert.equal(quorum.ok, false);
    const quorumEvent = seen.find((e) => e.event === "verifyQuorum");
    assert.ok(quorumEvent);
    assert.equal(quorumEvent.outcome, "error");
    assert.equal(quorumEvent.reason, "core/input.invalid_quorum");
    // Web Bot Auth: an invalid policy reports without touching the message.
    const wba = await api.WebBotAuth.verify({}, {invalid: true});
    assert.equal(wba.ok, false);
    const wbaEvent = seen.find((e) => e.event === "webBotAuthVerify");
    assert.ok(wbaEvent);
    assert.equal(wbaEvent.outcome, "error");
    assert.equal(wbaEvent.reason, "core/input.invalid_policy");
    // Replay: a required-replay verification claims once, then reports a replay.
    const h = value(await api.Custody.local("ed25519", execFileSync("openssl", ["genpkey", "-algorithm", "ed25519"], { encoding: "utf8" })));
    try {
      const store = value(api.createMemoryStore({maxEntries: 16}));
      const pub = value(await h.publicKey());
      const now = Math.floor(Date.now() / 1000);
      const policy = value(api.Policy.create({algorithms: ["ed25519"], components: '("@method")', keyResolver: () => api.ok({algorithm: "ed25519", key: pub}), freshness: {clock: () => now, maxAge: null, skew: 0, requireExpires: true}, content: "not_required",
        replay: {identifier: "nonce", namespace: new TextEncoder().encode("telemetry-test"), store, timeoutMs: 1000, commitment: (_facts: api.ReplayFacts) => api.ok(new TextEncoder().encode("telemetry-commitment"))}}));
      const message = value(await api.Message.request("POST", "https://partner.example/r", [], "body"));
      const signOne = async (label: string) => value(await api.sign(message, {label, algorithm: "ed25519", signatureInput: `("@method");nonce="${label}";created=${now};expires=${now + 60}`}, (a: api.SigningAlgorithm, d: Uint8Array, c = value(api.withDeadline())) => h.sign(a, d, c)));
      const first = await api.verify(await signOne("n1"), policy, {label: "n1"});
      assert.equal(first.ok, true, JSON.stringify(first));
      const claim = seen.filter((e) => e.event === "replayClaim").pop() as Record<string, unknown>;
      assert.equal(claim.outcome, "claimed");
      assert.equal(claim.reason, null);
      const replayed = await api.verify(await signOne("n1"), policy, {label: "n1"});
      assert.equal(replayed.ok, false);
      const again = seen.filter((e) => (e as api.TelemetryEvent).event === "replayClaim").pop() as Record<string, unknown>;
      assert.equal(again.outcome, "already_claimed");
      assert.equal(again.reason, "core/replay.replayed");
      // A plain function signer emits custodySign through the shared library
      // path, not only through a custody handle.
      seen.length = 0;
      const fnSigned = await api.sign(message, {label: "fn", algorithm: "ed25519", signatureInput: '("@method");nonce="fn";created=' + now + ';expires=' + (now + 60)}, (_a: api.SigningAlgorithm, _d: Uint8Array, _c: unknown) => Promise.resolve(api.ok(new Uint8Array(64))));
      assert.equal(fnSigned.ok, true, JSON.stringify(fnSigned));
      assert.ok(seen.some((e) => (e as api.TelemetryEvent).event === "custodySign" && (e as api.TelemetryEvent).outcome === "ok"), "function signer emitted custodySign");
      // Custody signing: the shared handle path reports ok, then its bounded error.
      seen.length = 0;
      const context = value(api.withDeadline());
      await h.sign("ed25519", new TextEncoder().encode("payload"), context);
      const signed = seen.find((e) => e.event === "custodySign") as Record<string, unknown>;
      assert.equal(signed.outcome, "ok");
      const expired = value(api.withDeadline({timeoutMs: 1}));
      await new Promise((done) => setTimeout(done, 20));
      await h.sign("ed25519", new TextEncoder().encode("payload"), expired);
      const failed = seen.filter((e) => e.event === "custodySign").pop() as Record<string, unknown>;
      assert.equal(failed.outcome, "error");
      assert.equal(failed.reason, "custody/deadline_exceeded");
    } finally { await h.release(); }
  } finally { handle.detach(); }
});
test("a throwing subscriber degrades and never fails the operation", async () => {
  const received: unknown[] = [];
  const boom = value(api.Telemetry.attach(() => { throw new Error("subscriber secret"); }));
  const fine = value(api.Telemetry.attach((event: api.TelemetryEvent) => received.push(event)));
  try {
    const h = value(await api.Custody.local("ed25519", execFileSync("openssl", ["genpkey", "-algorithm", "ed25519"], { encoding: "utf8" })));
    try {
      const message = value(await api.Message.request("POST", "https://partner.example/y", [], "b"));
      const signed = value(await api.sign(message, {label: "s", algorithm: "ed25519", signatureInput: '("@method")'}, (a: api.SigningAlgorithm, d: Uint8Array, c = value(api.withDeadline())) => h.sign(a, d, c)));
      const pub = value(await h.publicKey());
      const policy = value(api.Policy.create({algorithms: ["ed25519"], components: '("@method")', keyResolver: () => api.ok({algorithm: "ed25519", key: pub}), freshness: "not_evaluated", content: "not_required", replay: "not_required"}));
      const result = await api.verify(signed, policy, {label: "s"});
      assert.equal(result.ok, true, "a throwing subscriber never fails verification");
      assert.equal(received.filter((e) => (e as api.TelemetryEvent).event === 'verify').length, 1);
      assert.doesNotMatch(JSON.stringify(received), /subscriber secret/);
    } finally { await h.release(); }
  } finally { boom.detach(); fine.detach(); }
});
test("attachment is bounded and detach frees the slot", () => {
  const handles = [];
  try {
    for (let i = 0; i < 16; i++) handles.push(value(api.Telemetry.attach(() => {})));
    const refused = api.Telemetry.attach(() => {});
    assert.equal(refused.ok, false);
    if (!refused.ok) assert.equal(refused.error.kind, "core");
    handles.pop()!.detach();
    const refill = value(api.Telemetry.attach(() => {}));
    assert.equal(api.Telemetry.attach(() => {}).ok, false, "the bound holds after one free");
    refill.detach();
    const bad = api.Telemetry.attach("not a function");
    assert.equal(bad.ok, false);
    // Two attachments of one function are independently detachable.
    handles[0]!.detach();
    const twin = () => {};
    const first = value(api.Telemetry.attach(twin));
    const second = value(api.Telemetry.attach(twin));
    first.detach();
    const reclaimed = value(api.Telemetry.attach(() => {}));
    reclaimed.detach();
    second.detach();
  } finally { for (const h of handles) h.detach(); }
});
