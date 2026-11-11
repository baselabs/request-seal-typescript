import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as Seal from "../src/index.ts";
import {
  value,
  now,
  request,
  policy,
  rewrite,
  rejection,
  custody,
  trust,
} from "./support/web-bot-auth.ts";
import { schemas } from "../src/web-bot-auth/support.ts";
function counting() {
  const memory = value(Seal.createMemoryStore({ maxEntries: 20 })),
    claims: Seal.ReplayClaim[] = [];
  return {
    claims,
    store: {
      identity: "counting-memory",
      claim: (claim: Seal.ReplayClaim, c: Seal.Context) => {
        claims.push(claim);
        return memory.claim(claim, c);
      },
      sweep: memory.sweep,
    },
  };
}
test("documented profile commitment separates equal nonces while nonce-only commitments collide", async () => {
  const doc = readFileSync("docs/reference/replay.md", "utf8");
  const snippet = /```js\n(\/\/ Profile-aware commitment[\s\S]*?)\n```/.exec(doc);
  assert.ok(snippet, "replay reference provides an executable profile-aware recipe");
  const commitment = new Function("ok", `${snippet[1]}\nreturn commitment;`)(Seal.ok) as
    (f: Seal.ReplayFacts | Seal.WebBotAuthReplayFacts) => Promise<Seal.Result<Uint8Array>>;
  const set = value(await trust({type: "directory", location: "https://signature-agent.test", identifier: ""}));
  const key = Object.values(set.keys).find(k => k.algorithm === "ed25519")!.key;
  const m = await request();
  const identifiers: string[] = [];
  for (const scoped of [true, false]) {
    const counted = counting();
    const commit = async (facts: Seal.ReplayFacts | Seal.WebBotAuthReplayFacts) => {
      identifiers.push(facts.identifier);
      const encoded = JSON.stringify(scoped
        ? [facts.profile, facts.identifier]
        : facts.identifier);
      const expected = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(encoded)));
      if (!scoped) return Seal.ok(expected);
      const result = await commitment(facts);
      assert.deepEqual(value(result), expected);
      return result;
    };
    const replay = {identifier: "nonce", namespace: new Uint8Array([9]), timeoutMs: 5000, store: counted.store, commitment: commit};
    const p = policy({replay});
    const generic = value(Seal.Policy.create({
      algorithms: ["ed25519"], components: "()", keyResolver: () => Seal.ok({algorithm: "ed25519", key}),
      freshness: {clock: () => now, maxAge: null, skew: 0, requireExpires: true},
      content: "not_required", replay, fieldSchemas: schemas({}),
    }));
    value(await Seal.WebBotAuth.verify(m, p));
    const other = await Seal.verify(m, generic, {label: "agent"});
    if (scoped) value(other); else rejection(other, "replayed");
    assert.deepEqual(identifiers.at(-2), identifiers.at(-1));
    assert.deepEqual(counted.claims[0]!.namespace, replay.namespace);
    assert.deepEqual(counted.claims[1]!.namespace, replay.namespace);
    if (scoped) assert.notDeepEqual(counted.claims[0]!.key, counted.claims[1]!.key);
    else assert.deepEqual(counted.claims[0]!.key, counted.claims[1]!.key);
    rejection(await Seal.WebBotAuth.verify(m, p), "replayed");
    rejection(await Seal.verify(m, generic, {label: "agent"}), "replayed");
  }
});
test("required replay claims one selected signature over covered facts only", async (t) => {
  const counted = counting();
  const committed: Seal.WebBotAuthReplayFacts[] = [];
  const replay = {
    identifier: "nonce",
    namespace: new Uint8Array([1]),
    timeoutMs: 5000,
    store: counted.store,
    commitment: async (f: Seal.WebBotAuthReplayFacts) => {
      committed.push(f);
      return Seal.ok(
        new Uint8Array(
          await crypto.subtle.digest(
            "SHA-256",
            new TextEncoder().encode(JSON.stringify(f)),
          ),
        ),
      );
    },
  };
  const p = policy({ replay }),
    m = await request("nested");
  rejection(
    await Seal.WebBotAuth.verify(
      rewrite(m, (n, w) =>
        n === "signature" && w.startsWith("browser=")
          ? w.replace("browser=:", "browser=:AAAA")
          : w,
      ),
      p,
    ),
    "invalid_signature",
  );
  rejection(
    await Seal.WebBotAuth.verify(await request("nested-incomplete"), p),
    "nested_coverage_incomplete",
  );
  assert.equal(counted.claims.length, 0);
  assert.equal(committed.length, 0);
  value(await Seal.WebBotAuth.verify(m, policy()));
  const multiple = await Seal.WebBotAuth.verify(m, p);
  rejection(multiple, "unexpected_signature");
  assert.equal(!multiple.ok && multiple.error.kind === "core" && multiple.error.layer, "policy");
  assert.equal(counted.claims.length, 0);
  assert.equal(committed.length, 0);
  const single = await request();
  const r = value(await Seal.WebBotAuth.verify(single, p));
  assert.equal(counted.claims.length, 1);
  assert.equal(committed.length, 1);
  assert.deepEqual(Object.keys(committed[0]!).sort(),
    ["agent", "algorithm", "created", "expires", "identifier", "keyid", "profile"]);
  assert.equal(Object.hasOwn(committed[0]!, "label"), false);
  assert.equal(Object.isFrozen(committed[0]), true);
  assert.equal(Object.isFrozen(committed[0]!.agent), true);
  assert.deepEqual(Object.keys(committed[0]!.agent).sort(),
    ["identifier", "kind", "origin", "thumbprint", "type"]);
  assert.equal(
    committed[0]!.profile.revision,
    "draft-ietf-webbotauth-httpsig-protocol-00",
  );
  assert.equal("provenance" in committed[0]!.agent, false);
  for (const v of Object.values(r.signatures)) assert.equal(v.replay, r.replay);
  assert.equal(r.replay !== "not_required" && r.replay.retainUntil, now + 3600);
  rejection(await Seal.WebBotAuth.verify(single, p), "replayed");
  assert.equal(counted.claims.length, 2);
  t.diagnostic(
    "failed and multiple-signature envelopes: no claim; one verified signature: one claim; replay: already_claimed",
  );
});

for (const attack of ["relabel", "removal", "combination"] as const)
test(`required replay rejects captured signature ${attack}`, async () => {
  const h = await custody();
  try {
    const key = value(await h.publicKey());
    const keyid = value(await key.thumbprint());
    const heldKeys = () => Seal.ok({ algorithm: "ed25519" as const, key });
    const counted = counting();
    let commitments = 0;
    const replay = {
      identifier: "nonce", namespace: new Uint8Array([7]), timeoutMs: 5000,
      store: counted.store,
      commitment: async (facts: Seal.WebBotAuthReplayFacts) => {
        commitments++;
        return Seal.ok(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(facts)))));
      },
    };
    const p = policy({ unresolved: { heldKeys }, replay });
    const withoutReplay = policy({ unresolved: { heldKeys } });
    const original = await request("held-key");
    const relabeled = rewrite(original, (n, w) =>
      ["signature", "signature-input"].includes(n) ? w.replace(/^agent=/, "other=") : w);
    value(await Seal.WebBotAuth.verify(relabeled, withoutReplay));
    if (attack === "relabel") {
      value(await Seal.WebBotAuth.verify(original, p));
      rejection(await Seal.WebBotAuth.verify(relabeled, p), "replayed");
      assert.equal(commitments, 2);
      return;
    }
    const unsigned = value(Seal.Message.create({ ...original, fields: [] }));
    const other = value(await Seal.sign(unsigned, {
      label: "other", algorithm: "ed25519",
      signatureInput: `("@authority");created=${now};expires=${now + 60};keyid="${keyid}";nonce="second-capture";tag="web-bot-auth"`,
    }, h));
    const combined = value(Seal.Message.create({
      ...original, fields: [...original.fields, ...other.fields],
    }));
    value(await Seal.WebBotAuth.verify(combined, withoutReplay));
    if (attack === "combination") {
      value(await Seal.WebBotAuth.verify(original, p));
      value(await Seal.WebBotAuth.verify(other, p));
    }
    const rejected = await Seal.WebBotAuth.verify(combined, p);
    rejection(rejected, "unexpected_signature");
    assert.equal(!rejected.ok && rejected.error.kind === "core" && rejected.error.layer, "policy");
    assert.equal(commitments, attack === "combination" ? 2 : 0);
    assert.equal(counted.claims.length, commitments);
    if (attack === "removal") {
      value(await Seal.WebBotAuth.verify(original, p));
      rejection(await Seal.WebBotAuth.verify(original, p), "replayed");
    }
  } finally {
    await h.release();
  }
});
test("identical nonces have distinct generic and Web Bot Auth commitments in one namespace", async (t) => {
  const counted = counting(),
    facts: (Seal.ReplayFacts | Seal.WebBotAuthReplayFacts)[] = [];
  const commitment = async (
    f: Seal.ReplayFacts | Seal.WebBotAuthReplayFacts,
  ) => {
    facts.push(f);
    return Seal.ok(
      new Uint8Array(
        await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(JSON.stringify([f.profile, f.identifier, f.keyid])),
        ),
      ),
    );
  };
  const replay = {
    identifier: "nonce",
    namespace: new Uint8Array([2]),
    timeoutMs: 5000,
    store: counted.store,
    commitment,
  };
  const m = await request(),
    p = policy({ replay });
  value(await Seal.WebBotAuth.verify(m, p));
  const publicKey = value(
    await (
      await import("./support/web-bot-auth.ts")
    ).trust({
      type: "directory",
      location: "https://signature-agent.test",
      identifier: "",
    }),
  );
  const key = Object.values(publicKey.keys).find(
    (k) => k.algorithm === "ed25519",
  )!.key;
  const generic = value(
    Seal.Policy.create({
      algorithms: ["ed25519"],
      components: "()",
      keyResolver: async () => Seal.ok({ algorithm: "ed25519", key }),
      freshness: {
        clock: () => now,
        maxAge: null,
        skew: 0,
        requireExpires: true,
      },
      content: "not_required",
      replay,
      fieldSchemas: schemas({}),
    }),
  );
  value(await Seal.verify(m, generic, { label: "agent" }));
  assert.equal(counted.claims.length, 2);
  assert.notDeepEqual(counted.claims[0]!.key, counted.claims[1]!.key);
  assert.equal(
    facts[0]!.identifier,
    facts[1]!.identifier,
  );
  t.diagnostic(
    "same nonce, same namespace: Web Bot Auth=claimed, generic=claimed; commitment bytes distinct",
  );
});
for (const exceeds of [false, true])
test(exceeds
  ? "signature rejects retention beyond the clock maximum without claiming storage"
  : "signature retention accepts the clock ceiling", async () => {
  const h = await custody();
  try {
    const key = value(await h.publicKey()),
      created = Seal.CLOCK_MAX_SECONDS - 30,
      clock = () => created + 1;
    const source = value(
      Seal.DiscoverySource.create({
        type: "jwks_uri",
        location: "https://agent.example/keys",
      }),
    );
    const set = value(
      await Seal.Discovery.resolver.fromSnapshot(
        source,
        new TextEncoder().encode(JSON.stringify({ keys: [value(key.jwk())] })),
        clock(),
        [
          ["content-type", "application/json"],
          ["cache-control", "max-age=60"],
        ],
      ),
    );
    const signer = (
      a: Seal.SigningAlgorithm,
      b: Uint8Array,
      c = value(Seal.withDeadline()),
    ) => h.sign(a, b, c);
    let m = value(
      await Seal.Message.request("GET", "https://example.com/a", [], ""),
    );
    for (const [label, expires] of [
      ["early", Seal.CLOCK_MAX_SECONDS + (exceeds ? 1 : 0)],
    ] as const)
      m = value(
        await Seal.WebBotAuth.sign(
          m,
          {
            label,
            key,
            algorithm: "ed25519",
            agent: { location: source.location, type: "jwks_uri" },
            created,
            expires,
            nonce: "same",
          },
          signer,
        ),
      );
    const counted = counting();
    let commitments = 0;
    const final = policy({
      agents: (_a: unknown) => Seal.ok(set),
      freshness: { clock, maxAge: null, skew: 0 },
      replay: {
        identifier: "nonce",
        namespace: new Uint8Array([3]),
        timeoutMs: 5000,
        store: counted.store,
        commitment: async (f: Seal.WebBotAuthReplayFacts) => {
          commitments++;
          return Seal.ok(
            new Uint8Array(
              await crypto.subtle.digest(
                "SHA-256",
                new TextEncoder().encode(JSON.stringify(f)),
              ),
            ),
          );
        },
      },
    });
    const verified = await Seal.WebBotAuth.verify(m, final);
    if (exceeds) {
      rejection(verified, "retention_exceeded");
      assert.equal(counted.claims.length, 0);
      assert.equal(commitments, 0);
      return;
    }
    const result = value(verified);
    assert.equal(
      result.replay !== "not_required" && result.replay.retainUntil,
      Seal.CLOCK_MAX_SECONDS,
    );
    assert.equal(counted.claims.length, 1);
    assert.equal(commitments, 1);
  } finally {
    await h.release();
  }
});

test("missing nonces and late commitments never reach the memory store", async (t) => {
  const h = await custody();
  let releaseCommitment!: () => void;
  const heldCommitment = new Promise<void>(resolve => {releaseCommitment = resolve;});
  let commitmentWork: Promise<Seal.Result<Uint8Array>> | undefined;
  try {
    const key = value(await h.publicKey());
    const signer = (
      a: Seal.SigningAlgorithm,
      b: Uint8Array,
      c = value(Seal.withDeadline()),
    ) => h.sign(a, b, c);
    const unsigned = value(
      await Seal.Message.request("GET", "https://example.com/a", [], ""),
    );
    const spec = {
      label: "agent",
      agent: { location: "https://signature-agent.test", type: "directory" },
      key,
      algorithm: "ed25519",
      created: now,
      expires: now + 60,
      nonce: null,
    };
    const counted = counting();
    let commitments = 0;
    const replay = {
      identifier: "nonce",
      namespace: new Uint8Array([4]),
      timeoutMs: 300,
      store: counted.store,
      commitment: (_facts: Seal.WebBotAuthReplayFacts) => {
        commitments++;
        return commitmentWork = heldCommitment.then(() => Seal.ok(new Uint8Array([1])));
      },
    };
    const p = policy({ replay });
    rejection(
      await Seal.WebBotAuth.verify(
        value(await Seal.WebBotAuth.sign(unsigned, spec, signer)),
        p,
      ),
      "missing_replay_identifier",
    );
    assert.equal(commitments, 0);
    assert.equal(counted.claims.length, 0);
    rejection(
      await Seal.WebBotAuth.verify(
        value(
          await Seal.WebBotAuth.sign(
            unsigned,
            { ...spec, nonce: "late" },
            signer,
          ),
        ),
        p,
      ),
      "store_timeout",
    );
    assert.equal(commitments, 1);
    releaseCommitment();
    await commitmentWork;
    assert.equal(counted.claims.length, 0);
    t.diagnostic(
      "missing nonce: commitments=0 claims=0; late commitment: commitments=1 claims=0 after settlement",
    );
  } finally {
    releaseCommitment();
    await commitmentWork;
    await h.release();
  }
});
