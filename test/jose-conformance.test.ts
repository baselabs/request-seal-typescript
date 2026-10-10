import test from "node:test";
import assert from "node:assert/strict";
import {
  surfaceRegistry,
  runCorpus,
  canonicalJson,
} from "../tools/conformance/loader.ts";
import { itemRegistry } from "../tools/conformance/batch.ts";
test(
  "JOSE registers each declared surface and batch format and executes the pinned corpus",
  { timeout: 30000 },
  async () => {
    for (const name of [
      "jws.sign",
      "jws.verify",
      "jwe.decrypt",
      "nested.decrypt",
    ])
      assert.ok(surfaceRegistry().has(name), "registered " + name);
    for (const name of ["wycheproof-aes-gcm/1", "wycheproof-rsa-oaep/1"])
      assert.ok(itemRegistry().has(name), "registered " + name);
    const r = await runCorpus("conformance", { pendingOk: true });
    assert.equal(r.ok, true, canonicalJson(r));
    assert.ok(
      r.pending.every(
        (p) =>
          !p.surface.startsWith("jws.") &&
          !p.surface.startsWith("jwe.") &&
          !p.surface.startsWith("nested."),
      ),
    );
  },
);
test("RFC 7520 compact, detached and JSON serialization classes follow the explicit policy", async (t) => {
  const { readFile } = await import("node:fs/promises");
  const { JWS, JWE, PublicKey, ok } = await import("../src/index.ts");
  const { publicMembers } = await import("../src/custody/jwk.ts");
  const load = async (name: string) =>
    JSON.parse(
      await readFile("conformance/sources/rfc7520/" + name + ".json", "utf8"),
    );
  const rsa = await load("4_1.rsa_v15_signature");
  const key = await PublicKey.import(publicMembers(rsa.input.key));
  assert.ok(key.ok);
  const policy = {
    algorithms: ["RS256"],
    timeout: 5000,
    key_resolver: () =>
      key.ok ? ok({ algorithm: "RS256", key: key.value }) : key,
  };
  for (const name of [
    "4_5.signature_with_detached_content",
    "4_6.protecting_specific_header_fields",
    "4_7.protecting_content_only",
    "4_8.multiple_signatures",
  ]) {
    const v = await load(name);
    if (v.output.compact) {
      const r = await JWS.verify(v.output.compact, {
        ...policy,
        algorithms: [v.input.alg],
      });
      assert.equal(r.ok, false);
      if (!r.ok) assert.equal(r.error.reason, "detached_payload");
      t.diagnostic(
        "RFC 7520 " +
          name.slice(0, 3).replace("_", ".") +
          " rejection detached_payload",
      );
    }
    for (const format of ["json", "json_flat"])
      if (v.output[format]) {
        const r = await JWS.verify(JSON.stringify(v.output[format]), policy);
        assert.equal(r.ok, false);
        if (!r.ok) assert.equal(r.error.reason, "unsupported_serialization");
        t.diagnostic(
          "RFC 7520 " +
            name.slice(0, 3).replace("_", ".") +
            " " +
            format +
            " rejection unsupported_serialization",
        );
      }
  }
  const v = await load("5_8.key_wrap_using_aes-keywrap_with_aes-gcm");
  const r = await JWE.decrypt(v.output.compact, {
    algorithms: [v.input.alg],
    encryption: [v.input.enc],
    max_plaintext: 1048576,
    timeout: 5000,
    key_resolver: policy.key_resolver,
  });
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.error.reason, "invalid_policy");
  t.diagnostic(
    "RFC 7520 5.8 rejection invalid_policy (A128KW outside registered algorithms)",
  );
});
test(
  "a valid published AES verdict replaced by a rejection pin executes and reports both outcomes",
  { timeout: 30000 },
  async () => {
    const { mkdtemp, cp, readFile, writeFile, rm } = await import(
      "node:fs/promises"
    );
    const { createHash } = await import("node:crypto");
    const root = await mkdtemp("test/.tmp-jose-override-");
    try {
      await cp("conformance", root, { recursive: true });
      const path = "cases/jwe/aes_gcm_test.json",
        m = JSON.parse(await readFile(root + "/" + path, "utf8"));
      m.overrides["1"] = {
        outcome: "reject",
        rule_id: "jose/input.invalid_iv",
        clause:
          "Deliberate applicability-pin mutation to prove execution against the declared verdict.",
      };
      const raw = canonicalJson(m);
      await writeFile(root + "/" + path, raw);
      const index = JSON.parse(await readFile(root + "/index.json", "utf8"));
      index.files.find((f: { path: string }) => f.path === path).sha256 =
        createHash("sha256").update(raw).digest("hex");
      await writeFile(root + "/index.json", canonicalJson(index));
      const report = await runCorpus(root, { unpinned: true, pendingOk: true });
      assert.equal(report.ok, false);
      const f = report.failures.find((f) => f.id === "jwe/aes_gcm_test/0:1");
      assert.ok(f);
      assert.deepEqual(f.expected, { rule_id: "jose/input.invalid_iv" });
      assert.equal(f.actual, "valid");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

test('AES-GCM corpus adapter independently excludes AAD-bearing published vectors', async () => {
  const {joseBatchItem} = await import('../tools/conformance/jose-surfaces.ts');
  const {readFile} = await import('node:fs/promises');
  const m = JSON.parse(await readFile('conformance/cases/jwe/aes_gcm_test.json', 'utf8'));
  const data = JSON.parse(await readFile('conformance/' + m.batch.file, 'utf8'));
  const group = data.testGroups.find((g: any) => g.tests.some((t: any) => t.aad !== ''));
  const vector = group.tests.find((t: any) => t.aad !== '');
  assert.equal(m.overrides[String(vector.tcId)].outcome, 'not_applicable');
  const result = await joseBatchItem({id: String(vector.tcId), value: vector, parent: group, position: 0, notApplicable: false}, m);
  assert.equal(result.notApplicable, true);
});
