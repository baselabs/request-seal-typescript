import test from "node:test";
import assert from "node:assert/strict";
import {
  runCorpus,
  surfaceRegistry,
  canonicalJson,
} from "../tools/conformance/loader.ts";
test("sign verify and content digest surfaces execute the shared corpus", {timeout: 30_000}, async () => {
  const registry = surfaceRegistry();
  for (const name of ["sign", "verify", "digest.content"])
    assert.equal(registry.has(name), true, name);
  const r = await runCorpus("conformance", { pendingOk: true });
  assert.equal(r.ok, true, canonicalJson(r));
  // JOSE adds 309 items to the signing registry; discovery four, replay eleven, quorum and negotiation three more; Web Bot Auth fourteen.
  assert.equal(r.executed + r.runtime_limited, 3002);
  assert.equal(
    r.pending.some((p) =>
      ["sign", "verify", "digest.content"].includes(p.surface),
    ),
    false,
  );
});
import { readFileSync } from "node:fs";
import { decodeJson, decodeBase64Url, ok } from "../src/index.ts";
import {
  resolvePointer,
  type CorpusResources,
  type CorpusCase,
} from "../tools/conformance/loader.ts";
const resources: CorpusResources = {
  read(path) {
    return ok(new Uint8Array(readFileSync("conformance/" + path)));
  },
  reference(value) {
    const ref = (value as any).ref;
    const r = decodeJson(readFileSync("conformance/" + ref.file), {
      maxBytes: 16_777_216,
      maxDepth: 64,
      maxMembers: 100000,
      maxArrayLength: 100000,
      maxStringBytes: 16_777_216,
    });
    assert.equal(r.ok, true);
    if (!r.ok) return r;
    return ok(resolvePointer(r.value.node, ref.pointer));
  },
};
for (const id of [
  "rfc9421-sig-b21",
  "rfc9421-sig-b22",
  "rfc9421-sig-b23",
  "rfc9421-sig-b24",
  "rfc9421-sig-b25",
  "rfc9421-sig-b26",
  "rfc9421-ttrp",
  "rfc9421-transform",
  "rfc9421-proxy",
  "rfc9421-linkage-0",
  "rfc9421-linkage-1",
])
  test("published signature facts agree for " + id, async () => {
    const m = JSON.parse(
      readFileSync("conformance/cases/verify/" + id + ".json", "utf8"),
    );
    const r = await surfaceRegistry().get("verify")!(m, resources);
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.ok(r.ok && "verification" in r.value);
    if (r.ok && "verification" in r.value)
      assert.equal(
        canonicalJson(r.value.verification),
        canonicalJson(m.expected.verification),
      );
  });
for (const n of [21, 22, 23, 24])
  test("randomized signing verifies Appendix B.2." + (n - 20), async () => {
    const m = JSON.parse(
      readFileSync(
        "conformance/cases/verify/rfc9421-sig-b" + n + ".json",
        "utf8",
      ),
    );
    const b = decodeBase64Url(m.inputs.append_fields[0][1].b64);
    assert.equal(b.ok, true);
    if (!b.ok) return;
    const wire = new TextDecoder().decode(b.value),
      algorithm = m.policy.key_resolver.key;
    const signing: CorpusCase = {
      ...m,
      id: "sign/appendix-b" + n,
      surface: "sign",
      class: "verify_only",
      inputs: {
        message: m.inputs.message,
        spec: {
          label: m.inputs.label,
          signature_input: wire.slice(wire.indexOf("=") + 1),
          algorithm,
        },
        key: algorithm,
      },
      expected: { valid: true },
    };
    const r = await surfaceRegistry().get("sign")!(signing, resources);
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.deepEqual(r.ok ? r.value : null, { valid: true });
  });
