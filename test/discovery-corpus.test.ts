import test from "node:test";
import assert from "node:assert/strict";
import { surfaceRegistry, runCorpus } from "../tools/conformance/loader.ts";
test(
  "the discovery body surface executes every pinned case",
  { timeout: 30000 },
  async () => {
    const registry = surfaceRegistry();
    assert.equal(registry.has("smoke"), true);
    assert.equal(
      registry.has("discovery.body"),
      true,
      "discovery.body must be registered",
    );
    const report = await runCorpus("conformance", { pendingOk: true });
    assert.equal(report.ok, true, JSON.stringify(report));
    assert.equal(
      report.pending.some((p) => p.surface === "discovery.body"),
      false,
    );
    assert.equal(report.executed + report.runtime_limited, 2993);
  },
);

test('tampered discovery expected keys report outcome mismatch through the body surface', async () => {
  const {cp, mkdtemp, readFile, writeFile, rm} = await import('node:fs/promises');
  const {join} = await import('node:path'); const {tmpdir} = await import('node:os');
  const {createHash} = await import('node:crypto'); const {canonicalJson} = await import('../tools/conformance/loader.ts');
  const root = await mkdtemp(join(tmpdir(), 'request-seal-discovery-tamper-'));
  try {
    await cp('conformance', root, {recursive: true});
    const index = JSON.parse(await readFile(join(root, 'index.json'), 'utf8'));
    const entry = index.cases.find((c: any) => c.surface === 'discovery.body' && c.class !== 'rejection'); assert.ok(entry);
    const manifest = JSON.parse(await readFile(join(root, entry.manifest), 'utf8')); manifest.expected.keys = ['tampered'];
    const bytes = canonicalJson(manifest); await writeFile(join(root, entry.manifest), bytes);
    index.files.find((f: any) => f.path === entry.manifest).sha256 = createHash('sha256').update(bytes).digest('hex');
    await writeFile(join(root, 'index.json'), canonicalJson(index));
    const report = await runCorpus(root, {unpinned: true, pendingOk: true});
    assert.ok(report.failures.some(f => f.id === entry.id && f.reason === 'outcome_mismatch'), JSON.stringify(report));
  } finally {await rm(root, {recursive: true, force: true});}
});
