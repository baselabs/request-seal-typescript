import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { extract } from '../scripts/extract-elixir-reasons.ts';
// Tooling test: requires the authorized pinned reference and Elixir/OTP parser.
test('extractor derives known call-site reasons from the real pinned reference without overwriting the fixture', async () => {
  const repo = process.env.REQUEST_SEAL_REPO;
  assert.ok(repo, 'REQUEST_SEAL_REPO is required for the real extraction check');
  const root = await mkdtemp(join(tmpdir(), 'request-seal-extraction-'));
  const fixtureUrl = new URL('./fixtures/elixir-reasons-0a6568a.json', import.meta.url);
  const before = await readFile(fixtureUrl, 'utf8');
  try {
    const output = join(root, 'reasons.json'); extract(repo, '0a6568aa246326617f760e94e21b359285c6ddfc', output, 'v0.4.1');
    const actual = JSON.parse(await readFile(output, 'utf8'));
    for (const rule_id of ['jose/key.algorithm_mismatch', 'structured_fields/revision_type', 'digest/invalid_state']) {
      assert.ok(actual.entries.some((e: {rule_id: string}) => e.rule_id === rule_id), rule_id);
      assert.ok(actual.modules.some((m: any) => m.call_sites.some((s: any) => s.rule_id === rule_id && s.path.startsWith('lib/request_seal/'))), rule_id);
    }
    const rules = new Set(actual.entries.map((e: {rule_id: string}) => e.rule_id));
    assert.ok(rules.has('jose/crypto.deadline_exceeded'));
    for (const layer of ['input', 'key', 'nesting']) assert.equal(rules.has(`jose/${layer}.deadline_exceeded`), false);
    const deadline = actual.modules.find((m: any) => m.kind === 'jose').call_sites.find((s: any) => s.rule_id === 'jose/crypto.deadline_exceeded');
    assert.ok(deadline.via.some((s: any) => s.expression.includes(':crypto')));
    assert.deepEqual(actual, JSON.parse(before));
    assert.equal(await readFile(fixtureUrl, 'utf8'), before);
  } finally {await rm(root, {recursive: true, force: true});}
});
