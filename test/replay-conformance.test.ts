import test from 'node:test';
import assert from 'node:assert/strict';
import {runCorpus, surfaceRegistry, matches} from '../tools/conformance/loader.ts';
test('every vendored replay claim executes with its exact pinned outcome', {timeout: 30000}, async () => {
  assert.equal(surfaceRegistry().has('replay.claim'), true, 'replay.claim is registered');
  const registry = new Map(surfaceRegistry());
  const surface = registry.get('replay.claim')!;
  const outcomes: {id: string; expected: unknown; observed: unknown; matches: boolean}[] = [];
  registry.set('replay.claim', Object.assign(async (m: import('../tools/conformance/loader.ts').CorpusCase, resources: import('../tools/conformance/loader.ts').CorpusResources) => {
    const r = await surface(m, resources);
    outcomes.push({id: m.id, expected: m.expected, observed: r, matches: !('loaderReason' in r) && matches(m, r)});
    return r;
  }, {errorKinds: surface.errorKinds ?? []}));
  const report = await runCorpus('conformance', {pendingOk: true, registry});
  assert.equal(report.ok, true, JSON.stringify(report));
  assert.equal(outcomes.length, 11);
  for (const result of outcomes) assert.equal(result.matches, true, JSON.stringify(result));
  console.log('CORPUS replay.claim: cases=11 executed=11 disagreements=0');
});
test('replay registration leaves pending and adds exactly eleven executed items', {timeout: 30000}, async () => {
  const report = await runCorpus('conformance', {pendingOk: true});
  assert.equal(report.pending.some(p => p.surface === 'replay.claim'), false);
  assert.equal(report.ok, true, JSON.stringify(report));
  assert.equal(report.executed + report.runtime_limited, 2993);
  assert.equal(report.pending.reduce((n,p) => n+p.items,0), 9);
});

test('receipt retention drift rejects every successful corpus claim while preserving sweep and bound rejections', {timeout: 60000}, async () => {
  const {cp, mkdtemp, writeFile, readFile, rm} = await import('node:fs/promises');
  const {tmpdir} = await import('node:os');
  const {join, resolve} = await import('node:path');
  const {spawnSync} = await import('node:child_process');
  const root = await mkdtemp(join(tmpdir(), 'request-seal-receipt-drift-'));
  try {
    for (const folder of ['src', 'tools', 'test/fixtures/upstream/httpwg-structured-fields']) await cp(folder, join(root, folder), {recursive: true});
    await writeFile(join(root, 'package.json'), '{"type":"module"}');
    const receipt = join(root, 'src/replay/receipt.ts');
    const original = await readFile(receipt, 'utf8');
    const mutant = original.replace('retainUntil: r.value.retainUntil}', 'retainUntil: r.value.retainUntil + 1}');
    assert.notEqual(mutant, original, 'receipt mutation must change the constructor');
    await writeFile(receipt, mutant);
    await writeFile(join(root, 'probe.ts'), `
      import {runCorpus, surfaceRegistry, matches} from './tools/conformance/loader.ts';
      const registry = new Map(surfaceRegistry()), surface = registry.get('replay.claim');
      const outcomes = [];
      registry.set('replay.claim', Object.assign(async (m, resources) => {
        const result = await surface(m, resources);
        outcomes.push({id: m.id, expected: m.expected, matches: !('loaderReason' in result) && matches(m, result)});
        return result;
      }, {errorKinds: surface.errorKinds ?? []}));
      runCorpus(process.argv[2], {pendingOk: true, registry}).then(report => {
        console.log(JSON.stringify({outcomes, failures: report.failures}));
        process.exitCode = report.ok ? 0 : 1;
      });
    `);
    const prefix = Object.hasOwn(process.versions, 'deno') ? ['run', '--allow-read'] : Object.hasOwn(process.versions, 'bun') ? ['run'] : ['--experimental-strip-types', '--no-warnings'];
    const env = {...process.env}; delete env.NODE_TEST_CONTEXT;
    const result = spawnSync(process.execPath, [...prefix, join(root, 'probe.ts'), resolve('conformance')], {encoding: 'utf8', env, timeout: 50000});
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.ok(result.stdout.trim(), result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.outcomes.length, 11);
    const successful = report.outcomes.filter((o: {expected: object}) => Object.hasOwn(o.expected, 'retain_until'));
    assert.equal(successful.length, 6);
    for (const outcome of report.outcomes) assert.equal(outcome.matches, !Object.hasOwn(outcome.expected, 'retain_until'), outcome.id);
    assert.equal(report.failures.filter((f: {id: string}) => f.id.startsWith('replay/')).length, 6);
    for (const failure of report.failures.filter((f: {id: string}) => !f.id.startsWith('replay/'))) assert.ok(['known_positive_not_executed', 'execution_count_mismatch'].includes(failure.reason), failure.reason);
    console.log('MUTATION receipt +1: cases=11 successful claims=6 disagreements=6; sweep=4 and bound rejection=1 unchanged; exit=1');
  } finally {await rm(root, {recursive: true, force: true});}
});
