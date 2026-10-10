import test from 'node:test';
import {coreError} from '../src/errors/types.ts';
import {err} from '../src/result.ts';
import assert from 'node:assert/strict';
import {cp, mkdtemp, readFile, writeFile, rm, symlink} from 'node:fs/promises';
import {join, resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {runCorpus, canonicalJson, surfaceRegistry, matches, type CorpusCase} from '../tools/conformance/loader.ts';
const prefix = Object.hasOwn(process.versions, 'deno') ? ['run', '--allow-read'] : Object.hasOwn(process.versions, 'bun') ? ['run'] : ['--experimental-strip-types', '--no-warnings'];
async function copy(action: (root: string) => Promise<void>) {
  const root = await mkdtemp(join(tmpdir(), 'request-seal-vendor-test-'));
  try {await cp(resolve('conformance'), root, {recursive: true}); await action(root);}
  finally {await rm(root, {recursive: true, force: true});}
}
async function rewrite(root: string, path: string, change: (v: any) => void) {
  const v = JSON.parse(await readFile(join(root, path), 'utf8')); change(v);
  const bytes = canonicalJson(v); await writeFile(join(root, path), bytes);
  if (path !== 'index.json') await rewrite(root, 'index.json', i => {i.files.find((f: any) => f.path === path).sha256 = createHash('sha256').update(bytes).digest('hex');});
}
test('vendored release inventory ties out implemented and pending items', {timeout: 90_000}, async () => {
  const report = await runCorpus('conformance', {pendingOk: true});
  assert.equal(report.ok, true, canonicalJson(report));
  assert.equal(report.listed, report.executed + report.not_applicable + report.runtime_limited + report.pending.reduce((n, p) => n + p.items, 0));
  assert.equal(report.cases, 173);
  assert.equal(report.listed, 3064);
  // Foundation/wire/crypto/sign: 2,652; JOSE: 309; discovery.body: 4; replay.claim: 11; quorum.verify: 2; accept_signature.parse: 1; web_bot_auth.verify: 14.
  // 3,064 listed = 2,993 executed/runtime-limited + 62 not applicable + 9 pending.
  assert.equal(report.executed + report.runtime_limited, 2993);
  assert.equal(report.not_applicable, 62);
  assert.deepEqual(report.pending.map(({ids, ...entry}) => entry), [
    {surface: 'profile.name', cases: 9, items: 9},
  ]);
  const expected = JSON.parse(await readFile('tools/conformance/pending.json', 'utf8'));
  assert.deepEqual(report.pending, expected);
});
test('pending release surfaces fail closed; CLI flag only permits pending', {timeout: 90_000}, async () => {
  for (const pendingOk of [false, true]) {
    const child = spawnSync(process.execPath, [...prefix, 'tools/conformance/cli.ts', '--corpus', 'conformance', ...(pendingOk ? ['--pending-ok'] : [])], {encoding: 'utf8', timeout: 30_000});
    assert.equal(child.status, pendingOk ? 0 : 1, child.stdout + child.stderr);
    const report = JSON.parse(child.stdout);
    assert.equal(report.ok, pendingOk); assert.ok(report.pending.length > 0);
    assert.equal(report.known_positive_executed, true);
  }
});
for (const path of ['index.json', 'sources/httpwg-structured-fields/binary.json']) test(`vendored byte tamper: ${path}`, {timeout: 90_000}, async () => {
  await copy(async root => {
    const bytes = await readFile(join(root, path)); bytes[0] = bytes[0]! ^ 1; await writeFile(join(root, path), bytes);
    const report = await runCorpus(root, {pendingOk: true});
    assert.equal(report.ok, false);
    assert.equal(report.failures[0]?.reason, path === 'index.json' ? 'index_pin_mismatch' : 'file_digest_mismatch');
  });
});
for (const [name, path, change, reason] of [
  ['upstream count', 'sources/wycheproof/ed25519_test.json', (source: any) => {source.numberOfTests++;}, 'batch_count_mismatch'],
  ['batch count', 'cases/structured_fields/httpwg-binary.json', (m: any) => {m.batch.count.int = '1';}, 'batch_count_mismatch'],
  ['not applicable', 'cases/jwe/aes_gcm_test.json', (m: any) => {m.batch.not_applicable.int = '0';}, 'not_applicable_count'],
  ['unknown override', 'cases/jwe/aes_gcm_test.json', (m: any) => {m.overrides.absent = {outcome: 'not_applicable', reason: 'Absent item'};}, 'invalid_overrides'],
  ['missing can_fail pin', 'cases/structured_fields/httpwg-binary.json', (m: any) => {delete m.pins[Object.keys(m.pins)[0]!];}, 'invalid_pins'],
  ['positive reference', 'cases/structured_fields/nonzero-pad-bits-one-byte.json', (m: any) => {m.positive = m.id;}, 'invalid_positive_reference'],
] as const) test(`vendored inventory rejects ${name}`, {timeout: 90_000}, async () => {
  await copy(async root => {
    await rewrite(root, path, change);
    if (name === 'batch count' || name === 'not applicable') await rewrite(root, 'index.json', i => {
      const entry = i.cases.find((c: any) => c.manifest === path); entry[name === 'batch count' ? 'count' : 'not_applicable'] = {int: name === 'batch count' ? '1' : '0'};
    });
    const report = await runCorpus(root, {unpinned: true, pendingOk: true});
    assert.equal(report.ok, false); assert.ok(report.failures.some(f => f.reason === reason), canonicalJson(report));
  });
});
for (const [name, bytes, allowed] of [
  ['Finder metadata', Buffer.from([0,0,0,1,66,117,100,49]), true],
  ['ordinary .DS_Store file', Buffer.from('{}'), false],
] as const) test(`inventory identifies ${name}`, {timeout: 90_000}, async () => {
  await copy(async root => {
    await writeFile(join(root, 'sources/.DS_Store'), bytes);
    const report = await runCorpus(root, {pendingOk: true});
    assert.equal(report.ok, allowed, canonicalJson(report));
    if (!allowed) assert.equal(report.failures[0]?.reason, 'unlisted_or_missing_file');
  });
});
test('Finder-named symlink cannot bypass inventory', {timeout: 90_000}, async () => {
  await copy(async root => {
    await symlink('httpwg-structured-fields/binary.json', join(root, 'sources/.DS_Store'));
    assert.equal((await runCorpus(root, {pendingOk: true})).ok, false);
  });
});
test('an unregistered item format reports pending without invoking a wire adapter', {timeout: 90_000}, async () => {
  await copy(async root => {
    await rewrite(root, 'cases/structured_fields/httpwg-binary.json', m => {m.batch.item_format = 'future-httpwg/1';});
    const report = await runCorpus(root, {unpinned: true, pendingOk: true});
    assert.equal(report.ok, false, canonicalJson(report));
    assert.ok(report.failures.some(f => f.reason === 'pending_not_allowlisted'));
    const pending = report.pending.find(p => p.item_format === 'future-httpwg/1');
    assert.equal(pending?.cases, 1); assert.equal(pending?.items, 17);
    assert.ok(!(await runCorpus(root, {unpinned: true})).ok);
  });
});
test('changed upstream expectation reports the individual item and both values', {timeout: 90_000}, async () => {
  await copy(async root => {
    await rewrite(root, 'sources/httpwg-structured-fields/examples.json', cases => {cases[0].canonical = ['wrong'];});
    const report = await runCorpus(root, {unpinned: true, pendingOk: true});
    assert.equal(report.ok, false);
    const disagreement = report.failures.find(f => f.reason === 'outcome_mismatch');
    assert.ok(disagreement); assert.ok(disagreement.id.startsWith('structured_fields/httpwg-examples/0:'));
    assert.equal(disagreement.expected, 'wrong'); assert.notEqual(disagreement.actual, 'wrong');
  });
});
test('a declared known positive must match, not merely return a success', {timeout: 90_000}, async () => {
  const root = await mkdtemp(join(tmpdir(), 'request-seal-known-positive-'));
  try {
    await cp(resolve('test/fixtures/corpus-smoke'), root, {recursive: true});
    await rewrite(root, 'cases/smoke/bytes.json', m => {m.expected.bytes.b64 = 'YWJk';});
    const report = await runCorpus(root, {unpinned: true, pendingOk: true});
    assert.equal(report.ok, false); assert.equal(report.known_positive_executed, false);
    assert.ok(report.failures.some(f => f.reason === 'known_positive_not_executed'));
  } finally {await rm(root, {recursive: true, force: true});}
});
test('Finder-named directories and extra root directories are unlisted', {timeout: 90_000}, async () => {
  const {mkdir} = await import('node:fs/promises');
  for (const path of ['sources/.DS_Store', 'extra']) await copy(async root => {
    await mkdir(join(root, path));
    const report = await runCorpus(root, {pendingOk: true});
    assert.equal(report.ok, false); assert.equal(report.failures[0]?.reason, 'unlisted_or_missing_file');
  });
});
test('HTTPWG batches reject overrides instead of changing manifest pins', {timeout: 90_000}, async () => {
  await copy(async root => {
    await rewrite(root, 'cases/structured_fields/httpwg-binary.json', m => {m.overrides = {'extra padding': {outcome: 'reject', rule_id: 'core/input.invalid_options', clause: 'Deliberately mismatched rule for the rejection check'}};});
    const report = await runCorpus(root, {unpinned: true, pendingOk: true});
    assert.equal(report.ok, false);
    assert.ok(report.failures.some(f => f.reason === 'unsupported_overrides'));
  });
});
test('pending permission cannot turn a rejection into the known positive', {timeout: 90_000}, async () => {
  await copy(async root => {
    await rewrite(root, 'index.json', i => {i.known_positive = 'verify/replay-retention-exceeded';});
    const report = await runCorpus(root, {unpinned: true, pendingOk: true});
    assert.equal(report.ok, false);
    assert.ok(report.failures.some(f => f.reason === 'invalid_known_positive'));
  });
});
test('registered batch formats cannot execute under a different surface', {timeout: 90_000}, async () => {
  await copy(async root => {
    await rewrite(root, 'cases/signature_base/rfc9421-bases.json', m => {m.surface = 'message.validate';});
    await rewrite(root, 'index.json', i => {i.cases.find((c: any) => c.id === 'signature_base/rfc9421-bases').surface = 'message.validate';});
    const report = await runCorpus(root, {unpinned: true, pendingOk: true});
    assert.equal(report.ok, false); assert.ok(report.failures.some(f => f.reason === 'invalid_batch_surface'));
  });
});

test('pending permission rejects a dropped registered surface', {timeout: 90_000}, async () => {
  const registry = new Map(surfaceRegistry()); registry.delete('signature_base.build');
  const report = await runCorpus('conformance', {pendingOk: true, registry});
  assert.equal(report.ok, false);
  assert.ok(report.failures.some(f => f.reason === 'registered_surface_pending'));
});
test('pending permission rejects changed pending counts', {timeout: 90_000}, async () => {
  await copy(async root => {
    await rewrite(root, 'cases/verify/invalid-policy.json', m => {m.surface = 'profile.name';});
    await rewrite(root, 'index.json', i => {i.cases.find((c: any) => c.id === 'verify/invalid-policy').surface = 'profile.name';});
    const report = await runCorpus(root, {unpinned: true, pendingOk: true});
    assert.equal(report.ok, false);
    assert.ok(report.failures.some(f => f.reason === 'pending_count_mismatch'));
  });
});
for (const id of ['signature_base/rfc9421-bases', 'verify/replay-retention-exceeded']) {
  test(`known positive requires a single positive case: ${id}`, {timeout: 90_000}, async () => {
    await copy(async root => {
      await rewrite(root, 'index.json', i => {i.known_positive = id;});
      const report = await runCorpus(root, {unpinned: true, pendingOk: true});
      assert.equal(report.ok, false);
      assert.ok(report.failures.some(f => f.reason === 'invalid_known_positive'));
    });
  });
}
test('RFC 9421 batches refuse even empty overrides', {timeout: 90_000}, async () => {
  await copy(async root => {
    await rewrite(root, 'cases/signature_base/rfc9421-bases.json', m => {m.overrides = {};});
    const report = await runCorpus(root, {unpinned: true, pendingOk: true});
    assert.equal(report.ok, false);
    assert.ok(report.failures.some(f => f.reason === 'unsupported_overrides'));
  });
});
for (const [name, bytes, allowed] of [
  ['Finder metadata', Buffer.from([0,0,0,1,66,117,100,49]), true],
  ['empty metadata', Buffer.alloc(0), true],
  ['ordinary bytes', Buffer.from('{}'), false],
] as const) test(`root inventory identifies ${name}`, {timeout: 90_000}, async () => {
  await copy(async root => {
    await writeFile(join(root, '.DS_Store'), bytes);
    const report = await runCorpus(root, {pendingOk: true});
    assert.equal(report.ok, allowed, canonicalJson(report));
    if (!allowed) assert.equal(report.failures[0]?.reason, 'unlisted_or_missing_file');
  });
});
test('listing ordinary Finder-named bytes does not make them corpus data', {timeout: 90_000}, async () => {
  await copy(async root => {
    const bytes = '{}'; await writeFile(join(root, 'sources/.DS_Store'), bytes);
    await rewrite(root, 'index.json', i => {
      i.files.push({path: 'sources/.DS_Store', sha256: createHash('sha256').update(bytes).digest('hex')});
      i.files.sort((a: any, b: any) => a.path < b.path ? -1 : 1);
    });
    const report = await runCorpus(root, {unpinned: true, pendingOk: true});
    assert.equal(report.ok, false);
    assert.equal(report.failures[0]?.reason, 'unlisted_or_missing_file');
  });
});
test('missing corpus files keep a specific loader reason', {timeout: 90_000}, async () => {
  await copy(async root => {
    await rm(join(root, 'sources/httpwg-structured-fields/binary.json'));
    assert.equal((await runCorpus(root, {pendingOk: true})).failures[0]?.reason, 'missing_file');
  });
});
test('symbolic corpus directories keep a specific loader reason', {timeout: 90_000}, async () => {
  await copy(async root => {
    await symlink('httpwg-structured-fields', join(root, 'sources/link'));
    assert.equal((await runCorpus(root, {pendingOk: true})).failures[0]?.reason, 'symbolic_link');
  });
});
for (const value of [NaN, Infinity, -Infinity, new Map(), new Set(), new (class Example {})(), () => {}]) {
  test(`canonical serialization rejects ${typeof value === 'number' ? String(value) : value.constructor.name}`, () => {
    assert.throws(() => canonicalJson(value), /invalid_canonical_value/);
  });
}
test('an unfamiliar source layout is pending rather than an integrity failure', {timeout: 90_000}, async () => {
  await copy(async root => {
    await rewrite(root, 'sources/httpwg-structured-fields/binary.json', v => {
      // Preserve real source items inside a future layout.
      const cases = [...v]; v.length = 0; v.push({vectors: cases});
    });
    await rewrite(root, 'cases/structured_fields/httpwg-binary.json', m => {m.batch.item_format = 'future-httpwg/2';});
    const report = await runCorpus(root, {unpinned: true, pendingOk: true});
    assert.ok(report.pending.some(p => p.item_format === 'future-httpwg/2' && p.items === 17));
    assert.ok(report.failures.every(f => f.reason !== 'unexpected_item_shape'), canonicalJson(report));
    assert.ok(report.failures.some(f => f.reason === 'pending_not_allowlisted'));
  });
});
for (const path of ['cases/jwe/aes_gcm_test.json', 'cases/jwe/rsa_oaep_2048_sha256_mgf1sha256_test.json', 'cases/crypto/ed25519_test.json', 'cases/crypto/ecdsa_secp256r1_sha256_p1363_test.json']) {
  test(`a declared Wycheproof pin replaces a valid verdict: ${path}`, {timeout: 90_000}, async () => {
    await copy(async root => {
      const manifest = JSON.parse(await readFile(join(root, path), 'utf8'));
      const source = JSON.parse(await readFile(join(root, manifest.batch.file), 'utf8'));
      const item = source.testGroups.flatMap((g: any) => g.tests).find((t: any) => t.result === 'valid' && manifest.overrides?.[String(t.tcId)]?.outcome !== 'not_applicable');
      assert.ok(item);
      await rewrite(root, path, m => {
        m.overrides ??= {};
        m.overrides[String(item.tcId)] = {outcome: 'not_applicable', reason: 'RFC 7518 Section 4: explicit applicability pin for this loader test'};
        m.batch.not_applicable.int = String(Number(m.batch.not_applicable.int) + 1);
      });
      await rewrite(root, 'index.json', i => {
        const c = i.cases.find((c: any) => c.manifest === path);
        c.not_applicable.int = String(Number(c.not_applicable.int) + 1);
      });
      const report = await runCorpus(root, {unpinned: true, pendingOk: true});
      assert.equal(report.not_applicable, 63, canonicalJson(report));
      assert.equal(report.ok, true, canonicalJson(report));
      // One newly excluded item leaves each registered Wycheproof batch format.
      assert.equal(report.executed + report.runtime_limited, 2992);
      assert.ok(report.failures.every(f => !['invalid_overrides', 'unexpected_item_shape', 'not_applicable_count'].includes(f.reason)));
    });
  });
}
test('signature transformations use their own parameters over the parent', {timeout: 90_000}, async () => {
  await copy(async root => {
    await rewrite(root, 'sources/rfc9421/rfc9421.json', cases => {
      const parent = cases.find((v: any) => v.transformations?.length);
      assert.ok(parent);
      parent.transformations[0].parameters = parent.parameters + ';nonce="changed"';
      parent.transformations[0].same_base = false;
    });
    const report = await runCorpus(root, {unpinned: true, pendingOk: true});
    assert.equal(report.ok, true, canonicalJson(report));
  });
});
test('message overrides reject undocumented body members before execution', {timeout: 90_000}, async () => {
  await copy(async root => {
    await rewrite(root, 'cases/message/ipv6-literal.json', m => {
      m.class = 'rejection'; m.evidence_class = 'reviewed_derivation';
      m.derivation = 'Replace constructed unavailable body with an unvalidated raw value.';
      m.expected = {rule_id: 'message/invalid_body'};
      m.inputs.message_override = {body: 'unavailable'};
    });
    await rewrite(root, 'index.json', i => {i.cases.find((c: any) => c.id === 'message/ipv6-literal').class = 'rejection';});
    const report = await runCorpus(root, {unpinned: true, pendingOk: true});
    assert.ok(report.failures.some(f => f.reason === 'invalid_manifest'));
  });
});
test('Structured Fields rejection cannot pass on an options error', {timeout: 90_000}, async () => {
  await copy(async root => {
    await rewrite(root, 'cases/structured_fields/nonzero-pad-bits-one-byte.json', m => {
      m.inputs.schema = 'not-a-schema'; m.expected = {rule_id: 'core/input.invalid_options'};
    });
    const report = await runCorpus(root, {unpinned: true, pendingOk: true});
    assert.equal(report.ok, false);
    assert.ok(report.failures.some(f => f.id === 'structured_fields/nonzero-pad-bits-one-byte' && f.reason === 'outcome_mismatch'));
  });
});
const liveVendorSkip = (() => {
  if (Object.hasOwn(process.env, 'REQUEST_SEAL_OFFLINE')) return 'REQUEST_SEAL_OFFLINE is set';
  return undefined;
})();
if (liveVendorSkip) console.log(`Live vendoring skipped: ${liveVendorSkip}`);
test('release vendoring compares extracted index bytes with the resolved commit', {timeout: 180_000, skip: liveVendorSkip !== undefined}, async () => {
  const root = await mkdtemp(join(tmpdir(), 'request-seal-live-vendor-'));
  try {
    const {mkdir} = await import('node:fs/promises'); await mkdir(join(root, 'src'));
    await cp('src/constants.ts', join(root, 'src/constants.ts'));
    const oldPin = await readFile(join(root, 'src/constants.ts'), 'utf8');
    await writeFile(join(root, 'src/constants.ts'), oldPin.replace(/indexSha256: '[a-f0-9]{64}'/, "indexSha256: '" + '0'.repeat(64) + "'"));
    const vendorPrefix = Object.hasOwn(process.versions, 'deno')
      ? ['run', '--allow-read', '--allow-write', '--allow-env', '--allow-net', '--allow-run=tar,git'] : prefix;
    const {CORPUS_PIN} = await import('../src/constants.ts');
    const child = spawnSync(process.execPath, [...vendorPrefix, resolve('scripts/vendor-corpus.ts'), CORPUS_PIN.tag, '--update-pin'], {cwd: root, encoding: 'utf8', timeout: 120_000});
    assert.equal(child.status, 0, child.stdout + child.stderr);
    assert.match(child.stdout, /index.json: commit bytes match/);
    const committed = await fetch(`https://raw.githubusercontent.com/baselabs/request_seal/${CORPUS_PIN.commit}/corpus/index.json`, {signal: AbortSignal.timeout(30000)});
    assert.equal(committed.status, 200);
    const bytes = await readFile(join(root, 'conformance/index.json'));
    assert.deepEqual(bytes, Buffer.from(await committed.arrayBuffer()));
    const constants = await readFile(join(root, 'src/constants.ts'), 'utf8');
    assert.ok(constants.includes(CORPUS_PIN.commit));
    assert.ok(constants.includes(createHash('sha256').update(bytes).digest('hex')));
  } finally {await rm(root, {recursive: true, force: true});}
});
test('format documentation states the release and override contract', {timeout: 90_000}, async () => {
  const doc = await readFile('docs/reference/corpus-format.md', 'utf8');
  assert.match(doc, /"elixir_release": "v0\.4\.0"/);
  assert.match(doc, /valid, invalid, or acceptable/);
  assert.match(doc, /unsupported_overrides/);
  const changelog = await readFile('CHANGELOG.md', 'utf8');
  assert.doesNotMatch(changelog.split('## Unreleased')[1] ?? '', /\n- [^\n]+\n\n- /);
  assert.match(changelog, /valid, invalid, or acceptable/);
});

test('rejection comparisons require the expected surface error family', {timeout: 90_000}, async () => {
  const manifest = JSON.parse(await readFile('conformance/cases/structured_fields/nonzero-pad-bits-one-byte.json', 'utf8')) as CorpusCase;
  const planted = coreError('invalid_options', 'input');
  const expected = {...manifest, expected: {rule_id: 'core/input.invalid_options'}};
  assert.equal(matches(expected, err(planted)), false);
});

test('quorum corpus defaults use published principals and reject unmatched or invalid labels', {timeout: 90_000}, async () => {
  const {quorumSurface} = await import('../tools/conformance/quorum-surfaces.ts');
  const registry = new Map(surfaceRegistry());
  const observed: any[] = [];
  registry.set('quorum.verify', Object.assign(async (manifest: CorpusCase, resources: import('../tools/conformance/loader.ts').CorpusResources) => {
    const actual = await quorumSurface(manifest, resources);
    if (manifest.id === 'quorum/rfc9421-ed25519') {
      observed.push(actual);
      observed.push(await quorumSurface({...manifest, inputs: {...manifest.inputs, label: 'unmatched'}}, resources));
      observed.push(await quorumSurface({...manifest, policy: {...manifest.policy, components: '("@query")'}}, resources));
    }
    return actual;
  }, {errorKinds: registry.get('quorum.verify')!.errorKinds ?? []}));
  const report = await runCorpus('conformance', {pendingOk: true, registry});
  assert.equal(report.ok, true, JSON.stringify(report));
  assert.equal(observed.length, 3);
  assert.equal(observed[0].value.verification.unit, 'principal');
  assert.equal(observed[0].value.verification.qualifying[0].principal, 'published');
  assert.equal(observed[1].error.reason, 'unexpected_signature');
  assert.equal(observed[2].error.reason, 'nonqualifying_signature');
});

test('vendoring skips only an explicit offline request', {timeout:30_000}, () => {
  const env = {...process.env};
  delete env.REQUEST_SEAL_OFFLINE;
  delete env.NODE_TEST_CONTEXT;
  const runtime = Object.hasOwn(process.versions,'deno')
    ? ['test','--no-check','--allow-read','--allow-env','--allow-run=gh','--filter=format documentation']
    : Object.hasOwn(process.versions,'bun')
      ? ['test','--test-name-pattern=format documentation']
      : ['--experimental-strip-types','--no-warnings','--test','--test-name-pattern=format documentation'];
  const output = (selected: NodeJS.ProcessEnv) => {
    // Deno's Node subprocess compatibility merges omitted environment keys.
    // Its native clearEnv option preserves an explicitly unset offline switch.
    const native = (globalThis as unknown as {Deno?: {Command: new (command: string, options: {
      args: string[]; env: Record<string,string>; clearEnv: boolean; stdout: "piped"; stderr: "piped";
    }) => {outputSync: () => {code: number; stdout: Uint8Array; stderr: Uint8Array}}}}).Deno;
    if (native) {
      const env = Object.fromEntries(Object.entries(selected).filter((pair): pair is [string,string] => typeof pair[1] === 'string'));
      const r = new native.Command(process.execPath,{args:[...runtime,'test/conformance-vendor.test.ts'],env,clearEnv:true,stdout:'piped',stderr:'piped'}).outputSync();
      const out = new TextDecoder().decode(r.stdout), error = new TextDecoder().decode(r.stderr);
      assert.equal(r.code,0,out+error);
      return out;
    }
    const r = spawnSync(process.execPath,[...runtime,'test/conformance-vendor.test.ts'],{env:selected,encoding:'utf8',timeout:10_000});
    assert.equal(r.status,0,r.stdout+r.stderr);
    return r.stdout;
  };
  assert.match(output({...env,REQUEST_SEAL_OFFLINE:''}),/Live vendoring skipped: REQUEST_SEAL_OFFLINE is set/);
  // The real test directory has no gh; no replacement executable is installed.
  const unavailable = {...env,PATH:resolve('test')};
  assert.notEqual(spawnSync('gh',['--version'],{env:unavailable}).status,0);
  assert.doesNotMatch(output(unavailable),/Live vendoring skipped:/);
  assert.doesNotMatch(output(env),/Live vendoring skipped:/);
});

test('rejection manifests reject unknown rule vocabulary before execution', async () => {
  await copy(async root => {
    await rewrite(root, 'cases/structured_fields/nonzero-pad-bits-one-byte.json', m => {m.expected.rule_id = 'structured_fields/absent_reason';});
    const report = await runCorpus(root, {unpinned: true, pendingOk: true});
    assert.ok(report.failures.some(f => f.reason === 'invalid_manifest'));
    assert.equal(report.executed, 0);
  });
});
test('message overrides reject undocumented keys and decode tagged field bytes', {timeout: 30_000}, async () => {
  await copy(async root => {
    await rewrite(root, 'cases/message/ipv6-literal.json', m => {m.inputs.message_override = {body: 'unavailable'};});
    const report = await runCorpus(root, {unpinned: true, pendingOk: true});
    assert.ok(report.failures.some(f => f.reason === 'invalid_manifest'));
  });
  await copy(async root => {
    await rewrite(root, 'cases/message/ipv6-literal.json', m => {m.inputs.message_override = {fields: [['X-Test', {b64: 'YQ'}]], authority: '[2001:db8::1]', scheme: 'https'};});
    const report = await runCorpus(root, {unpinned: true, pendingOk: true});
    assert.ok(report.ok, canonicalJson(report));
  });
});
test('smoke rejection matching declares its JOSE error family', async () => {
  const {joseError} = await import('../src/errors/types.ts');
  const manifest = {format: 'request-seal-conformance-case/1', id: 'smoke/test', source: {}, evidence_class: 'reviewed_derivation', inputs: {}, surface: 'smoke', class: 'rejection', expected: {rule_id: 'core/input.invalid_options'}} as CorpusCase;
  assert.equal(matches(manifest, err(coreError('invalid_options', 'input'))), false);
  assert.ok(matches({...manifest, expected: {rule_id: 'jose/input.invalid_base64'}}, err(joseError('invalid_base64', 'input'))));
  for (const [name, surface] of surfaceRegistry()) assert.ok(surface.errorKinds?.length, name);
});
test('pending permission rejects stale entries even when no surfaces remain pending', {timeout: 30_000}, async () => {
  await copy(async root => {
    await rewrite(root, 'index.json', i => {
      const removed = i.cases.filter((c: any) => ['profile.name', 'web_bot_auth.verify'].includes(c.surface));
      i.cases = i.cases.filter((c: any) => !removed.includes(c));
      const paths = new Set(removed.map((c: any) => c.manifest));
      i.files = i.files.filter((f: any) => !paths.has(f.path));
    });
    const original = JSON.parse(await readFile('conformance/index.json', 'utf8'));
    for (const c of original.cases.filter((c: any) => ['profile.name','web_bot_auth.verify'].includes(c.surface))) await rm(join(root, c.manifest));
    const report = await runCorpus(root, {unpinned: true, pendingOk: true});
    assert.ok(report.failures.some(f => f.reason === 'stale_pending_allowlist'), canonicalJson(report));
  });
});

test('malformed pending JSON reports the bounded allowlist diagnostic', async () => {
  const {parsePendingAllowlist} = await import('../tools/conformance/loader.ts');
  for (const raw of ['{', '{}', '[{}]', '[null]']) assert.throws(() => parsePendingAllowlist(raw), /invalid_pending_allowlist/);
  assert.deepEqual(parsePendingAllowlist('[]'), []);
});

test('verifying the pinned corpus leaves directory identity and source bytes unchanged', {timeout: 180_000, skip: liveVendorSkip !== undefined}, async () => {
  const root = await mkdtemp(join(tmpdir(), 'request-seal-vendor-readonly-'));
  try {
    const {mkdir, stat} = await import('node:fs/promises'); await mkdir(join(root, 'src'));
    await cp('src/constants.ts', join(root, 'src/constants.ts')); await cp('conformance', join(root, 'conformance'), {recursive: true});
    const constants = await readFile(join(root, 'src/constants.ts')), before = await stat(join(root, 'conformance'));
    const {CORPUS_PIN} = await import('../src/constants.ts');
    const vendorPrefix = Object.hasOwn(process.versions, 'deno') ? ['run','--allow-read','--allow-write','--allow-env','--allow-net', '--allow-run=tar,git'] : prefix;
    for (const flags of [[], ['--update-pin']]) {
      const child = spawnSync(process.execPath, [...vendorPrefix, resolve('scripts/vendor-corpus.ts'), CORPUS_PIN.tag, ...flags], {cwd: root, encoding: 'utf8', timeout: 120_000});
      assert.equal(child.status, 0, child.stdout + child.stderr);
      const after = await stat(join(root, 'conformance')); assert.equal(after.ino, before.ino); assert.equal(after.mtimeMs, before.mtimeMs);
      assert.deepEqual(await readFile(join(root, 'src/constants.ts')), constants);
    }
  } finally {await rm(root, {recursive: true, force: true});}
});

test('message override containers must be documented objects', {timeout: 30_000}, async () => {
  for (const override of [null, [], '', 1]) await copy(async root => {
    await rewrite(root, 'cases/message/ipv6-literal.json', m => {m.inputs.message_override = override;});
    const report = await runCorpus(root, {unpinned: true, pendingOk: true});
    assert.ok(report.failures.some(f => f.reason === 'invalid_manifest'), canonicalJson(report));
  });
});
