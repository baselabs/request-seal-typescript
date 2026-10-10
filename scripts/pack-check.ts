import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { readFileSync, mkdtempSync, mkdirSync, renameSync, writeFileSync, rmSync, existsSync, realpathSync } from 'node:fs';
import assert from 'node:assert/strict';
import {tmpdir} from 'node:os';
import {dirname, join} from 'node:path';
import {pathToFileURL, fileURLToPath} from 'node:url';
import { testBuilt } from './test-built.ts';
export function assertPackedSources(files: readonly {path: string}[], root = process.cwd()): void {
  const documents = new Set(['package.json','README.md','CHANGELOG.md','LICENSE','NOTICE']);
  for (const file of files) {
    assert.ok(documents.has(file.path) || /^dist\/[a-z_/-]+(?:\.js|\.d\.ts)$/.test(file.path), `Unexpected packed file: ${file.path}`);
    if (file.path.startsWith('dist/')) {
      const source = file.path.replace(/^dist\//, 'src/').replace(/(?:\.d\.ts|\.js)$/, '.ts');
      assert.ok(existsSync(join(root, source)), `Orphan packed file: ${file.path}`);
    }
  }
}
async function main(): Promise<void> {
  const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
  assert.equal(pkg.name, '@request-seal/core');
  assert.equal(pkg.publishConfig.access, 'public');
  assert.equal(pkg.dependencies, undefined);
  assert.deepEqual(Object.keys(pkg.devDependencies).sort(), ['@types/node', 'fast-check', 'typescript']);
  const [pack] = JSON.parse(execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {encoding: 'utf8'}));
  assert.equal(pack.name, '@request-seal/core');
  assert.equal(pack.filename, `request-seal-core-${pkg.version}.tgz`);
  const documents = new Set(['package.json', 'README.md', 'CHANGELOG.md', 'LICENSE', 'NOTICE']);
  assertPackedSources(pack.files);
  const paths = new Set(pack.files.map((f: {path: string}) => f.path));
  for (const path of [...documents, 'dist/index.js', 'dist/index.d.ts']) assert.ok(paths.has(path), `Required packed file: ${path}`);
  for (const path of ['dist/discovery/node.js', 'dist/discovery/node.d.ts', 'dist/node_hasher.js', 'dist/node_hasher.d.ts']) assert.ok(paths.has(path), `Required packed subpath: ${path}`);
  assert.deepEqual(pkg.exports['./discovery-node'], {
    types: './dist/discovery/node.d.ts', node: './dist/discovery/node.js', default: './dist/discovery/node.js',
  });
  for (const [name, path] of [['node-http', 'adapters/node-http/index'], ['fetch', 'adapters/fetch/index'], ['custody-ssh-agent', 'custody/ssh-agent/index']]) {
    for (const extension of ['js', 'd.ts']) assert.ok(paths.has(`dist/${path}.${extension}`), `Required packed adapter: ${path}.${extension}`);
    assert.deepEqual(pkg.exports[`./${name}`], {types: `./dist/${path}.d.ts`, default: `./dist/${path}.js`});
  }
  const toolRequire = createRequire(import.meta.url);
  const scratch = mkdtempSync(join(tmpdir(), 'request-seal-pack-'));
  try {
    writeFileSync(join(scratch, 'package.json'), JSON.stringify({name: 'request-seal-pack-consumer', private: true, type: 'module'}));
    const [artifact] = JSON.parse(execFileSync('npm', ['pack', '--json', '--ignore-scripts', '--pack-destination', scratch], {encoding: 'utf8'}));
    assert.equal(artifact.filename, `request-seal-core-${pkg.version}.tgz`);
    // A nested TMPDIR must not inherit this package's self-reference scope.
    writeFileSync(join(scratch, 'package.json'), JSON.stringify({name: 'request-seal-pack-consumer', private: true, type: 'module'}));
    mkdirSync(join(scratch, 'node_modules'));
    execFileSync('tar', ['-xzf', join(scratch, artifact.filename), '-C', join(scratch, 'node_modules')]);
    mkdirSync(join(scratch, 'node_modules', '@request-seal'));
    renameSync(join(scratch, 'node_modules', 'package'), join(scratch, 'node_modules', '@request-seal', 'core'));
    const require = createRequire(join(scratch, 'probe.cjs'));
    for (const [subpath, entry] of Object.entries(pkg.exports)) {
      const name = subpath === '.' ? '@request-seal/core' : `@request-seal/core/${subpath.slice(2)}`;
      const path = typeof entry === 'string' ? entry : (entry as {default: string}).default;
      assert.equal(require.resolve(name), realpathSync(join(scratch, 'node_modules', '@request-seal', 'core', path)));
    }
    assert.equal(require('@request-seal/core/package.json').name, '@request-seal/core');
    for (const [name, entry] of [['node-http', 'captureRequest'], ['fetch', 'signRequest'], ['custody-ssh-agent', 'createSshAgent']]) assert.equal(typeof require(`@request-seal/core/${name}`)[entry!], 'function');
    assert.equal(typeof require('@request-seal/core/node-http').verifyWebBotAuth, 'function');
    const discovery = require('@request-seal/core/discovery-node');
    assert.equal(typeof discovery.Discovery.fetch, 'function');
    assert.equal(typeof discovery.Discovery.resolver.fromSnapshot, 'function');
    writeFileSync(join(scratch, 'consumer.mts'), `import { DiscoverySource } from '@request-seal/core/discovery-node';
import { verifyWebBotAuth, verification, type VerifiedWebBotAuthRequest, type WebBotAuthVerification } from '@request-seal/core/node-http';
async function verifyBot(req: unknown, policy: unknown): Promise<WebBotAuthVerification | null> {
  const result = await verifyWebBotAuth(req, policy);
  if (!result.ok) return null;
  const captured: VerifiedWebBotAuthRequest = result.value;
  const stored = verification(req);
  void stored;
  return captured.verification;
}
void verifyBot;
const result = DiscoverySource.create({type: 'jwks_uri', location: 'https://example.com/keys'});
if (result.ok) { const s: DiscoverySource = result.value; void s; }
`);
    execFileSync(process.execPath, [join(dirname(toolRequire.resolve('typescript/package.json')), 'bin/tsc'), '--ignoreConfig', '--noEmit', '--strict', '--skipLibCheck', '--module', 'nodenext', '--target', 'es2024', join(scratch, 'consumer.mts')], {cwd: scratch, stdio: 'inherit'});
    const discoveryProbe = `
      import assert from 'node:assert/strict';
      import {createRequire} from 'node:module';
      const require = createRequire(import.meta.url);
      const required = require('@request-seal/core/discovery-node');
      const imported = await import('@request-seal/core/discovery-node');
      assert.equal(imported.Discovery, required.Discovery);
      assert.equal(imported.DiscoverySource, required.DiscoverySource);
      assert.equal(import.meta.resolve('@request-seal/core/discovery-node'), new URL('./node_modules/@request-seal/core/dist/discovery/node.js', import.meta.url).href);
      console.log('PASS packed @request-seal/core/discovery-node: typed consumer and import identity');
    `;
    process.stdout.write(execFileSync(process.execPath, ['--input-type=module', '-e', discoveryProbe], {cwd: scratch, encoding: 'utf8'}));
    const built = require('@request-seal/core');
    assert.equal(built.VERSION, pkg.version);
    assert.deepEqual(built.byteString('abc').value, new Uint8Array([97, 98, 99]));
    assert.equal(built.decodeBase64Url('Zh').ok, false);
    assert.equal(built.decodeJson(new TextEncoder().encode('\ufeff{}')).ok, false);
    const esm = await import(pathToFileURL(require.resolve('@request-seal/core')).href);
    const subpathProbe = `
      import assert from 'node:assert/strict';
      import {DigestState, digest} from '@request-seal/core';
      import {createStore, ddl} from '@request-seal/core/replay-postgres';
      assert.equal(typeof createStore, 'function');
      assert.deepEqual(ddl('t'), {ok: true, value: 'CREATE TABLE "t" (namespace bytea NOT NULL, key bytea NOT NULL, retain_until bigint NOT NULL, PRIMARY KEY (namespace, key))'});
      console.log('PASS packed @request-seal/core/replay-postgres: createStore import; exact reference DDL');
      async function probe() {
        const {createNodeHasher} = await import('@request-seal/core/node-hasher');
        const hasher = createNodeHasher(); assert.equal(hasher.ok, true);
        const state = await DigestState.create('content', ['sha-256', 'sha-512'], hasher.value); assert.equal(state.ok, true);
        for (const chunk of ['a', '', 'bc']) assert.equal((await state.value.update(new TextEncoder().encode(chunk))).ok, true);
        const actual = await state.value.finish(); const expected = await digest(new TextEncoder().encode('abc'), ['sha-256', 'sha-512']);
        assert.equal(actual.ok, true); assert.equal(expected.ok, true); assert.deepEqual(actual.value, expected.value);
        console.log('PASS packed @request-seal/core/node-hasher: multichunk SHA-256/SHA-512');
      }
      probe().catch(() => {process.exitCode = 1;});
    `;
    process.stdout.write(execFileSync(process.execPath, ['--input-type=module', '-e', subpathProbe], {cwd: scratch, encoding: 'utf8'}));
    assert.equal(esm.VERSION, pkg.version);
    for (const entry of [built, esm]) {
      for (const name of ['withDeadline', 'run', 'remainingMs', 'isContext']) assert.equal(typeof entry[name], 'function');
      assert.equal(Object.hasOwn(entry, 'releaseContext'), false);
      const parsed = entry.StructuredFields.parse('item', '42', {schema: 'rfc8941'});
      assert.equal(parsed.ok, true);
      const serialized = entry.StructuredFields.serialize(parsed.value);
      assert.equal(serialized.ok, true);
      assert.equal(new TextDecoder().decode(serialized.value), '42');
      const message = await entry.Message.request('GET', 'https://example.com/', [], null);
      assert.equal(message.ok, true);
      assert.equal(entry.Message.validate(message.value).ok, true);
      const base = entry.SignatureBase.build(message.value, '("@method")');
      assert.equal(base.ok, true);
      assert.equal(new TextDecoder().decode(base.value), '"@method": GET\n"@signature-params": ("@method")');
    }
    await testBuilt();
    console.log(`PASS pack boundary: ${pack.files.length} files; ESM import and require(esm), four wire surfaces; version ${pkg.version}`);
  } finally {rmSync(scratch, {recursive: true, force: true});}
}
if (process.argv[1] === fileURLToPath(import.meta.url)) main().catch(() => { console.error('FAIL package boundary or built entry point'); process.exitCode = 1; });
