import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, mkdir, copyFile, readFile, rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {execFileWithEnvSync} from './support/child-env.ts';

test('both parity regeneration paths produce identical bytes and are idempotent', async () => {
  const root = await mkdtemp(join(tmpdir(), 'rs-parity-'));
  try {
    for (const dir of ['scripts', 'src/errors', 'test/fixtures']) await mkdir(join(root, dir), {recursive: true});
    const files = ['scripts/generate-parity.ts', 'scripts/render-parity.ts', 'src/errors/parity.ts', 'test/fixtures/elixir-reasons-0a6568a.json'];
    for (const file of files) await copyFile(file, join(root, file));
    // Copy any shared script dependencies along with the two entry points.
    const {readdir} = await import('node:fs/promises');
    for (const file of await readdir('scripts'))
      if (file.endsWith('.ts')) await copyFile(join('scripts', file), join(root, 'scripts', file));
    const run = (script: string, args: string[] = []) => execFileWithEnvSync('node', ['--experimental-strip-types', '--no-warnings', script, ...args], {env: {...process.env}, cwd: root, encoding: 'utf8', timeout: 10000});
    const generated = join(root, 'src/errors/parity.ts');
    run('scripts/generate-parity.ts');
    const first = await readFile(generated, 'utf8');
    run('scripts/render-parity.ts', ['--update-table', 'test/fixtures/elixir-reasons-0a6568a.json']);
    assert.equal(await readFile(generated, 'utf8'), first);
    run('scripts/generate-parity.ts');
    assert.equal(await readFile(generated, 'utf8'), first);
    run('scripts/render-parity.ts', ['--update-table', 'test/fixtures/elixir-reasons-0a6568a.json']);
    assert.equal(await readFile(generated, 'utf8'), first);
  } finally {await rm(root, {recursive: true, force: true});}
});
