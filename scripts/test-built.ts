import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
/** Execute the existing core contracts against emitted JavaScript on the current lane. */
export async function testBuilt(): Promise<void> {
  const folder = await mkdtemp(join(tmpdir(), 'request-seal-built-tests-'));
  try {
    const files = ['errors', 'bytes', 'json', 'numbers', 'context', 'brand', 'discovery', 'discovery-cache', 'discovery-proof', 'discovery-gzip', 'discovery-node', 'web-bot-auth-policy', 'web-bot-auth', 'web-bot-auth-replay', 'web-bot-auth-discovery'];
    const tests: string[] = [];
    // Helpers that construct branded values must use the same emitted module
    // graph as the copied tests, never a second source-module brand registry.
    const helperFile = join(folder, 'discovery-snapshot.ts');
    const helper = await readFile(resolve('test/support/discovery-snapshot.ts'), 'utf8');
    await writeFile(helperFile, helper.replace('../../src/index.ts', pathToFileURL(resolve('dist/index.js')).href));
    const webBotAuthHelper = join(folder, 'web-bot-auth.ts');
    const webBotAuthSource = await readFile(resolve('test/support/web-bot-auth.ts'), 'utf8');
    await writeFile(webBotAuthHelper, webBotAuthSource.replace('../../src/index.ts', pathToFileURL(resolve('dist/index.js')).href));
    for (const name of files) {
      const original = resolve(`test/${name}.test.ts`);
      let source = await readFile(original, 'utf8');
      source = source.replace(/(['"])fast-check\1/g, (_, quote: string) => quote + import.meta.resolve('fast-check') + quote);
      source = source.replace(/(['"])(\.\.\/src\/[^'"\n]+)\1/g, (_, quote: string, path: string) => quote + pathToFileURL(resolve(path.replace('../src/', 'dist/').replace(/\.ts$/, '.js'))).href + quote);
      source = source.replace(/(['"])(\.\.\/(?:scripts|docs)\/[^'"\n]+|\.\/fixtures\/[^'"\n]+)\1/g, (_, quote: string, path: string) => quote + new URL(path, pathToFileURL(original)).href + quote);
      source = source.replace(/(['"])(\.\/support\/[^'"\n]+)\1/g, (_, quote: string, path: string) => quote + (path === './support/discovery-snapshot.ts' ? pathToFileURL(helperFile).href : path === './support/web-bot-auth.ts' ? pathToFileURL(webBotAuthHelper).href : new URL(path, pathToFileURL(original)).href) + quote);
      const file = join(folder, `${name}.test.ts`); await writeFile(file, source); tests.push(file);
    }
    const run = spawnSync(process.execPath, ['--unhandled-rejections=strict', '--experimental-strip-types', '--no-warnings', '--test-concurrency=4', '--test', ...tests], {stdio: 'inherit'});
    if (run.status !== 0) throw new Error('Built core contracts failed');
  } finally { await rm(folder, {recursive: true, force: true}); }
}
