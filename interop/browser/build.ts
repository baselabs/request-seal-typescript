import {readFile, writeFile, mkdir, rm} from 'node:fs/promises';
import {resolve, dirname, relative} from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {imports, assertPortableFiles, discoverPortableFiles} from './selection.ts';

const workspace = dirname(fileURLToPath(import.meta.url));
const root = resolve(workspace, '../..');
// Native ESM is the bundle format. Only the test runner/assertion imports are
// translated; tests requiring a Node substrate or third-party modules stay native.
function transform(source: string, prefix: string): string {
  return source.replace(/(['"])(node:test|node:assert\/strict|\.\.\/src\/[^'"\n]+)\1/g, (_, quote: string, specifier: string) => {
    const target = specifier === 'node:test' ? prefix + 'harness.ts' : specifier === 'node:assert/strict' ? prefix + 'assert.ts' : '../../../../dist/' + specifier.slice('../src/'.length).replace(/\.ts$/, '.js');
    return quote + target + quote;
  });
}
async function main(): Promise<void> {
  execFileSync(process.execPath, [resolve(root, 'node_modules/typescript/bin/tsc'), '-p', resolve(workspace, 'tsconfig.tools.json')], {stdio: 'inherit', cwd: root});
  await rm(resolve(workspace, '.generated'), {recursive: true, force: true});
  await rm(resolve(workspace, 'bundle'), {recursive: true, force: true});
  await mkdir(resolve(workspace, '.generated/test'), {recursive: true});
  const selected = await discoverPortableFiles(root);
  assertPortableFiles(selected);
  for (const name of selected) {
    const file = resolve(root, 'test', name);
    // Relative test helpers require translation too; fail closed until supported.
    const source = await readFile(file, 'utf8');
    if (imports(source).some(s => s.startsWith('.') && !s.startsWith('../src/'))) throw new Error('Unsupported portable test import: ' + name);
    await writeFile(resolve(workspace, '.generated/test', name), transform(source, '../../'));
  }
  await writeFile(resolve(workspace, '.generated/index.ts'), selected.map(n => `import './test/${n}';`).join('\n') + '\nexport const files = ' + JSON.stringify(selected) + ';\n');
  await writeFile(resolve(workspace, '.generated/planted.test.ts'), transform(await readFile(resolve(root, 'test/red/planted.test.ts'), 'utf8'), '../'));
  execFileSync(process.execPath, [resolve(root, 'node_modules/typescript/bin/tsc'), '-p', resolve(workspace, 'tsconfig.json')], {stdio: 'inherit', cwd: root});
  console.log(`Browser ESM bundle: ${selected.length} core test files from dist; ${relative(root, workspace)}/bundle`);
  console.log(selected.join('\n'));
}
main().catch(error => {console.error(error); process.exitCode = 1;});
