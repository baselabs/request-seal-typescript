import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, mkdtempSync, writeFileSync, mkdirSync, rmSync, existsSync, cpSync, symlinkSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {isUnpublished} from '../scripts/registry-check.ts';
const read = (p: string) => readFileSync(p, 'utf8');
test('packed dist rejects an orphan after a source is removed', async () => {
  const {assertPackedSources} = await import('../scripts/pack-check.ts');
  const root = mkdtempSync(join(tmpdir(), 'request-seal-orphan-pack-'));
  try {
    mkdirSync(join(root,'dist')); mkdirSync(join(root,'src'));
    writeFileSync(join(root,'package.json'), JSON.stringify({name:'request-seal-boundary-check', version:'0.0.0', files:['dist']}));
    writeFileSync(join(root,'dist/orphan.js'), 'export const orphan = true;');
    const packed = spawnSync('npm',['pack','--dry-run','--json','--ignore-scripts'],{cwd:root,encoding:'utf8'});
    assert.equal(packed.status,0,packed.stderr);
    const files = JSON.parse(packed.stdout)[0].files;
    assert.ok(files.some((file: {path:string})=>file.path==='dist/orphan.js'));
    assert.throws(()=>assertPackedSources(files, root), /Orphan packed file: dist\/orphan\.js/);
  } finally {rmSync(root,{recursive:true,force:true});}
});
test('building removes compiled output from deleted source files', () => {
  const root = mkdtempSync(join(tmpdir(), 'request-seal-clean-build-'));
  try {
    mkdirSync(join(root,'dist')); mkdirSync(join(root,'src')); mkdirSync(join(root,'scripts'));
    const pkg = JSON.parse(read('package.json'));
    writeFileSync(join(root,'package.json'), JSON.stringify({name:'request-seal-build-check', version:'0.0.0', type:'module',scripts:{build:pkg.scripts.build}}));
    symlinkSync(resolve('node_modules'),join(root,'node_modules'),'dir');
    if (existsSync('scripts/clean-dist.ts')) cpSync('scripts/clean-dist.ts',join(root,'scripts/clean-dist.ts'));
    writeFileSync(join(root,'tsconfig.build.json'), JSON.stringify({compilerOptions:{target:'es2024',module:'esnext',rootDir:'src',outDir:'dist',declaration:true,types:[]},include:['src/*.ts']}));
    writeFileSync(join(root,'src/current.ts'), 'export const current = true;');
    writeFileSync(join(root,'dist/orphan.js'), 'export const orphan = true;');
    const child=spawnSync('npm',['run','build'],{cwd:root,encoding:'utf8'}); assert.equal(child.status,0,child.stdout+child.stderr);
    assert.ok(existsSync(join(root,'dist/current.js'))); assert.equal(existsSync(join(root,'dist/orphan.js')),false);
  } finally {rmSync(root,{recursive:true,force:true});}
});

test('cleaning compiled output uses the script package root instead of the working directory', () => {
  const root = mkdtempSync(join(tmpdir(), 'request-seal-clean-root-'));
  try {
    const pkg = join(root, 'package'), elsewhere = join(root, 'elsewhere');
    mkdirSync(join(pkg, 'scripts'), {recursive: true}); mkdirSync(join(pkg, 'dist'));
    mkdirSync(join(elsewhere, 'dist'), {recursive: true});
    cpSync('scripts/clean-dist.ts', join(pkg, 'scripts/clean-dist.ts'));
    writeFileSync(join(elsewhere, 'dist/owned.txt'), 'caller-owned');
    writeFileSync(join(pkg, 'dist/stale.js'), 'stale');
    const prefix = Object.hasOwn(process.versions, 'deno') ? ['run', '--allow-read', '--allow-write'] : Object.hasOwn(process.versions, 'bun') ? ['run'] : ['--experimental-strip-types', '--no-warnings'];
    const child = spawnSync(process.execPath, [...prefix, join(pkg, 'scripts/clean-dist.ts')], {cwd: elsewhere, encoding: 'utf8'});
    assert.equal(child.status, 0, child.stdout + child.stderr);
    assert.ok(existsSync(join(elsewhere, 'dist/owned.txt')));
    assert.equal(existsSync(join(pkg, 'dist')), false);
  } finally {rmSync(root, {recursive: true, force: true});}
});
