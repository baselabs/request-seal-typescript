import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {cp, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {CORPUS_PIN} from '../src/constants.ts';
const repository = 'baselabs/request_seal';
const sha256 = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
async function inventory(root: string, path = ''): Promise<string[]> {
  const files: string[] = [];
  for (const entry of await readdir(join(root, path), {withFileTypes: true})) {
    const relative = path ? `${path}/${entry.name}` : entry.name;
    if (entry.isDirectory()) files.push(...await inventory(root, relative));
    else if (entry.isFile()) files.push(relative);
    else throw new Error('nonregular_archive_entry');
  }
  return files.sort();
}
async function main(): Promise<void> {
  const args = process.argv.slice(2), tag = args[0], update = args[1] === '--update-pin';
  if (!tag || !/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$/.test(tag) || args.length !== (update ? 2 : 1)) throw new Error('Usage: vendor-corpus <tag> [--update-pin]');
  const temporary = await mkdtemp(join(tmpdir(), 'request-seal-release-'));
  let stage: string | undefined;
  try {
    for (const asset of ['corpus.tar.gz', 'corpus.sha256']) {
      const response = await fetch(`https://github.com/${repository}/releases/download/${tag}/${asset}`, {signal: AbortSignal.timeout(30000)});
      if (!response.ok) throw new Error('release_asset_unavailable');
      await writeFile(join(temporary, asset), new Uint8Array(await response.arrayBuffer()));
    }
    const checksum = await readFile(join(temporary, 'corpus.sha256'), 'utf8');
    const match = /^([a-f0-9]{64}) [ *]corpus\.tar\.gz\n?$/.exec(checksum);
    if (!match || sha256(await readFile(join(temporary, 'corpus.tar.gz'))) !== match[1]) throw new Error('asset_checksum_mismatch');
    console.log('corpus.tar.gz: OK');
    const archive = join(temporary, 'corpus.tar.gz');
    const names = execFileSync('tar', ['-tzf', archive], {encoding: 'utf8'}).trimEnd().split('\n');
    const seen = new Set<string>();
    for (const name of names) {
      const path = name.replace(/\/$/, '');
      if (!(path === 'index.json' || path === 'sources' || path === 'cases' || /^(sources|cases)\/[A-Za-z0-9_.\/-]+$/.test(path)) || path.split('/').some(p => !p || p === '.' || p === '..') || seen.has(path)) throw new Error('unsafe_archive_path');
      seen.add(path);
    }
    const types = execFileSync('tar', ['-tvzf', archive], {encoding: 'utf8'}).trimEnd().split('\n');
    if (types.length !== names.length || types.some(line => !['-', 'd'].includes(line[0]!))) throw new Error('nonregular_archive_entry');
    const extracted = join(temporary, 'extracted'); await mkdir(extracted);
    execFileSync('tar', ['-xzf', archive, '-C', extracted]);
    const rawIndex = await readFile(join(extracted, 'index.json')), indexSha256 = sha256(rawIndex);
    const refs = execFileSync('git', ['ls-remote', `https://github.com/${repository}.git`, `refs/tags/${tag}`, `refs/tags/${tag}^{}`], {encoding: 'utf8', timeout: 30000}).trim().split('\n').map(line => line.split('\t'));
    const commit = (refs.find(([, name]) => name === `refs/tags/${tag}^{}`) ?? refs.find(([, name]) => name === `refs/tags/${tag}`))?.[0] ?? '';
    if (!/^[a-f0-9]{40}$/.test(commit)) throw new Error('invalid_release_commit');
    if (update) {
      const response = await fetch(`https://raw.githubusercontent.com/${repository}/${commit}/corpus/index.json`, {signal: AbortSignal.timeout(30000)});
      if (!response.ok) throw new Error('committed_index_unavailable');
      const committedIndex = Buffer.from(await response.arrayBuffer());
      if (!rawIndex.equals(committedIndex)) throw new Error('release_index_commit_mismatch');
      console.log('index.json: commit bytes match');
    }
    if (!update && (tag !== CORPUS_PIN.tag || commit !== CORPUS_PIN.commit || indexSha256 !== CORPUS_PIN.indexSha256)) throw new Error('index_pin_mismatch');
    const index = JSON.parse(rawIndex.toString('utf8'));
    if (index.elixir_release !== tag || index.format !== 'request-seal-conformance-corpus-index/1' || !Array.isArray(index.files)) throw new Error('invalid_release_index');
    const observed = await inventory(extracted), listed = ['index.json'];
    for (const file of index.files) {
      if (typeof file.path !== 'string' || !/^(sources|cases)\/[A-Za-z0-9_.\/-]+$/.test(file.path) || file.path.split('/').some((p: string) => !p || p === '.' || p === '..') || listed.includes(file.path) || !/^[a-f0-9]{64}$/.test(file.sha256)) throw new Error('invalid_file_inventory');
      if (sha256(await readFile(join(extracted, file.path))) !== file.sha256) throw new Error('file_digest_mismatch');
      listed.push(file.path);
    }
    if (JSON.stringify(observed) !== JSON.stringify(listed.sort())) throw new Error('unlisted_or_missing_file');
    const constants = resolve('src/constants.ts'), oldConstants = await readFile(constants, 'utf8');
    const line = oldConstants.split('\n').find(line => line.startsWith('export const CORPUS_PIN = '));
    if (!line) throw new Error('pin_declaration_not_found');
    const newConstants = oldConstants.replace(line, `export const CORPUS_PIN = Object.freeze({tag: '${tag}', commit: '${commit}', indexSha256: '${indexSha256}'});`);
    if (!update || newConstants === oldConstants) {
      console.log(`Verified ${index.files.length} files from ${tag} (${commit}); working tree unchanged.`);
      return;
    }
    // Replace the inventory only when its declared pin changes.
    stage = await mkdtemp(resolve('.corpus-vendor-'));
    await cp(extracted, join(stage, 'next'), {recursive: true});
    let existed = false;
    try {await lstat(resolve('conformance')); existed = true;} catch (e) {if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;}
    if (existed) await rename(resolve('conformance'), join(stage, 'previous'));
    try {
      await rename(join(stage, 'next'), resolve('conformance'));
      if (update) await writeFile(constants, newConstants);
    } catch (e) {
      await rm(resolve('conformance'), {recursive: true, force: true});
      if (existed) await rename(join(stage, 'previous'), resolve('conformance'));
      if (update) await writeFile(constants, oldConstants);
      throw e;
    }
    console.log(`index.json: ${indexSha256}`);
    console.log(`Vendored ${index.files.length} files from ${tag} (${commit}); ${update ? 'pin updated' : 'pin verified'}. Review the bytes and pin together.`);
  } finally {
    if (stage) await rm(stage, {recursive: true, force: true});
    await rm(temporary, {recursive: true, force: true});
  }
}
main().catch(e => {console.error(e instanceof Error ? e.message : 'corpus_vendoring_failed'); process.exitCode = 1;});
