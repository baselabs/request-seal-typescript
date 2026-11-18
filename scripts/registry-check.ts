import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync, appendFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';

export type Identity = Readonly<{name: string; version: string}>;
type Document = Record<string, unknown>;
const registry = 'https://registry.npmjs.org';
const record = (value: unknown): value is Document => value !== null && typeof value === 'object' && !Array.isArray(value);

/** Package absence is a different refusal from a version that has not been staged yet. */
export function existingPackage(name: string, status: number, document: unknown): Document {
  assert.notEqual(status, 404, `${name} has never been published to npm or is unpublished: this workflow publishes new versions of existing packages only. A first publication is the owner's decision.`);
  assert.equal(status, 200, `npm registry could not be read for ${name} (HTTP ${status})`);
  assert.ok(record(document) && document.name === name && record(document.versions), `Invalid npm package metadata for ${name}`);
  assert.ok(Object.keys(document.versions).length > 0, `${name} has no published versions: a first publication is the owner's decision.`);
  assert.ok(!record(document.time) || !Object.hasOwn(document.time, 'unpublished'), `${name} is unpublished`);
  return document;
}

export function registryURL(value: unknown): string {
  assert.equal(typeof value, 'string', 'Missing npm registry asset URL');
  const url = new URL(value as string);
  assert.equal(url.origin, registry, 'Asset must be served by the public npm registry');
  assert.ok(!url.username && !url.password && !url.hash && !url.search, 'Invalid npm registry asset URL');
  return url.href;
}

export function publicationPlan(identity: Identity, status: number, document: unknown, archive: Uint8Array): 'stage' | 'read-back' {
  const pkg = existingPackage(identity.name, status, document);
  const versions = pkg.versions as Document;
  if (!Object.hasOwn(versions, identity.version)) {
    assert.ok(!record(pkg.time) || !Object.hasOwn(pkg.time, identity.version), `${identity.name}@${identity.version} was unpublished; it cannot be replaced`);
    return 'stage';
  }
  const published = versions[identity.version];
  const label = `${identity.name}@${identity.version}`;
  assert.ok(record(published) && published.name === identity.name && published.version === identity.version, `Invalid npm version metadata for ${label}`);
  assert.ok(published.deprecated === undefined || published.deprecated === '', `${label} is deprecated`);
  assert.ok(record(published.dist), `Missing npm dist metadata for ${label}`);
  const {integrity, shasum, tarball} = published.dist;
  assert.ok(integrity !== undefined || shasum !== undefined, `Missing npm archive digest for ${label}`);
  if (integrity !== undefined) {
    const expected = 'sha512-' + createHash('sha512').update(archive).digest('base64');
    assert.equal(integrity, expected, `npm dist.integrity differs from the inspected archive for ${label}`);
  }
  if (shasum !== undefined) {
    assert.equal(shasum, createHash('sha1').update(archive).digest('hex'), `npm dist.shasum differs from the inspected archive for ${label}`);
  }
  registryURL(tarball);
  return 'read-back';
}

export function verifyReadBack(inspected: Uint8Array, served: Uint8Array): void {
  assert.equal(Buffer.compare(inspected, served), 0, 'npm served bytes differ from the inspected package.tgz');
}

async function packageMetadata(name: string): Promise<{status: number; document: unknown}> {
  const response = await fetch(`${registry}/${encodeURIComponent(name)}`, {signal: AbortSignal.timeout(30_000), cache: 'no-store', redirect: 'error'});
  return {status: response.status, document: response.status === 200 ? await response.json() : null};
}

async function asset(value: unknown): Promise<Uint8Array> {
  const response = await fetch(registryURL(value), {signal: AbortSignal.timeout(30_000), cache: 'no-store', redirect: 'error'});
  assert.equal(response.status, 200, 'npm registry asset read-back failed');
  return new Uint8Array(await response.arrayBuffer());
}

async function main(): Promise<void> {
  const mode = process.argv[2];
  assert.ok(mode === 'existing' || mode === 'plan' || mode === 'read-back', 'Expected existing, plan, or read-back');
  const identity = JSON.parse(readFileSync('package.json', 'utf8')) as Identity;
  const {status, document} = await packageMetadata(identity.name);
  existingPackage(identity.name, status, document);
  if (mode === 'existing') return;
  const archive = readFileSync('artifacts/package.tgz');
  const action = publicationPlan(identity, status, document, archive);
  const output = process.env.GITHUB_OUTPUT;
  assert.ok(output, 'GITHUB_OUTPUT is required');
  if (mode === 'plan') {
    appendFileSync(output, `action=${action}\n`);
    return;
  }
  if (action === 'stage') {
    // npm's OIDC tokens cannot list/view/download pending stages. Do not claim publication.
    console.log(`${identity.name}@${identity.version} is awaiting approval on npmjs.com; rerun this commit after approval for public read-back.`);
    appendFileSync(output, 'published=false\n');
    return;
  }
  const published = ((document as Document).versions as Document)[identity.version] as Document;
  const dist = published.dist as Document;
  verifyReadBack(archive, await asset(dist.tarball));
  writeFileSync('artifacts/registry.json', JSON.stringify({name: identity.name, version: identity.version, sourceCommit: process.env.GITHUB_SHA, dist}, null, 2) + '\n');
  if (dist.attestations !== undefined) {
    assert.ok(record(dist.attestations), 'Invalid npm attestations metadata');
    const provenance = await asset(dist.attestations.url);
    assert.ok(record(JSON.parse(new TextDecoder().decode(provenance))), 'Invalid npm provenance document');
    writeFileSync('artifacts/provenance.json', provenance);
  }
  appendFileSync(output, 'published=true\n');
  console.log(`Read back identical public bytes for ${identity.name}@${identity.version}; nothing was replaced.`);
}
if (process.argv[1] === fileURLToPath(import.meta.url)) main().catch(error => {
  console.error(error instanceof Error ? error.message : 'npm registry check failed');
  process.exitCode = 1;
});
