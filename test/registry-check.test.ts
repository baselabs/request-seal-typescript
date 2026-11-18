import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {existingPackage, publicationPlan, registryURL, verifyReadBack} from '../scripts/registry-check.ts';

// Constructed response data exercises pure decisions; no registry or service is simulated.
const identity = {name: '@request-seal/core', version: '0.5.1'};
const archive = new TextEncoder().encode('inspected archive bytes');
const dist = {
  integrity: 'sha512-' + createHash('sha512').update(archive).digest('base64'),
  shasum: createHash('sha1').update(archive).digest('hex'),
  tarball: 'https://registry.npmjs.org/@request-seal/core/-/core-0.5.1.tgz',
};
const version = {...identity, dist};
const pkg = {name: identity.name, versions: {[identity.version]: version}, time: {[identity.version]: '2026-11-18T00:00:00Z'}};

test('an existing name and new version can stage; an identical published archive only reads back', () => {
  assert.equal(publicationPlan(identity, 200, {name: identity.name, versions: {'0.5.0': {name: identity.name, version: '0.5.0'}}}, archive), 'stage');
  assert.equal(publicationPlan(identity, 200, pkg, archive), 'read-back');
  for (const selected of [{integrity: dist.integrity}, {shasum: dist.shasum}]) {
    assert.equal(publicationPlan(identity, 200, {...pkg, versions: {[identity.version]: {...version, dist: {...selected, tarball: dist.tarball}}}}, archive), 'read-back');
  }
  assert.equal(publicationPlan(identity, 200, {...pkg, versions: {[identity.version]: {...version, deprecated: ''}}}, archive), 'read-back');
});

test('missing package names, unreadable metadata, and unpublished packages refuse before a version decision', () => {
  assert.throws(() => existingPackage(identity.name, 404, null), /@request-seal\/core.*first publication is the owner's decision/);
  for (const status of [401, 403, 429, 500, 503]) assert.throws(() => publicationPlan(identity, status, pkg, archive), /could not be read/);
  for (const document of [null, [], {}, {...pkg, name: 'other'}, {...pkg, versions: null}]) {
    assert.throws(() => publicationPlan(identity, 200, document, archive), /Invalid npm package metadata/);
  }
  assert.throws(() => existingPackage(identity.name, 200, {...pkg, versions: {}}), /has no published versions/);
  assert.throws(() => publicationPlan(identity, 200, {...pkg, time: {unpublished: {versions: [identity.version]}}}, archive), /is unpublished/);
  assert.throws(() => publicationPlan(identity, 200, {...pkg, versions: {'0.5.0': {}}}, archive), /was unpublished/);
});

test('deprecated, mismatched, or incomplete versions cannot be replaced', () => {
  for (const [mutation, reason] of [
    [{...version, deprecated: 'withdrawn'}, /is deprecated/],
    [{...version, name: 'other'}, /Invalid npm version metadata/],
    [{...version, version: '0.5.0'}, /Invalid npm version metadata/],
    [{...version, dist: null}, /Missing npm dist metadata/],
    [{...version, dist: {tarball: dist.tarball}}, /Missing npm archive digest/],
    [{...version, dist: {...dist, integrity: 'sha512-different'}}, /dist.integrity differs/],
    [{...version, dist: {...dist, shasum: 'different'}}, /dist.shasum differs/],
    [{...version, dist: {...dist, integrity: null}}, /dist.integrity differs/],
  ] as const) {
    assert.throws(() => publicationPlan(identity, 200, {...pkg, versions: {[identity.version]: mutation}}, archive), reason);
  }
  assert.throws(() => publicationPlan(identity, 200, pkg, new TextEncoder().encode('different bytes')), /dist.integrity differs/);
});

test('read-back checks actual bytes and refuses unsafe registry asset destinations', () => {
  assert.doesNotThrow(() => verifyReadBack(archive, archive.slice()));
  assert.throws(() => verifyReadBack(archive, archive.slice(1)), /served bytes differ/);
  const modified = archive.slice(); modified[0] = modified[0]! ^ 1;
  assert.throws(() => verifyReadBack(archive, modified), /served bytes differ/);
  assert.equal(registryURL(dist.tarball), dist.tarball);
  for (const url of [undefined, 'invalid', 'http://registry.npmjs.org/a', 'https://example.com/a', 'https://user:pass@registry.npmjs.org/a', dist.tarball + '?token=value', dist.tarball + '#fragment']) {
    assert.throws(() => registryURL(url));
  }
});
