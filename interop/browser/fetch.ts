import test from './harness.ts';
import assert from './assert.ts';
import * as Seal from '../../dist/index.js';
import {signRequest, verifyRequest, verifyResponse, signedFetch} from '../../dist/adapters/fetch/index.js';
function value<T>(r: Seal.Result<T>): T { if (!r.ok) assert.fail(`${r.error.kind}/${r.error.reason}`); return r.value; }
const payload = () => crypto.getRandomValues(new Uint8Array(257));
export function registerFetchTests(origin: string): void {
test('Fetch signing returns bytes authenticated by the built core', async () => {
  const owner = value(await Seal.Custody.local('hmac-sha256', {hmac: crypto.getRandomValues(new Uint8Array(32))}));
  try {
    const bytes = payload();
    const request = new Request(origin + '/signed#fragment', {method: 'POST', body: bytes});
    const result = await signRequest(request,
      {label: 'sig', components: '("@method" "@path")', algorithm: 'hmac-sha256', expiresIn: 60}, owner);
    assert.equal(result.ok, true, "POST body signing must succeed");
    if (!result.ok) return;
    const signed = result.value;
    assert.equal(signed.request.url.includes('#'), false);
    assert.deepEqual(new Uint8Array(await signed.request.arrayBuffer()), bytes);
    const policy = value(Seal.Policy.create({algorithms: ['hmac-sha256'], keyResolver: () => Seal.ok({algorithm: 'hmac-sha256', key: owner}), components: '("@method" "@path")', freshness: 'not_evaluated', content: 'not_required', replay: 'not_required'}));
    assert.equal((await Seal.verify(signed.message, policy, {label: 'sig'})).ok, true);
  } finally {await owner.release();}
});

test('browser empty-query Fetch signing preserves the target', async () => {
  const owner = value(await Seal.Custody.local('hmac-sha256', {hmac: crypto.getRandomValues(new Uint8Array(32))}));
  try {
    const request = new Request(origin + '/empty?');
    const result = await signRequest(request, {label: 'sig', components: '("@request-target")', algorithm: 'hmac-sha256', expiresIn: 60}, owner);
    assert.equal(result.ok, true);
    if (result.ok) assert.equal(result.value.message.rawTarget, '/empty?');
  } finally {await owner.release();}
});

for (const method of ['GET', 'POST']) test(`browser Fetch signing accepts bodyless ${method}`, async () => {
  const owner = value(await Seal.Custody.local('hmac-sha256', {hmac: crypto.getRandomValues(new Uint8Array(32))}));
  try {
    const signed = value(await signRequest(new Request(origin + '/bodyless', {method}),
      {label: 'sig', components: '("@method" "@path")', algorithm: 'hmac-sha256', expiresIn: 60}, owner));
    assert.equal((await signed.request.arrayBuffer()).byteLength, 0);
    assert.equal(signed.request.headers.has('signature'), true);
  } finally {await owner.release();}
});

test('browser signedFetch delivers an authenticated POST to the page server', async () => {
  const owner = value(await Seal.Custody.local('hmac-sha256', {hmac: crypto.getRandomValues(new Uint8Array(32))}));
  try {
    const result = value(await signedFetch(new Request(origin, {method: 'POST', body: payload()}), undefined,
      {spec: {label: 'sig', components: '("@method")', algorithm: 'hmac-sha256', expiresIn: 60}, signer: owner, signingTimeout: 30000}));
    assert.equal(result.response.status, 200);
    await result.response.arrayBuffer();
  } finally {await owner.release();}
});

test('browser Fetch body bounds reject materialized input over maxBytes', async () => {
  const owner = value(await Seal.Custody.local('hmac-sha256', {hmac: crypto.getRandomValues(new Uint8Array(32))}));
  try {
    const result = await signRequest(new Request(origin, {method: 'POST', body: payload()}),
      {label: 'sig', components: '("@method")', algorithm: 'hmac-sha256', expiresIn: 60}, owner, {maxBytes: 256});
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.error.reason, 'limit');
  } finally {await owner.release();}
});

test('browser Fetch verification refuses requests and responses before reading options', async () => {
  const options = Object.defineProperty({}, 'label', {get() {assert.fail('Ineligible browser read verification options');}});
  const results = [await verifyRequest(new Request(origin), {}, options), await verifyResponse(new Response('body'), {}, options)];
  for (const result of results) {
    assert.equal(result.ok, false);
    if (!result.ok) {assert.equal(result.error.kind, 'adapter'); assert.equal(result.error.reason, 'invalid_request');}
  }
});
test('browser Fetch verified delivery refuses an ineligible runtime', async () => {
  const owner = value(await Seal.Custody.local('hmac-sha256', {hmac: crypto.getRandomValues(new Uint8Array(32))}));
  try {
    const request = new Request(origin, {method: 'POST', body: payload()});
    const result = await signedFetch(request, undefined,
      {spec: {label: 'sig', components: '("@method")', algorithm: 'hmac-sha256', expiresIn: 60}, signer: owner},
      {verify: {policy: {}, label: 'sig'}});
    assert.equal(result.ok, false);
    if (!result.ok) {assert.equal(result.error.kind, 'adapter'); assert.equal(result.error.reason, 'invalid_request');}
    assert.equal(request.bodyUsed, false, 'Ineligible verification must refuse before consuming caller bytes');
  } finally {await owner.release();}
});
}
