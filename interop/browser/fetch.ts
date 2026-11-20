import test from './harness.ts';
import assert from './assert.ts';
import {assertObservation} from './limits.ts';
import * as Seal from '../../dist/index.js';
import {signRequest, verifyRequest, verifyResponse, signedFetch, classify} from '../../dist/adapters/fetch/index.js';
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
      {spec: {label: 'sig', components: '("@method")', algorithm: 'hmac-sha256', expiresIn: 60}, signer: owner}, {signingTimeout: 30000}));
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
    assert.equal(classify(result), 'unknown', 'a verify-stage refusal establishes no origin answer');
  } finally {await owner.release();}
});

test('browser delivery classification uses real statuses and transport peers', async () => {
  const owner = value(await Seal.Custody.local('hmac-sha256', {hmac: crypto.getRandomValues(new Uint8Array(32))}));
  const signing = {spec: {label: 'sig', components: '("@method")', algorithm: 'hmac-sha256', expiresIn: 60}, signer: owner};
  const send = (url: string, options = {}) => signedFetch(url, undefined, signing,
    {context: value(Seal.withDeadline({timeoutMs: 3000})), ...options});
  try {
    for (const status of [200, 401, 500, 502, 504]) {
      const result = await send(origin + '/__delivery/status/' + status);
      assert.ok(result.ok);
      assert.equal(classify(result), status === 502 || status === 504 ? 'unknown' : 'answered');
      if (result.ok) await result.value.response.body?.cancel();
      assert.equal(classify({...result}), 'unknown');
    }
    const attach = await send(origin, {unknown: true});
    assert.equal(attach.ok, false); assert.equal(classify(attach), 'refused');
    const sign = await signedFetch(origin, undefined, {...signing, signer: {}});
    assert.equal(sign.ok, false); assert.equal(classify(sign), 'refused');
    const info = await fetch(origin + '/__delivery/closed-port');
    const {port} = await info.json() as {port: number};
    for (const url of [`http://127.0.0.1:${port}/`, 'http://delivery-canary.invalid/', origin + '/__delivery/reset']) {
      const result = await send(url);
      assert.equal(result.ok, false); assert.equal(classify(result), 'unknown');
      assert.doesNotMatch(JSON.stringify(result), /delivery-canary|ECONN|stack/);
    }
    assert.equal(classify({ok: true, value: {response: {status: 200}}}), 'unknown');
  } finally {await owner.release();}
});

for (const allowed of [false, true]) test(`browser POST 303 ${allowed ? 'to an allowed .invalid target' : 'to a disallowed origin'} is opaque and remains unknown`, async () => {
  const owner = value(await Seal.Custody.local('hmac-sha256', {hmac: crypto.getRandomValues(new Uint8Array(32))}));
  try {
    const before = await (await fetch(origin + '/__delivery/redirect-count')).json() as {requests: number};
    const result = await signedFetch(origin + '/__delivery/redirect', {method: 'POST', body: payload()},
      {spec: {label: 'sig', components: '("@method")', algorithm: 'hmac-sha256', expiresIn: 60}, signer: owner},
      {context: value(Seal.withDeadline({timeoutMs: 10000})), maxRedirects: 1,
        ...(allowed ? {allowedOrigins: ['http://delivery-canary.invalid']} : {})});
    // Fetch's manual redirect response hides both the 303 status and Location,
    // even for a same-origin peer. No second signed hop can be constructed.
    const exchange = value(result);
    assert.equal(classify(result), 'unknown');
    assert.equal(exchange.response.type, 'opaqueredirect');
    assert.equal(exchange.response.status, 0);
    assert.equal(exchange.response.headers.get('location'), null);
    assert.equal(exchange.response.body, null);
    assert.equal(exchange.request.request.url, origin + '/__delivery/redirect');
    if (!allowed) assertObservation('fetch/manual_redirect', 'fetch/' + exchange.response.type);
    const after = await (await fetch(origin + '/__delivery/redirect-count')).json() as {requests: number; method: string};
    assert.equal(after.requests, before.requests + 1); assert.equal(after.method, 'POST');
  } finally {await owner.release();}
});

test('browser retry after a real 503 and closed listener remains unknown', async () => {
  const owner = value(await Seal.Custody.local('hmac-sha256', {hmac: crypto.getRandomValues(new Uint8Array(32))}));
  try {
    const peer = await (await fetch(origin + '/__delivery/retry-peer')).json() as {origin: string};
    const result = await signedFetch(peer.origin, undefined,
      {spec: {label: 'sig', components: '("@method")', algorithm: 'hmac-sha256', expiresIn: 60}, signer: owner},
      {context: value(Seal.withDeadline({timeoutMs: 10000})), maxRetries: 1});
    assert.equal(result.ok, false); assert.equal(classify(result), 'unknown');
    if (!result.ok) {assert.equal(result.error.kind, 'adapter'); if (result.error.kind === 'adapter') assert.equal(result.error.attempt, 2);}
    const counts = await (await fetch(origin + '/__delivery/retry-count?origin=' + encodeURIComponent(peer.origin))).json() as {requests: number};
    assert.equal(counts.requests, 1, 'the first peer received the request and answered 503');
  } finally {await owner.release();}
});

}
