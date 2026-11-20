import nodeTest from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server, type ServerResponse } from 'node:http';
import { once } from 'node:events';
import { connect } from 'node:net';
import { Custody, Policy, ok, withDeadline, type Result, type KeyHandle } from '../src/index.ts';
import { nodeAdapterTest } from './support/node-adapter-test.ts';
import * as fetchAdapter from '../src/adapters/fetch/index.ts';
import * as nodeAdapter from '../src/adapters/node-http/index.ts';
function value<T>(r: Result<T>): T { assert.ok(r.ok, JSON.stringify(r)); return r.value; }
async function listen(server: Server): Promise<string> {
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const address = server.address(); assert.ok(address && typeof address === 'object');
  return `http://127.0.0.1:${address.port}`;
}
async function close(server: Server): Promise<void> {
  if (!server.listening) {server.closeAllConnections(); return;}
  const done = new Promise<void>((resolve, reject) => server.close(e => e ? reject(e) : resolve()));
  server.closeAllConnections(); await done;
}
// Waits until a new connection to the port is refused, so a later attempt cannot reach the peer
// on any runtime, whatever its listener's close timing.
async function refusedAt(port: number): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt++) {
    const code = await new Promise<string>(resolve => {
      const socket = connect(port, '127.0.0.1');
      socket.once('connect', () => {socket.destroy(); resolve('open');});
      socket.once('error', (error: NodeJS.ErrnoException) => resolve(error.code ?? 'error'));
    });
    if (code === 'ECONNREFUSED') return;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.fail('the closed listener still accepts connections');
}
async function withPeer(server: Server, check: (url: string, key: KeyHandle) => Promise<void>): Promise<void> {
  const key = value(await Custody.local('hmac-sha256', {hmac: crypto.getRandomValues(new Uint8Array(32))}));
  try {await check(await listen(server), key);}
  finally {await key.release(); await close(server);}
}
const spec = {label: 'sig', components: '("@method")', algorithm: 'hmac-sha256', expiresIn: 60};
const nativeNode = !process.versions.bun && !(globalThis as {Deno?: unknown}).Deno;
const denoVersion = (globalThis as {Deno?: {version?: {deno?: string}}}).Deno?.version?.deno;
const fetchVerification = (fetchAdapter.FETCH_VERIFICATION_RUNTIMES as readonly string[]).includes(`deno:${denoVersion}`);
const nodeHTTPTest = nodeAdapterTest(import.meta.url);
for (const name of ['fetch', 'node-http'] as const) {
  const test = name === 'node-http' ? nodeHTTPTest : nodeTest;
  const classify = name === 'fetch' ? fetchAdapter.classify : nodeAdapter.classify;
  const other = name === 'fetch' ? nodeAdapter.classify : fetchAdapter.classify;
  const send = (url: string, signer: unknown, options: Record<string, unknown> = {}, request: {method?: string; body?: Uint8Array} = {}) => {
    const context = value(withDeadline({timeoutMs: 10000}));
    return name === 'fetch'
      ? fetchAdapter.signedFetch(url, request, {spec, signer}, {context, ...options})
      : nodeAdapter.signedRequest({url, context, ...request, ...options}, spec, signer);
  };
  for (const status of [200, 401, 500, 502, 504]) test(`${name} delivery classifies received ${status}`, async () => {
    let received = 0;
    await withPeer(createServer((_req, res) => {received++; res.writeHead(status).end();}), async (url, key) => {
      const result = await send(url, key);
      assert.ok(result.ok, JSON.stringify(result));
      assert.equal(received, 1, 'classification never retries');
      assert.equal(classify(result), status === 502 || status === 504 ? 'unknown' : 'answered');
      assert.equal(other(result), 'unknown');
      assert.equal(classify({...result}), 'unknown', 'a structural copy carries no delivery evidence');
      if ('response' in result.value) await result.value.response.body?.cancel();
    });
  });
  test(`${name} delivery refuses first attach and sign failures before a peer receives bytes`, async () => {
    let received = 0;
    await withPeer(createServer((_req, res) => {received++; res.end();}), async (url, key) => {
      for (const result of [await send(url, key, {unknown: true}), await send(url, {})]) {
        assert.ok(!result.ok); assert.equal(classify(result), 'refused');
        assert.equal(other(result), 'unknown');
      }
      assert.equal(received, 0);
    });
  });
  test(`${name} delivery uses runtime phase evidence for a first closed port and reserved DNS name`, async () => {
    const server = createServer(); const closed = await listen(server); await close(server);
    const key = value(await Custody.local('hmac-sha256', {hmac: crypto.getRandomValues(new Uint8Array(32))}));
    try {
      for (const url of [closed, 'http://delivery-canary.invalid/']) {
        const result = await send(url, key);
        assert.ok(!result.ok);
        assert.equal(classify(result), nativeNode ? 'refused' : 'unknown');
        assert.doesNotMatch(JSON.stringify(result), /delivery-canary|127\.0\.0\.1|ECONN|ENOTFOUND|stack/);
      }
    } finally {await key.release();}
  });
  // A hang fails this test by name instead of exhausting the lane's job limit.
  test(`${name} delivery keeps an open-connection reset and stalled peer unknown`, {timeout: 30_000}, async () => {
    let received = 0;
    const stalled: ServerResponse[] = [];
    await withPeer(createServer((req, res) => {received++; if (req.url === '/reset') req.socket.destroy(); else stalled.push(res);}), async (url, key) => {
      try {
        for (const path of ['/reset', '/stall']) {
          const result = await send(url + path, key, {context: value(withDeadline({timeoutMs: 2000}))});
          assert.ok(!result.ok); assert.equal(classify(result), 'unknown');
          assert.doesNotMatch(JSON.stringify(result), /stack|ECONN|socket hang up/);
        }
        assert.equal(received, 2, 'both failures followed real request bytes');
      } finally {
        // Deno's node:http close waits for in-flight requests; the stalled one ends only after the client gave up.
        for (const res of stalled) res.end();
      }
    });
  });
  test(`${name} delivery keeps failed response verification unknown`, async () => {
    let received = 0;
    await withPeer(createServer((_req, res) => {received++; res.end();}), async (url, key) => {
      const policy = value(Policy.create({algorithms: ['hmac-sha256'], components: '("@status")',
        keyResolver: () => ok({algorithm: 'hmac-sha256', key}), freshness: 'not_evaluated',
        content: 'not_required', replay: 'not_required'}));
      const result = await send(url, key, {verify: {policy, label: 'sig'}});
      assert.ok(!result.ok);
      assert.equal(classify(result), 'unknown');
      assert.equal(received, name === 'fetch' && !fetchVerification ? 0 : 1);
      assert.equal(result.error.kind, 'adapter');
      if (result.error.kind === 'adapter') assert.equal(result.error.stage, 'verify');
    });
  });
  test(`${name} delivery does not trust a response capture failure`, async () => {
    await withPeer(createServer((_req, res) => res.end('received')), async (url, key) => {
      const result = await send(url, key, {maxBytes: 0});
      assert.equal(classify(result), name === 'node-http' ? 'unknown' : 'answered');
      if (name === 'node-http') assert.equal(result.ok, false);
      if (result.ok && 'response' in result.value) await result.value.response.body?.cancel();
    });
  });
  for (const allowed of [false, true]) test(`${name} delivery keeps a POST 303 ${allowed ? 'followed by DNS failure' : 'to a disallowed origin'} unknown`, async () => {
    const methods: string[] = [];
    await withPeer(createServer((req, res) => {methods.push(req.method!); req.resume();
      res.writeHead(303, {location: 'http://delivery-canary.invalid/'}).end();}), async (url, key) => {
      const result = await send(url, key, {maxRedirects: 1,
        ...(allowed ? {allowedOrigins: ['http://delivery-canary.invalid']} : {})},
        {method: 'POST', body: new Uint8Array([1, 2, 3])});
      assert.deepEqual(methods, ['POST']);
      assert.ok(!result.ok); assert.equal(classify(result), 'unknown');
      assert.equal(result.error.kind, 'adapter');
      if (result.error.kind === 'adapter') {
        assert.equal(result.error.attempt, allowed ? 2 : 1);
        if (!allowed) assert.equal(result.error.reason, 'cross_origin_redirect');
      }
    });
  });
  test(`${name} delivery keeps a 503 retry with a refused second connection unknown`, async () => {
    let received = 0;
    const server = createServer(async (req, res) => {
      received++; req.resume();
      const {port} = server.address() as {port: number};
      server.close(); await refusedAt(port);
      // The answering connection ends with the response, so no attempt can reuse it.
      res.writeHead(503, {connection: 'close'}).end(() => req.socket.destroy());
    });
    await withPeer(server, async (url, key) => {
      const result = await send(url, key, {maxRetries: 1});
      assert.ok(!result.ok); assert.equal(classify(result), 'unknown');
      assert.equal(received, 1, 'the first peer really answered before closing its listener');
      assert.equal(result.error.kind, 'adapter');
      if (result.error.kind === 'adapter') assert.equal(result.error.attempt, 2);
    });
  });
  test(`${name} delivery rejects unrelated and adversarial result shapes without reading them`, () => {
    for (const result of [null, undefined, 1, 'answered', {}, {ok:true,value:{status:200}},
      {ok:false,error:{kind:'adapter',adapter:name,stage:'sign'}},
      Object.defineProperty({}, 'ok', {get() {assert.fail('classifier read caller shape');}})]) {
      assert.equal(classify(result), 'unknown');
    }
  });
}
