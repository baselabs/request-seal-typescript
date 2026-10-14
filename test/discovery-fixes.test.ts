import { X509Certificate } from "node:crypto";
import nodeTest from 'node:test';
import {runtimeTest} from './support/discovery-runtime.ts';
const test = runtimeTest(nodeTest, 'discovery-fixes.test.ts');
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as tls from 'node:tls';
import { createSocket } from 'node:dgram';
import { Discovery, DiscoverySource, createCache, withDeadline, run, ok, Custody, type Result } from '../src/index.ts';
import { Discovery as NodeDiscovery, DiscoverySource as NodeSource } from '../src/discovery/node.ts';
import { bodyKeys } from '../src/discovery/body.ts';
import { peer, jwk, jwks, kid } from './support/discovery-peer.ts';
const bytes = (s: string) => new TextEncoder().encode(s);
const headers = [['content-type', 'application/json']] as const;
function value<T>(r: Result<T>): T { assert.equal(r.ok, true, JSON.stringify(r)); return (r as {ok:true;value:T}).value; }
function reason(r: Result<unknown>, why: string) { assert.equal(r.ok, false); if (!r.ok) assert.equal(r.error.reason, why); }
const source = (more = {}) => value(DiscoverySource.create({type:'jwks_uri', location:'https://agent.example/keys', ...more}));
const snapshot = (s: unknown, now: number) => Discovery.resolver.fromSnapshot(s, bytes(jwks()), now, headers);
const read = (p: string) => readFileSync(p, 'utf8');
test('status-derived retryability at the real TLS entry point', async () => {
  const fixture = JSON.parse(read('test/fixtures/elixir-reasons-0a6568a.json'));
  assert.equal(fixture.modules.find((m: {kind:string})=>m.kind==='discovery').retryable.rules.unexpected_status.kind, 'status-derived (5xx)');
  let status = 200;
  const p = await peer((_q,r) => { r.writeHead(status, {'content-type':'application/json'}); r.end(); });
  try { for (const code of [500,503,599,400,404,499]) {
    status = code;
    const s = value(DiscoverySource.create({type:'jwks_uri', location:`https://127.0.0.1:${p.port}/keys`, cacerts:[p.ca], permittedAddresses:['127.0.0.1']}));
    const r = await NodeDiscovery.fetch(s); reason(r, 'unexpected_status');
    assert.equal(!r.ok && 'retryable' in r.error && r.error.retryable, code >= 500, String(code));
  }} finally { await p.close(); }
});
test('chunk-extension amplification and aggregate TLS plaintext are bounded', async () => {
  const p = await peer((_q,r) => { r.setHeader('content-type','application/json'); r.end(jwks()); });
  // This publisher speaks HTTP/1 directly on its actual TLS sockets.
  p.server.removeAllListeners('request');
  let extension = 16000;
  p.server.on('secureConnection', socket => {
    socket.on('error', () => {});
    socket.once('data', () => {
      socket.write('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n');
      let count = 0;
      const pump = () => { while (count++ < 2000 && !socket.destroyed) {
        if (!socket.write(`1;${'a'.repeat(extension)}\r\n \r\n`)) { socket.once('drain', pump); return; }
      } if (!socket.destroyed) socket.end(`${jwks().length.toString(16)}\r\n${jwks()}\r\n0\r\n\r\n`); };
      pump();
    });
  });
  try { for (extension of [16000, 1000]) {
    const s = value(DiscoverySource.create({type:'jwks_uri', location:`https://127.0.0.1:${p.port}/keys`, cacerts:[p.ca], permittedAddresses:['127.0.0.1'], maxBytes:3000}));
    reason(await NodeDiscovery.fetch(s), 'limit');
  }} finally {await p.close();}
});
for (const status of [100,101,103]) test(`first ${status} status rejects and closes TLS`, async () => {
  const p = await peer((_q,r) => { if (status === 103) r.writeEarlyHints({link:'</x>; rel=preload'}); else if (status === 100) r.writeContinue(); else {r.writeHead(101, {Connection:'Upgrade',Upgrade:'websocket'}); r.flushHeaders(); return;} r.setHeader('content-type','application/json'); r.end(jwks()); });
  try { const s = value(DiscoverySource.create({type:'jwks_uri',location:`https://127.0.0.1:${p.port}/keys`,cacerts:[p.ca],permittedAddresses:['127.0.0.1'],timeoutMs:150})); reason(await NodeDiscovery.fetch(s),'unexpected_status'); }
  finally {await p.close();}
});
test('future and rolled-back snapshots reject without replacing the held set', async () => {
  const s = source(), c = value(createCache({clock:()=>120}));
  try { value(await c.refresh(s, value(await snapshot(s,110))));
    reason(await c.refresh(s,value(await snapshot(s,100))), 'invalid_options');
    reason(await c.refresh(s,value(await snapshot(s,121))), 'invalid_options');
    assert.equal(value(await c.resolve(s,kid)).fetchedAt,110);
    value(await c.refresh(s,value(await snapshot(s,120))));
  } finally {c.close();}
});
test('OS trust rejects an untrusted TLS peer or refuses an unavailable system store', async () => {
  const system = typeof tls.getCACertificates === 'function' ? tls.getCACertificates('system') : [];
  const supported = system.length > 0;
  console.log(`OS trust branch: ${supported ? 'non-empty system store; tls_failed' : 'system store absent or empty; transport_unavailable'}`);
  const p = await peer((_q,r) => {r.setHeader('content-type','application/json');r.end(jwks());});
  try {
    const input = {type:'jwks_uri',location:`https://127.0.0.1:${p.port}/keys`,cacerts:'os',permittedAddresses:['127.0.0.1']};
    const created = NodeSource.create(input);
    if (supported) value(created);
    else {reason(created,'transport_unavailable'); if (!created.ok) assert.equal(created.error.kind,'discovery');}
    const fetched = await NodeDiscovery.fetch(value(DiscoverySource.create(input)));
    reason(fetched, supported ? 'tls_failed' : 'transport_unavailable');
    if (!supported && !fetched.ok) assert.equal(fetched.error.kind,'discovery');
    assert.equal(p.requests,0);
    assert.equal(p.connections,supported ? 1 : 0);
  } finally {await p.close();}
});
test('redirect dot segments resolve before source vetting', async () => {
  let target = '../keys';
  const p=await peer((q,r)=>{ if(q.url==='/keys'){r.setHeader('content-type','application/json');r.end(jwks());} else {r.writeHead(302,{location:target});r.end();} });
  try {for(target of ['../keys','./../keys','/a/../keys']) {
    const s=value(DiscoverySource.create({type:'jwks_uri',location:`https://127.0.0.1:${p.port}/a/start`,cacerts:[p.ca],permittedAddresses:['127.0.0.1'],maxRedirects:1}));
    assert.equal(value(await NodeDiscovery.fetch(s)).keys[kid]!.location,`https://127.0.0.1:${p.port}/keys`);
  }} finally {await p.close();}
});
test('real silent DNS resolver reaches deadline_exceeded',async()=>{
  const socket=createSocket('udp4'); await new Promise<void>(done=>socket.bind(0,'127.0.0.1',done));
  try {const s=source({location:'https://directory.test/keys',timeoutMs:30,cacerts:[new Uint8Array(new X509Certificate(tls.rootCertificates[0]!).raw)]}); reason(await NodeDiscovery.fetch(s,{dnsServers:[`127.0.0.1:${socket.address().port}`]}),'deadline_exceeded');}
  finally {socket.close();}
});
test('default lookup fetches the real localhost peer twice',async()=>{
  const p=await peer((_q,r)=>{r.setHeader('content-type','application/json');r.end(jwks());});
  try {const s=value(DiscoverySource.create({type:'jwks_uri',location:`https://localhost:${p.port}/keys`,cacerts:[p.ca],permittedAddresses:['127.0.0.1','::1']}));
    value(await NodeDiscovery.fetch(s)); value(await NodeDiscovery.fetch(s)); assert.equal(p.requests,2);
  }finally{await p.close();}
});


test('cancellation stops the real multi-key import loop', async () => {
  const s = source({keyId:'directory',maxKeys:128});
  const caller = new AbortController(), c = value(withDeadline({signal:caller.signal}));
  let reads = 0;
  const doc = {keys:Array.from({length:128},(_,i)=>({...jwk, get kid(){
    reads++; if(reads === 1) setTimeout(()=>caller.abort(),0); return `key-${i}`;
  }}))};
  const r = await run(c,async()=>ok(await bodyKeys(doc,s,100,s.location,c)));
  reason(r,'deadline_exceeded'); const stopped = reads;
  await new Promise(done=>setTimeout(done,100));
  assert.equal(reads,stopped,'key imports continued after cancellation returned');
  assert.ok(reads < 128);
});
test('actual custody import failure is bounded by the cache',async()=>{
  const s=source(); const cache=value(createCache({clock:()=>100,fetch:async()=>{
    const imported=await Custody.local('ed25519',new Uint8Array([1,2,3]));
    assert.equal(imported.ok,false);
    if (imported.ok) throw new Error('Expected custody rejection');
    assert.equal(imported.error.kind,'custody');
    return imported;
  }}));
  try{reason(await cache.resolve(s,kid),'source_unavailable');}finally{cache.close();}
});
test('snapshot time guards preserve the real fetch caller clock', async () => {
  const p = await peer((_q,r)=>{r.setHeader('content-type','application/json');r.end(jwks());});
  const s = value(DiscoverySource.create({type:'jwks_uri',location:`https://127.0.0.1:${p.port}/keys`,cacerts:[p.ca],permittedAddresses:['127.0.0.1']}));
  const cache = value(createCache({clock:()=>100,fetch:NodeDiscovery.fetch}));
  try {assert.equal(value(await cache.resolve(s,kid,{clock:()=>110})).fetchedAt,110);}
  finally {cache.close();await p.close();}
});

for (const lineBytes of [1022,1023]) test(`chunk line of ${lineBytes} bytes counts its CRLF toward the limit`, async () => {
  const p = await peer((_q,r)=>r.end());
  p.server.removeAllListeners('request');
  p.server.on('secureConnection', socket => {
    socket.on('error',()=>{});
    socket.once('data',()=>{
      const body = jwks(), digits = body.length.toString(16);
      const line = `${digits};${'a'.repeat(lineBytes-digits.length-1)}`;
      assert.equal(Buffer.byteLength(line),lineBytes);
      socket.end(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n${line}\r\n${body}\r\n0\r\n\r\n`);
    });
  });
  try {
    const s=value(DiscoverySource.create({type:'jwks_uri',location:`https://127.0.0.1:${p.port}/keys`,cacerts:[p.ca],permittedAddresses:['127.0.0.1']}));
    const r=await NodeDiscovery.fetch(s);
    if(lineBytes===1022) assert.ok(value(r).keys[kid]); else reason(r,'limit');
  } finally {await p.close();}
});

test('real TLS peer mismatches prohibit connection retry', async () => {
  const {checkPeer, allowConnectionRetry} = await import('../src/discovery/node-connection.ts');
  const p = await peer((_q,r)=>r.end());
  let socket: tls.TLSSocket | undefined;
  try {
    socket = tls.connect({host:'127.0.0.1',port:p.port,ca:`-----BEGIN CERTIFICATE-----\n${Buffer.from(p.ca).toString('base64')}\n-----END CERTIFICATE-----`});
    await new Promise<void>((done,fail)=>{socket!.once('secureConnect',done);socket!.once('error',fail);});
    const observed = {address:socket.remoteAddress,port:socket.remotePort};
    assert.doesNotThrow(()=>checkPeer(observed,'127.0.0.1',p.port,['127.0.0.1']));
    for(const [ip,port,allowed] of [['127.0.0.2',p.port,['127.0.0.1']],['127.0.0.1',p.port+1,['127.0.0.1']],['127.0.0.1',p.port,[]]] as const) {
      let denial: unknown;
      try {checkPeer(observed,ip,port,allowed);} catch(error) {denial=error;}
      assert.ok(denial && typeof denial==='object' && 'reason' in denial && denial.reason==='address_denied');
      assert.throws(()=>allowConnectionRetry(denial),error=>error===denial);
    }
  } finally {socket?.destroy();await p.close();}
});

test('peer close during a real TLS handshake is a retryable connect failure', async () => {
  const {createServer} = await import('node:net');
  let accepted = 0;
  const listener = createServer(socket => {accepted++; socket.destroy();});
  await new Promise<void>(resolve => listener.listen(0, '127.0.0.1', resolve));
  const bound = listener.address(); assert.ok(bound && typeof bound === 'object');
  try {
    const s = source({location: `https://127.0.0.1:${bound.port}/keys`, permittedAddresses: ['127.0.0.1'], cacerts: [new Uint8Array(new X509Certificate(tls.rootCertificates[0]!).raw)]});
    const result = await NodeDiscovery.fetch(s);
    assert.equal(accepted, 1, 'the actual TLS handshake contacted the listener');
    assert.deepEqual(result, {ok: false, error: {kind: 'discovery', reason: 'connect_failed', retryable: true}});
  } finally {await new Promise<void>(resolve => listener.close(() => resolve()));}
});

for (const order of ['tls-first', 'connect-first']) test(`address retries preserve a TLS failure with ${order} ordering`, {timeout: 15_000}, async () => {
  const {spawnWithEnvSync: spawnSync} = await import('./support/child-env.ts');
  const prefix = Object.hasOwn(process.versions, 'deno') ? ['run', '--no-check', '--allow-all'] : Object.hasOwn(process.versions, 'bun') ? ['run'] : ['--experimental-strip-types', '--no-warnings'];
  const env = {...process.env}; delete env.NODE_TEST_CONTEXT;
  const child = spawnSync(process.execPath, [...prefix, 'test/support/discovery-address-order.ts', order], {env, encoding: 'utf8', timeout: 10_000});
  assert.equal(child.status, 0, child.stdout + child.stderr);
  assert.equal(child.stdout, 'tls_failed retryable=false connections=1 order=::1,127.0.0.1\n');
});
test('an IP-literal source requires that exact IP in the certificate, on IPv4 and IPv6', async () => {
  // Each peer listens on one loopback address but its certificate names only the other one.
  for (const [address, altNames, host] of [['::1', 'DNS:localhost,IP:127.0.0.1', '[::1]'], ['127.0.0.1', 'DNS:localhost,IP:::1', '127.0.0.1']] as const) {
    const p = await peer((_q,r) => {r.setHeader('content-type','application/json');r.end(jwks());}, address, altNames);
    try {
      const s = value(NodeSource.create({type:'jwks_uri',location:`https://${host}:${p.port}/keys`,cacerts:[p.ca],permittedAddresses:[address]}));
      reason(await NodeDiscovery.fetch(s), 'tls_failed');
      assert.equal(p.requests, 0, `${address}: no HTTP bytes after a certificate that does not name it`);
    } finally {await p.close();}
  }
});
