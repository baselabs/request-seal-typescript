import assert from 'node:assert/strict';
import {X509Certificate} from 'node:crypto';
import {rootCertificates} from 'node:tls';
import {createServer} from 'node:net';
import {peer} from './discovery-peer.ts';
import {dnsPublisher} from './discovery-dns.ts';
import {Discovery, DiscoverySource} from '../../src/discovery/node.ts';
// The reference resolves IPv6 before IPv4. Both real listeners share a port;
// closing the TCP peer during the handshake supplies a connect-class failure.
const address = process.argv[2] === 'connect-first' ? '127.0.0.1' : '::1';
const other = address === '::1' ? '127.0.0.1' : '::1';
const accepted: string[] = [];
const tcp = createServer(socket => {accepted.push(other); socket.destroy();});
// The peer's ephemeral port can already be taken on the other family; pick a new one.
let p: Awaited<ReturnType<typeof peer>> | undefined;
for (let attempt = 0; attempt < 5 && !p; attempt++) {
  const candidate = await peer((_req, res) => res.end(), address);
  const bound = await new Promise<boolean>((done, fail) => {
    const refused = (error: NodeJS.ErrnoException) => error.code === 'EADDRINUSE' ? done(false) : fail(error);
    tcp.once('error', refused);
    tcp.listen({host: other, port: candidate.port, ipv6Only: true}, () => {tcp.removeListener('error', refused); done(true);});
  });
  if (bound) p = candidate; else await candidate.close();
}
assert.ok(p, 'no port was free on both loopback families after five attempts');
p.server.on('connection', () => accepted.push(address));
let dns: Awaited<ReturnType<typeof dnsPublisher>> | undefined;
const dog = setTimeout(() => {console.log('held');process.exit(3);}, 2000); dog.unref();
try {
  dns = await dnsPublisher();
  const source = DiscoverySource.create({type: 'jwks_uri', location: `https://localhost:${p.port}/keys`, permittedAddresses: ['::1', '127.0.0.1'], cacerts: [new Uint8Array(new X509Certificate(rootCertificates[0]!).raw)]});
  assert.ok(source.ok);
  const result = await Discovery.fetch(source.value, {dnsServers: [dns.server]});
  assert.deepEqual(result, {ok: false, error: {kind: 'discovery', reason: 'tls_failed', retryable: false}});
  assert.deepEqual(accepted, ['::1', '127.0.0.1'], 'reference resolver tries IPv6 before IPv4');
  assert.equal(p.connections, 1);
  assert.equal(p.requests, 0);
  assert.ok(dns.queries.includes(1));
  assert.ok(dns.queries.includes(28));
  console.log('tls_failed retryable=false connections=' + p.connections + ' order=' + accepted.join(','));
} finally {clearTimeout(dog); await dns?.close(); await new Promise<void>(done => tcp.close(() => done())); await p!.close();}
