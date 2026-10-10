import assert from 'node:assert/strict';
import {X509Certificate} from 'node:crypto';
import {rootCertificates} from 'node:tls';
import {peer} from './discovery-peer.ts';
import {dnsPublisher} from './discovery-dns.ts';
import {Discovery, DiscoverySource} from '../../src/discovery/node.ts';
// The real DNS publisher returns IPv4 before IPv6. Move the TLS listener between
// those addresses to exercise TLS-first and connect-first without replacing DNS.
const address = process.argv[2] === 'connect-first' ? '::1' : '127.0.0.1';
const p = await peer((_req, res) => res.end(), address);
const dns = await dnsPublisher();
const dog = setTimeout(() => {console.log('held');process.exit(3);}, 2000); dog.unref();
try {
  const source = DiscoverySource.create({type: 'jwks_uri', location: `https://localhost:${p.port}/keys`, permittedAddresses: ['::1', '127.0.0.1'], cacerts: [new Uint8Array(new X509Certificate(rootCertificates[0]!).raw)]});
  assert.ok(source.ok);
  const result = await Discovery.fetch(source.value, {dnsServers: [dns.server]});
  assert.deepEqual(result, {ok: false, error: {kind: 'discovery', reason: 'tls_failed', retryable: false}});
  assert.equal(p.connections, 1);
  assert.equal(p.requests, 0);
  assert.ok(dns.queries.includes(1));
  assert.ok(dns.queries.includes(28));
  console.log('tls_failed retryable=false connections=' + p.connections);
} finally {clearTimeout(dog); await dns.close(); await p.close();}
