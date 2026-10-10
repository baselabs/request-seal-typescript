import test from 'node:test';
import assert from 'node:assert/strict';
import {connect} from 'node:tls';
import {readFileSync} from 'node:fs';
import {selectRuntimeLimits} from '../tools/conformance/runtime-limits.ts';
import {Discovery, DiscoverySource} from '../src/discovery/node.ts';
import {peer, jwks} from './support/discovery-peer.ts';
test('declared native HTTPS limitations remain observable against a trusted real peer', async t => {
  const limits = selectRuntimeLimits(JSON.parse(readFileSync('tools/conformance/runtime-limits.json', 'utf8')), process.versions).filter(entry => entry.id.startsWith('test_file/'));
  if (!limits.length) {t.skip('This exact runtime has no declared HTTPS limitation'); return;}
  const p = await peer((_request, response) => {response.setHeader('content-type', 'application/json'); response.end(jwks());});
  try {
    const socket = connect({host: '127.0.0.1', port: p.port, ca: '-----BEGIN CERTIFICATE-----\n' + Buffer.from(p.ca).toString('base64') + '\n-----END CERTIFICATE-----'});
    try {await new Promise<void>((resolve, reject) => {socket.once('secureConnect', resolve); socket.once('error', reject);}); assert.equal(socket.authorized, true);}
    finally {socket.destroy();}
    const s = DiscoverySource.create({type: 'jwks_uri', location: `https://127.0.0.1:${p.port}/keys`, cacerts: [p.ca], permittedAddresses: ['127.0.0.1']}); assert.ok(s.ok);
    const fetched = await Discovery.fetch(s.value); assert.equal(fetched.ok, false);
    if (!fetched.ok) for (const limit of limits) assert.equal(fetched.error.kind + '/' + fetched.error.reason, limit.observed, limit.id);
  } finally {await p.close();}
});
