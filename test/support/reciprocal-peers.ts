import assert from 'node:assert/strict';
import {resolve} from 'node:path';
import {spawnPeer, requireHex} from './peer-process.ts';
import {peer} from './discovery-peer.ts';

export async function reciprocalPeers(signal: AbortSignal) {
  await requireHex({cwd: resolve('interop/elixir'), signal});
  const ts = spawnPeer('node', ['--experimental-strip-types', '--no-warnings', 'interop/reciprocal/driver.ts'], {signal});
  const ex = spawnPeer('mix', ['run', '--no-compile', '--no-deps-check', 'driver.exs'], {cwd: resolve('interop/elixir'), signal});
  let sequence = 0;
  const call = async (p: typeof ts, request: Record<string, unknown>): Promise<Record<string, any>> => {
    const id = String(++sequence), waiting = p.waitLine(line => {try {return JSON.parse(line).id === id;} catch {return false;}}, 10000);
    p.write(JSON.stringify({...request, id}) + '\n');
    return JSON.parse(await waiting);
  };
  const close = async () => {
    for (const p of [ts, ex]) p.end();
    await Promise.all([ts, ex].map(async p => {
      try {await p.waitExit(2000);} catch { /* stop also handles an already-failed peer. */ }
      finally {await p.stop();}
    }));
  };
  try {
    for (const p of [ts, ex]) await p.waitLine(line => {try {return JSON.parse(line).ready === true;} catch {return false;}}, 15000);
    const tsDirectory = await call(ts, {op: 'directory.start'});
    const tls = await peer((_req, res) => {res.writeHead(503); res.end();});
    let exDirectory: Record<string, any>;
    try {exDirectory = await call(ex, {op: 'directory.start', key: Buffer.from(tls.tlsOptions.key).toString('base64url'), cert: Buffer.from(tls.tlsOptions.cert).toString('base64url'), ca: Buffer.from(tls.ca).toString('base64url')});}
    finally {await tls.close();}
    assert.ok(tsDirectory.location); assert.ok(exDirectory.location);
    return {ts, ex, tsDirectory, exDirectory, call, close};
  } catch (error) {await close(); throw error;}
}

export function reciprocalRequest(family: string, algorithm: string) {
  return {family, algorithm, enc: 'A128GCM', bytes: Buffer.from(crypto.getRandomValues(new Uint8Array(48))).toString('base64url'), method: 'POST', url: 'https://exchange.example/%2F?a=%20', now: String(Math.floor(Date.now() / 1000)), nonce: crypto.randomUUID(), fields: [['x-exchange', Buffer.from('real exchange').toString('base64url')]]};
}
