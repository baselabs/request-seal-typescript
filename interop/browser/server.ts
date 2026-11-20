import {createServer, type Server} from 'node:http';
import {readFile} from 'node:fs/promises';
import {dirname, resolve, sep} from 'node:path';
import {fileURLToPath} from 'node:url';

async function stop(server: Server): Promise<void> {
  if (!server.listening) {server.closeAllConnections(); return;}
  await new Promise<void>((done, fail) => {server.close(error => error ? fail(error) : done()); server.closeAllConnections();});
}

export async function serve(): Promise<{url: string; closedOrigin: string; deliveryOrigins: ReadonlySet<string>; close: () => Promise<void>}> {
  const workspace = dirname(fileURLToPath(import.meta.url)), root = resolve(workspace, '../..');
  let closedPort = 0;
  let redirectRequests = 0, redirectMethod: string | undefined;
  const peers = new Set<Server>(), deliveryOrigins = new Set<string>(), retryRequests = new Map<string, number>();
  async function retryPeer(): Promise<string> {
    let origin = '';
    const peer = createServer((req, res) => {
      const cors = {'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET, POST',
        'access-control-allow-headers': '*', 'access-control-max-age': '60'};
      if (req.method === 'OPTIONS') {res.writeHead(204, cors).end(); return;}
      retryRequests.set(origin, (retryRequests.get(origin) ?? 0) + 1);
      req.resume(); peer.close();
      res.writeHead(503, {...cors, connection: 'close'}).end();
    });
    peers.add(peer); peer.once('close', () => peers.delete(peer));
    try {
      await new Promise<void>((done, fail) => {peer.once('error', fail); peer.listen(0, '127.0.0.1', done);});
      const address = peer.address();
      if (!address || typeof address !== 'object') throw new Error('Retry peer did not bind');
      origin = `http://127.0.0.1:${address.port}`;
      // Retain this origin after close so the second request reaches the real
      // closed listener instead of being aborted by the browser harness.
      deliveryOrigins.add(origin); retryRequests.set(origin, 0);
      return origin;
    } catch (error) {await stop(peer); peers.delete(peer); throw error;}
  }
  const server = createServer((req, res) => {
    async function respond(): Promise<void> {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1');
      const path = decodeURIComponent(url.pathname);
      if (path === '/__delivery/closed-port') {res.writeHead(200, {'content-type': 'application/json'}).end(JSON.stringify({port: closedPort})); return;}
      if (path === '/__delivery/reset') {req.socket.destroy(); return;}
      if (path === '/__delivery/redirect') {
        redirectRequests++; redirectMethod = req.method; req.resume();
        res.writeHead(303, {location: 'http://delivery-canary.invalid/'}).end(); return;
      }
      if (path === '/__delivery/redirect-count') {res.writeHead(200, {'content-type': 'application/json'}).end(JSON.stringify({requests: redirectRequests, method: redirectMethod})); return;}
      if (path === '/__delivery/retry-peer') {const origin = await retryPeer(); res.writeHead(200, {'content-type': 'application/json'}).end(JSON.stringify({origin})); return;}
      if (path === '/__delivery/retry-count') {res.writeHead(200, {'content-type': 'application/json'}).end(JSON.stringify({requests: retryRequests.get(url.searchParams.get('origin') ?? '')})); return;}
      if (path.startsWith('/__delivery/status/')) {
        const status = Number(path.slice('/__delivery/status/'.length));
        if ([200, 401, 500, 502, 504].includes(status)) {res.writeHead(status).end(); return;}
      }
      const base = path.startsWith('/dist/') ? resolve(root, 'dist') : path.startsWith('/bundle/') ? resolve(workspace, 'bundle') : workspace;
      const file = path === '/' ? resolve(workspace, 'index.html') : resolve(base, '.' + (path.startsWith('/dist/') ? path.slice(5) : path.startsWith('/bundle/') ? path.slice(7) : path));
      if (!(file.startsWith(base + sep)) || (base === workspace && file !== resolve(workspace, 'index.html'))) {res.writeHead(404).end(); return;}
      const bytes = await readFile(file);
      res.writeHead(200, {'content-type': file.endsWith('.html') ? 'text/html; charset=utf-8' : 'text/javascript; charset=utf-8', 'cache-control': 'no-store'});
      res.end(bytes);
    }
    respond().catch(() => {res.writeHead(404).end();});
  });
  await new Promise<void>((done, fail) => {server.once('error', fail); server.listen(0, '127.0.0.1', done);});
  const address = server.address();
  if (!address || typeof address !== 'object') throw new Error('Loopback listener did not bind');
  const close = async () => {
    const results = await Promise.allSettled([stop(server), ...[...peers].map(stop)]);
    const failure = results.find(result => result.status === 'rejected');
    if (failure?.status === 'rejected') throw failure.reason;
  };
  const unused = createServer();
  try {
    await new Promise<void>((done, fail) => {unused.once('error', fail); unused.listen(0, '127.0.0.1', done);});
    const unusedAddress = unused.address();
    if (!unusedAddress || typeof unusedAddress !== 'object') throw new Error('Closed-port probe did not bind');
    closedPort = unusedAddress.port;
    await new Promise<void>((done, fail) => unused.close(error => error ? fail(error) : done()));
    return {url: `http://127.0.0.1:${address.port}/`, closedOrigin: `http://127.0.0.1:${closedPort}`, deliveryOrigins, close};
  } catch (error) {
    if (unused.listening) await new Promise<void>((done, fail) => unused.close(e => e ? fail(e) : done()));
    await close();
    throw error;
  }
}
