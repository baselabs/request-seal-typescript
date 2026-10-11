import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {dirname, resolve, sep} from 'node:path';
import {fileURLToPath} from 'node:url';

export async function serve(): Promise<{url: string; close: () => Promise<void>}> {
  const workspace = dirname(fileURLToPath(import.meta.url)), root = resolve(workspace, '../..');
  const server = createServer((req, res) => {
    async function respond(): Promise<void> {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1');
      const path = decodeURIComponent(url.pathname);
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
  return {url: `http://127.0.0.1:${address.port}/`, close: () => new Promise<void>((done, fail) => {server.close(error => error ? fail(error) : done()); server.closeAllConnections();})};
}
