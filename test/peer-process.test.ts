import {nodeAdapterTest} from './support/node-adapter-test.ts';
const test = nodeAdapterTest(import.meta.url);
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtemp, rm, stat} from 'node:fs/promises';
import {resolve} from 'node:path';
import {spawnPeer, requireHex} from './support/peer-process.ts';

test('a peer that never announces readiness is killed within its owned startup bound', {timeout: 5000}, async () => {
  const p = spawnPeer('node', ['-e', 'console.error("startup diagnostic"); setInterval(() => {}, 1000)']);
  p.child.stdin.end();
  let watchdog: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([
      p.waitLine(line => line === 'READY', 200).then(() => 'unexpected readiness', e => String(e)),
      new Promise<string>(done => {watchdog = setTimeout(() => done('UNBOUNDED peer wait'), 1500);}),
    ]);
    assert.match(result, /Peer wait exceeded 200 ms.*startup diagnostic/s, 'startup bound rejects with captured diagnostics');
    assert.throws(() => process.kill(p.child.pid!, 0), /ESRCH/, 'peer was reaped before rejection');
  } finally {clearTimeout(watchdog); await p.stop();}
});

test('non-interactive startup closes input and observes readiness', {timeout: 5000}, async () => {
  const p = spawnPeer('node', ['-e', 'process.stdin.resume(); process.stdin.on("end", () => console.log("READY"))']);
  try {const ready = p.waitLine(line => line === 'READY', 1000); p.child.stdin.end(); assert.equal(await ready, 'READY');}
  finally {await p.stop();}
});

test('a stalled peer wait kills descendants that retain its pipes', {timeout: 5000}, async () => {
  const root = await mkdtemp(resolve('test/.tmp-peer-'));
  const heartbeat = resolve(root, 'heartbeat');
  const worker = 'const fs=require("node:fs"); const path=process.argv[1]; fs.appendFileSync(path,"alive"); console.log("DESCENDANT="+process.pid); setInterval(()=>fs.appendFileSync(path,"alive"),20)';
  const program = 'const {spawn}=require("node:child_process"); spawn(process.execPath,["-e",' + JSON.stringify(worker) + ',' + JSON.stringify(heartbeat) + '],{stdio:"inherit"}); setInterval(()=>{},1000)';
  const p = spawnPeer('node', ['-e', program]);
  p.child.stdin.end(); let descendant: number | undefined;
  const pause = () => new Promise<void>(done => setTimeout(done, 100));
  try {
    const line = await p.waitLine(s => s.startsWith('DESCENDANT='), 1000);
    descendant = Number(line.split('=')[1]);
    const before = (await stat(heartbeat)).size;
    await pause();
    assert.ok((await stat(heartbeat)).size > before, 'live descendant advances its heartbeat');
    await assert.rejects(p.waitLine(s => s === 'READY', 200), /Peer wait exceeded 200 ms/);
    const stopped = (await stat(heartbeat)).size;
    await pause();
    assert.equal((await stat(heartbeat)).size, stopped, 'peer wait terminates the whole process group');
  } finally {
    await p.stop();
    if (descendant) {try {process.kill(descendant, 'SIGKILL');} catch { /* Already reaped. */ }}
    await rm(root, {recursive: true, force: true});
  }
});

test('an empty Mix archive home fails explicitly without an interactive Hex prompt', {timeout: 15000}, async t => {
  const installed = spawnSync('mix', ['--version'], {encoding: 'utf8', timeout: 5000});
  if (installed.error?.message.includes('ENOENT')) {t.skip('Mix is not installed'); return;}
  assert.equal(installed.status, 0, installed.stderr);
  const root = await mkdtemp(resolve('test/.tmp-hex-'));
  try {
    await assert.rejects(requireHex({cwd: resolve('interop/elixir'), env: {...process.env, MIX_HOME: root}, signal: t.signal}), /PEER_HEX_UNAVAILABLE: run mix local.hex --force/);
  } finally {await rm(root, {recursive: true, force: true});}
});
