import {nodeAdapterTest} from './support/node-adapter-test.ts';
const test = nodeAdapterTest(import.meta.url);
import assert from 'node:assert/strict';
import {spawnSync, spawn} from 'node:child_process';
import {mkdtemp, rm, stat, writeFile, readFile} from 'node:fs/promises';
import {resolve, join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {appendFileSync} from 'node:fs';
import {spawnPeer, requireHex} from './support/peer-process.ts';

test('a peer that never announces readiness is killed within its owned startup bound', {timeout: 5000}, async () => {
  const p = spawnPeer('node', ['-e', 'console.error("startup diagnostic"); console.log("STARTED"); setInterval(() => {}, 1000)']);
  p.child.stdin.end();
  let watchdog: ReturnType<typeof setTimeout> | undefined;
  try {
    await p.waitLine(line => line === 'STARTED', 2500);
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


test('failures include only the last 8 KiB from each stream', {timeout: 5000}, async () => {
  const p = spawnPeer('node', ['-e', 'process.stdout.write("😀".repeat(30000)+"\\n"); process.stderr.write("😀".repeat(30000)); console.log("WRITTEN"); setInterval(()=>{},1000)']);
  const root = await mkdtemp(resolve('test/.tmp-capture-'));
  try {
    await p.waitLine(s => s === 'WRITTEN', 2500);
    await assert.rejects(p.waitLine(s => s === 'READY', 500), e => {
      assert.ok(Buffer.byteLength(String(e)) <= 16480, 'diagnostic tails are bounded');
      const message = (e as Error).message;
      const [stdout, stderr] = message.split('stdout: ')[1]!.split('\nstderr: ');
      assert.ok(Buffer.byteLength(stdout!) <= 8192); assert.ok(Buffer.byteLength(stderr!) <= 8192);
      assert.ok(Buffer.byteLength(p.output()) >= 120000, 'stdout below the capture bound is available for the record');
      return true;
    });
    const record = resolve(root, 'capture.jsonl');
    await writeFile(record, JSON.stringify({stdout: p.output(), stderr: p.diagnostics()}) + '\n');
    const captured = JSON.parse(await readFile(record, 'utf8'));
    assert.ok(Buffer.byteLength(captured.stdout) >= 120000);
    assert.ok(Buffer.byteLength(captured.stderr) >= 120000);
  } finally {await p.stop(); await rm(root, {recursive: true, force: true});}
});

test('unmatched lines remain available to subsequent waits', {timeout: 5000}, async () => {
  const p = spawnPeer('node', ['-e', 'console.log("LATER");console.log("READY");process.stdin.resume()']);
  try {
    assert.equal(await p.waitLine(s => s === 'READY', 1000), 'READY');
    assert.equal(await p.waitLine(s => s === 'LATER', 200), 'LATER');
  } finally {await p.stop();}
});

test('early exit reports failure and guarded input permits cleanup', {timeout: 5000}, async () => {
  const p = spawnPeer('node', ['-e', 'process.exit(3)']);
  let ended = false;
  try {
    await p.waitExit(1000);
    assert.ok(p.child.stdin.listenerCount('error') > 0, 'peer stdin errors are observed');
    p.child.stdin.write('after exit\n');
    await assert.rejects(p.waitLine(s => s === 'READY', 200), /write|Peer exited 3/i);
  } finally {
    try {p.end(); await p.stop();} finally {ended = true;}
  }
  assert.equal(ended, true, 'cleanup completes');
});

test('stop does not signal a closed peer group', {timeout: 5000}, async () => {
  const p = spawnPeer('node', ['-e', 'process.exit(0)']);
  assert.equal(await p.waitExit(1000), 0);
  // stop reports whether this invocation signaled the owned group.
  assert.equal(await p.stop(), false);
});


for (const stage of ['startup', 'ready']) test(`watchdog ends an EOF-ignoring peer after harness death during ${stage}`, {timeout: 20000, skip: process.env.REQUESTSEAL_REPLAY_ELIXIR !== '1'}, async t => {
  const installed = spawnSync('mix', ['--version'], {encoding: 'utf8', timeout: 5000});
  if (installed.error?.message.includes('ENOENT')) {t.skip('Mix is not installed'); return;}
  const args = stage === 'startup'
    ? ['run', '--no-compile', '--no-deps-check', '--eval', 'IO.binwrite(:stdio, "STARTUP\\n"); Process.sleep(5000)', 'driver.exs']
    : ['run', '--no-compile', '--no-deps-check', '--eval', 'IO.binwrite(:stdio, ~s({"ready":true}) <> "\\n"); Process.sleep(:infinity)'];
  const source = `import {spawnPeer} from ${JSON.stringify(new URL('./support/peer-process.ts', import.meta.url).href)};
    const p=spawnPeer('mix',${JSON.stringify(args)},{cwd:${JSON.stringify(resolve('interop/elixir'))}});
    console.log('GROUP='+p.child.pid);
    if (${JSON.stringify(stage)} === 'startup') {await p.waitLine(s=>s==='STARTUP',10000);console.log('STARTUP');}
    if (${JSON.stringify(stage)} === 'ready') {await p.waitLine(s=>{try{return JSON.parse(s).ready===true}catch{return false}},10000);console.log('READY');}
    setInterval(()=>{},1000);`;
  const harness = spawn('node', ['--experimental-strip-types', '--no-warnings', '--input-type=module', '-e', source], {stdio: ['ignore', 'pipe', 'pipe']});
  if (process.env.REQUESTSEAL_PEER_LEDGER && harness.pid) appendFileSync(process.env.REQUESTSEAL_PEER_LEDGER, JSON.stringify({pid: harness.pid}) + '\n');
  let captured = '', group: number | undefined;
  let gone = false, original: unknown;
  harness.stdout.setEncoding('utf8'); harness.stdout.on('data', s => {captured += s;});
  const closed = new Promise<void>(done => harness.once('close', () => done()));
  const deadline = Date.now() + 12000;
  const pause = () => new Promise<void>(done => setTimeout(done, 50));
  try {
    while (!captured.includes(stage === 'startup' ? 'STARTUP' : 'READY') && Date.now() < deadline) await pause();
    group = Number(/GROUP=(\d+)/.exec(captured)?.[1]); assert.ok(group, captured);
    assert.match(captured, stage === 'startup' ? /STARTUP/ : /READY/);
    process.kill(-group, 0); // Known-positive group probe before the external kill.
    harness.kill('SIGKILL'); await closed;
    const end = Date.now() + 2500;
    const alive = () => {try {process.kill(-group!, 0); return true;} catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ESRCH') return false;
      // Permission denial never proves absence; keep polling within the bound.
      if ((error as NodeJS.ErrnoException).code === 'EPERM') return true;
      throw error;
    }};
    while (alive() && Date.now() < end) await pause();
    gone = !alive();
    assert.equal(gone, true, `${stage}: peer group exits after harness SIGKILL`);
  } catch (error) {original = error; throw error;}
  finally {
    harness.kill('SIGKILL');
    if (group && !gone) {try {process.kill(-group, 'SIGKILL');} catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ESRCH' && original === undefined) throw error;
    }}
    await closed;
  }
});

test('watchdog rejects a living owner that is no longer its parent', {timeout: 5000}, async () => {
  const program = 'process.stdin.resume(); console.log("READY"); setInterval(()=>{},1000)';
  // Positive control: the same real child reaches readiness with its actual owner.
  const owned = spawnPeer('node', ['-e', program]);
  try {assert.equal(await owned.waitLine(line => line === 'READY', 2500), 'READY');}
  finally {await owned.stop();}

  process.kill(process.ppid, 0); // The claimed owner exists, but is not the watchdog's parent.
  const directory = await mkdtemp(join(tmpdir(), 'request-seal-watchdog-'));
  const ledger = join(directory, 'peers.jsonl');
  const p = spawn('node', [fileURLToPath(new URL('./support/peer-watchdog.mjs', import.meta.url)), String(process.ppid), 'node', '-e', program], {detached: true, stdio: 'pipe', env: {...process.env, REQUESTSEAL_PEER_LEDGER: ledger}});
  if (process.env.REQUESTSEAL_PEER_LEDGER && p.pid) appendFileSync(process.env.REQUESTSEAL_PEER_LEDGER, JSON.stringify({pid: p.pid, group: p.pid}) + '\n');
  let diagnostic = '';
  p.stdout.resume(); p.stderr.setEncoding('utf8'); p.stderr.on('data', chunk => {diagnostic += chunk;});
  const closed = new Promise<{code: number | null; signal: NodeJS.Signals | null}>(done => p.once('close', (code, signal) => done({code, signal})));
  let exceeded = false;
  const bound = setTimeout(() => {exceeded = true; try {process.kill(-p.pid!, 'SIGKILL');} catch {}}, 2500);
  try {
    await new Promise<void>((done, reject) => {p.once('spawn', done); p.once('error', reject);});
    process.kill(-p.pid!, 0); // Known-positive group probe before observing termination.
    let childPid: number | undefined;
    const deadline = Date.now() + 1000;
    while (!childPid && Date.now() < deadline) {
      try {childPid = JSON.parse((await readFile(ledger, 'utf8')).trim().split('\n')[0]!).pid;}
      catch (error) {if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;}
      if (!childPid) await new Promise<void>(done => setTimeout(done, 5));
    }
    assert.ok(childPid, 'the watchdog records the real child before termination');
    process.kill(childPid, 0); // Known-positive child probe before watchdog termination.
    const ended = await closed;
    assert.deepEqual(ended, {code: null, signal: "SIGKILL"});
    assert.match(diagnostic, /PEER_PARENT_MISMATCH/, 'termination is attributed to the parent mismatch');
    assert.throws(() => process.kill(childPid, 0), /ESRCH/, 'the watchdog ended its recorded child');
    process.kill(process.ppid, 0); // The claimed owner is still alive.
    assert.equal(exceeded, false, 'the watchdog detects parent mismatch while the recorded owner is still alive');
    assert.throws(() => process.kill(-p.pid!, 0), /ESRCH/, 'the invalid owner process group was reaped');
  } finally {
    clearTimeout(bound); p.stdin.destroy();
    try {process.kill(-p.pid!, 'SIGKILL');} catch {}
    await closed;
    await rm(directory, {recursive: true, force: true});
  }
});


for (const stream of ['stdout', 'stderr'] as const) test(`peer ${stream} capture retains at most the last 1 MiB`, {timeout: 20000}, async () => {
  const p = spawnPeer('node', ['-e', `process.${stream}.write("😀".repeat(400000)); process.${stream}.write("TAIL");`]);
  try {
    // Writing 1.6 MB through a child process can take seconds on a loaded host.
    try {await p.waitExit(15000);} catch (error) {assert.match(String(error), /Peer output limit exceeded/);}
    const captured = stream === 'stdout' ? p.output() : p.diagnostics();
    assert.ok(Buffer.byteLength(captured) >= 1000000, 'the real writer crossed the capture bound');
    assert.ok(Buffer.byteLength(captured) <= 1048576, 'capture is bounded in bytes');
    assert.doesNotMatch(captured, /\ufffd/, 'the UTF-8 tail starts at a complete code point');
    if (stream === 'stderr') assert.ok(captured.endsWith('TAIL'), 'the latest bytes are retained');
  } finally {await p.stop();}
});

test('a failing real Mix setup step reports only the last 8 KiB per stream', {timeout: 15000, skip: process.env.REQUESTSEAL_REPLAY_ELIXIR !== '1'}, async () => {
  const {runSetupStep} = await import('../interop/reciprocal/setup-step.ts');
  await assert.rejects(runSetupStep(['run', '--no-mix-exs', '--eval', 'IO.binwrite(:stdio, String.duplicate("😀", 40000) <> "OUT_END"); IO.binwrite(:stderr, String.duplicate("😀", 40000) <> "ERR_END"); System.halt(3)'], resolve('interop/elixir')), error => {
    const message = (error as Error).message;
    assert.ok(Buffer.byteLength(message) <= 16480, 'setup failure diagnostics are bounded');
    assert.ok(message.includes('OUT_END')); assert.ok(message.includes('ERR_END'));
    return true;
  });
});
