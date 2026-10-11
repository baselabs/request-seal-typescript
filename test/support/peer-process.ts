import {spawn} from 'node:child_process';

/** Owned real process group, bounded diagnostics, and one bounded wait at a time. */
export function spawnPeer(command: string, args: string[], options: {
  cwd?: string; env?: NodeJS.ProcessEnv; signal?: AbortSignal;
} = {}) {
  const {signal, ...spawnOptions} = options;
  const child = spawn(command, args, {...spawnOptions, detached: true, stdio: 'pipe'});
  let output = '', diagnostics = '', partial = '', closed = false;
  let failure: Error | undefined;
  const lines: string[] = [];
  let wake: (() => void) | undefined;
  const limit = 1_048_576;
  const append = (old: string, text: string) => (old + text).slice(-limit);
  child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data', (s: string) => {
    output = append(output, s); partial += s;
    for (;;) {const at = partial.indexOf('\n'); if (at < 0) break;
      lines.push(partial.slice(0, at)); partial = partial.slice(at + 1);
    }
    if (partial.length > limit || lines.length > 4096) {
      failure = new Error('Peer output limit exceeded'); void stop();
    }
    wake?.();
  });
  child.stderr.on('data', (s: string) => {diagnostics = append(diagnostics, s);});
  child.on('error', e => {failure = e; wake?.();});
  const completion = new Promise<number | null>(done => child.once('close', code => {
    closed = true; signal?.removeEventListener('abort', abort); done(code); wake?.();
  }));
  async function stop() {
    // Kill the whole session even if its leader exited and descendants hold pipes.
    if (child.pid) {try {process.kill(-child.pid, 'SIGKILL');} catch {child.kill('SIGKILL');}}
    child.stdin.destroy();
    let timer: ReturnType<typeof setTimeout> | undefined;
    await Promise.race([completion, new Promise<void>(done => {timer = setTimeout(() => {
      child.stdout.destroy(); child.stderr.destroy(); done();
    }, 1000);})]);
    clearTimeout(timer);
  }
  function abort() {failure = new Error('Peer wait canceled'); void stop().then(() => wake?.());}
  signal?.addEventListener('abort', abort, {once: true});
  if (signal?.aborted) abort();
  async function bounded<T>(inspect: () => {value: T} | undefined, timeoutMs: number): Promise<T> {
    if (wake) throw new Error('Peer already has an active wait');
    return new Promise<T>((done, fail) => {
      let settled = false;
      const cleanup = () => {clearTimeout(timer); wake = undefined;};
      const reject = (e: Error) => {
        if (settled) return; settled = true; cleanup();
        void stop().then(() => fail(new Error(`${e.message}\nstdout: ${output}\nstderr: ${diagnostics}`)));
      };
      const check = () => {
        if (settled) return;
        if (failure) {reject(failure); return;}
        const found = inspect();
        if (found) {settled = true; cleanup(); done(found.value);}
        else if (closed) reject(new Error(`Peer exited ${child.exitCode}`));
      };
      const timer = setTimeout(() => reject(new Error(`Peer wait exceeded ${timeoutMs} ms`)), timeoutMs);
      wake = check; check();
    });
  }
  return {
    child, output: () => output, diagnostics: () => diagnostics, stop,
    waitLine(predicate: (line: string) => boolean, timeoutMs: number) {
      return bounded(() => {
        while (lines.length) {const line = lines.shift()!; if (predicate(line)) return {value: line};}
        return undefined;
      }, timeoutMs);
    },
    waitExit(timeoutMs: number) {return bounded(() => closed ? {value: child.exitCode} : undefined, timeoutMs);},
  };
}

/** Mix startup must never try to install Hex through an interactive prompt. */
export async function requireHex(options: {cwd: string; env?: NodeJS.ProcessEnv; signal?: AbortSignal}) {
  const p = spawnPeer('mix', ['archive'], options);
  p.child.stdin.end();
  try {
    const code = await p.waitExit(10000);
    if (code !== 0 || !/^\* hex-[^\s]+/m.test(p.output())) {
      throw new Error(`PEER_HEX_UNAVAILABLE: run mix local.hex --force before peer startup.\n${p.output()}${p.diagnostics()}`);
    }
  } finally {await p.stop();}
}
