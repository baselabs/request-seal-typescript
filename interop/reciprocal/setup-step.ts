import {spawnPeer, diagnosticTail} from '../../test/support/peer-process.ts';

/** Execute a real Mix step with the same process ownership as the exchange. */
export async function runSetupStep(args: string[], cwd: string) {
  const p = spawnPeer('mix', args, {cwd}); p.end();
  try {
    if (await p.waitExit(120000) !== 0) throw new Error(`stdout: ${diagnosticTail(p.output())}\nstderr: ${diagnosticTail(p.diagnostics())}`);
    return p.output();
  } finally {await p.stop();}
}
