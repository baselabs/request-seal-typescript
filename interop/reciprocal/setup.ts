import {resolve} from 'node:path';
import {requireHex, spawnPeer} from '../../test/support/peer-process.ts';
async function main() {
  const cwd = resolve('../elixir');
  await requireHex({cwd});
  for (const args of [['deps.get', '--check-locked'], ['deps.compile'], ['compile', '--warnings-as-errors']]) {
    const p = spawnPeer('mix', args, {cwd}); p.child.stdin.end();
    try {if (await p.waitExit(120000) !== 0) throw new Error(p.output() + p.diagnostics()); console.log(p.output());}
    finally {await p.stop();}
  }
}
main().catch(e => {console.error(e); process.exitCode = 1;});
