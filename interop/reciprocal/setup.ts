import {fileURLToPath} from 'node:url';
import {requireHex} from '../../test/support/peer-process.ts';
import {runSetupStep} from './setup-step.ts';
async function main() {
  const cwd = fileURLToPath(new URL('../elixir', import.meta.url));
  await requireHex({cwd});
  for (const args of [['deps.get', '--check-locked'], ['deps.compile'], ['compile', '--warnings-as-errors']]) {
    console.log(await runSetupStep(args, cwd));
  }
}
main().catch(e => {console.error(e); process.exitCode = 1;});
