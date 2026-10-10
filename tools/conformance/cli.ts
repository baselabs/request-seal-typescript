import { runCorpus, canonicalJson } from './loader.ts';
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  let folder: string | undefined, unpinned = false, smoke = false, pendingOk = false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--corpus' && !folder && args[i + 1] && !args[i + 1]!.startsWith('--')) folder = args[++i];
    else if (args[i] === '--unpinned' && !unpinned) unpinned = true;
    else if (args[i] === '--pending-ok' && !pendingOk) pendingOk = true;
    else if (args[i] === '--smoke' && !smoke) smoke = true;
    else { console.error('Usage: conformance --corpus <folder> [--unpinned] [--smoke] [--pending-ok]'); process.exitCode = 1; return; }
  }
  if (!folder) { console.error('A corpus folder is required'); process.exitCode = 1; return; }
  const report = await runCorpus(folder, {unpinned, smoke, pendingOk});
  console.log(JSON.stringify(JSON.parse(canonicalJson(report)), null, 2)); process.exitCode = report.ok ? 0 : 1;
}
main().catch(() => { console.error('Conformance failed'); process.exitCode = 1; });
