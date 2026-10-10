import { execFileSync } from 'node:child_process';
import { readFileSync, appendFileSync } from 'node:fs';
import {fileURLToPath} from 'node:url';
export function isUnpublished(failure: {stdout?: string; stderr?: string}): boolean {
  const stdout = failure.stdout ?? '', stderr = failure.stderr ?? '';
  const codes = [...stderr.matchAll(/^npm (?:error|ERR!) code ([A-Z0-9_]+)\r?$/gm)].map(match => match[1]);
  if (codes.some(code => code !== 'E404') || codes.length > 1) return false;
  if (stdout.trim()) {
    try {return JSON.parse(stdout).error?.code === 'E404';} catch {return false;}
  }
  return codes.length === 1 && codes[0] === 'E404';
}
function main(): void {
const pkg = JSON.parse(readFileSync('package.json', 'utf8')) as {version: string};
if (process.env.GITHUB_REF_NAME !== `v${pkg.version}`) throw new Error('Release tag must match package version');
let published = false;
try {
  const actual = JSON.parse(execFileSync('npm', ['view', `@request-seal/core@${pkg.version}`, 'version', '--json'], {encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe']}));
  if (actual !== pkg.version) throw new Error('Unexpected registry version');
  published = true;
} catch (error) {
  if (!isUnpublished(error as {stdout?: string; stderr?: string})) throw new Error('Registry check failed');
}
const output = process.env.GITHUB_OUTPUT;
if (!output) throw new Error('GITHUB_OUTPUT is required');
appendFileSync(output, `published=${published}\n`);

}
if (process.argv[1] === fileURLToPath(import.meta.url)) main();
