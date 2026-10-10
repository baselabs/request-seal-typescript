import { decodeBase64Url, encodeBase64Url } from './src/bytes.ts';
import { decodeJson } from './src/json.ts';
import { clockSeconds, timeoutMs, structuredInteger } from './src/numbers.ts';
const digest = crypto.subtle.digest.bind(crypto.subtle);
export async function selfChecks(): Promise<{name: string; ok: boolean}[]> {
  const checks: {name: string; ok: boolean}[] = [];
  for (const [input, expected] of [['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'], ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad']] as const) {
    const actual = Array.from(new Uint8Array(await digest('SHA-256', new TextEncoder().encode(input))), b => b.toString(16).padStart(2, '0')).join('');
    checks.push({name: `SHA-256 ${input || 'empty'}`, ok: actual === expected});
  }
  checks.push({name: 'base64url canonical bits', ok: encodeBase64Url(new Uint8Array([102])) === 'Zg' && !decodeBase64Url('Zh').ok && !decodeBase64Url('Zg=').ok});
  checks.push({name: 'JSON BOM rejection', ok: !decodeJson(new Uint8Array([239, 187, 191, 123, 125])).ok});
  checks.push({name: 'clock and timeout range', ok: clockSeconds(253_402_300_799).ok && !clockSeconds(253_402_300_800).ok && timeoutMs(300000).ok && !timeoutMs(300001).ok});
  checks.push({name: 'symmetric integer range', ok: structuredInteger(999_999_999_999_999).ok && !structuredInteger(1e15).ok && !structuredInteger(-1e15).ok});
  return checks;
}
async function main(): Promise<void> {
  const checks = await selfChecks();
  for (const check of checks) console.log(`${check.ok ? 'PASS' : 'FAIL'} ${check.name}`);
  if (checks.some(c => !c.ok)) process.exitCode = 1;
}
if (process.argv[1]?.endsWith('/self-checks.ts')) main().catch(() => { console.error('FAIL self-checks'); process.exitCode = 1; });
