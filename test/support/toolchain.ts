import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';

// Parse only the shared reader's outputs; runtime declarations belong to it.
export function readToolchain(file?: string): Map<string, string> {
  const child = spawnSync('scripts/toolchain.sh', file === undefined ? [] : [file], {encoding: 'utf8', timeout: 10_000});
  assert.equal(child.status, 0, child.stderr || String(child.error));
  return new Map(child.stdout.trim().split('\n').filter(Boolean).map(line => {
    const separator = line.indexOf('=');
    assert.ok(separator > 0, 'shared reader output must name a value');
    return [line.slice(0, separator), line.slice(separator + 1)] as const;
  }));
}
