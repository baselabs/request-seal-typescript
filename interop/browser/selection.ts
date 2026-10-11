import {readFile, readdir} from 'node:fs/promises';
import {resolve, dirname} from 'node:path';

export const imports = (source: string) => [...source.matchAll(/(?:from\s*|import\s*\(?\s*)(['"])([^'"\n]+)\1/g)].map(m => m[2]!);
async function eligible(file: string, seen = new Set<string>()): Promise<boolean> {
  if (seen.has(file)) return true;
  seen.add(file);
  const source = await readFile(file, 'utf8');
  if (/\bprocess\s*[.[]|\bBuffer\b/.test(source)) return false;
  if (/\bskip\s*:/.test(source) && file.endsWith('.test.ts')) return false;
  for (const specifier of imports(source)) {
    if (specifier === 'node:test' || specifier === 'node:assert/strict') continue;
    if (file.endsWith('.test.ts') && !specifier.startsWith('../src/')) return false;
    if (!specifier.startsWith('.')) return false;
    const next = resolve(dirname(file), specifier);
    if (!await eligible(next, seen)) return false;
  }
  return true;
}

export const portableFiles = [
  'context-deadline-in-process.test.ts',
  'discovery-core-fixes.test.ts',
  'discovery-transport-errors.test.ts',
  'error-branding.test.ts',
  'jose-header.test.ts',
  'policy.test.ts',
  'profile-types.test.ts',
  'wire-brand.test.ts',
  'wire-error-boundary.test.ts',
  'wire-input-boundaries.test.ts',
] as const;
export function assertPortableFiles(selected: readonly string[]): void {
  const actual = [...selected].sort();
  if (actual.length !== portableFiles.length || actual.some((name, index) => name !== portableFiles[index]))
    throw new Error('Portable test set changed: ' + JSON.stringify({expected: portableFiles, actual}));
}
export async function discoverPortableFiles(root: string): Promise<string[]> {
  const selected: string[] = [];
  for (const name of (await readdir(resolve(root, 'test'))).filter(n => n.endsWith('.test.ts')).sort()) {
    if (name === 'runtime-query.test.ts') continue;
    if (await eligible(resolve(root, 'test', name))) selected.push(name);
  }
  return selected;
}
