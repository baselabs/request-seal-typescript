/** Shared corpus decisions; human-readable rationale and standards links: PINNED.md. */
export const PINNED = [
  { file: 'date.json', name: 'syntactic max date - 999,999,999,999,999', outcome: 'accept' },
  { file: 'date.json', name: 'syntactic min date - -999,999,999,999,999', outcome: 'accept' },
  { file: 'display-string.json', name: 'two lines display string', outcome: 'accept' },
  { file: 'string.json', name: 'two lines string', outcome: 'accept' },
  { file: 'binary.json', name: 'unpadded', outcome: 'accept' },
  { file: 'binary.json', name: 'partially padded', raw: ':uuueGVsbG8=:', outcome: 'reject', reason: 'canonical padding' },
  { file: 'binary.json', name: 'extra padding', raw: ':aGVsbG8==:', outcome: 'reject', reason: 'surplus padding' },
  { file: 'binary.json', name: 'non-zero pad bits', raw: ':iZ==:', outcome: 'reject', reason: 'canonical padding' },
  { file: 'supplemental', name: 'canonical padding without equals', raw: ':QR:', outcome: 'reject', reason: 'canonical padding' },
] as const;
export function pinnedRejects(file: string, name: string): boolean {
  return PINNED.some(p => p.file === file && p.name === name && p.outcome === 'reject');
}
