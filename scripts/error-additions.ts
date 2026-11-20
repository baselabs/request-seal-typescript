import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';

type Entry = {kind: string; layer?: string; reason: string; rule_id: string};
type Rule = {kind: string; value?: boolean; minimum?: number; maximum?: number; path?: string; line?: number};
type Vocabulary = {
  commit: string;
  entries: Entry[];
  modules: {kind: string; reasons: string[]; entries: Entry[]; retryable: {rules: Record<string, Rule>}}[];
};
type Additions = {
  commit: string;
  sources: {path: string; blob: string; body: string}[];
  entries: Entry[];
};
// Preserve public source bytes, independently of the released corpus. A new
// implemented operation can add a reason without claiming the whole base pin
// already describes that newer release's unrelated APIs and vocabulary.
export const additions = JSON.parse(readFileSync(new URL('../test/fixtures/elixir-error-additions.json', import.meta.url), 'utf8')) as Additions;

export function validateAdditions(input: Additions): void {
  if (input.commit !== '0ce86730c7c70e92efdabc9a3b4867b90fc67053') throw new Error('Unexpected error-addition pin');
  const expected = new Map([
    ['lib/request_seal/signature_base/error.ex', 'eac428433ee4b40fe20f64124871f8b1c9982e6a'],
    ['lib/request_seal/signature_base.ex', '5c821e9a3d86fb159146c731d62f9619b093d1e6'],
  ]);
  if (input.sources.length !== expected.size) throw new Error('Incomplete error-addition source inventory');
  for (const source of input.sources) {
    const bytes = Buffer.from(source.body, 'utf8');
    const digest = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
    if (expected.get(source.path) !== source.blob || digest !== source.blob) throw new Error('Error-addition source differs from its pinned Git blob');
    expected.delete(source.path);
  }
  if (expected.size || JSON.stringify(input.entries) !== JSON.stringify([
    {kind: 'signature_base', reason: 'malformed', rule_id: 'signature_base/malformed'},
  ])) throw new Error('Unexpected error additions');
  const error = input.sources.find(source => source.path.endsWith('/error.ex'))!.body;
  const base = input.sources.find(source => source.path.endsWith('/signature_base.ex'))!.body;
  if (!/@type reason ::[\s\S]*?\| :malformed\b/.test(error) ||
    !/def parse\(bytes\) when is_binary\(bytes\) and byte_size\(bytes\) > 1_048_576,[\s\S]*?reason: :limit/.test(base) ||
    !/def parse\(bytes\) do[\s\S]*?rescue\s+_ -> .*reason: :malformed[\s\S]*?catch\s+_, _ -> .*reason: :malformed/.test(base)) {
    throw new Error('Pinned source does not establish the parse refusal contract');
  }
}

export function withErrorAdditions<T extends Vocabulary>(base: T): T {
  validateAdditions(additions);
  const result = structuredClone(base);
  for (const entry of additions.entries) {
    const existing = result.entries.find(item => item.rule_id === entry.rule_id);
    if (existing) {
      if (JSON.stringify(existing) !== JSON.stringify(entry)) throw new Error('Conflicting error-addition rule');
      continue;
    }
    const module = result.modules.find(item => item.kind === entry.kind);
    if (!module) throw new Error('Error addition has no existing error family');
    module.entries.push(structuredClone(entry));
    module.entries.sort((a, b) => a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0);
    module.reasons.push(entry.reason); module.reasons.sort();
    module.retryable.rules[entry.reason] = {kind: 'constant', value: false};
    module.retryable.rules = Object.fromEntries(Object.entries(module.retryable.rules).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));
  }
  result.entries = result.modules.flatMap(module => module.entries);
  return result;
}
