import {PARITY_HEADER} from './parity-header.ts';
import { readFileSync, writeFileSync } from 'node:fs';
import { ERROR_PARITY, ELIXIR_ERROR_PIN, ERROR_RETRYABLE } from '../src/errors/parity.ts';
export function renderParity(): string {
  const retryable = Object.entries(ERROR_RETRYABLE).flatMap(([kind, rules]) => {
    const constants = Object.entries(rules).filter(([, rule]) => rule.kind === 'constant' && rule.value).map(([reason]) => `\`${kind}/${reason}\``);
    const statuses = Object.entries(rules).flatMap(([reason, rule]) => rule.kind === 'constant' ? [] : [`${kind}/${reason}: ${rule.minimum}–${rule.maximum} (status-derived)`]);
    return [...(constants.length ? [`${kind}: ${constants.join(', ')}.`] : []), ...statuses];
  }).join(' · ');
  return `**Status:** maintained · **Kind:** reference · **Updated:** October 10, 2026 · **Governed by:** Elixir release 0.4.1 at ${ELIXIR_ERROR_PIN} · **Review when:** the shared error vocabulary changes

# Error parity

OBSERVED: extraction with \`REQUEST_SEAL_REPO=<reference-repo> node --experimental-strip-types --no-warnings scripts/extract-elixir-reasons.ts ${ELIXIR_ERROR_PIN} <output.json>\` reads pinned constructors and call sites through Git. Core and JOSE pairs follow helper arguments, defaults, guards, and variable bindings. Parameterized helper layers resolve only from bindings at actual call sites. The internal JOSE worker is called with the crypto layer, so JOSE deadline errors exist only on that layer. Structured Fields and Digest have open Elixir reason types: their reasons come from call sites; moduledoc lists only cross-check the extraction.

The error vocabulary is pinned to v0.4.1; the shared corpus stays at v0.4.0. The corpus index is byte-identical between those tags, and v0.4.1 supplied no corpus release assets. These pins track different artifacts.

Extension-profile reasons are defined by extension packages and arrive with the profile row. The core layer union does not include \`profile\`.

Errors are frozen plain objects, branded by a private WeakSet for their type. Fields mirror the corresponding Elixir struct, with \`kind\` as the discriminant. Core and Adapter generate a 16-character lowercase hex correlation; JOSE correlation is null. Other kinds carry no correlation. Core \`message\` is null except for \`signer_algorithm_mismatch\`, which uses \"signer algorithm does not match signature specification\". Core \`source\` is null except for handle \`signing_failed\`, where it carries a branded, bounded custody error; the outer retryable value remains false. Constructors are internal. Every constructor takes a per-kind reason literal union. An unknown runtime reason or an invalid core or JOSE (layer, reason) pair throws \`TypeError\`, a programmer error equivalent to Elixir's \`FunctionClauseError\`; it never silently substitutes another reason. This TypeScript vocabulary bounds even Elixir's open reason types to the pinned call sites.

Retryable rules: ${retryable} All other retryable fields are false; reason-only structs have no retryable field.

Results are frozen on construction. \`deepFreeze\` returns a Result containing a snapshot of plain data structures. It freezes only the owned snapshot and never the caller's graph. Uint8Array children are copied and remain mutable because JavaScript cannot freeze nonempty typed arrays; accessors and other object types reject.

| Kind | Layer | Reason | Rule ID |
| --- | --- | --- | --- |
` + ERROR_PARITY.map(e => `| ${e.kind} | ${'layer' in e ? e.layer : ''} | ${e.reason} | ${e.rule_id} |`).join('\n') + '\n';
}
if (process.argv[1]?.endsWith('/render-parity.ts')) {
  if (process.argv[2] === '--update-table' && process.argv.length === 4) {
    const fixture = JSON.parse(readFileSync(process.argv[3]!, 'utf8'));
    const source = readFileSync('src/errors/parity.ts', 'utf8');
    const entriesStart = source.indexOf('const entries = ');
    const end = source.indexOf(' as const;', entriesStart) + ' as const;'.length;
    const suffix = source.slice(end);
    const retryStart = suffix.indexOf('const retryableRules = ');
    const retryExport = suffix.indexOf('export const ERROR_RETRYABLE = ');
    const retryEnd = suffix.indexOf('\n', retryExport);
    if (entriesStart < 0 || end < ' as const;'.length || retryStart < 0 || retryExport < 0 || retryEnd < 0 || !/^[a-f0-9]{40}$/.test(fixture.commit) || !Array.isArray(fixture.entries) || !Array.isArray(fixture.modules)) throw new Error('Invalid parity input');
    const retryable = Object.fromEntries(fixture.modules.map((m: {kind: string; retryable: {rules: unknown}}) => [m.kind, m.retryable.rules]));
    writeFileSync('src/errors/parity.ts', PARITY_HEADER
      + `export const ELIXIR_ERROR_PIN = '${fixture.commit}';\nconst entries = `
      + JSON.stringify(fixture.entries, null, 2) + ' as const;'
      + suffix.slice(0, retryStart) + 'const retryableRules = '
      + JSON.stringify(retryable, null, 2) + ' as const;\n'
      + 'export const ERROR_RETRYABLE = Object.freeze(Object.fromEntries(Object.entries(retryableRules).map(([kind, rules]) => [kind, Object.freeze(Object.fromEntries(Object.entries(rules).map(([reason, rule]) => [reason, Object.freeze(rule)])))]))) as typeof retryableRules;\n'
      + suffix.slice(retryEnd + 1));
    // Render docs in a fresh invocation so imports read the regenerated table.
  } else if (process.argv.length === 2) writeFileSync('docs/reference/error-parity.md', renderParity());
  else throw new Error('Usage: render-parity.ts [--update-table <extraction.json>]');
}
