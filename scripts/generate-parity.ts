import { readFileSync, writeFileSync } from 'node:fs';
const fixture = JSON.parse(readFileSync('test/fixtures/elixir-reasons-b239287.json', 'utf8'));
const retryable = Object.fromEntries(fixture.modules.map((m: {kind: string; retryable: {rules: unknown}}) => [m.kind, m.retryable.rules]));
const current = readFileSync('src/errors/parity.ts', 'utf8');
const footer = current.slice(current.indexOf('export const ERROR_PARITY'));
const header = `// Derived from pinned Elixir constructors and call sites; regenerate with scripts/generate-parity.ts.\nexport const ELIXIR_ERROR_PIN = '${fixture.commit}';\nconst entries = ${JSON.stringify(fixture.entries, null, 2)} as const;\n\nconst retryableRules = ${JSON.stringify(retryable, null, 2)} as const;\nexport const ERROR_RETRYABLE = Object.freeze(Object.fromEntries(Object.entries(retryableRules).map(([kind, rules]) => [kind, Object.freeze(Object.fromEntries(Object.entries(rules).map(([reason, rule]) => [reason, Object.freeze(rule)])))]))) as typeof retryableRules;\n\n`;
writeFileSync('src/errors/parity.ts', header + footer);
console.log(`Generated ${fixture.entries.length} error pairs and per-reason retryable rules`);
