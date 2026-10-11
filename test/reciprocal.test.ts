import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, existsSync} from 'node:fs';
import {ELIXIR_ERROR_PIN} from '../src/errors/parity.ts';
import {CORPUS_PIN} from '../src/constants.ts';

test('the reciprocal peer tracks the error release while preserving the unchanged corpus pin', () => {
  assert.ok(existsSync('interop/elixir/mix.exs'), 'published reciprocal peer workspace exists');
  const project = readFileSync('interop/elixir/mix.exs', 'utf8');
  const fixture = JSON.parse(readFileSync('test/fixtures/elixir-reasons-0a6568a.json', 'utf8')) as Record<string, unknown>;
  assert.equal(ELIXIR_ERROR_PIN, '0a6568aa246326617f760e94e21b359285c6ddfc');
  assert.ok(JSON.stringify(fixture).includes(ELIXIR_ERROR_PIN));
  assert.match(project, /\{:request_seal, "== 0\.4\.1"\}/);
  assert.equal(CORPUS_PIN.tag, 'v0.4.0', 'v0.4.1 changed no corpus bytes; the published peer follows ELIXIR_ERROR_PIN release 0.4.1');
  assert.match(readFileSync('docs/reference/reciprocity.md', 'utf8'), /v0\.4\.1 changed no corpus bytes/);
});

test('the reciprocal job requires the published peer and runs through release verification', () => {
  const ci = readFileSync('.github/workflows/ci.yml', 'utf8');
  assert.match(ci, /^  reciprocal:\n    name: reciprocal\n/m, 'CI exposes the reciprocal check');
  const job = ci.slice(ci.indexOf('  reciprocal:'));
  assert.match(job, /mix deps.get --check-locked/);
  assert.match(job, /npm run exchange/);
  assert.match(job, /elixir-version: '1.20.3'/);
  assert.match(job, /otp-version: '29.0.3'/);
  assert.match(readFileSync('.github/workflows/release.yml', 'utf8'), /uses: \.\/\.github\/workflows\/ci.yml/);
});
