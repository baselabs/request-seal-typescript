import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, existsSync} from 'node:fs';
import {ELIXIR_ERROR_PIN} from '../src/errors/parity.ts';
import {CORPUS_PIN} from '../src/constants.ts';

test('the reciprocal peer and both pins track the same Elixir release', () => {
  assert.ok(existsSync('interop/elixir/mix.exs'), 'published reciprocal peer workspace exists');
  const project = readFileSync('interop/elixir/mix.exs', 'utf8');
  const fixture = JSON.parse(readFileSync('test/fixtures/elixir-reasons-53b6690.json', 'utf8')) as Record<string, unknown>;
  assert.equal(ELIXIR_ERROR_PIN, '53b6690ccd5036d58b280d08cf0cacc6427262fe');
  assert.ok(JSON.stringify(fixture).includes(ELIXIR_ERROR_PIN));
  assert.match(project, /\{:request_seal, "== 0\.5\.2"\}/);
  assert.equal(CORPUS_PIN.tag, 'v0.5.2', 'the corpus, the error vocabulary, and the reciprocal peer all track the v0.5.2 release');
  assert.match(readFileSync('docs/reference/reciprocity.md', 'utf8'), /request_seal == 0\.5\.2/);
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

test('both published peers and every CI setup use the same exact pins', () => {
  for (const folder of ['interop/elixir', 'interop/replay']) {
    const project = readFileSync(folder + '/mix.exs', 'utf8');
    assert.match(project, /elixir: "1\.20\.3"/);
    assert.match(project, /\{:request_seal, "== 0\.5\.2"\}/);
    assert.equal(readFileSync(folder + '/.tool-versions', 'utf8'), 'elixir 1.20.3-otp-29\nerlang 29.0.3\n');
    const pin = readFileSync(folder + '/mix.lock', 'utf8').split('\n').find(line => line.startsWith('  "request_seal":'));
    assert.ok(pin);
    assert.match(pin, /:request_seal, "0.5.2", "ff1b09bcddde0c92c44b6ece467cf86e4ef71709358de6bdf07f2ba1c008da96"/);
    assert.match(pin, /"hexpm", "b8632c4cd4ec8ab989cf5d919765c34dbb3a2774939a0e3e7f104f329558229b"/);
  }
  const ci = readFileSync('.github/workflows/ci.yml', 'utf8');
  const setups = [...ci.matchAll(/uses: erlef\/setup-beam@[^\n]+\n\s+with:\n\s+otp-version: '([^']+)'\n\s+elixir-version: '([^']+)'/g)];
  assert.equal(setups.length, 3);
  for (const match of setups) assert.deepEqual(match.slice(1), ['29.0.3', '1.20.3']);
});
