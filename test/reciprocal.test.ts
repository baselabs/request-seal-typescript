import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, existsSync} from 'node:fs';
import {ELIXIR_ERROR_PIN} from '../src/errors/parity.ts';
import {CORPUS_PIN} from '../src/constants.ts';

test('the reciprocal peer, corpus and public errors pin the same published release', () => {
  assert.ok(existsSync('interop/elixir/mix.exs'), 'published reciprocal peer workspace exists');
  const project = readFileSync('interop/elixir/mix.exs', 'utf8');
  const fixture = JSON.parse(readFileSync('test/fixtures/elixir-reasons-511fed1.json', 'utf8')) as Record<string, unknown>;
  assert.equal(ELIXIR_ERROR_PIN, '511fed142044ccea28bdcbb317c091cb2c8a515d');
  assert.equal(ELIXIR_ERROR_PIN, CORPUS_PIN.commit);
  assert.ok(JSON.stringify(fixture).includes(ELIXIR_ERROR_PIN));
  assert.match(project, /\{:request_seal, "== 1\.0\.0"\}/);
  assert.equal(CORPUS_PIN.tag, 'v1.0.0', 'the corpus and reciprocal peer use the v1.0.0 release');
  assert.match(readFileSync('docs/reference/reciprocity.md', 'utf8'), /request_seal == 1\.0\.0/);
});

test('the reciprocal job requires the published peer before candidate qualification', () => {
  const ci = readFileSync('.github/workflows/ci.yml', 'utf8');
  assert.match(ci, /^  reciprocal:\n    name: reciprocal\n/m, 'CI exposes the reciprocal check');
  const job = ci.slice(ci.indexOf('  reciprocal:'));
  assert.match(job, /mix deps.get --check-locked/);
  assert.match(job, /npm run exchange/);
  assert.match(job, /version-file: \.tool-versions\n\s+version-type: strict/);
  assert.match(ci, /needs: \[node, native, os-trust-denied, browsers, reciprocal\]/);
  assert.match(readFileSync('.github/workflows/publish.yml', 'utf8'), /npm stage publish/);
});

test('both published peers and every CI setup use the same exact pins', () => {
  for (const folder of ['interop/elixir', 'interop/replay']) {
    const project = readFileSync(folder + '/mix.exs', 'utf8');
    assert.match(project, /elixir: "1\.20\.3"/);
    assert.match(project, /\{:request_seal, "== 1\.0\.0"\}/);
    assert.equal(readFileSync(folder + '/.tool-versions', 'utf8'), 'elixir 1.20.3-otp-29\nerlang 29.0.3\n');
    const pin = readFileSync(folder + '/mix.lock', 'utf8').split('\n').find(line => line.startsWith('  "request_seal":'));
    assert.ok(pin);
    assert.match(pin, /:request_seal, "1.0.0", "7fc147859ad0d070a4da5b17ff3599476dd8bda80ca1b5120ee7ea1363ec73c9"/);
    assert.match(pin, /"hexpm", "b2c9746349be720d7052d209b697a62829e1c2dd89467562633a2f60d9c56285"/);
  }
  const ci = readFileSync('.github/workflows/ci.yml', 'utf8');
  const setups = [...ci.matchAll(/uses: erlef\/setup-beam@[^\n]+\n\s+with:\n\s+version-file: \.tool-versions\n\s+version-type: strict/g)];
  assert.equal(setups.length, 3);
  assert.match(readFileSync('.tool-versions', 'utf8'), /^elixir 1\.20\.3-otp-29\nerlang 29\.0\.3$/m);
  assert.equal((ci.match(/test "\$actual_elixir" = "\$expected_elixir"/g) ?? []).length, 3);
  assert.equal((ci.match(/test "\$actual_otp" = "\$expected_otp"/g) ?? []).length, 3);
});
