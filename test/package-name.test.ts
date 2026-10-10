import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, readdirSync} from 'node:fs';

test('README and reference documents use the scoped npm package name', () => {
  const reference = new URL('../docs/reference/', import.meta.url);
  const documents = [new URL('../README.md', import.meta.url),
    ...readdirSync(reference).filter(name => name.endsWith('.md')).map(name => new URL(name, reference))];
  assert.ok(documents.some(document => document.pathname.endsWith('/wire.md')));
  for (const document of documents) {
    assert.doesNotMatch(readFileSync(document, 'utf8'),
      /from\s+["']request-seal|npm install request-seal(?:[ \t]|\r?$)/m,
      `Unscoped npm package in ${document.pathname.split('/').pop()}`);
  }
});
