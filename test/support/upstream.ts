import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { decodeJson, type JsonNode } from '../../src/json.ts';
export const root = new URL('../fixtures/upstream/', import.meta.url);
export function read(origin: string, file: string): Uint8Array {
  return readFileSync(new URL(`${origin}/${file}`, root));
}
export function json(origin: string, file: string): any {
  const decoded = decodeJson(read(origin, file), {
    maxBytes: 16_777_216,
    maxDepth: 64,
    maxMembers: 100_000,
    maxArrayLength: 100_000,
    maxStringBytes: 1_048_576,
  });
  if (!decoded.ok) throw new Error('Invalid upstream JSON');
  const plain = (node: JsonNode): any =>
    node === null || typeof node !== 'object'
      ? node
      : node.kind === 'number'
        ? node
        : node.kind === 'array'
          ? node.items.map(plain)
          : Object.fromEntries(node.pairs.map(([k, v]) => [k, plain(v)]));
  return plain(decoded.value.node);
}
export function files(origin: string, path = ''): string[] {
  return readdirSync(new URL(`${origin}/${path}`, root), { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? files(origin, join(path, e.name) + '/') : [path + e.name],
  );
}
