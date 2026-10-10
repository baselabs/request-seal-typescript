import type nodeTest from 'node:test';
import {readFileSync} from 'node:fs';
import {selectRuntimeLimits} from '../../tools/conformance/runtime-limits.ts';
export function runtimeTest(test: typeof nodeTest, file: string): typeof nodeTest {
  const limits = selectRuntimeLimits(JSON.parse(readFileSync(new URL('../../tools/conformance/runtime-limits.json', import.meta.url), 'utf8')), process.versions);
  const limit = limits.find(entry => entry.id === 'test_file/' + file);
  if (!limit) return test;
  return ((name: string, options: unknown, fn?: unknown) => {
    const attrs = typeof options === 'function' ? {} : options as object;
    return test(name, {...attrs, skip: limit.reason}, (typeof options === 'function' ? options : fn) as () => void);
  }) as typeof nodeTest;
}
