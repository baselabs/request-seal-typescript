import { err, ok, type Result } from './result.ts';
import { coreError } from './errors/types.ts';
/** Node and Deno inspection that shows only `view()`. Deno passes a render callback
 * and prints the string it returns; Node formats the returned object itself. */
export function inspection(view: () => unknown): PropertyDescriptorMap {
  return {
    [Symbol.for('nodejs.util.inspect.custom')]: {value: view},
    [Symbol.for('Deno.customInspect')]: {value: (render?: unknown) => denoInspection(render, view())},
  };
}
/** Deno.customInspect body: render the redacted view through Deno's callback when given. */
export function denoInspection(render: unknown, view: unknown): unknown {
  return typeof render === 'function' ? (render as (value: unknown) => string)(view) : view;
}
/** Snapshot plain data, then freeze the owned structures. Uint8Array copies remain mutable:
 * JavaScript cannot freeze nonempty typed arrays; caller buffers are never retained.
 * Accessors and other object types reject without being invoked or frozen.
 */
export function deepFreeze<T>(value: T): Result<T> {
  try {
    const copies = new WeakMap<object, object>(), pending: [object, object][] = [];
    function copy(input: unknown): unknown {
      if (typeof input === 'function') throw new TypeError();
      if (typeof input !== 'object' || input === null) return input;
      const existing = copies.get(input); if (existing) return existing;
      if (input instanceof Uint8Array) {
        const bytes = new Uint8Array(input); copies.set(input, bytes); return bytes;
      }
      const prototype = Object.getPrototypeOf(input);
      if (!Array.isArray(input) && prototype !== Object.prototype && prototype !== null) throw new TypeError();
      const output = Array.isArray(input) ? [] : Object.create(prototype) as object;
      copies.set(input, output); pending.push([input, output]); return output;
    }
    const snapshot = copy(value) as T;
    while (pending.length) {
      const [input, output] = pending.pop()!;
      for (const key of Reflect.ownKeys(input)) {
        const descriptor = Object.getOwnPropertyDescriptor(input, key)!;
        if (!Object.hasOwn(descriptor, 'value')) throw new TypeError();
        if (Array.isArray(input) && key === 'length') { (output as unknown[]).length = descriptor.value as number; continue; }
        Object.defineProperty(output, key, {value: copy(descriptor.value), enumerable: descriptor.enumerable ?? false, configurable: true, writable: true});
      }
      Object.freeze(output);
    }
    return ok(snapshot);
  } catch { return err(coreError('invalid_options', 'input')); }
}
/** Read each allowed own property once. Inherited options never become choices. */
export function snapshotOptions<K extends string>(input: unknown, knownKeys: readonly K[]): Result<Readonly<Partial<Record<K, unknown>>>> {
  try {
    if (!input || typeof input !== 'object' || Array.isArray(input)) return err(coreError('invalid_options', 'input'));
    const allowed = new Set<string>(knownKeys);
    for (const key of Reflect.ownKeys(input)) if (typeof key !== 'string' || !allowed.has(key)) return err(coreError('invalid_options', 'input'));
    const snapshot = Object.create(null) as Partial<Record<K, unknown>>;
    for (const key of allowed as Set<K>) if (Object.hasOwn(input, key)) snapshot[key] = (input as Record<K, unknown>)[key];
    return ok(Object.freeze(snapshot));
  } catch { return err(coreError('invalid_options', 'input')); }
}
