import type { Result } from '../result.ts';
import type { Adapter } from './support.ts';
export type DeliveryOutcome = 'answered' | 'refused' | 'unknown';
export type DeliveryState = { outcome: DeliveryOutcome; transports: number };
// Keep only the conclusion, keyed by the actual returned Result. No runtime error,
// caller bytes, address, message or stack survives this boundary.
const deliveries = {
  fetch: {answered: new WeakSet<object>(), refused: new WeakSet<object>()},
  'node-http': {answered: new WeakSet<object>(), refused: new WeakSet<object>()},
};
export function recordDelivery<T>(adapter: Adapter, result: Result<T>, state: DeliveryState): Result<T> {
  let outcome = state.outcome;
  if (!result.ok) {
    if (result.error.kind === 'adapter' && result.error.stage === 'verify') outcome = 'unknown';
    else if (outcome !== 'refused' || state.transports > 1) outcome = 'unknown';
  }
  const evidence = deliveries[adapter];
  evidence.answered.delete(result);
  evidence.refused.delete(result);
  if (outcome !== 'unknown') evidence[outcome].add(result);
  return result;
}
export function classifyDelivery(adapter: Adapter, result: unknown): DeliveryOutcome {
  if (result === null || typeof result !== 'object') return 'unknown';
  const evidence = deliveries[adapter];
  return evidence.answered.has(result) ? 'answered' : evidence.refused.has(result) ? 'refused' : 'unknown';
}
export function responseOutcome(status: number): DeliveryOutcome {
  return Number.isInteger(status) && status > 0 && status !== 502 && status !== 504
    ? 'answered' : 'unknown';
}
function own(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}
function unsent(error: unknown, depth: number): boolean {
  if (!error || typeof error !== 'object' || depth === 0) return false;
  // Node net.js lookupAndConnect/afterConnect reports getaddrinfo/connect as
  // syscall, before the HTTP write queue can flush. Codes alone (ECONNRESET,
  // ETIMEDOUT, TLS alerts) prove no phase: https://nodejs.org/api/errors.html#errorsystemcall
  const syscall = own(error, 'syscall');
  if (syscall === 'getaddrinfo' || syscall === 'connect') return true;
  // Undici v6.21.0 lib/core/connect.js onConnectTimeout runs only before the
  // connector callback succeeds; lib/web/fetch/index.js preserves it as cause.
  // https://github.com/nodejs/undici/blob/v6.21.0/lib/core/connect.js
  if (own(error, 'code') === 'UND_ERR_CONNECT_TIMEOUT') return true;
  const errors = own(error, 'errors');
  if (Array.isArray(errors)) {
    return errors.length > 0 && errors.length <= 16 &&
      errors.every(e => unsent(e, depth - 1));
  }
  return unsent(own(error, 'cause'), depth - 1);
}
export function transportOutcome(error: unknown, node: boolean): DeliveryOutcome {
  if (!node) return 'unknown';
  try { return unsent(error, 4) ? 'refused' : 'unknown'; }
  catch { return 'unknown'; }
}
