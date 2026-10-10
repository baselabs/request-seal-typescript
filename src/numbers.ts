import { SF_MAX_INTEGER, CLOCK_MAX_SECONDS, TIMEOUT_MAX_MS } from './constants.ts';
import { ok, err, type Result } from './result.ts';
import { structuredFieldsError, coreError, custodyError } from './errors/types.ts';
export const safeInteger = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value);
export function structuredInteger(value: unknown): Result<number> {
  return safeInteger(value) && !Object.is(value, -0) && Math.abs(value) <= SF_MAX_INTEGER ? ok(value) : err(structuredFieldsError('invalid_value'));
}
export const structuredDate = structuredInteger;
export type Decimal = Readonly<{scaled: number; scale: 3}>;
/** Parse decimal source text without rounding or a floating-point conversion. */
export function parseDecimal(value: unknown): Result<Decimal> {
  if (typeof value !== 'string') return err(structuredFieldsError('invalid_value'));
  const match = /^(-?)([0-9]{1,12})\.([0-9]{1,3})$/.exec(value);
  if (!match) return err(structuredFieldsError('invalid_value'));
  const magnitude = Number(match[2]) * 1000 + Number(match[3]!.padEnd(3, '0'));
  return ok(Object.freeze({scaled: match[1] === '-' && magnitude !== 0 ? -magnitude : magnitude, scale: 3}));
}
export function clockSeconds(value: unknown): Result<number> {
  return safeInteger(value) && value >= 0 && value <= CLOCK_MAX_SECONDS ? ok(value) : err(coreError('invalid_clock', 'freshness'));
}
export function timeoutMs(value: unknown): Result<number> {
  return safeInteger(value) && value >= 1 && value <= TIMEOUT_MAX_MS ? ok(value) : err(custodyError('invalid_options'));
}
