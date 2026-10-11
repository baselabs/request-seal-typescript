import { SF_MAX_INTEGER, CLOCK_MAX_SECONDS, TIMEOUT_MAX_MS } from './constants.ts';
import { ok, err, type Result } from './result.ts';
import { structuredFieldsError, coreError, custodyError } from './errors/types.ts';
/** Check whether a value is a JavaScript safe integer. */
export const safeInteger = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value);
/** Validate the Structured Fields integer range and reject negative zero. */
export function structuredInteger(value: unknown): Result<number> {
  return safeInteger(value) && !Object.is(value, -0) && Math.abs(value) <= SF_MAX_INTEGER ? ok(value) : err(structuredFieldsError('invalid_value'));
}
/** Validate a Structured Fields date using the integer range. */
export const structuredDate = structuredInteger;
/** A decimal stored as an integer scaled by one thousand. */
export type Decimal = Readonly<{scaled: number; scale: 3}>;
/** Parse decimal source text without rounding or a floating-point conversion. */
export function parseDecimal(value: unknown): Result<Decimal> {
  if (typeof value !== 'string') return err(structuredFieldsError('invalid_value'));
  const match = /^(-?)([0-9]{1,12})\.([0-9]{1,3})$/.exec(value);
  if (!match) return err(structuredFieldsError('invalid_value'));
  const magnitude = Number(match[2]) * 1000 + Number(match[3]!.padEnd(3, '0'));
  return ok(Object.freeze({scaled: match[1] === '-' && magnitude !== 0 ? -magnitude : magnitude, scale: 3}));
}
/** Validate a nonnegative Unix clock value within the supported range. */
export function clockSeconds(value: unknown): Result<number> {
  return safeInteger(value) && value >= 0 && value <= CLOCK_MAX_SECONDS ? ok(value) : err(coreError('invalid_clock', 'freshness'));
}
/** Validate a positive timeout within the custody time limit. */
export function timeoutMs(value: unknown): Result<number> {
  return safeInteger(value) && value >= 1 && value <= TIMEOUT_MAX_MS ? ok(value) : err(custodyError('invalid_options'));
}
