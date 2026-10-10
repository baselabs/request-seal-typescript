import { snapshotOptions } from '../brand.ts';
import { CLOCK_MAX_SECONDS, KEY_IDENTITY_MAX_BYTES, FRESHNESS_MAX_SKEW_SECONDS, SF_MAX_INTEGER } from '../constants.ts';
import { coreError, replayError } from '../errors/types.ts';
import { ok, err, type Result } from '../result.ts';
import type { ReplayClaim } from '../replay-port.ts';
const claims = new WeakSet<object>();
export function validSeconds(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= CLOCK_MAX_SECONDS;
}
/** Exact signed-64-bit lower bound; bigint preserves ends outside safe numbers. */
export function validRetention(value: unknown): value is number | bigint {
  return typeof value === 'bigint'
    ? value >= -9223372036854775808n && value <= BigInt(CLOCK_MAX_SECONDS)
    : typeof value === 'number' && Number.isSafeInteger(value) && value <= CLOCK_MAX_SECONDS;
}
// Read the actual typed-array byte length; subclasses may shadow length.
const arrayLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint16Array.prototype), 'length')!.get!;
const apply = Reflect.apply;
export function boundedReplayBytes(v: unknown): v is Uint8Array {
  if (!(v instanceof Uint8Array)) return false;
  const length: number = apply(arrayLength, v, []);
  return length >= 1 && length <= KEY_IDENTITY_MAX_BYTES;
};
export function isReplayClaim(value: unknown): value is ReplayClaim {
  return typeof value === 'object' && value !== null && claims.has(value);
}
export function createClaim(input: unknown): Result<ReplayClaim> {
  try {
    const r = snapshotOptions(input, ['namespace', 'key', 'retainUntil']);
    if (!r.ok || !boundedReplayBytes(r.value.namespace) || !boundedReplayBytes(r.value.key) || !validRetention(r.value.retainUntil)) return err(replayError('invalid_claim'));
    const namespace = new Uint8Array(r.value.namespace), key = new Uint8Array(r.value.key), retainUntil = r.value.retainUntil;
    const claim = Object.freeze({get namespace() { return new Uint8Array(namespace); }, get key() { return new Uint8Array(key); }, retainUntil});
    claims.add(claim); return ok(claim);
  } catch { return err(replayError('invalid_claim')); }
}
/** Exclusive expiration, inclusive max age. Authenticate the window before deriving retention. */
export function retentionEnd(input: unknown): Result<number> {
  try {
    const r = snapshotOptions(input, ['created', 'expires', 'maxAge', 'skew']);
    if (!r.ok || Object.keys(r.value).length !== 4) return err(replayError('invalid_options'));
    const {created, expires, maxAge, skew} = r.value;
    const timestamp = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && Math.abs(v) <= SF_MAX_INTEGER;
    if (!(created === null || timestamp(created)) || !(expires === null || timestamp(expires)) || !(maxAge === null || validSeconds(maxAge) && maxAge > 0) || typeof skew !== 'number' || !Number.isInteger(skew) || skew < 0 || skew > FRESHNESS_MAX_SKEW_SECONDS || expires === null && maxAge === null || maxAge !== null && created === null) return err(replayError('invalid_options'));
    const end = Math.min(expires === null ? Infinity : expires + skew, maxAge === null ? Infinity : (created as number) + maxAge + skew + 1);
    return ok(end);
  } catch { return err(replayError('invalid_options')); }
}
/** Public claim retention caps the authenticated acceptance end. */
export function retainUntil(input: unknown): Result<number> {
  const r = retentionEnd(input);
  return r.ok && r.value > CLOCK_MAX_SECONDS ? err(coreError('retention_exceeded', 'replay')) : r;
}
/** Injective byte encoding, also suitable for PostgreSQL decode($n,'hex'). */
export function hex(bytes: Uint8Array): string { return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(''); }
export function claimRow(input: unknown): Result<readonly [string, string, string]> {
  if (!isReplayClaim(input)) return err(replayError('invalid_claim'));
  return ok(Object.freeze([hex(input.namespace), hex(input.key), input.retainUntil.toString()] as const));
}
export const Claim = Object.freeze({create: createClaim, valid: isReplayClaim});
