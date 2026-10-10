import {snapshotOptions} from '../brand.ts';
import {CRYPTO_MAX_BYTES_CEILING, CRYPTO_DEFAULT_MAX_BYTES} from '../constants.ts';
import {cryptoError} from '../errors/types.ts';
import {err, ok, type Result} from '../result.ts';
/** Read caller-owned operation options once, before algorithm or key resolution. */
export function byteLimit(options: unknown): Result<number> {
  const snapshot = snapshotOptions(options, ['maxBytes']);
  if (!snapshot.ok) return err(cryptoError('invalid_options'));
  const value = Object.hasOwn(snapshot.value, 'maxBytes')
    ? snapshot.value.maxBytes : CRYPTO_DEFAULT_MAX_BYTES;
  return typeof value === 'number' && Number.isInteger(value) &&
    value >= 1 && value <= CRYPTO_MAX_BYTES_CEILING
    ? ok(value) : err(cryptoError('invalid_options'));
}
