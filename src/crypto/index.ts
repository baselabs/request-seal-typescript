import {byteLimit} from './options.ts';
import {CRYPTO_MAX_BYTES_CEILING, SIGNATURE_MAX_BYTES} from '../constants.ts';
import {err, type Result} from '../result.ts';
import {cryptoError} from '../errors/types.ts';
import {isKeyHandle, verifyHandle} from '../key_handle.ts';
import {isPublicKey, verifyPublicKey, bindPublicKey} from '../public_key.ts';
import {withDeadline} from '../context.ts';
import {resolveAlgorithm, algorithms} from './algorithm.ts';
import {dataBytes, boundedData, boundedBinary} from './primitive.ts';
function normalize<T>(r: Result<T>): Result<T> {
  if (r.ok) return r;
  if (r.error.kind === 'custody' &&
      ['key_not_found', 'deadline_exceeded', 'custodian_failure', 'custodian_unavailable'].includes(r.error.reason)) return r;
  const reason = r.error.reason;
  return err(
    cryptoError(
      [
        'unsupported_algorithm',
        'unsupported_format',
        'invalid_key',
        'invalid_options',
        'key_mismatch',
        'invalid_data',
        'invalid_signature',
      ].includes(reason)
        ? (reason as 'invalid_key')
        : 'invalid_key',
    ),
  );
}
/** Sign bounded bytes with a branded custody handle. */
export async function sign(
  algorithm: unknown,
  key: unknown,
  data: unknown,
  options: unknown = {},
): Promise<Result<Uint8Array<ArrayBuffer>>> {
  const maximum = byteLimit(options);
  if (!maximum.ok) return maximum;
  const spec = resolveAlgorithm(algorithm);
  if (!spec.ok) return spec;
  if (!boundedData(data, maximum.value)) return err(cryptoError('invalid_data'));
  if (!isKeyHandle(key)) return err(cryptoError('invalid_key'));
  const c = withDeadline();
  if (!c.ok) return err(cryptoError('invalid_key'));
  return normalize(await key.sign(algorithm, data, c.value, {maxBytes: maximum.value}));
}
/** Verify a signature using a branded key or custody handle. */
export async function verify(
  algorithm: unknown,
  key: unknown,
  signature: unknown,
  data: unknown,
  options: unknown = {},
): Promise<Result<true>> {
  const maximum = byteLimit(options);
  if (!maximum.ok) return maximum;
  const spec = resolveAlgorithm(algorithm);
  if (!spec.ok) return spec;
  const bytes = dataBytes(data, maximum.value);
  if (!bytes.ok) return bytes;
  try {
    if (isPublicKey(key)) {
      const bound = bindPublicKey(key, algorithm);
      if (!bound.ok) return bound;
    } else if (isKeyHandle(key)) {
      const bound = resolveAlgorithm(key.algorithm);
      if (!bound.ok || bound.value.id !== spec.value.id)
        return err(cryptoError('key_mismatch'));
    } else return err(cryptoError('invalid_key'));
    if (
      !boundedBinary(signature, SIGNATURE_MAX_BYTES)
    )
      return err(cryptoError('invalid_signature'));
    if (isPublicKey(key))
      return await verifyPublicKey(key, algorithm, signature, bytes.value, maximum.value);
    const c = withDeadline();
    if (!c.ok) return c;
    return normalize(
      await verifyHandle(key, algorithm, signature, bytes.value, c.value, {maxBytes: maximum.value}),
    );
  } catch {
    return err(cryptoError('invalid_signature'));
  } finally {
    bytes.value.fill(0);
  }
}
/** Return the fixed maximum cryptographic input byte limit. */
export function maxBytesCeiling(): number {return CRYPTO_MAX_BYTES_CEILING;}
/** Bounded cryptographic signing and verification operations. */
export const Crypto = Object.freeze({
  /** List supported HTTP signature algorithm tokens. */
  algorithms,
  /** Sign bounded bytes with a branded custody handle. */
  sign,
  /** Verify a signature using a branded key or custody handle. */
  verify,
  /** Return the fixed maximum cryptographic input byte limit. */
  maxBytesCeiling});
