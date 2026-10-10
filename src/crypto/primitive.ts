import {byteString} from '../bytes.ts';
import {CRYPTO_DEFAULT_MAX_BYTES, SIGNATURE_MAX_BYTES} from '../constants.ts';
import {cryptoError} from '../errors/types.ts';
import {err, ok, type Result} from '../result.ts';
import {
  CURVE_ORDERS,
  ED25519_ORDER,
  operationParameters,
  type Spec,
} from './algorithm.ts';
import * as subtle from './subtle.ts';
// Caller properties can shadow length and byteLength; capture the shared TypedArray getter.
// Uint16Array reaches that intrinsic even when Uint8Array allocations are instrumented.
const byteLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint16Array.prototype), 'byteLength')!.get!;
export function boundedBinary(input: unknown, maximum: number): input is Uint8Array {
  try {return input instanceof Uint8Array && byteLength.call(input) <= maximum;} catch {return false;}
}
export function dataBytes(input: unknown, maximum = CRYPTO_DEFAULT_MAX_BYTES): Result<Uint8Array<ArrayBuffer>> {
  try {
    if (
      !(typeof input === 'string' ? input.length <= maximum : boundedBinary(input, maximum))
    )
      return err(cryptoError('invalid_data'));
    const r = byteString(input);
    return r.ok && r.value.length <= maximum ? r : err(cryptoError('invalid_data'));
  } catch {
    return err(cryptoError('invalid_data'));
  }
}
export function unsigned(bytes: Uint8Array, little = false): bigint {
  let n = 0n;
  if (little)
    for (let i = bytes.length - 1; i >= 0; i--)
      n = n * 256n + BigInt(bytes[i]!);
  else for (const b of bytes) n = n * 256n + BigInt(b);
  return n;
}
function bound(spec: Spec, key: CryptoKey, op: 'sign' | 'verify'): boolean {
  const a = key.algorithm as {
    name: string;
    hash?: {name: string};
    namedCurve?: string;
    modulusLength?: number;
  };
  return (
    a.name === spec.name &&
    key.usages.includes(op) &&
    (!spec.hash || spec.family === 'ec' || a.hash?.name === spec.hash) &&
    (!spec.curve || a.namedCurve === spec.curve)
  );
}
function signatureValid(
  spec: Spec,
  key: CryptoKey,
  bytes: Uint8Array,
): boolean {
  const width =
    spec.family === 'rsa'
      ? Math.ceil((key.algorithm as {name: string; modulusLength: number}).modulusLength / 8)
      : spec.width;
  if (bytes.length !== width || bytes.length > SIGNATURE_MAX_BYTES)
    return false;
  if (spec.family === 'ec') {
    const r = unsigned(bytes.subarray(0, width / 2)),
      s = unsigned(bytes.subarray(width / 2)),
      order = CURVE_ORDERS[spec.curve!]!;
    return r > 0n && r < order && s > 0n && s < order;
  }
  if (spec.family === 'ed25519')
    return unsigned(bytes.subarray(32), true) < ED25519_ORDER;
  return true;
}
export async function signKey(
  spec: Spec,
  key: CryptoKey,
  input: unknown,
  maximum = CRYPTO_DEFAULT_MAX_BYTES,
): Promise<Result<Uint8Array<ArrayBuffer>>> {
  const data = dataBytes(input, maximum);
  if (!data.ok) return data;
  try {
    if (!bound(spec, key, 'sign')) return err(cryptoError('key_mismatch'));
    const bytes = new Uint8Array(
      await subtle.sign(operationParameters(spec), key, data.value),
    );
    return signatureValid(spec, key, bytes)
      ? ok(bytes)
      : err(cryptoError('invalid_signature'));
  } catch {
    return err(cryptoError('invalid_key'));
  } finally {
    data.value.fill(0);
  }
}
export async function verifyKey(
  spec: Spec,
  key: CryptoKey,
  signature: unknown,
  input: unknown,
  maximum = CRYPTO_DEFAULT_MAX_BYTES,
): Promise<Result<true>> {
  const data = dataBytes(input, maximum);
  if (!data.ok) return data;
  try {
    if (!bound(spec, key, 'verify')) return err(cryptoError('key_mismatch'));
    if (
      !(signature instanceof Uint8Array) ||
      !signatureValid(spec, key, signature)
    )
      return err(cryptoError('invalid_signature'));
    const copied = new Uint8Array(signature);
    try {
      return (await subtle.verify(
        operationParameters(spec),
        key,
        copied,
        data.value,
      )) === true
        ? ok(true)
        : err(cryptoError('invalid_signature'));
    } finally {
      copied.fill(0);
    }
  } catch {
    return err(cryptoError('invalid_key'));
  } finally {
    data.value.fill(0);
  }
}
