import { err, ok, type Result } from './result.ts';
import { JOSE_MAX_COMPACT_BYTES } from './constants.ts';
import { messageError, joseError } from './errors/types.ts';
/** Fetch ByteString: every UTF-16 code unit represents one octet. Always copied. */
export function byteString(input: unknown): Result<Uint8Array<ArrayBuffer>> {
  try {
    if (input instanceof Uint8Array) return ok(new Uint8Array(input));
    if (typeof input !== 'string') return err(messageError('invalid_message'));
    const bytes = new Uint8Array(input.length);
    for (let i = 0; i < input.length; i++) {
      const code = input.charCodeAt(i);
      // boundedData in crypto/primitive.ts checks the same rule before copying.
      if (code > 255) return err(messageError('invalid_message'));
      bytes[i] = code;
    }
    return ok(bytes);
  } catch { return err(messageError('invalid_message')); }
}
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function encode(bytes: Uint8Array, url: boolean): string {
  const chars = url ? alphabet.slice(0, 62) + '-_' : alphabet;
  const out: string[] = [];
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!, b = bytes[i + 1] ?? 0, c = bytes[i + 2] ?? 0;
    out.push(chars[a >>> 2]!, chars[((a & 3) << 4) | (b >>> 4)]!);
    if (i + 1 < bytes.length) out.push(chars[((b & 15) << 2) | (c >>> 6)]!); else if (!url) out.push('=');
    if (i + 2 < bytes.length) out.push(chars[c & 63]!); else if (!url) out.push('=');
  }
  return out.join('');
}
export const encodeBase64 = (bytes: Uint8Array): string => encode(bytes, false);
export const encodeBase64Url = (bytes: Uint8Array): string => encode(bytes, true);
function decode(input: unknown, url: boolean): Result<Uint8Array<ArrayBuffer>> {
  const invalid = () => err<Uint8Array<ArrayBuffer>>(joseError('invalid_base64', 'input'));
  if (typeof input !== 'string') return invalid();
  if (input.length > JOSE_MAX_COMPACT_BYTES) return err(joseError('limit', 'input'));
  if (url ? !/^[A-Za-z0-9_-]*$/.test(input) || input.length % 4 === 1 : !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(input)) return invalid();
  const chars = url ? alphabet.slice(0, 62) + '-_' : alphabet;
  const end = input.indexOf('='); const length = end === -1 ? input.length : end;
  const bytes = new Uint8Array(Math.floor(length * 6 / 8));
  let bits = 0, value = 0, offset = 0;
  for (let i = 0; i < length; i++) {
    value = (value << 6) | chars.indexOf(input[i]!); bits += 6;
    if (bits >= 8) { bits -= 8; bytes[offset++] = (value >>> bits) & 255; value &= (1 << bits) - 1; }
  }
  if (value !== 0) return invalid();
  return ok(bytes);
}
export const decodeBase64 = (input: unknown): Result<Uint8Array<ArrayBuffer>> => decode(input, false);
export const decodeBase64Url = (input: unknown): Result<Uint8Array<ArrayBuffer>> => decode(input, true);
