import {denoInspection} from '../brand.ts';
import {snapshotOptions} from '../brand.ts';
import {isContext, remainingMs, run, type Context} from '../context.ts';
import {
  JOSE_MAX_PLAINTEXT_BYTES,
  JOSE_MAX_COMPACT_BYTES,
} from '../constants.ts';
import {custodyError} from '../errors/types.ts';
import {err, ok, type Result} from '../result.ts';
import * as subtle from '../crypto/subtle.ts';
const keys = new WeakSet<object>();
const token = Object.freeze({});
/** A confined AES decryption capability without an exported key. */
export type UnwrappedKey = Readonly<{
  length: 128 | 256;
  /** Authenticate and decrypt content using confined key material. */
  decrypt: (
    ciphertext: unknown,
    options: unknown,
    context: Context,
  ) => Promise<Result<Uint8Array<ArrayBuffer>>>;
  /** Release retained custody and invalidate the capability. */
  release: () => Promise<Result<true>>;
}>;
/** Check the private brand of an unwrapped content key. */
export function isUnwrappedKey(value: unknown): value is UnwrappedKey {
  return typeof value === 'object' && value !== null && keys.has(value);
}
/** Operation-only AES capability; never exports the unwrapped key or CryptoKey. */
class ContentKey implements UnwrappedKey {
  #length: 128 | 256;
  #key: CryptoKey | undefined;
  constructor(t: object, key: CryptoKey) {
    if (t !== token) throw new TypeError('Invalid content key construction');
    const length = (key.algorithm as {name: string; length: number}).length;
    if (key.algorithm.name !== 'AES-GCM' || (length !== 128 && length !== 256)) throw new TypeError('Invalid content key');
    this.#length = length;
    this.#key = key;
    keys.add(this);
    Object.freeze(this);
  }
  get length(): 128 | 256 { return this.#length; }
  async decrypt(
    ciphertext: unknown,
    options: unknown,
    context: Context,
  ): Promise<Result<Uint8Array<ArrayBuffer>>> {
    if (!this.#key) return err(custodyError('key_not_found'));
    if (!isContext(context)) return err(custodyError('invalid_options'));
    const r = snapshotOptions(options, ['iv', 'additionalData', 'tagLength']);
    if (!r.ok) return err(custodyError('invalid_options'));
    const {iv, additionalData, tagLength} = r.value;
    if (
      !(iv instanceof Uint8Array) ||
      iv.length !== 12 ||
      (additionalData !== undefined &&
        !(additionalData instanceof Uint8Array)) ||
      (tagLength !== undefined && tagLength !== 128)
    )
      return err(custodyError('invalid_options'));
    if (
      !(ciphertext instanceof Uint8Array) ||
      ciphertext.length < 16 ||
      ciphertext.length > JOSE_MAX_PLAINTEXT_BYTES + 16 ||
      (additionalData instanceof Uint8Array &&
        additionalData.length > JOSE_MAX_COMPACT_BYTES)
    )
      return err(custodyError('invalid_data'));
    const key = this.#key;
    const data = new Uint8Array(ciphertext),
      nonce = new Uint8Array(iv),
      aad =
        additionalData instanceof Uint8Array
          ? new Uint8Array(additionalData)
          : new Uint8Array();
    let produced: Uint8Array<ArrayBuffer> | undefined;
    const result = await run(context, async () => {
      try {
        const plain = new Uint8Array(
          await subtle.decrypt(
            {name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128},
            key,
            data,
          ),
        );
        produced = plain;
        if (remainingMs(context) <= 0) {
          plain.fill(0);
          return err(custodyError('deadline_exceeded'));
        }
        if (!this.#key) {
          plain.fill(0);
          return err(custodyError('key_not_found'));
        }
        return ok(plain);
      } catch {
        return err(custodyError('decryption_failed'));
      } finally {
        data.fill(0);
        nonce.fill(0);
        aad.fill(0);
      }
    });
    if (!result.ok) produced?.fill(0);
    return result;
  }
  async release(): Promise<Result<true>> {
    this.#key = undefined;
    return ok(true);
  }
  toJSON(): Readonly<{kind: string}> {
    return Object.freeze({kind: 'UnwrappedKey'});
  }
  [Symbol.for('nodejs.util.inspect.custom')](): unknown {
    return this.toJSON();
  }
  [Symbol.for('Deno.customInspect')](render?: unknown): unknown {
    return denoInspection(render, this.toJSON());
  }
}
export function confineContentKey(key: CryptoKey): UnwrappedKey {
  return new ContentKey(token, key);
}

Object.freeze(ContentKey.prototype);
Object.freeze(ContentKey);
