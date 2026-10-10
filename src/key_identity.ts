import {ok, err, type Result} from './result.ts';
import {custodyError} from './errors/types.ts';
import {KEY_IDENTITY_MAX_BYTES} from './constants.ts';
import {byteString} from './bytes.ts';
import {isPublicKey, type PublicKey} from './public_key.ts';
const identities = new WeakSet<object>();
const classKeys = new WeakMap<KeyIdentity, string>();
/** Internal, nonserialized canonical equivalence key for scoped identity merging. */
export function identityClassKey(identity: KeyIdentity): string | undefined { return classKeys.get(identity); }
const token = Object.freeze({});
export function isKeyIdentity(value: unknown): value is KeyIdentity {
  return typeof value === 'object' && value !== null && identities.has(value);
}
export class KeyIdentity {
  readonly kind: 'public' | 'symmetric' | 'unknown';
  #bytes: Uint8Array<ArrayBuffer> | undefined;
  private constructor(
    t: object,
    kind: KeyIdentity['kind'],
    bytes?: Uint8Array<ArrayBuffer>,
  ) {
    if (t !== token) throw new TypeError('Invalid identity construction');
    this.kind = kind;
    this.#bytes = bytes ? new Uint8Array(bytes) : undefined;
    if (this.#bytes) classKeys.set(this, kind + ":" + Array.from(this.#bytes, b => b.toString(16).padStart(2, "0")).join(""));
    identities.add(this);
    Object.freeze(this);
  }
  static fromPublic(key: PublicKey): Result<KeyIdentity> {
    if (!isPublicKey(key)) return err(custodyError('invalid_key'));
    const r = key.identityBytes();
    return r.ok
      ? ok(new KeyIdentity(token, 'public', r.value))
      : err(custodyError('invalid_key'));
  }
  static symmetric(value: unknown): Result<KeyIdentity> {
    try {
      if (
        (!(value instanceof Uint8Array) && typeof value !== 'string') ||
        (value as Uint8Array | string).length > KEY_IDENTITY_MAX_BYTES
      )
        return err(custodyError('invalid_options'));
      const r = byteString(value);
      return r.ok &&
        r.value.length > 0 &&
        r.value.length <= KEY_IDENTITY_MAX_BYTES
        ? ok(new KeyIdentity(token, 'symmetric', r.value))
        : err(custodyError('invalid_options'));
    } catch {
      return err(custodyError('invalid_options'));
    }
  }
  static unknown(): Result<KeyIdentity> {
    return ok(new KeyIdentity(token, 'unknown'));
  }
  static same(a: unknown, b: unknown): Result<boolean> {
    if (!isKeyIdentity(a) || !isKeyIdentity(b))
      return err(custodyError('invalid_key'));
    if (
      a.kind === 'unknown' ||
      b.kind !== a.kind ||
      a.#bytes!.length !== b.#bytes!.length
    )
      return ok(false);
    let diff = 0;
    for (let i = 0; i < a.#bytes!.length; i++)
      diff |= a.#bytes![i]! ^ b.#bytes![i]!;
    return ok(diff === 0);
  }
  toJSON(): Readonly<{kind: KeyIdentity['kind']}> {
    return Object.freeze({kind: this.kind});
  }
  [Symbol.for('nodejs.util.inspect.custom')](): unknown {
    return this.toJSON();
  }
  [Symbol.for('Deno.customInspect')](): unknown {
    return this.toJSON();
  }
}

Object.freeze(KeyIdentity.prototype);
Object.freeze(KeyIdentity);
