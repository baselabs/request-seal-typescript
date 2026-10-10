import {encodeUtf8} from './runtime.ts';
import {ok, err, type Result} from './result.ts';
import {cryptoError} from './errors/types.ts';
import {encodeBase64Url} from './bytes.ts';
import {
  resolveAlgorithm,
  importParameters,
  type Spec,
} from './crypto/algorithm.ts';
import * as subtle from './crypto/subtle.ts';
import {verifyKey} from './crypto/primitive.ts';
import {decodeKey, publicSpki, writePem} from './custody/der.ts';
import {
  snapshotJwk,
  publicMembers,
  compatible,
  permitted,
  type Jwk,
} from './custody/jwk.ts';
const branded = new WeakSet<object>();
const token = Object.freeze({});
export function isPublicKey(value: unknown): value is PublicKey {
  return typeof value === 'object' && value !== null && branded.has(value);
}
/** Public components only. Metadata restrictions survive every use and export. */
export class PublicKey {
  #jwk: Jwk;
  #pssOnly: boolean;
  #spki: Uint8Array<ArrayBuffer>;
  private constructor(
    t: object,
    jwk: Jwk,
    pssOnly: boolean,
    spki: Uint8Array<ArrayBuffer>,
  ) {
    if (t !== token) throw new TypeError('Invalid public key construction');
    this.#jwk = jwk;
    this.#pssOnly = pssOnly;
    this.#spki = new Uint8Array(spki);
    branded.add(this);
    Object.freeze(this);
  }
  static async import(
    material: unknown,
    format: 'jwk' | 'pem' | 'spki' | 'der' = 'jwk',
  ): Promise<Result<PublicKey>> {
    try {
      let jwk: Jwk,
        pssOnly = false;
      if (format === 'jwk') {
        const r = snapshotJwk(material, false);
        if (!r.ok) return err(cryptoError('invalid_key'));
        jwk = r.value;
      } else if (format === 'pem' || format === 'spki' || format === 'der') {
        const r = decodeKey(material, format === 'der' ? 'spki' : format);
        if (!r.ok) return err(cryptoError('invalid_key'));
        try {
          if (r.value.privateKey) return err(cryptoError('invalid_key'));
          jwk = r.value.jwk;
          pssOnly = r.value.pssOnly;
        } finally {
          r.value.der.fill(0);
        }
        const checked = snapshotJwk(jwk, false);
        if (!checked.ok) return err(cryptoError('invalid_key'));
        jwk = checked.value;
      } else return err(cryptoError('unsupported_format'));
      const der = publicSpki(jwk, pssOnly);
      if (!der.ok) return err(cryptoError('invalid_key'));
      // Runtime point validation supplements the owned structural checks.
      const selector =
        jwk.kty === 'RSA'
          ? 'rsa-pss-sha512'
          : jwk.kty === 'EC'
            ? jwk.crv === 'P-256'
              ? 'ecdsa-p256-sha256'
              : 'ecdsa-p384-sha384'
            : 'ed25519';
      const resolved = resolveAlgorithm(selector);
      if (!resolved.ok) return resolved;
      await subtle.importKey(
        'jwk',
        publicMembers(jwk) as {kty?: string},
        importParameters(resolved.value),
        false,
        ['verify'],
      );
      return ok(new PublicKey(token, jwk, pssOnly, der.value));
    } catch {
      return err(cryptoError('invalid_key'));
    }
  }
  jwk(): Result<Jwk> {
    return this.#pssOnly
      ? err(cryptoError('unsupported_format'))
      : ok(this.#jwk);
  }
  spki(): Result<Uint8Array<ArrayBuffer>> {
    return ['alg', 'use', 'key_ops'].some((k) => Object.hasOwn(this.#jwk, k))
      ? err(cryptoError('unsupported_format'))
      : ok(new Uint8Array(this.#spki));
  }
  pem(): Result<string> {
    const r = this.spki();
    if (!r.ok) return r;
    const p = writePem('PUBLIC KEY', r.value);
    return p.ok ? p : err(cryptoError('invalid_key'));
  }
  async thumbprint(): Promise<Result<string>> {
    try {
      return ok(
        encodeBase64Url(
          new Uint8Array(
            await subtle.digest(
              'SHA-256',
              encodeUtf8(
                JSON.stringify(publicMembers(this.#jwk)),
              ),
            ),
          ),
        ),
      );
    } catch {
      return err(cryptoError('invalid_key'));
    }
  }
  /** Internal equivalence ignores PSS-only type and JWK metadata. */
  identityBytes(): Result<Uint8Array<ArrayBuffer>> {
    return ok(
      encodeUtf8(JSON.stringify(publicMembers(this.#jwk))),
    );
  }
  bind(algorithm: unknown): Result<true> {
    const resolved = resolveAlgorithm(algorithm, true);
    if (!resolved.ok) return resolved;
    const spec = resolved.value;
    const allowed = spec.unwrap
      ? permitted(this.#jwk, spec, 'encrypt') ||
        permitted(this.#jwk, spec, 'wrapKey')
      : permitted(this.#jwk, spec, 'verify');
    return compatible(this.#jwk, spec, this.#pssOnly) && allowed
      ? ok(true)
      : err(cryptoError('key_mismatch'));
  }
  async verify(
    algorithm: unknown,
    signature: unknown,
    data: unknown,
  ): Promise<Result<true>> {
    const resolved = resolveAlgorithm(algorithm);
    if (!resolved.ok) return resolved;
    const spec: Spec = resolved.value;
    try {
      if (
        !compatible(this.#jwk, spec, this.#pssOnly) ||
        !permitted(this.#jwk, spec, 'verify')
      )
        return err(cryptoError('key_mismatch'));
      const key = await subtle.importKey(
        'jwk',
        publicMembers(this.#jwk) as {kty?: string},
        importParameters(spec),
        false,
        ['verify'],
      );
      return await verifyKey(spec, key, signature, data);
    } catch {
      return err(cryptoError('invalid_key'));
    }
  }
  toJSON(): Readonly<{kind: string; pssOnly: boolean}> {
    return Object.freeze({kind: 'PublicKey', pssOnly: this.#pssOnly});
  }
  [Symbol.for('nodejs.util.inspect.custom')](): unknown {
    return this.toJSON();
  }
  [Symbol.for('Deno.customInspect')](): unknown {
    return this.toJSON();
  }
}

Object.freeze(PublicKey.prototype);
Object.freeze(PublicKey);
const publicVerify = Function.prototype.call.bind(PublicKey.prototype.verify);
const publicBind = Function.prototype.call.bind(PublicKey.prototype.bind);
export function verifyPublicKey(
  key: PublicKey,
  algorithm: unknown,
  signature: unknown,
  data: unknown,
): Promise<Result<true>> {
  return publicVerify(key, algorithm, signature, data);
}
export function bindPublicKey(
  key: PublicKey,
  algorithm: unknown,
): Result<true> {
  return publicBind(key, algorithm);
}
