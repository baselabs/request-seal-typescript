import {snapshotOptions} from '../brand.ts';
import {
  CRYPTO_MAX_BYTES_CEILING,
  HMAC_MIN_BYTES,
  HMAC_MAX_BYTES,
  KEY_MAX_BYTES,
  SIGNATURE_MAX_BYTES,
} from '../constants.ts';
import {custodyError} from '../errors/types.ts';
import {err, ok, type Result} from '../result.ts';
import {withDeadline, run, type Context} from '../context.ts';
import {
  createKeyHandle,
  type KeyHandle,
  type Custodian,
} from '../key_handle.ts';
import {KeyIdentity} from '../key_identity.ts';
import {PublicKey} from '../public_key.ts';
import {
  resolveAlgorithm,
  selection,
  importParameters,
  type Spec,
} from '../crypto/algorithm.ts';
import {boundedBinary, signKey, verifyKey} from '../crypto/primitive.ts';
import * as subtle from '../crypto/subtle.ts';
import {decodeKey, publicSpki, type DecodedKey} from './der.ts';
import {
  component,
  snapshotJwk,
  publicMembers,
  publicMetadata,
  compatible,
  permitted,
  type Jwk,
} from './jwk.ts';
import {confineContentKey, type UnwrappedKey} from './content_key.ts';
/** @internal Direct custodian implementation; use the public factory for handles. */
export class LocalPort implements Custodian {
  #key: CryptoKey | undefined;
  #verify: CryptoKey | undefined;
  #public: PublicKey | undefined;
  #identity: KeyIdentity;
  #spec: Spec;
  constructor(
    key: CryptoKey,
    verify: CryptoKey | undefined,
    publicKey: PublicKey | undefined,
    identity: KeyIdentity,
    spec: Spec,
  ) {
    this.#key = key;
    this.#verify = verify;
    this.#public = publicKey;
    this.#identity = identity;
    this.#spec = spec;
    Object.freeze(this);
  }
  async sign(
    _algorithm: unknown,
    data: unknown,
    _context: Context,
  ): Promise<Result<Uint8Array<ArrayBuffer>>> {
    if (!boundedBinary(data, CRYPTO_MAX_BYTES_CEILING)) return err(custodyError('invalid_data'));
    return this.#key
      ? signKey(this.#spec, this.#key, data, CRYPTO_MAX_BYTES_CEILING)
      : err(custodyError('key_not_found'));
  }
  async verify(
    _algorithm: unknown,
    signature: unknown,
    data: unknown,
    _context: Context,
  ): Promise<Result<true>> {
    if (!boundedBinary(data, CRYPTO_MAX_BYTES_CEILING)) return err(custodyError('invalid_data'));
    return this.#verify
      ? verifyKey(this.#spec, this.#verify, signature, data, CRYPTO_MAX_BYTES_CEILING)
      : err(custodyError('key_not_found'));
  }
  async publicKey(): Promise<Result<PublicKey>> {
    return !this.#key
      ? err(custodyError('key_not_found'))
      : this.#public
        ? ok(this.#public)
        : err(custodyError('no_public_key'));
  }
  async identity(): Promise<Result<KeyIdentity>> {
    return this.#key ? ok(this.#identity) : err(custodyError('key_not_found'));
  }
  async unwrap(
    _algorithm: unknown,
    wrappedKey: unknown,
    _context: Context,
    options: unknown = {},
  ): Promise<Result<UnwrappedKey>> {
    if (!this.#key) return err(custodyError('key_not_found'));
    const r = snapshotOptions(options, ['length']);
    if (!r.ok) return err(custodyError('invalid_options'));
    const length = r.value.length ?? 256;
    if (length !== 128 && length !== 256)
      return err(custodyError('invalid_options'));
    if (
      !(wrappedKey instanceof Uint8Array) ||
      wrappedKey.length !==
        Math.ceil((this.#key.algorithm as {name: string; modulusLength: number}).modulusLength / 8) ||
      wrappedKey.length > SIGNATURE_MAX_BYTES
    )
      return err(custodyError('decryption_failed'));
    try {
      const key = await subtle.unwrapKey(
        'raw',
        new Uint8Array(wrappedKey),
        this.#key,
        {name: 'RSA-OAEP'},
        {name: 'AES-GCM', length},
        false,
        ['decrypt'],
      );
      if ((key.algorithm as {name: string; length: number}).length !== length)
        return err(custodyError('decryption_failed'));
      return ok(confineContentKey(key));
    } catch {
      return err(custodyError('decryption_failed'));
    }
  }
  async release(): Promise<Result<true>> {
    this.#key = undefined;
    this.#verify = undefined;
    this.#public = undefined;
    return ok(true);
  }
}
function sanitized(jwk: Jwk, privateKey: boolean): {kty?: string} {
  const out = Object.assign(
    Object.create(null),
    jwk.kty === 'oct' ? {kty: 'oct', k: jwk.k} : publicMembers(jwk),
  ) as Record<string, unknown>;
  if (privateKey)
    for (const name of ['d', 'p', 'q', 'dp', 'dq', 'qi'])
      if (Object.hasOwn(jwk, name)) out[name] = jwk[name];
  return out as {kty?: string};
}
function familyMatches(j: Jwk, spec: Spec): boolean {
  return compatible(j, spec);
}
/** Import explicitly owned material. All persistent CryptoKey references stay in private fields. */
export async function local(
  algorithm: unknown,
  material: unknown,
  options: unknown = {},
): Promise<Result<KeyHandle>> {
  const resolved = resolveAlgorithm(algorithm, true);
  if (!resolved.ok) return err(custodyError('unsupported_algorithm'));
  const spec = resolved.value;
  const opts = snapshotOptions(options, ['format', 'equivalence']);
  if (!opts.ok) return err(custodyError('invalid_options'));
  const attrs = opts.value;
  if (
    Object.hasOwn(attrs, 'format') &&
    !['pem', 'pkcs8', 'jwk'].includes(attrs.format as string)
  )
    return err(custodyError('unsupported_format'));
  if (Object.hasOwn(attrs, 'equivalence') && spec.family !== 'hmac')
    return err(custodyError('invalid_options'));
  const context = withDeadline();
  if (!context.ok) return context;
  return run(context.value, async () => {
    let decoded: DecodedKey | undefined,
      secret: Uint8Array<ArrayBuffer> | undefined;
    try {
      let jwk: Jwk | undefined;
      let pssOnly = false;
      let identity: KeyIdentity | undefined;
      if (
        material &&
        typeof material === 'object' &&
        Object.hasOwn(material, 'hmac')
      ) {
        const r = snapshotOptions(material, ['hmac', 'identity']);
        if (!r.ok) return err(custodyError('invalid_key'));
        if (spec.family !== 'hmac') return err(custodyError('key_mismatch'));
        if (
          !(r.value.hmac instanceof Uint8Array) ||
          r.value.hmac.length < HMAC_MIN_BYTES ||
          r.value.hmac.length > HMAC_MAX_BYTES
        )
          return err(custodyError('invalid_key'));
        secret = new Uint8Array(r.value.hmac);
        if (Object.hasOwn(r.value, 'identity')) {
          if (Object.hasOwn(attrs, 'equivalence'))
            return err(custodyError('invalid_options'));
          const id = KeyIdentity.symmetric(r.value.identity);
          if (!id.ok) return id;
          identity = id.value;
        }
      } else {
        const format =
          attrs.format ??
          (typeof material === 'string'
            ? 'pem'
            : material instanceof Uint8Array
              ? 'pkcs8'
              : 'jwk');
        if (format === 'jwk') {
          const r = snapshotJwk(material, true, spec);
          if (!r.ok) return r;
          jwk = r.value;

        } else {
          if (
            (typeof material === 'string' && material.length > KEY_MAX_BYTES) ||
            (material instanceof Uint8Array && material.length > KEY_MAX_BYTES)
          )
            return err(custodyError('invalid_key'));
          const r = decodeKey(material, format as 'pem' | 'pkcs8');
          if (!r.ok) return r;
          decoded = r.value;
          pssOnly = decoded.pssOnly;
          jwk = decoded.jwk;
          if (!decoded.privateKey) return err(custodyError('invalid_key'));
        }
        if (!familyMatches(jwk, spec) || (pssOnly && spec.name !== 'RSA-PSS'))
          return err(custodyError('key_mismatch'));
        if (
          !permitted(jwk, spec, spec.unwrap ? 'unwrapKey' : 'sign') &&
          !(spec.unwrap && permitted(jwk, spec, 'decrypt'))
        )
          return err(custodyError('key_mismatch'));
        if (jwk.kty === 'oct') secret = component(jwk.k);
      }
      if (Object.hasOwn(attrs, 'equivalence')) {
        const r = KeyIdentity.symmetric(attrs.equivalence);
        if (!r.ok) return r;
        identity = r.value;
      }
      const params = importParameters(spec);
      let key: CryptoKey,
        verification: CryptoKey | undefined,
        publicKey: PublicKey | undefined;
      if (secret) {
        key = await subtle.importKey('raw', secret, params, false, [
          'sign',
          'verify',
        ]);
        verification = key;
        const sig = await signKey(spec, key, new Uint8Array());
        if (!sig.ok)
          return err(custodyError(sig.error.reason as 'invalid_key'));
        const v = await verifyKey(spec, key, sig.value, new Uint8Array());
        sig.value.fill(0);
        if (!v.ok) return err(custodyError('invalid_key'));
        identity ??= (KeyIdentity.unknown() as {ok: true; value: KeyIdentity})
          .value;
      } else {
        let publicJwk: Jwk;
        if (
          (jwk!.kty === 'EC' && Object.hasOwn(jwk!, 'x')) ||
          jwk!.kty === 'RSA' ||
          (jwk!.kty === 'OKP' && Object.hasOwn(jwk!, 'x'))
        )
          publicJwk = publicMetadata(jwk!);
        else {
          if (!decoded) return err(custodyError('invalid_key'));
          const temporary = await subtle.importKey(
            'pkcs8',
            decoded.der,
            params,
            true,
            [spec.unwrap ? 'unwrapKey' : 'sign'],
          );
          const exported = await subtle.exportKey('jwk', temporary);
          publicJwk = publicMembers(exported as Jwk);
          // Private strings and bigints cannot be overwritten; retain no reference beyond this frame.
          for (const name of ['d', 'p', 'q', 'dp', 'dq', 'qi'])
            delete (exported as Record<string, unknown>)[name];
        }
        const pub = await PublicKey.import(publicJwk, 'jwk');
        if (!pub.ok) return err(custodyError('invalid_key'));
        publicKey = pub.value;
        if (pssOnly) {
          const der = publicSpki(publicJwk, true);
          if (!der.ok) return der;
          const result = await PublicKey.import(der.value, 'spki');
          if (!result.ok) return err(custodyError('invalid_key'));
          publicKey = result.value;
        }
        key = decoded
          ? await subtle.importKey('pkcs8', decoded.der, params, false, [
              spec.unwrap ? 'unwrapKey' : 'sign',
            ])
          : await subtle.importKey(
              'jwk',
              sanitized(jwk!, true),
              params,
              false,
              [spec.unwrap ? 'unwrapKey' : 'sign'],
            );
        verification = await subtle.importKey(
          'jwk',
          sanitized(publicJwk, false),
          params,
          false,
          spec.unwrap ? ['encrypt', 'wrapKey'] : ['verify'],
        );
        if (spec.unwrap) {
          const cek = subtle.random(new Uint8Array(32));
          const aes = await subtle.importKey(
            'raw',
            cek,
            {name: 'AES-GCM'},
            true,
            ['encrypt', 'decrypt'],
          );
          cek.fill(0);
          const wrapped = await subtle.wrapKey('raw', aes, verification, {
            name: 'RSA-OAEP',
          });
          const recovered = await subtle.unwrapKey(
            'raw',
            wrapped,
            key,
            {name: 'RSA-OAEP'},
            {name: 'AES-GCM', length: 256},
            false,
            ['decrypt'],
          );
          const iv = new Uint8Array(12),
            message = new Uint8Array([1, 2, 3]);
          const ciphertext = await subtle.encrypt(
            {name: 'AES-GCM', iv},
            aes,
            message,
          );
          const plain = new Uint8Array(
            await subtle.decrypt({name: 'AES-GCM', iv}, recovered, ciphertext),
          );
          if (
            plain.length !== message.length ||
            plain.some((b, i) => b !== message[i])
          )
            return err(custodyError('invalid_key'));
          plain.fill(0);
        } else {
          const sig = await signKey(spec, key, new Uint8Array());
          if (!sig.ok) return err(custodyError('invalid_key'));
          const valid = await verifyKey(
            spec,
            verification,
            sig.value,
            new Uint8Array(),
          );
          sig.value.fill(0);
          if (!valid.ok) return err(custodyError('invalid_key'));
        }
        const id = KeyIdentity.fromPublic(publicKey);
        if (!id.ok) return id;
        identity = id.value;
      }
      const capabilities: KeyHandle['capabilities'] = spec.unwrap
        ? ['unwrap']
        : jwk?.key_ops && !permitted(jwk, spec, 'verify')
          ? ['sign']
          : ['sign', 'verify'];
      return createKeyHandle(
        selection(spec),
        new LocalPort(key, verification, publicKey, identity!, spec),
        capabilities,
      );
    } catch (e) {
      return err(
        custodyError(
          e instanceof DOMException && e.name === 'NotSupportedError'
            ? 'unsupported_algorithm'
            : 'invalid_key',
        ),
      );
    } finally {
      secret?.fill(0);
      decoded?.der.fill(0);
    }
  });
}
