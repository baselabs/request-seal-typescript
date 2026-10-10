import {snapshotOptions} from '../brand.ts';
import {ok, err, type Result} from '../result.ts';
import {cryptoError} from '../errors/types.ts';
export type HttpAlgorithm =
  | 'rsa-pss-sha512'
  | 'rsa-v1_5-sha256'
  | 'hmac-sha256'
  | 'ecdsa-p256-sha256'
  | 'ecdsa-p384-sha384'
  | 'ed25519';
export type JwsAlgorithm =
  | 'RS256'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'HS256'
  | 'ES256'
  | 'ES384'
  | 'EdDSA';
export type SigningAlgorithm = HttpAlgorithm | Readonly<{jws: JwsAlgorithm}>;
export type UnwrapAlgorithm = Readonly<{jwe: 'RSA-OAEP' | 'RSA-OAEP-256'}>;
export type CustodyAlgorithm = SigningAlgorithm | UnwrapAlgorithm;
export type Spec = Readonly<{
  id: string;
  jose: string;
  family: 'rsa' | 'ec' | 'ed25519' | 'hmac';
  name: string;
  hash?: string;
  curve?: string;
  width: number;
  salt?: number;
  unwrap: boolean;
}>;
const jws: Readonly<Record<JwsAlgorithm, Spec>> = Object.freeze({
  RS256: Object.freeze({
    id: 'jws:RS256',
    jose: 'RS256',
    family: 'rsa',
    name: 'RSASSA-PKCS1-v1_5',
    hash: 'SHA-256',
    width: 0,
    unwrap: false,
  }),
  PS256: Object.freeze({
    id: 'jws:PS256',
    jose: 'PS256',
    family: 'rsa',
    name: 'RSA-PSS',
    hash: 'SHA-256',
    width: 0,
    salt: 32,
    unwrap: false,
  }),
  PS384: Object.freeze({
    id: 'jws:PS384',
    jose: 'PS384',
    family: 'rsa',
    name: 'RSA-PSS',
    hash: 'SHA-384',
    width: 0,
    salt: 48,
    unwrap: false,
  }),
  PS512: Object.freeze({
    id: 'jws:PS512',
    jose: 'PS512',
    family: 'rsa',
    name: 'RSA-PSS',
    hash: 'SHA-512',
    width: 0,
    salt: 64,
    unwrap: false,
  }),
  HS256: Object.freeze({
    id: 'jws:HS256',
    jose: 'HS256',
    family: 'hmac',
    name: 'HMAC',
    hash: 'SHA-256',
    width: 32,
    unwrap: false,
  }),
  ES256: Object.freeze({
    id: 'jws:ES256',
    jose: 'ES256',
    family: 'ec',
    name: 'ECDSA',
    hash: 'SHA-256',
    curve: 'P-256',
    width: 64,
    unwrap: false,
  }),
  ES384: Object.freeze({
    id: 'jws:ES384',
    jose: 'ES384',
    family: 'ec',
    name: 'ECDSA',
    hash: 'SHA-384',
    curve: 'P-384',
    width: 96,
    unwrap: false,
  }),
  EdDSA: Object.freeze({
    id: 'jws:EdDSA',
    jose: 'EdDSA',
    family: 'ed25519',
    name: 'Ed25519',
    width: 64,
    unwrap: false,
  }),
});
const http: Readonly<Record<HttpAlgorithm, JwsAlgorithm>> = Object.freeze({
  'rsa-pss-sha512': 'PS512',
  'rsa-v1_5-sha256': 'RS256',
  'hmac-sha256': 'HS256',
  'ecdsa-p256-sha256': 'ES256',
  'ecdsa-p384-sha384': 'ES384',
  ed25519: 'EdDSA',
});
export function algorithms(): Result<readonly HttpAlgorithm[]> {
  return ok(Object.freeze(Object.keys(http) as HttpAlgorithm[]));
}
export function resolveAlgorithm(
  value: unknown,
  allowUnwrap = false,
): Result<Spec> {
  const invalid = () => err<Spec>(cryptoError('unsupported_algorithm'));
  try {
    if (typeof value === 'string')
      return Object.hasOwn(http, value)
        ? ok(Object.freeze({...jws[http[value as HttpAlgorithm]], id: value}))
        : invalid();
    const r = snapshotOptions(value, allowUnwrap ? ['jws', 'jwe'] : ['jws']);
    if (!r.ok || Object.keys(r.value).length !== 1) return invalid();
    const {jws: name, jwe: unwrap} = r.value as {jws?: unknown; jwe?: unknown};
    if (typeof name === 'string' && Object.hasOwn(jws, name))
      return ok(jws[name as JwsAlgorithm]);
    if (allowUnwrap && (unwrap === 'RSA-OAEP' || unwrap === 'RSA-OAEP-256'))
      return ok(
        Object.freeze({
          id: 'jwe:' + unwrap,
          jose: unwrap,
          family: 'rsa',
          name: 'RSA-OAEP',
          hash: unwrap === 'RSA-OAEP' ? 'SHA-1' : 'SHA-256',
          width: 0,
          unwrap: true,
        }),
      );
    return invalid();
  } catch {
    return invalid();
  }
}
export function selection(spec: Spec): CustodyAlgorithm {
  if (spec.id.startsWith('jws:'))
    return Object.freeze({jws: spec.jose as JwsAlgorithm});
  if (spec.unwrap)
    return Object.freeze({jwe: spec.jose as UnwrapAlgorithm['jwe']});
  return spec.id as HttpAlgorithm;
}
export function importParameters(spec: Spec): {
  name: string;
  hash?: string;
  namedCurve?: string;
} {
  if (spec.family === 'rsa' || spec.family === 'hmac')
    return {name: spec.name, hash: spec.hash!};
  if (spec.family === 'ec') return {name: 'ECDSA', namedCurve: spec.curve!};
  return {name: 'Ed25519'};
}
export function operationParameters(spec: Spec): {
  name: string;
  saltLength?: number;
  hash?: string;
} {
  if (spec.name === 'RSA-PSS') return {name: spec.name, saltLength: spec.salt!};
  if (spec.name === 'ECDSA') return {name: spec.name, hash: spec.hash!};
  return {name: spec.name};
}
export const CURVE_ORDERS: Readonly<Record<string, bigint>> = Object.freeze({
  'P-256': 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
  'P-384':
    0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n,
});
export const ED25519_ORDER =
  0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;
