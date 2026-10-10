import {snapshotOptions} from '../brand.ts';
import {decodeBase64Url} from '../bytes.ts';
import {
  KEY_MAX_MEMBERS,
  KEY_COMPONENT_MAX_ENCODED_BYTES,
  RSA_COMPONENT_MAX_ENCODED_BYTES,
  JWK_ALGORITHM_MAX_BYTES,
  JWK_MAX_OPERATIONS,
  HMAC_MIN_BYTES,
  HMAC_MAX_BYTES,
} from '../constants.ts';
import {custodyError} from '../errors/types.ts';
import {err, ok, type Result} from '../result.ts';
import {unsigned} from '../crypto/primitive.ts';
import {CURVE_ORDERS, type Spec} from '../crypto/algorithm.ts';
import {validateRsa} from './der.ts';
export type Jwk = Readonly<Record<string, unknown>>;
function ensure(value: unknown, reason = 'invalid_key'): asserts value {
  if (!value) throw reason;
}
export function component(
  value: unknown,
  integer = false,
): Uint8Array<ArrayBuffer> {
  ensure(
    typeof value === 'string' &&
      value.length > 0 &&
      value.length <=
        (integer
          ? RSA_COMPONENT_MAX_ENCODED_BYTES
          : KEY_COMPONENT_MAX_ENCODED_BYTES),
  );
  const r = decodeBase64Url(value);
  ensure(r.ok);
  const b = (r as {ok: true; value: Uint8Array<ArrayBuffer>}).value;
  ensure(b.length > 0 && (!integer || b[0] !== 0));
  return b;
}
export function snapshotJwk(input: unknown, privateKey: boolean, spec?: Spec): Result<Jwk> {
  try {
    ensure(input && typeof input === 'object' && !Array.isArray(input));
    const proto = Object.getPrototypeOf(input);
    ensure(proto === null || proto === Object.prototype);
    const keys = Reflect.ownKeys(input);
    ensure(
      keys.length <= KEY_MAX_MEMBERS &&
        keys.every((k) => typeof k === 'string'),
    );
    const r = snapshotOptions(input, keys as string[]);
    ensure(r.ok);
    const j = (r as {ok: true; value: Jwk}).value;
    if (!privateKey)
      ensure(
        !['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some((k) =>
          Object.hasOwn(j, k),
        ),
      );
    ensure(!Object.hasOwn(j, 'oth'));
    for (const k of ['alg', 'use', 'key_ops'])
      ensure(!Object.hasOwn(j, k) || (j[k] !== null && j[k] !== undefined));
    if (privateKey && spec) {
      ensure(!Object.hasOwn(j, 'alg') || j.alg === spec.jose, 'key_mismatch');
      ensure(!Object.hasOwn(j, 'use') || j.use === (spec.unwrap ? 'enc' : 'sig'), 'key_mismatch');
    }
    if (Object.hasOwn(j, 'alg'))
      ensure(
        typeof j.alg === 'string' &&
          j.alg.length > 0 &&
          j.alg.length <= JWK_ALGORITHM_MAX_BYTES &&
          /^[\x20-\x7e]+$/.test(j.alg),
      );
    if (Object.hasOwn(j, 'use')) ensure(j.use === 'sig' || j.use === 'enc');
    if (Object.hasOwn(j, 'key_ops')) {
      const ops = j.key_ops;
      ensure(
        Array.isArray(ops) &&
          ops.length <= JWK_MAX_OPERATIONS &&
          new Set(ops).size === ops.length &&
          ops.every((k) =>
            [
              'sign',
              'verify',
              'encrypt',
              'decrypt',
              'wrapKey',
              'unwrapKey',
              'deriveKey',
              'deriveBits',
            ].includes(k),
          ),
      );
      ensure(
        !j.use ||
          ops.every((k) =>
            (j.use === 'sig'
              ? ['sign', 'verify']
              : [
                  'encrypt',
                  'decrypt',
                  'wrapKey',
                  'unwrapKey',
                  'deriveKey',
                  'deriveBits',
                ]
            ).includes(k),
          ),
      );
    }
    if (privateKey && spec && Object.hasOwn(j, 'key_ops')) {
      const ops = j.key_ops as readonly string[];
      const allowed = spec.unwrap ? ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'] : ['sign', 'verify'];
      const required = spec.unwrap ? ['decrypt', 'unwrapKey'] : ['sign'];
      ensure(ops.length <= allowed.length && ops.every(op => allowed.includes(op)));
      ensure(ops.some(op => required.includes(op)), 'key_mismatch');
    }
    const out = Object.create(null) as Record<string, unknown>;
    const fields =
      j.kty === 'RSA'
        ? [
            'kty',
            'n',
            'e',
            ...(privateKey ? ['d', 'p', 'q', 'dp', 'dq', 'qi'] : []),
          ]
        : j.kty === 'EC'
          ? ['kty', 'crv', 'x', 'y', ...(privateKey ? ['d'] : [])]
          : j.kty === 'OKP'
            ? ['kty', 'crv', 'x', ...(privateKey ? ['d'] : [])]
            : privateKey && j.kty === 'oct'
              ? ['kty', 'k']
              : [];
    ensure(fields.length > 0 && fields.every((k) => Object.hasOwn(j, k)));
    for (const k of fields) out[k] = j[k];
    for (const k of ['alg', 'use', 'key_ops'])
      if (Object.hasOwn(j, k))
        out[k] =
          k === 'key_ops' ? Object.freeze([...(j.key_ops as string[])]) : j[k];
    validateComponents(out, privateKey);
    return ok(Object.freeze(out));
  } catch (reason) {
    return err(custodyError(reason === 'key_mismatch' ? 'key_mismatch' : 'invalid_key'));
  }
}
export function validateComponents(j: Jwk, privateKey: boolean): void {
  if (j.kty === 'RSA') {
    for (const k of [
      'n',
      'e',
      ...(privateKey ? ['d', 'p', 'q', 'dp', 'dq', 'qi'] : []),
    ])
      component(j[k], true).fill(0);
    validateRsa(j, privateKey);
  } else if (j.kty === 'EC') {
    ensure(j.crv === 'P-256' || j.crv === 'P-384');
    const width = j.crv === 'P-256' ? 32 : 48;
    for (const k of ['x', 'y']) ensure(component(j[k]).length === width);
    if (privateKey) {
      const d = component(j.d);
      try {
        ensure(
          d.length === width &&
            unsigned(d) > 0n &&
            unsigned(d) < CURVE_ORDERS[j.crv]!,
        );
      } finally {
        d.fill(0);
      }
    }
  } else if (j.kty === 'OKP') {
    ensure(j.crv === 'Ed25519');
    const x = component(j.x);
    ensure(x.length === 32);
    const y = unsigned(x, true) & ((1n << 255n) - 1n);
    const small = [
      0n,
      1n,
      0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffecn,
      0x05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826n,
      0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7n,
    ];
    ensure(y < (1n << 255n) - 19n && !small.includes(y));
    if (privateKey) {
      const d = component(j.d);
      try {
        ensure(d.length === 32);
      } finally {
        d.fill(0);
      }
    }
  } else if (privateKey && j.kty === 'oct') {
    const key = component(j.k);
    try {
      ensure(key.length >= HMAC_MIN_BYTES && key.length <= HMAC_MAX_BYTES);
    } finally {
      key.fill(0);
    }
  } else throw 'invalid_key';
}
export function publicMembers(j: Jwk): Jwk {
  const out = Object.create(null) as Record<string, unknown>;
  const names =
    j.kty === 'RSA'
      ? ['e', 'kty', 'n']
      : j.kty === 'EC'
        ? ['crv', 'kty', 'x', 'y']
        : ['crv', 'kty', 'x'];
  for (const k of names) out[k] = j[k];
  return Object.freeze(out);
}
export function publicMetadata(j: Jwk): Jwk {
  const out = Object.assign(Object.create(null), publicMembers(j)) as Record<
    string,
    unknown
  >;
  for (const k of ['alg', 'use', 'key_ops'])
    if (Object.hasOwn(j, k)) out[k] = j[k];
  return Object.freeze(out);
}
export function compatible(j: Jwk, spec: Spec, pssOnly = false): boolean {
  return (
    (!pssOnly || spec.name === 'RSA-PSS') &&
    (spec.family === 'rsa'
      ? j.kty === 'RSA'
      : spec.family === 'ec'
        ? j.kty === 'EC' && j.crv === spec.curve
        : spec.family === 'ed25519'
          ? j.kty === 'OKP' && j.crv === 'Ed25519'
          : j.kty === 'oct')
  );
}
export function permitted(j: Jwk, spec: Spec, op: string): boolean {
  return (
    (!Object.hasOwn(j, 'alg') || j.alg === spec.jose) &&
    (!Object.hasOwn(j, 'use') || j.use === (spec.unwrap ? 'enc' : 'sig')) &&
    (!Object.hasOwn(j, 'key_ops') ||
      (j.key_ops as readonly string[]).includes(op))
  );
}
