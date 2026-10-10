import {decodeBase64, encodeBase64, encodeBase64Url} from '../bytes.ts';
import {
  DER_MAX_DEPTH,
  DER_MAX_NODES,
  KEY_MAX_BYTES,
  RSA_MIN_BITS,
  RSA_MAX_BITS,
  RSA_MAX_EXPONENT,
} from '../constants.ts';
import {custodyError} from '../errors/types.ts';
import {err, ok, type Result} from '../result.ts';
import {unsigned} from '../crypto/primitive.ts';
import {CURVE_ORDERS} from '../crypto/algorithm.ts';
export type DerNode = Readonly<{
  tag: number;
  bytes: Uint8Array<ArrayBuffer>;
  children: readonly DerNode[];
}>;
export const OIDS = Object.freeze({
  rsa: '2a864886f70d010101',
  pss: '2a864886f70d01010a',
  ec: '2a8648ce3d0201',
  p256: '2a8648ce3d030107',
  p384: '2b81040022',
  ed: '2b6570',
});
function requireValue(
  value: unknown,
  reason: 'invalid_key' | 'unsupported_format' = 'invalid_key',
): asserts value {
  if (!value) throw reason;
}
const hex = (bytes: Uint8Array) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
export function readDer(input: unknown): Result<DerNode> {
  let owned: Uint8Array<ArrayBuffer> | undefined;
  const contents: Uint8Array[] = [];
  let success = false;
  try {
    requireValue(
      input instanceof Uint8Array &&
        input.length > 0 &&
        input.length <= KEY_MAX_BYTES,
    );
    const bytes = new Uint8Array(input as Uint8Array);
    owned = bytes;
    let nodes = 0;
    function read(
      start: number,
      end: number,
      depth: number,
    ): [DerNode, number] {
      requireValue(
        depth <= DER_MAX_DEPTH && ++nodes <= DER_MAX_NODES && start + 2 <= end,
      );
      const tag = bytes[start++]!;
      requireValue((tag & 31) !== 31 && tag !== 0);
      let length = bytes[start++]!;
      if (length >= 128) {
        const n = length & 127;
        requireValue(n > 0 && n <= 4 && start + n <= end && bytes[start] !== 0);
        length = 0;
        for (let i = 0; i < n; i++) length = length * 256 + bytes[start++]!;
        requireValue(length >= 128);
      }
      const stop = start + length;
      requireValue(stop <= end);
      const content = bytes.slice(start, stop);
      contents.push(content);
      const children: DerNode[] = [];
      if ((tag & 32) !== 0) {
        while (start < stop) {
          const [child, next] = read(start, stop, depth + 1);
          children.push(child);
          start = next;
        }
      }
      if (tag === 2)
        requireValue(
          length > 0 &&
            !(content[0] === 0 && length > 1 && content[1]! < 128) &&
            !(content[0] === 255 && length > 1 && content[1]! >= 128),
        );
      if (tag === 3)
        requireValue(
          length > 0 &&
            content[0]! <= 7 &&
            (length > 1 || content[0] === 0) &&
            (content[0] === 0 ||
              (content.at(-1)! & ((1 << content[0]!) - 1)) === 0),
        );
      if (tag === 5) requireValue(length === 0);
      if (tag === 6)
        requireValue(
          length > 0 &&
            (content.at(-1)! & 128) === 0 &&
            !content.some(
              (b, i) => b === 128 && (i === 0 || (content[i - 1]! & 128) === 0),
            ),
        );
      return [{tag, bytes: content, children: Object.freeze(children)}, stop];
    }
    const [node, end] = read(0, bytes.length, 0);
    requireValue(end === bytes.length);
    success = true;
    return ok(node);
  } catch {
    return err(custodyError('invalid_key'));
  } finally {
    owned?.fill(0);
    if (!success) for (const bytes of contents) bytes.fill(0);
  }
}
export function tlv(tag: number, bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const size = bytes.length;
  const width = size < 128 ? 0 : Math.ceil(Math.log2(size + 1) / 8);
  const out = new Uint8Array(2 + width + size);
  out[0] = tag;
  if (width === 0) out[1] = size;
  else {
    out[1] = 128 + width;
    for (let i = 0; i < width; i++)
      out[2 + i] = (size / 2 ** (8 * (width - i - 1))) & 255;
  }
  out.set(bytes, 2 + width);
  return out;
}
export function concat(
  ...chunks: readonly Uint8Array[]
): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(chunks.reduce((n, b) => n + b.length, 0));
  let at = 0;
  for (const b of chunks) {
    out.set(b, at);
    at += b.length;
  }
  return out;
}
export function sequence(...nodes: readonly Uint8Array[]): Uint8Array<ArrayBuffer> {
  const body = concat(...nodes);
  try {
    return tlv(48, body);
  } finally {
    body.fill(0);
  }
}
export const oid = (value: string) =>
  tlv(6, new Uint8Array(value.match(/../g)!.map((s) => parseInt(s, 16))));
export function integer(value: bigint): Uint8Array<ArrayBuffer> {
  requireValue(value >= 0n);
  let h = value.toString(16);
  if (h.length % 2) h = '0' + h;
  let b = new Uint8Array(h.match(/../g)!.map((s) => parseInt(s, 16)));
  if (b[0]! >= 128) b = concat(new Uint8Array([0]), b);
  return tlv(2, b);
}
export function encodeDer(node: DerNode): Result<Uint8Array<ArrayBuffer>> {
  try {
    let count = 0;
    function encode(n: DerNode, depth: number): Uint8Array<ArrayBuffer> {
      requireValue(depth <= DER_MAX_DEPTH && ++count <= DER_MAX_NODES);
      requireValue(
        Number.isInteger(n.tag) &&
          n.tag > 0 &&
          n.tag < 255 &&
          (n.tag & 31) !== 31,
      );
      const b =
        (n.tag & 32) !== 0
          ? concat(...n.children.map((c) => encode(c, depth + 1)))
          : new Uint8Array(n.bytes);
      requireValue(b.length <= KEY_MAX_BYTES);
      return tlv(n.tag, b);
    }
    const bytes = encode(node, 0);
    const valid = readDer(bytes);
    return valid.ok ? ok(bytes) : valid;
  } catch {
    return err(custodyError('invalid_key'));
  }
}
export type Pem = Readonly<{label: string; der: Uint8Array<ArrayBuffer>}>;
export function readPem(input: unknown): Result<Pem> {
  try {
    requireValue(
      typeof input === 'string' &&
        input.length > 0 &&
        input.length <= KEY_MAX_BYTES,
    );
    requireValue(
      !(input as string).includes('ENCRYPTED PRIVATE KEY') &&
        !(input as string).includes('Proc-Type: 4,ENCRYPTED'),
      'unsupported_format',
    );
    // OTP pem_decode splits all line endings, trims only BEGIN line tails,
    // ignores surrounding text, and ends an entry at any "-----END " prefix.
    const lines = (input as string).split(/\r\n|\r|\n/);
    const entries: {label: string; body: string}[] = [];
    const known = ['CERTIFICATE', 'RSA PRIVATE KEY', 'RSA PUBLIC KEY', 'PUBLIC KEY',
      'DSA PRIVATE KEY', 'DH PARAMETERS', 'PRIVATE KEY', 'ENCRYPTED PRIVATE KEY',
      'CERTIFICATE REQUEST', 'PKCS7', 'X509 CRL', 'EC PARAMETERS', 'EC PRIVATE KEY',
      'OPENSSH PRIVATE KEY'];
    for (let i = 0; i < lines.length; i++) {
      const begin = /^-----BEGIN ([A-Z0-9 ]+)-----$/.exec(lines[i]!.replace(/[ \t\v\f]+$/, ''));
      if (!begin || !known.includes(begin[1]!)) continue;
      const body: string[] = [];
      while (++i < lines.length && !lines[i]!.startsWith('-----END ')) body.push(lines[i]!);
      requireValue(i < lines.length);
      entries.push({label: begin[1]!, body: body.join('')});
    }
    requireValue(entries.length === 1);
    const {label, body} = entries[0]!;
    requireValue(['PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'PUBLIC KEY', 'RSA PUBLIC KEY'].includes(label));
    const result = decodeBase64(body.replace(/[^A-Za-z0-9+/=]/g, ''));
    requireValue(result.ok);
    return ok({
      label: label!,
      der: (result as {ok: true; value: Uint8Array<ArrayBuffer>}).value,
    });
  } catch (reason) {
    return err(
      custodyError(
        reason === 'unsupported_format' ? 'unsupported_format' : 'invalid_key',
      ),
    );
  }
}
export function writePem(label: string, der: Uint8Array): Result<string> {
  if (
    ![
      'PRIVATE KEY',
      'RSA PRIVATE KEY',
      'EC PRIVATE KEY',
      'PUBLIC KEY',
      'RSA PUBLIC KEY',
    ].includes(label)
  )
    return err(custodyError('unsupported_format'));
  const valid = readDer(der);
  if (!valid.ok) return valid;
  eraseTree(valid.value);
  const encoded = encodeBase64(der);
  return ok(
    '-----BEGIN ' +
      label +
      '-----\n' +
      encoded.match(/.{1,64}/g)!.join('\n') +
      '\n-----END ' +
      label +
      '-----\n',
  );
}
function children(node: DerNode, tag = 48): readonly DerNode[] {
  requireValue(node.tag === tag);
  return node.children;
}
function uint(node: DerNode): bigint {
  requireValue(node.tag === 2 && node.bytes.length > 0 && node.bytes[0]! < 128);
  return unsigned(node.bytes);
}
function octets(node: DerNode): Uint8Array<ArrayBuffer> {
  requireValue(node.tag === 4);
  return node.bytes;
}
function bits(node: DerNode): Uint8Array<ArrayBuffer> {
  requireValue(node.tag === 3 && node.bytes[0] === 0);
  return node.bytes.slice(1);
}
function curve(node: DerNode): 'P-256' | 'P-384' {
  requireValue(node.tag === 6);
  const id = hex(node.bytes);
  requireValue(id === OIDS.p256 || id === OIDS.p384);
  return id === OIDS.p256 ? 'P-256' : 'P-384';
}
export function validateRsa(
  jwk: Readonly<Record<string, unknown>>,
  privateKey: boolean,
): void {
  function n(field: string): bigint {
    const value = jwk[field];
    requireValue(typeof value === 'string' && value.length > 0);
    const b = decodeBase64UrlOwned(value as string);
    requireValue(b.length > 0 && b[0] !== 0);
    try {
      return unsigned(b);
    } finally {
      b.fill(0);
    }
  }
  const names = privateKey
    ? ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi']
    : ['n', 'e'];
  validateRsaValues(names.map(n));
}
function validateRsaValues(values: readonly bigint[]): void {
  const [modulus, exponent] = values as [bigint, bigint];
  requireValue(
    modulus >= 1n << BigInt(RSA_MIN_BITS - 1) &&
      modulus < 1n << BigInt(RSA_MAX_BITS) &&
      (modulus & 1n) === 1n,
  );
  requireValue(
    exponent >= 3n &&
      exponent <= BigInt(RSA_MAX_EXPONENT) &&
      exponent < modulus &&
      (exponent & 1n) === 1n,
  );
  if (values.length === 8) {
    const [, , d, p, q, dp, dq, qi] = values as [
      bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint,
    ];
    requireValue(
      [d, p, q, dp, dq, qi].every((v) => v > 0n && v < modulus) &&
        p > 1n &&
        q > 1n,
    );
    let a = p - 1n,
      b = q - 1n;
    while (b) {
      const r = a % b;
      a = b;
      b = r;
    }
    const lcm = ((p - 1n) * (q - 1n)) / a;
    requireValue(
      p * q === modulus &&
        d % (p - 1n) === dp &&
        d % (q - 1n) === dq &&
        (q * qi) % p === 1n &&
        (exponent * d) % lcm === 1n,
    );
  }
}
// Component decoder uses the foundation's strict Base64url codec.
import {decodeBase64Url} from '../bytes.ts';
function decodeBase64UrlOwned(value: string): Uint8Array<ArrayBuffer> {
  const r = decodeBase64Url(value);
  requireValue(r.ok);
  return (r as {ok: true; value: Uint8Array<ArrayBuffer>}).value;
}
function rsaJwk(node: DerNode, privateKey: boolean): Record<string, string> {
  const c = children(node);
  requireValue(c.length === (privateKey ? 9 : 2));
  if (privateKey) requireValue(uint(c[0]!) === 0n);
  const components = privateKey ? c.slice(1) : c;
  validateRsaValues(components.map(uint));
  const out: Record<string, string> = {kty: 'RSA'};
  for (const [i, name] of ['n', 'e'].entries()) {
    const b = components[i]!.bytes;
    out[name] = encodeBase64Url(b[0] === 0 ? b.subarray(1) : b);
  }
  return out;
}
function eraseTree(n: DerNode): void {
  n.bytes.fill(0);
  for (const c of n.children) eraseTree(c);
}
/** Copy private octets directly into the final container, without a private wrapper intermediate. */
function privateContainer(alg: Uint8Array, raw: Uint8Array): Uint8Array<ArrayBuffer> {
  const headerSize = (size: number) =>
    size < 128 ? 2 : 2 + Math.ceil(Math.log2(size + 1) / 8);
  const octetHeader = headerSize(raw.length);
  const bodyLength = 3 + alg.length + octetHeader + raw.length;
  const outerHeader = headerSize(bodyLength);
  const out = new Uint8Array(outerHeader + bodyLength);
  function header(at: number, tag: number, size: number): number {
    out[at++] = tag;
    const width = headerSize(size) - 2;
    if (!width) out[at++] = size;
    else {
      out[at++] = 128 + width;
      for (let i = width - 1; i >= 0; i--) out[at++] = (size / 2 ** (8 * i)) & 255;
    }
    return at;
  }
  let at = header(0, 48, bodyLength);
  out.set([2, 1, 0], at);
  at += 3;
  out.set(alg, at);
  at += alg.length;
  at = header(at, 4, raw.length);
  out.set(raw, at);
  return out;
}
export type DecodedKey = Readonly<{
  privateKey: boolean;
  pssOnly: boolean;
  jwk: Readonly<Record<string, string>>;
  der: Uint8Array<ArrayBuffer>;
}>;
function algorithm(node: DerNode): {
  family: 'rsa' | 'ec' | 'ed';
  pssOnly: boolean;
  curve?: 'P-256' | 'P-384';
} {
  const c = children(node);
  requireValue(c.length >= 1 && c.length <= 2 && c[0]!.tag === 6);
  const id = hex(c[0]!.bytes),
    params = c[1];
  if (id === OIDS.rsa) {
    requireValue(!params || params.tag === 5);
    return {family: 'rsa', pssOnly: false};
  }
  if (id === OIDS.pss) {
    requireValue(
      !params,
      'unsupported_format',
    );
    return {family: 'rsa', pssOnly: true};
  }
  if (id === OIDS.ec) {
    requireValue(params);
    return {family: 'ec', pssOnly: false, curve: curve(params!)};
  }
  if (id === OIDS.ed) {
    requireValue(!params);
    return {family: 'ed', pssOnly: false};
  }
  throw 'unsupported_format';
}
function ecPrivate(
  node: DerNode,
  outerCurve?: 'P-256' | 'P-384',
): Record<string, string> {
  const c = children(node);
  requireValue(c.length >= 2 && c.length <= 4 && uint(c[0]!) === 1n);
  const scalar = octets(c[1]!);
  let crv = outerCurve,
    point: Uint8Array | undefined;
  let last = 0;
  for (const attr of c.slice(2)) {
    requireValue(
      (attr.tag === 160 || attr.tag === 161) &&
        attr.tag > last &&
        attr.children.length === 1,
    );
    last = attr.tag;
    if (attr.tag === 160) {
      const inner = curve(attr.children[0]!);
      requireValue(!crv || crv === inner);
      crv = inner;
    } else point = bits(attr.children[0]!);
  }
  requireValue(crv);
  const width = crv === 'P-256' ? 32 : 48;
  requireValue(
    scalar.length === width &&
      unsigned(scalar) > 0n &&
      unsigned(scalar) < CURVE_ORDERS[crv!]!,
  );
  const jwk: Record<string, string> = {
    kty: 'EC',
    crv: crv!,
  };
  if (point) {
    requireValue(point.length === 1 + width * 2 && point[0] === 4);
    jwk.x = encodeBase64Url(point.subarray(1, 1 + width));
    jwk.y = encodeBase64Url(point.subarray(1 + width));
  }
  return jwk;
}
export function decodeKey(
  input: unknown,
  format: 'pem' | 'pkcs8' | 'spki',
): Result<DecodedKey> {
  let owned: Uint8Array<ArrayBuffer> | undefined;
  const parsedNodes: DerNode[] = [];
  function parsed(input: Uint8Array): Result<DerNode> {
    const r = readDer(input);
    if (r.ok) parsedNodes.push(r.value);
    return r;
  }
  try {
    let label = format === 'spki' ? 'PUBLIC KEY' : 'PRIVATE KEY';
    if (format === 'pem') {
      const p = readPem(input);
      if (!p.ok) return p;
      label = p.value.label;
      owned = p.value.der;
    } else {
      requireValue(input instanceof Uint8Array);
      owned = new Uint8Array(input as Uint8Array);
    }
    const decodedRoot = parsed(owned);
    if (!decodedRoot.ok)
      return err(custodyError(
        label === 'PRIVATE KEY' ? 'unsupported_format' : 'invalid_key',
      ));
    const root = decodedRoot.value;
    let jwk: Record<string, string>,
      der: Uint8Array<ArrayBuffer>,
      pssOnly = false;
    const privateKey = !['PUBLIC KEY', 'RSA PUBLIC KEY'].includes(label);
    if (label === 'RSA PRIVATE KEY' || label === 'RSA PUBLIC KEY') {
      jwk = rsaJwk(root, privateKey);
      const alg = sequence(oid(OIDS.rsa), tlv(5, new Uint8Array()));
      der = privateKey
        ? privateContainer(alg, owned)
        : sequence(alg, tlv(3, concat(new Uint8Array([0]), owned)));
    } else if (label === 'EC PRIVATE KEY') {
      jwk = ecPrivate(root);
      const alg = sequence(
        oid(OIDS.ec),
        oid(jwk.crv === 'P-256' ? OIDS.p256 : OIDS.p384),
      );
      der = privateContainer(alg, owned);
    } else {
      requireValue(root.tag === 48, privateKey ? 'unsupported_format' : 'invalid_key');
      const c = children(root);
      requireValue(c.length >= 2, privateKey ? 'unsupported_format' : 'invalid_key');
      if (privateKey) {
        requireValue(c.length >= 3, 'unsupported_format');
        requireValue(
          c[0]!.tag === 2 && c[0]!.bytes.length === 1 && c[0]!.bytes[0] === 0,
          'unsupported_format',
        );
        requireValue(
          c[1]!.tag === 48 && c[1]!.children.length >= 1 &&
            c[1]!.children[0]!.tag === 6 && c[2]!.tag === 4,
          'unsupported_format',
        );
        requireValue(
          c.length === 3 || (c.length === 4 && c[3]!.tag === 160),
          'unsupported_format',
        );
      } else requireValue(c.length === 2);
      const a = algorithm(c[privateKey ? 1 : 0]!);
      pssOnly = a.pssOnly;
      const raw = privateKey ? octets(c[2]!) : bits(c[1]!);
      if (a.family === 'rsa') {
        const p = parsed(raw);
        requireValue(p.ok);
        jwk = rsaJwk((p as {ok: true; value: DerNode}).value, privateKey);
        const alg = sequence(oid(OIDS.rsa), tlv(5, new Uint8Array()));
        der = privateKey
          ? privateContainer(alg, raw)
          : sequence(alg, tlv(3, concat(new Uint8Array([0]), raw)));
      } else if (a.family === 'ec') {
        if (privateKey) {
          const p = parsed(raw);
          requireValue(p.ok);
          jwk = ecPrivate((p as {ok: true; value: DerNode}).value, a.curve!);
        } else {
          const width = a.curve === 'P-256' ? 32 : 48;
          requireValue(raw.length === 1 + width * 2 && raw[0] === 4);
          jwk = {
            kty: 'EC',
            crv: a.curve!,
            x: encodeBase64Url(raw.subarray(1, width + 1)),
            y: encodeBase64Url(raw.subarray(width + 1)),
          };
        }
        der = new Uint8Array(owned);
      } else {
        if (privateKey) {
          const p = parsed(raw);
          requireValue(p.ok);
          const seed = octets((p as {ok: true; value: DerNode}).value);
          requireValue(seed.length === 32);
          jwk = {kty: 'OKP', crv: 'Ed25519'};
        } else {
          requireValue(raw.length === 32);
          jwk = {kty: 'OKP', crv: 'Ed25519', x: encodeBase64Url(raw)};
        }
        der = new Uint8Array(owned);
      }
    }
    return ok({privateKey, pssOnly, jwk: Object.freeze(jwk), der});
  } catch (reason) {
    return err(
      custodyError(
        reason === 'unsupported_format' ? 'unsupported_format' : 'invalid_key',
      ),
    );
  } finally {
    owned?.fill(0);
    for (const n of parsedNodes) eraseTree(n);
  }
}
export function publicSpki(
  jwk: Readonly<Record<string, unknown>>,
  pssOnly = false,
): Result<Uint8Array<ArrayBuffer>> {
  try {
    let alg: Uint8Array, raw: Uint8Array;
    if (jwk.kty === 'RSA') {
      validateRsa(jwk, false);
      alg = pssOnly
        ? sequence(oid(OIDS.pss))
        : sequence(oid(OIDS.rsa), tlv(5, new Uint8Array()));
      raw = sequence(
        integer(unsigned(decodeBase64UrlOwned(jwk.n as string))),
        integer(unsigned(decodeBase64UrlOwned(jwk.e as string))),
      );
    } else if (jwk.kty === 'EC') {
      requireValue(jwk.crv === 'P-256' || jwk.crv === 'P-384');
      alg = sequence(
        oid(OIDS.ec),
        oid(jwk.crv === 'P-256' ? OIDS.p256 : OIDS.p384),
      );
      raw = concat(
        new Uint8Array([4]),
        decodeBase64UrlOwned(jwk.x as string),
        decodeBase64UrlOwned(jwk.y as string),
      );
    } else {
      requireValue(jwk.kty === 'OKP' && jwk.crv === 'Ed25519');
      alg = sequence(oid(OIDS.ed));
      raw = decodeBase64UrlOwned(jwk.x as string);
    }
    return ok(sequence(alg, tlv(3, concat(new Uint8Array([0]), raw))));
  } catch {
    return err(custodyError('invalid_key'));
  }
}
