import { byteString, encodeBase64 } from '../bytes.ts';
import { digest as capturedDigest } from '../crypto/subtle.ts';
import { snapshotOptions } from '../brand.ts';
import {
  BODY_MAX_BYTES,
  MESSAGE_MAX_TARGET_BYTES,
  MESSAGE_MAX_FIELD_BYTES,
  MESSAGE_MAX_FIELDS_BYTES,
  MESSAGE_MAX_OCCURRENCES,
  MESSAGE_MAX_TOKEN_BYTES,
  MESSAGE_MAX_SCHEME_BYTES,
  MESSAGE_MAX_AUTHORITY_BYTES,
  MESSAGE_MAX_URL_BYTES,
} from '../constants.ts';
import { messageError, isRequestSealError } from '../errors/types.ts';
import type { Reason } from '../errors/parity.ts';
import { err, ok, type Result } from '../result.ts';
/** An owned HTTP field occurrence with its section and byte value. */
export type FieldOccurrence = Readonly<{
  name: string;
  value: Uint8Array;
  section: 'headers' | 'trailers';
  provenance: 'caller' | 'http1' | 'http2' | 'http3';
}>;
/** Owned or unavailable body bytes with explicit retention and completeness facts. */
export type Body = Readonly<{
  state: 'retained' | 'streaming' | 'consumed' | 'unavailable';
  bytes: Uint8Array | null;
  source: Pick<ReadableStream<Uint8Array>, 'getReader'> | null;
  ownership: 'caller';
  maxBytes: number;
}>;
/** Branded TLS and peer-certificate facts captured by an adapter. */
export type TransportFacts = Readonly<{
  httpVersion: 'unknown' | 'http1_0' | 'http1_1' | 'http2' | 'http3';
  tls: 'unknown' | 'plain' | 'tls';
  evidence: 'declared';
}>;
/** A branded HTTP request or response preserving target and field bytes. */
export type Message = Readonly<{
  kind: 'request' | 'response';
  method: string | null;
  rawTarget: string | null;
  targetForm: 'origin' | 'absolute' | 'authority' | 'asterisk' | null;
  scheme: string | null;
  authority: string | null;
  status: number | null;
  fields: readonly FieldOccurrence[];
  trailers: readonly FieldOccurrence[] | 'pending' | 'unavailable';
  body: Body;
  relatedRequest: Message | null;
  transport: TransportFacts;
}>;
const messages = new WeakSet<object>();
const fieldOccurrences = new WeakSet<object>();
const bodies = new WeakSet<object>();
const transportFacts = new WeakSet<object>();
/** Check the private brand of an HTTP message. */
export function isMessage(value: unknown): value is Message {
  return typeof value === 'object' && value !== null && messages.has(value);
}
/** Check the private brand of a field occurrence. */
export function isFieldOccurrence(value: unknown): value is FieldOccurrence {
  return typeof value === 'object' && value !== null && fieldOccurrences.has(value);
}
/** Check the private brand of a body snapshot. */
export function isBody(value: unknown): value is Body {
  return typeof value === 'object' && value !== null && bodies.has(value);
}
/** Check the private brand of captured transport facts. */
export function isTransportFacts(value: unknown): value is TransportFacts {
  return typeof value === 'object' && value !== null && transportFacts.has(value);
}
function fail(reason: Reason<'message'>): never {
  throw messageError(reason);
}
function ensure(v: unknown, reason: Reason<'message'>): asserts v {
  if (!v) fail(reason);
}
function protect<T>(fn: () => T, reason: Reason<'message'>): Result<T> {
  try {
    return ok(fn());
  } catch (e) {
    return err(
      isRequestSealError(e) && e.kind === 'message'
        ? (e as ReturnType<typeof messageError>)
        : messageError(reason),
    );
  }
}
function snapshot(
  input: unknown,
  keys: readonly string[],
  reason: Reason<'message'>,
): Record<string, unknown> {
  const s = snapshotOptions(input, keys);
  ensure(s.ok, reason);
  return s.value;
}
const own = (a: Record<string, unknown>, k: string, d: unknown) => (Object.hasOwn(a, k) ? a[k] : d);
function text(input: unknown, reason: Reason<'message'>, max = MESSAGE_MAX_TOKEN_BYTES): string {
  if (typeof input === 'string' || input instanceof Uint8Array) ensure(input.length <= max, reason);
  const b = byteString(input);
  ensure(b.ok, reason);
  const chunks: string[] = [];
  for (let i = 0; i < b.value.length; i += 8192)
    chunks.push(String.fromCharCode(...b.value.subarray(i, i + 8192)));
  return chunks.join('');
}
function frozen<T extends object>(x: T, registry: WeakSet<object>): T {
  registry.add(x);
  return Object.freeze(x);
}
export function token(value: unknown, max = MESSAGE_MAX_TOKEN_BYTES): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= max &&
    /^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/.test(value)
  );
}
export function uriBytes(s: string): boolean {
  return /^(?:[A-Za-z0-9\-._~:/?\[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})*$/.test(s);
}
function scheme(s: unknown): s is string {
  return (
    typeof s === 'string' &&
    s.length <= MESSAGE_MAX_SCHEME_BYTES &&
    /^[A-Za-z][A-Za-z0-9+.-]*$/.test(s)
  );
}
function ipv6(s: string): boolean {
  // IPv4 tails count as two groups. No address or percent-encoding normalization.
  if (s.includes('.')) {
    const pos = s.lastIndexOf(':');
    const tail = s.slice(pos + 1).split('.');
    if (
      tail.length !== 4 ||
      !tail.every((p) => /^(0|[1-9][0-9]{0,2})$/.test(p) && Number(p) <= 255)
    )
      return false;
    s = s.slice(0, pos) + ':0:0';
  }
  if (!/^[0-9A-Fa-f:]+$/.test(s)) return false;
  const halves = s.split('::');
  if (halves.length > 2) return false;
  const groups = (p: string) => (p === '' ? [] : p.split(':'));
  const all = halves.flatMap(groups);
  if (!all.every((p) => /^[0-9A-Fa-f]{1,4}$/.test(p))) return false;
  return halves.length === 2 ? all.length < 8 : all.length === 8;
}
export function authority(value: unknown, requirePort = false): value is string {
  if (typeof value !== 'string' || value.length < 1 || value.length > MESSAGE_MAX_AUTHORITY_BYTES)
    return false;
  const m = /^(\[[^\]]+\]|[^:]+)(?::([0-9]+))?$/.exec(value);
  if (!m) return false;
  const host = m[1]!,
    port = m[2];
  if (
    (requirePort && port === undefined) ||
    (port !== undefined && (port.length > 5 || Number(port) > 65535))
  )
    return false;
  return host.startsWith('[')
    ? host.endsWith(']') &&
        (ipv6(host.slice(1, -1)) ||
          /^[vV][0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+$/.test(host.slice(1, -1)))
    : /^(?:[A-Za-z0-9._~!$&'()*+,;=-]|%[0-9A-Fa-f]{2})+$/.test(host);
}
function field(input: unknown): FieldOccurrence {
  const a = snapshot(input, ['name', 'value', 'section', 'provenance'], 'invalid_field');
  const name = text(a.name, 'invalid_field');
  if (typeof a.value === 'string' || a.value instanceof Uint8Array)
    ensure(a.value.length <= MESSAGE_MAX_FIELD_BYTES, 'invalid_field');
  const b = byteString(a.value);
  ensure(token(name) && b.ok && b.value.length <= MESSAGE_MAX_FIELD_BYTES, 'invalid_field');
  ensure(
    b.value.every((n) => n === 9 || (n >= 32 && n <= 126) || n >= 128),
    'invalid_field',
  );
  ensure(a.section === 'headers' || a.section === 'trailers', 'invalid_field');
  const provenance = own(a, 'provenance', 'caller');
  ensure(['caller', 'http1', 'http2', 'http3'].includes(provenance as string), 'invalid_field');
  const bytes = b.value;
  return frozen({
    name,
    get value() {
      return new Uint8Array(bytes);
    },
    section: a.section,
    provenance: provenance as FieldOccurrence['provenance'],
  }, fieldOccurrences);
}
function body(input: unknown): Body {
  const a = snapshot(input, ['state', 'bytes', 'source', 'ownership', 'maxBytes'], 'invalid_body');
  const max = own(a, 'maxBytes', BODY_MAX_BYTES);
  ensure(typeof max === 'number' && Number.isSafeInteger(max) && max >= 0, 'invalid_body');
  ensure(own(a, 'ownership', 'caller') === 'caller', 'invalid_body');
  const source = own(a, 'source', null);
  let bytes: Uint8Array | null = null;
  const raw = own(a, 'bytes', null);
  if (a.state === 'retained') {
    if (typeof raw === 'string' || raw instanceof Uint8Array)
      ensure(raw.length <= max, 'invalid_body');
    const b = byteString(raw);
    ensure(b.ok && b.value.length <= max && source === null, 'invalid_body');
    bytes = b.value;
  } else if (a.state === 'streaming')
    ensure(
      raw === null && source !== null && typeof source === 'object' &&
        typeof (source as { getReader?: unknown }).getReader === 'function',
      'invalid_body',
    );
  else
    ensure(
      (a.state === 'unavailable' || a.state === 'consumed') && raw === null && source === null,
      'invalid_body',
    );
  return frozen({
    state: a.state as Body['state'],
    get bytes() {
      return bytes === null ? null : new Uint8Array(bytes);
    },
    source: source as Body['source'],
    ownership: 'caller',
    maxBytes: max,
  }, bodies);
}
function transport(input: unknown): TransportFacts {
  const a = snapshot(input, ['httpVersion', 'tls', 'evidence'], 'invalid_transport');
  const httpVersion = own(a, 'httpVersion', 'unknown'),
    tls = own(a, 'tls', 'unknown');
  ensure(
    ['unknown', 'http1_0', 'http1_1', 'http2', 'http3'].includes(httpVersion as string) &&
      ['unknown', 'plain', 'tls'].includes(tls as string) &&
      own(a, 'evidence', 'declared') === 'declared',
    'invalid_transport',
  );
  return frozen({
    httpVersion: httpVersion as TransportFacts['httpVersion'],
    tls: tls as TransportFacts['tls'],
    evidence: 'declared',
  }, transportFacts);
}
function message(input: unknown, related = false): Message {
  const keys = [
    'kind',
    'method',
    'rawTarget',
    'targetForm',
    'scheme',
    'authority',
    'status',
    'fields',
    'trailers',
    'body',
    'relatedRequest',
    'transport',
  ];
  const a = snapshot(input, keys, 'invalid_message');
  for (const k of ['kind', 'fields', 'trailers', 'body', 'transport'])
    ensure(Object.hasOwn(a, k), 'invalid_message');
  const b = body(a.body),
    t = transport(a.transport);
  const m = Object.assign(
    Object.create(null),
    Object.fromEntries(keys.map((k) => [k, own(a, k, null)])),
  ) as unknown as Message;
  let request: Message | null = null;
  if (m.kind === 'request') {
    ensure(m.status === null && m.relatedRequest === null, 'invalid_message');
    const method = text(m.method, 'invalid_message'),
      raw = text(m.rawTarget, 'invalid_message', MESSAGE_MAX_TARGET_BYTES);
    ensure(
      token(method) && raw.length > 0 && raw.length <= MESSAGE_MAX_TARGET_BYTES && uriBytes(raw),
      'invalid_message',
    );
    ensure(
      (m.scheme === null && m.authority === null) || (scheme(m.scheme) && authority(m.authority)),
      'invalid_message',
    );
    if (method === 'CONNECT')
      ensure(m.targetForm === 'authority' && authority(raw, true), 'invalid_message');
    else if (m.targetForm === 'asterisk')
      ensure(method === 'OPTIONS' && raw === '*', 'invalid_message');
    else if (m.targetForm === 'origin')
      ensure(raw.startsWith('/') && !/[\[\]]/.test(raw), 'invalid_message');
    else if (m.targetForm === 'absolute') {
      const parts = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?]+)((?:[/?].*)?)$/.exec(raw);
      ensure(
        parts && scheme(parts[1]) && authority(parts[2]) && !/[\[\]]/.test(parts[3]!),
        'invalid_message',
      );
      if (m.scheme !== null)
        ensure(parts[1] === m.scheme && parts[2] === m.authority, 'invalid_message');
    } else fail('invalid_message');
    if (m.targetForm === 'authority' && m.authority !== null)
      ensure(raw === m.authority, 'invalid_message');
    Object.assign(m, { method, rawTarget: raw });
  } else {
    ensure(
      !related &&
        m.kind === 'response' &&
        m.method === null &&
        m.rawTarget === null &&
        m.targetForm === null &&
        m.scheme === null &&
        m.authority === null &&
        Number.isSafeInteger(m.status) &&
        m.status! >= 100 &&
        m.status! <= 599,
      'invalid_message',
    );
    if (m.relatedRequest !== null) {
      ensure(isMessage(m.relatedRequest), 'invalid_message');
      request = message(m.relatedRequest, true);
      ensure(request.kind === 'request', 'invalid_message');
    }
  }
  let count = 0,
    size = 0;
  function fields(input: unknown, section: FieldOccurrence['section']): readonly FieldOccurrence[] {
    ensure(Array.isArray(input), 'invalid_field');
    ensure(input.length + count <= MESSAGE_MAX_OCCURRENCES, 'invalid_field');
    const out: FieldOccurrence[] = [];
    for (const x of input) {
      const f = field(x);
      ensure(f.section === section, 'invalid_field');
      count++;
      size += f.name.length + f.value.length;
      ensure(size <= MESSAGE_MAX_FIELDS_BYTES, 'invalid_field');
      out.push(f);
    }
    return Object.freeze(out);
  }
  const headers = fields(a.fields, 'headers');
  let trailers: Message['trailers'];
  if (a.trailers === 'unavailable') trailers = 'unavailable';
  else if (a.trailers === 'pending') {
    ensure(b.state === 'streaming', 'invalid_message');
    trailers = 'pending';
  } else trailers = fields(a.trailers, 'trailers');
  return frozen({
    ...m,
    fields: headers,
    trailers,
    body: b,
    transport: t,
    relatedRequest: request,
  }, messages);
}
/** Field occurrence construction and validation. */
export const FieldOccurrence = Object.freeze({
  /** Validate and brand the supplied HTTP snapshot. */
  create: (a: unknown): Result<FieldOccurrence> => protect(() => field(a), 'invalid_field'),
  /** Validate the snapshot using the same boundary as construction. */
  validate: (a: unknown): Result<FieldOccurrence> => protect(() => field(a), 'invalid_field'),
});
/** Body snapshot construction and validation. */
export const Body = Object.freeze({
  /** Validate and brand the supplied HTTP snapshot. */
  create: (a: unknown): Result<Body> => protect(() => body(a), 'invalid_body'),
  /** Validate the snapshot using the same boundary as construction. */
  validate: (a: unknown): Result<Body> => protect(() => body(a), 'invalid_body'),
});
/** Transport snapshot construction and validation. */
export const TransportFacts = Object.freeze({
  /** Validate and brand the supplied HTTP snapshot. */
  create: (a: unknown): Result<TransportFacts> => protect(() => transport(a), 'invalid_transport'),
  /** Validate the snapshot using the same boundary as construction. */
  validate: (a: unknown): Result<TransportFacts> =>
    protect(() => transport(a), 'invalid_transport'),
});
/** Validate and brand a lossless HTTP message snapshot. */
export function createMessage(a: unknown): Result<Message> {
  return protect(() => message(a), 'invalid_message');
}
/** Validate a message snapshot through the same constructor boundary. */
export const validateMessage = createMessage;
async function builder(
  kind: 'request' | 'response',
  first: unknown,
  target: unknown,
  headers: unknown,
  bytes: unknown,
  options: unknown,
): Promise<Result<Message>> {
  try {
    const a = snapshot(
      options,
      kind === 'request' ? ['digest'] : ['digest', 'request'],
      'invalid_message',
    );
    let protocol = '',
      origin = '',
      tail = '';
    if (kind === 'request') {
      const url = text(target, 'invalid_message', MESSAGE_MAX_URL_BYTES);
      ensure(url.length <= MESSAGE_MAX_URL_BYTES && !url.includes('#'), 'invalid_message');
      const parts = /^(https?):\/\/([^/?]+)((?:[/?].*)?)$/i.exec(url);
      ensure(parts, 'invalid_message');
      protocol = parts[1]!.toLowerCase();
      origin = parts[2]!.toLowerCase();
      const port = /^(\[[^\]]+\]|[^:]+):([0-9]+)$/.exec(origin);
      if (port && Number(port[2]) === (protocol === 'https' ? 443 : 80)) origin = port[1]!;
      tail = parts[3]!;
    }
    const content = body({ state: 'retained', bytes: bytes === null ? '' : bytes });
    ensure(Array.isArray(headers) && headers.length <= MESSAGE_MAX_OCCURRENCES, 'invalid_field');
    const fields: FieldOccurrence[] = headers.map((pair) => {
      ensure(Array.isArray(pair) && pair.length === 2, 'invalid_field');
      return field({ name: pair[0], value: pair[1], section: 'headers' });
    });
    const algorithms = own(a, 'digest', null);
    if (algorithms !== null) {
      ensure(
        Array.isArray(algorithms) &&
          algorithms.length > 0 &&
          algorithms.length <= 2 &&
          new Set(algorithms).size === algorithms.length &&
          algorithms.every((s) => s === 'sha-256' || s === 'sha-512') &&
          !fields.some((f) => f.name.toLowerCase() === 'content-digest'),
        'invalid_message',
      );
      const digests: string[] = [];
      for (const alg of algorithms) {
        try {
          const hash = await capturedDigest(
            alg === 'sha-256' ? 'SHA-256' : 'SHA-512',
            new Uint8Array(content.bytes!),
          );
          digests.push(alg + '=:' + encodeBase64(new Uint8Array(hash)) + ':');
        } catch {
          fail('invalid_body');
        }
      }
      fields.push(field({ name: 'content-digest', value: digests.join(', '), section: 'headers' }));
    }
    const common = {
      kind,
      fields,
      body: content,
      trailers: 'unavailable',
      transport: transport({}),
    };
    if (kind === 'response')
      return createMessage({ ...common, status: first, relatedRequest: own(a, 'request', null) });
    return createMessage({
      ...common,
      method: first,
      rawTarget: tail === '' || tail.startsWith('?') ? '/' + tail : tail,
      targetForm: 'origin',
      scheme: protocol,
      authority: origin,
    });
  } catch (e) {
    return err(
      isRequestSealError(e) && e.kind === 'message'
        ? (e as ReturnType<typeof messageError>)
        : messageError('invalid_message'),
    );
  }
}
/** Lossless HTTP message construction and validation. */
export const Message = Object.freeze({
  /** Validate and brand the supplied HTTP snapshot. */
  create: createMessage,
  /** Validate the snapshot using the same boundary as construction. */
  validate: validateMessage,
  /** Build a branded HTTP request with owned field and body bytes. */
  request: (
    method: unknown,
    target: unknown,
    fields: unknown,
    bytes: unknown,
    options: unknown = {},
  ): Promise<Result<Message>> => builder('request', method, target, fields, bytes, options),
  /** Build a branded HTTP response with owned field and body bytes. */
  response: (
    status: unknown,
    fields: unknown,
    bytes: unknown,
    options: unknown = {},
  ): Promise<Result<Message>> => builder('response', status, null, fields, bytes, options),
});
