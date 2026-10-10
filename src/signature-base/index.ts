import {encodeUtf8} from '../runtime.ts';
import {
  parse,
  serialize,
  createSchema,
  type Schema,
  type InnerList,
  type Value,
  type Parameters,
} from '../structured-fields/index.ts';
import {
  validateMessage,
  isMessage,
  token,
  uriBytes,
  type Message,
  type FieldOccurrence,
} from '../message/index.ts';
import { snapshotOptions } from '../brand.ts';
import { byteString, encodeBase64 } from '../bytes.ts';
import {
  SIGNATURE_BASE_MAX_BYTES,
  SIGNATURE_BASE_MAX_COMPONENTS,
  MESSAGE_MAX_OCCURRENCES,
} from '../constants.ts';
import { signatureBaseError, isRequestSealError } from '../errors/types.ts';
import type { Reason } from '../errors/parity.ts';
import { err, ok, type Result } from '../result.ts';
const derived = new Set([
  '@method',
  '@target-uri',
  '@authority',
  '@scheme',
  '@request-target',
  '@path',
  '@query',
  '@query-param',
  '@status',
]);
const signatureSchema: Schema = sf(createSchema({
  revision: 'rfc8941',
  type: 'list',
  itemTypes: Object.freeze(['string'] as const),
  parameterTypes: Object.freeze([
    'integer',
    'decimal',
    'string',
    'token',
    'bytes',
    'boolean',
  ] as const),
  innerLists: true,
}), 'invalid_signature_parameters');
function fail(reason: Reason<'signature_base'>): never {
  throw signatureBaseError(reason);
}
function ensure(v: unknown, reason: Reason<'signature_base'>): asserts v {
  if (!v) fail(reason);
}
function sf<T>(result: Result<T>, reason: Reason<'signature_base'>): T {
  if (!result.ok) fail(result.error.reason === 'limit' ? 'limit' : reason);
  return result.value;
}
const text = (b: Uint8Array) => {
  const out: string[] = [];
  for (let i = 0; i < b.length; i += 8192)
    out.push(String.fromCharCode(...b.subarray(i, i + 8192)));
  return out.join('');
};
function canonical(value: Value, schema: Schema, reason: Reason<'signature_base'>): string {
  return text(sf(serialize(value, { schema }), reason));
}
function fieldName(s: unknown): s is string {
  return token(s) && s === s.toLowerCase();
}
function origin(m: Message): [string, string] {
  if (m.targetForm === 'absolute') {
    const p = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?]+)/.exec(m.rawTarget!)!;
    return [p[1]!, p[2]!];
  }
  ensure(m.scheme !== null && m.authority !== null, 'unavailable_origin');
  return [m.scheme, m.authority];
}
function pathQuery(m: Message): [string, string | null] {
  const tail =
    m.targetForm === 'origin'
      ? m.rawTarget!
      : m.targetForm === 'absolute'
        ? m.rawTarget!.replace(/^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?]+/, '')
        : '';
  const i = tail.indexOf('?');
  return i < 0 ? [tail, null] : [tail.slice(0, i), tail.slice(i + 1)];
}
function decodeQuery(s: string): string {
  ensure(uriBytes(s), 'invalid_query_encoding');
  try {
    return decodeURIComponent(s.replace(/\+/g, ' '));
  } catch {
    return fail('invalid_query_encoding');
  }
}
function encodeQuery(s: string): string {
  return Array.from(encodeUtf8(s), (b) =>
    /[A-Za-z0-9*._-]/.test(String.fromCharCode(b))
      ? String.fromCharCode(b)
      : '%' + b.toString(16).toUpperCase().padStart(2, '0'),
  ).join('');
}
function trim(b: Uint8Array): Uint8Array {
  let start = 0,
    end = b.length;
  while (start < end && (b[start] === 32 || b[start] === 9)) start++;
  while (end > start && (b[end - 1] === 32 || b[end - 1] === 9)) end--;
  return b.subarray(start, end);
}
/** Ordered identifiers and parameters are serialized exactly once for each output line. */
export function build(
  input: unknown,
  parameters: unknown,
  options: unknown = {},
): Result<Uint8Array> {
  try {
    ensure(isMessage(input), 'invalid_message');
    const validated = validateMessage(input);
    ensure(validated.ok && isMessage(validated.value), 'invalid_message');
    const m = validated.value;
    const attrs = snapshotOptions(options, ['fieldSchemas', 'maxComponents', 'maxBytes']);
    ensure(attrs.ok, 'invalid_options');
    const a = attrs.value;
    const maxComponents = Object.hasOwn(a, 'maxComponents')
        ? a.maxComponents
        : SIGNATURE_BASE_MAX_COMPONENTS,
      maxBytes = Object.hasOwn(a, 'maxBytes') ? a.maxBytes : SIGNATURE_BASE_MAX_BYTES;
    ensure(
      typeof maxComponents === 'number' &&
        Number.isSafeInteger(maxComponents) &&
        maxComponents > 0 &&
        maxComponents <= SIGNATURE_BASE_MAX_COMPONENTS &&
        typeof maxBytes === 'number' &&
        Number.isSafeInteger(maxBytes) &&
        maxBytes > 0 &&
        maxBytes <= SIGNATURE_BASE_MAX_BYTES,
      'invalid_options',
    );
    const supplied = Object.hasOwn(a, 'fieldSchemas') ? a.fieldSchemas : {};
    ensure(supplied && typeof supplied === 'object' && !Array.isArray(supplied), 'invalid_options');
    const keys = Reflect.ownKeys(supplied);
    ensure(keys.length <= MESSAGE_MAX_OCCURRENCES && keys.every(fieldName), 'invalid_options');
    const schemas = snapshotOptions(supplied, keys as string[]);
    ensure(schemas.ok, 'invalid_options');
    const fieldSchemas = new Map<string, Schema>();
    for (const k of keys as string[])
      fieldSchemas.set(k, sf(createSchema(schemas.value[k]), 'invalid_options'));
    let p: InnerList;
    if (typeof parameters === 'string' || parameters instanceof Uint8Array) {
      const parsed = sf(
        parse('list', parameters, { schema: signatureSchema }),
        'invalid_signature_parameters',
      );
      ensure(
        parsed.kind === 'list' &&
          parsed.value.length === 1 &&
          parsed.value[0]?.kind === 'inner_list',
        'invalid_signature_parameters',
      );
      p = parsed.value[0];
    } else {
      ensure(
        parameters &&
          typeof parameters === 'object',
        'invalid_signature_parameters',
      );
      p = parameters as InnerList;
    }
    const serialized = canonical(
      { kind: 'list', value: [p] },
      signatureSchema,
      'invalid_signature_parameters',
    );
    const snapshot = sf(
      parse('list', serialized, { schema: signatureSchema, mode: 'unique' }),
      'invalid_signature_parameters',
    );
    ensure(snapshot.kind === 'list' && snapshot.value.length === 1 && snapshot.value[0]?.kind === 'inner_list', 'invalid_signature_parameters');
    p = snapshot.value[0];
    for (const [name, bare] of p.parameters) {
      if (name === 'created' || name === 'expires')
        ensure(bare.kind === 'integer', 'invalid_signature_parameters');
      if (['nonce', 'alg', 'keyid', 'tag'].includes(name))
        ensure(bare.kind === 'string', 'invalid_signature_parameters');
    }
    ensure(p.value.length <= maxComponents, 'limit');
    const seen = new Set<string>(),
      queries = new Map<Message, Map<string, string[]>>(),
      structured = new Map<Message, Map<string, Value>>(),
      sections = new Map<Message, Map<string, Map<string, FieldOccurrence[]>>>();
    function query(source: Message, name: string): string {
      ensure(encodeQuery(decodeQuery(name)) === name, 'noncanonical_query_name');
      let index = queries.get(source);
      if (!index) {
        index = new Map();
        for (const entry of (pathQuery(source)[1] ?? '').split('&')) {
          if (entry === '') continue;
          const pos = entry.indexOf('=');
          const key = encodeQuery(decodeQuery(pos < 0 ? entry : entry.slice(0, pos)));
          const value = pos < 0 ? '' : entry.slice(pos + 1);
          const values = index.get(key);
          if (values) values.push(value);
          else index.set(key, [value]);
        }
        queries.set(source, index);
      }
      const values = index.get(name);
      ensure(values && values.length > 0, 'missing_query_parameter');
      ensure(values.length === 1, 'ambiguous_query_parameter');
      return encodeQuery(decodeQuery(values[0]!));
    }
    function occurrences(
      source: Message,
      section: 'headers' | 'trailers',
      name: string,
    ): FieldOccurrence[] {
      let cache = sections.get(source);
      if (!cache) {
        cache = new Map();
        sections.set(source, cache);
      }
      let index = cache.get(section);
      if (!index) {
        const fs = section === 'headers' ? source.fields : source.trailers;
        ensure(Array.isArray(fs), 'unavailable_trailers');
        index = new Map();
        for (const f of fs as readonly FieldOccurrence[]) {
          const key = f.name.toLowerCase(),
            values = index.get(key);
          if (values) values.push(f);
          else index.set(key, [f]);
        }
        cache.set(section, index);
      }
      const selected = index.get(name);
      ensure(selected && selected.length > 0, 'missing_field');
      return selected;
    }
    function value(
      source: Message,
      name: string,
      params: Map<string, Parameters[number][1]>,
    ): string {
      if (derived.has(name)) {
        if (name === '@status') {
          ensure(source.kind === 'response', 'wrong_message_kind');
          return String(source.status);
        }
        ensure(source.kind === 'request', 'wrong_message_kind');
        if (name === '@method') return source.method!;
        if (name === '@request-target') return source.rawTarget!;
        if (name === '@path') return pathQuery(source)[0] || '/';
        if (name === '@query') return '?' + (pathQuery(source)[1] ?? '');
        if (name === '@query-param') {
          const n = params.get('name')!;
          ensure(n.kind === 'string', 'invalid_component_parameters');
          return query(source, n.value);
        }
        const [scheme, authority] = origin(source);
        if (name === '@scheme') return scheme.toLowerCase();
        if (name === '@target-uri')
          return source.targetForm === 'absolute'
            ? source.rawTarget!
            : scheme +
                '://' +
                authority +
                (source.targetForm === 'origin' ? source.rawTarget! : '');
        const match = /^(\[[^\]]+\]|[^:]+)(?::([0-9]+))?$/.exec(authority)!;
        const port = match[2],
          defaultPort =
            scheme.toLowerCase() === 'https' ? 443 : scheme.toLowerCase() === 'http' ? 80 : null;
        return (
          match[1]!.toLowerCase() +
          (port !== undefined && Number(port) !== defaultPort ? ':' + port : '')
        );
      }
      const section = params.has('tr') ? 'trailers' : 'headers';
      const fs = occurrences(source, section, name);
      if (params.has('bs'))
        return fs.map((f) => ':' + encodeBase64(trim(f.value)) + ':').join(', ');
      const raw = fs.map((f) => text(trim(f.value))).join(', ');
      if (!params.has('sf') && !params.has('key')) return raw;
      const schema = fieldSchemas.get(name);
      ensure(schema, 'unknown_field_schema');
      ensure(!params.has('key') || schema.type === 'dictionary', 'invalid_field_schema');
      let cache = structured.get(source);
      if (!cache) {
        cache = new Map();
        structured.set(source, cache);
      }
      const key = section + ':' + name;
      let parsed = cache.get(key);
      if (!parsed) {
        parsed = sf(parse(schema.type, raw, { schema }), 'invalid_structured_field');
        cache.set(key, parsed);
      }
      if (params.has('key')) {
        const n = params.get('key')!;
        ensure(n.kind === 'string' && parsed.kind === 'dictionary', 'invalid_field_schema');
        const selected = parsed.value.find(([key]) => key === n.value);
        ensure(selected, 'missing_dictionary_key');
        return canonical(
          { kind: 'list', value: [selected[1]] },
          { ...schema, type: 'list' },
          'invalid_structured_field',
        );
      }
      return canonical(parsed, schema, 'invalid_structured_field');
    }
    const output: string[] = [];
    let size = 0;
    const emit = (line: string) => {
      size += line.length;
      ensure(size <= maxBytes, 'limit');
      output.push(line);
    };
    for (const component of p.value) {
      ensure(
        component.kind === 'item' && component.value.kind === 'string',
        'invalid_signature_parameters',
      );
      const name = component.value.value;
      ensure(
        derived.has(name) || fieldName(name),
        name.startsWith('@') ? 'unknown_component' : 'invalid_component',
      );
      const allowed = derived.has(name)
        ? name === '@query-param'
          ? ['req', 'name']
          : ['req']
        : ['sf', 'key', 'bs', 'tr', 'req'];
      for (const [key, bare] of component.parameters)
        ensure(
          allowed.includes(key) &&
            ((bare.kind === 'boolean' &&
              bare.value === true &&
              ['sf', 'bs', 'tr', 'req'].includes(key)) ||
              (bare.kind === 'string' && ['key', 'name'].includes(key))),
          'invalid_component_parameters',
        );
      const params = new Map(component.parameters);
      ensure(name !== '@query-param' || params.has('name'), 'invalid_component_parameters');
      ensure(
        !(params.has('bs') && (params.has('sf') || params.has('key'))),
        'incompatible_parameters',
      );
      const identity = JSON.stringify([
        name,
        [...component.parameters]
          .sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0))
          .map(([key, bare]) => [key, bare.kind, bare.value]),
      ]);
      ensure(!seen.has(identity), 'duplicate_component');
      seen.add(identity);
      let source = m;
      if (params.has('req')) {
        ensure(m.kind === 'response', 'wrong_message_kind');
        ensure(m.relatedRequest, 'missing_request_context');
        source = m.relatedRequest;
      }
      const v = value(source, name, params);
      ensure(/^[\x09\x20-\x7e]*$/.test(v), 'non_ascii');
      const identifier = canonical(
        component,
        { ...signatureSchema, type: 'item' },
        'invalid_signature_parameters',
      );
      emit(identifier + ': ' + v + '\n');
    }
    emit('"@signature-params": ' + canonical(snapshot, signatureSchema, 'invalid_signature_parameters'));
    const bytes = byteString(output.join(''));
    ensure(bytes.ok, 'non_ascii');
    return ok(bytes.value);
  } catch (e) {
    return err(
      isRequestSealError(e) && e.kind === 'signature_base'
        ? (e as ReturnType<typeof signatureBaseError>)
        : signatureBaseError('invalid_signature_parameters'),
    );
  }
}
export const SignatureBase = Object.freeze({ build });
