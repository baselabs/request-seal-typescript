import type {BatchItem, BatchCheck} from './batch.ts';
import { parse, serialize, isStructuredFieldsValue, type Value } from '../../src/structured-fields/index.ts';
import { Message, Body, TransportFacts, FieldOccurrence, isMessage, isBody, isTransportFacts, isFieldOccurrence } from '../../src/message/index.ts';
import { build } from '../../src/signature-base/index.ts';
import { byteString, decodeBase64Url } from '../../src/bytes.ts';
import { type JsonNode } from '../../src/json.ts';
import { ruleId, signatureBaseError, isRequestSealError } from '../../src/errors/types.ts';
import { err, ok, type Result } from '../../src/result.ts';
import type { CorpusResources, Surface, SurfaceResult } from './loader.ts';
const invalid = (): SurfaceResult => ({ ok: false, loaderReason: 'invalid_manifest' });
function record(x: unknown): x is Record<string, any> {
  return x !== null && typeof x === 'object' && !Array.isArray(x);
}
export function sourcePlain(node: JsonNode): any {
  if (node === null || typeof node !== 'object') return node;
  if (node.kind === 'number') return node;
  if (node.kind === 'array') return node.items.map(sourcePlain);
  return Object.fromEntries(node.pairs.map(([k, v]) => [k, sourcePlain(v)]));
}
export function resolve(value: any, r: CorpusResources): any {
  if (record(value) && Object.hasOwn(value, 'ref')) {
    const x = r.reference(value);
    if (!x.ok) throw new Error();
    return sourcePlain(x.value);
  }
  return value;
}
export function decoded(value: any, r: CorpusResources): any {
  value = resolve(value, r);
  if (Array.isArray(value)) return value.map((v) => decoded(v, r));
  if (!record(value)) return value;
  const keys = Object.keys(value);
  if (keys.length === 1 && keys[0] === 'b64') {
    const b = decodeBase64Url(value.b64);
    if (!b.ok) throw new Error();
    return b.value;
  }
  if (keys.length === 1 && keys[0] === 'int') {
    if (typeof value.int !== 'string' || !/^-?(?:0|[1-9][0-9]*)$/.test(value.int))
      throw new Error();
    const n = Number(value.int);
    if (!Number.isSafeInteger(n)) throw new Error();
    return n;
  }
  if (keys.length === 1 && keys[0] === 'dec') {
    if (typeof value.dec !== 'string' || !/^-?[0-9]+\.[0-9]+$/.test(value.dec)) throw new Error();
    const scale = value.dec.split('.')[1]!.length,
      coefficient = BigInt(value.dec.replace('.', '')),
      scaled = coefficient <= BigInt(Number.MAX_SAFE_INTEGER) && coefficient >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(coefficient) : coefficient;
    return { scaled, scale };
  }
  if (keys.length === 1 && keys[0] === 'pairs') return decoded(value.pairs, r);
  return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, decoded(v, r)]));
}
function number(x: any): number {
  if (record(x) && x.kind === 'number') return Number(x.lexeme);
  return x;
}
function requireValue<T>(r: Result<T>, predicate: (value: unknown) => value is T): T {
  if (!r.ok) throw r.error;
  if (!predicate(r.value)) throw new Error();
  return r.value;
}
export function message(value: any, r: CorpusResources): Result<Message> {
  const v = decoded(value, r);
  if (!record(v)) return Message.validate(v);
  if (
    !Object.keys(v).every((k) =>
      [
        'kind',
        'method',
        'raw_target',
        'target_form',
        'scheme',
        'authority',
        'status',
        'fields',
        'trailers',
        'body',
        'related_request',
        'transport',
      ].includes(k),
    )
  )
    throw new Error();
  const fs = (input: any, section: string) =>
    Array.isArray(input)
      ? input.map((f) =>
          Array.isArray(f)
            ? requireValue(FieldOccurrence.create({ name: f[0], value: f[1], section }), isFieldOccurrence)
            : f,
        )
      : input;
  const body =
    v.body === 'unavailable'
      ? requireValue(Body.create({ state: 'unavailable' }), isBody)
      : v.body instanceof Uint8Array || typeof v.body === 'string'
        ? requireValue(Body.create({ state: 'retained', bytes: v.body }), isBody)
        : (v.body ?? requireValue(Body.create({ state: 'unavailable' }), isBody));
  const related =
    v.related_request === undefined || v.related_request === null
      ? null
      : requireValue(message(v.related_request, r), isMessage);
  return Message.validate({
    kind: v.kind,
    method: v.method ?? null,
    rawTarget: v.raw_target ?? null,
    targetForm: v.target_form ?? null,
    scheme: v.scheme ?? null,
    authority: v.authority ?? null,
    status: v.status === undefined ? null : number(v.status),
    fields: fs(v.fields, 'headers'),
    trailers: Array.isArray(v.trailers)
      ? fs(v.trailers, 'trailers')
      : (v.trailers ?? 'unavailable'),
    body,
    relatedRequest: related,
    transport: v.transport ?? requireValue(TransportFacts.create({}), isTransportFacts),
  });
}
function binary32(value: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes: number[] = [];
  let bits = 0,
    acc = 0;
  for (const c of value.replace(/=+$/, '')) {
    const n = alphabet.indexOf(c);
    if (n < 0) throw new Error();
    acc = (acc << 5) | n;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((acc >>> bits) & 255);
      acc &= (1 << bits) - 1;
    }
  }
  return new Uint8Array(bytes);
}
function bare(value: any): any {
  if (record(value) && value.kind === 'number') {
    const s = value.lexeme;
    if (!/[.eE]/.test(s)) return { kind: 'integer', value: Number(s) };
    const [mantissa, exponent = '0'] = s.toLowerCase().split('e');
    let scale = (mantissa.split('.')[1] ?? '').length - Number(exponent),
      scaled = BigInt(mantissa.replace('.', ''));
    if (scale < 0) {
      scaled *= 10n ** BigInt(-scale);
      scale = 0;
    }
    return { kind: 'decimal', value: { scaled: scaled <= BigInt(Number.MAX_SAFE_INTEGER) && scaled >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(scaled) : scaled, scale } };
  }
  if (record(value))
    return value.__type === 'binary'
      ? { kind: 'bytes', value: binary32(value.value) }
      : value.__type === 'date'
        ? { kind: 'date', value: number(value.value) }
        : {
            kind: value.__type === 'displaystring' ? 'display_string' : value.__type,
            value: value.value,
          };
  return { kind: typeof value === 'boolean' ? 'boolean' : 'string', value };
}
function expected(value: any, type: string): Value {
  if (type === 'dictionary')
    return {
      kind: 'dictionary',
      value: value.map(([k, v]: any) => [
        k,
        expected(v, Array.isArray(v[0]) ? 'inner_list' : 'item'),
      ]),
    };
  if (type === 'list')
    return {
      kind: 'list',
      value: value.map((v: any) => expected(v, Array.isArray(v[0]) ? 'inner_list' : 'item')),
    };
  return {
    kind: type,
    value: type === 'item' ? bare(value[0]) : value[0].map((v: any) => expected(v, 'item')),
    parameters: value[1].map(([k, v]: any) => [k, bare(v)]),
  } as Value;
}
const text = (b: Uint8Array) => new TextDecoder().decode(b);
function equivalent(a: any, b: any): boolean {
  if (a instanceof Uint8Array && b instanceof Uint8Array)
    return a.length === b.length && a.every((v, i) => v === b[i]);
  if (a?.kind === 'decimal' && b?.kind === 'decimal')
    return BigInt(a.value.scaled) * 10n ** BigInt(b.value.scale) === BigInt(b.value.scaled) * 10n ** BigInt(a.value.scale);
  if (Array.isArray(a) && Array.isArray(b))
    return a.length === b.length && a.every((v, i) => equivalent(v, b[i]));
  if (record(a) && record(b)) {
    const keys = Object.keys(a);
    return (
      keys.length === Object.keys(b).length &&
      keys.every((k) => Object.hasOwn(b, k) && equivalent(a[k], b[k]))
    );
  }
  return a === b;
}
function httpwg(cases: any, pin: string | undefined): boolean {
  if (!Array.isArray(cases) || cases.length === 0) return false;
  if (cases.some(v => record(v) && v.can_fail === true) && pin !== 'accept' && pin !== 'reject') return false;
  for (const v of cases) {
    if (
      !record(v) ||
      !['item', 'list', 'dictionary'].includes(v.header_type) ||
      typeof v.name !== 'string'
    )
      return false;
    const options = { schema: { revision: 'rfc9651', type: v.header_type, itemTypes: ['integer', 'decimal', 'string', 'token', 'bytes', 'boolean', 'date', 'display_string'], innerLists: true } };
    const canonical = (v.canonical ?? v.raw ?? []).join(', ');
    if (v.raw) {
      const parsed = parse(v.header_type, v.raw.join(', '), options);
      const rejects =
        v.must_fail ||
        (v.can_fail && pin === 'reject');
      if (rejects) {
        if (parsed.ok || parsed.error.kind !== 'structured_fields') return false;
      } else {
        if (!parsed.ok || !isStructuredFieldsValue(parsed.value) || !equivalent(parsed.value, expected(v.expected, v.header_type)))
          return false;
        const bytes = serialize(parsed.value);
        if (!bytes.ok || text(bytes.value) !== canonical) return false;
      }
    }
    if (v.expected) {
      const bytes = serialize(expected(v.expected, v.header_type), options);
      if (v.must_fail ? bytes.ok || bytes.error.kind !== 'structured_fields' : !bytes.ok || text(bytes.value) !== canonical) return false;
    }
    if (!v.raw && !v.expected) return false;
  }
  return true;
}
function rfc9421(cases: any, r: CorpusResources): boolean {
  if (!Array.isArray(cases) || cases.length === 0) return false;
  for (const v of cases) {
    if (!record(v) || typeof v.parameters !== 'string' || typeof v.base !== 'string') return false;
    const m = message(v.message, r);
    if (!m.ok || !isMessage(m.value)) return false;
    const bytes = build(m.value, v.parameters);
    if (!bytes.ok || text(bytes.value) !== v.base) return false;
    for (const t of v.transformations ?? []) {
      const m = message(t.message, r);
      if (!m.ok || typeof t.same_base !== 'boolean') return false;
      const transformed = {...v, ...t};
      const bytes = build(m.value, transformed.parameters);
      if (!bytes.ok || (text(bytes.value) === transformed.base) !== t.same_base) return false;
    }
  }
  return true;
}
export function wireSurface(surface: string): Surface {
  return (manifest, r) => {
    try {
      const i = manifest.inputs;
      if (Object.hasOwn(i, 'format')) {
        if (Object.keys(i).sort().join(',') !== 'cases,format') return invalid();
        const cases = resolve(i.cases, r);
        const valid =
          i.format === 'httpwg-structured-fields/1' &&
          (surface === 'structured_fields.parse' || surface === 'structured_fields.serialize')
            ? httpwg(cases, manifest.pin)
            : i.format === 'rfc9421-signature-bases/1' && surface === 'signature_base.build'
              ? rfc9421(cases, r)
              : false;
        return valid ? ok({ valid: true }) : invalid();
      }
      if (surface === 'structured_fields.parse') {
        if (!Object.keys(i).every((k) => ['field_type', 'raw', 'schema', 'mode'].includes(k)))
          return invalid();
        const v = parse(i.field_type, decoded(i.raw, r), {
          schema: decoded(i.schema, r),
          ...(Object.hasOwn(i, 'mode') ? { mode: i.mode } : {}),
        });
        return v.ok ? bytesResult(serialize(v.value)) : v;
      }
      if (surface === 'structured_fields.serialize') {
        if (!Object.keys(i).every((k) => ['value', 'schema'].includes(k))) return invalid();
        return bytesResult(
          serialize(
            decoded(i.value, r),
            Object.hasOwn(i, 'schema') ? { schema: decoded(i.schema, r) } : {},
          ),
        );
      }
      if (surface === 'message.validate') {
        if (!Object.keys(i).every(k => ['message','message_override','append_fields'].includes(k))) return invalid();
        const base = resolve(i.message, r);
        if (!record(base) || (i.message_override !== undefined && !record(i.message_override)) || (i.append_fields !== undefined && !Array.isArray(i.append_fields))) return invalid();
        const built = message(base, r);
        if (!built.ok) return built;
        const fields = [...built.value.fields, ...(i.append_fields ?? []).map((f: any) => requireValue(FieldOccurrence.create({name: f[0], value: decoded(f[1], r), section: 'headers'}), isFieldOccurrence))];
        const names: Record<string, string> = {raw_target: 'rawTarget', target_form: 'targetForm', related_request: 'relatedRequest'};
        if (!Object.keys(i.message_override ?? {}).every(key => ['raw_target','target_form','related_request','authority','scheme','fields'].includes(key))) return invalid();
        const overrides = Object.fromEntries(Object.entries(i.message_override ?? {}).map(([key, value]) => {
          const v = decoded(value, r);
          return [names[key] ?? key, key === 'fields' ? Array.isArray(v) ? v.map(f => {
            if (!Array.isArray(f) || f.length !== 2) throw new Error();
            return requireValue(FieldOccurrence.create({name: f[0], value: f[1], section: 'headers'}), isFieldOccurrence);
          }) : v : key === 'related_request' && v !== null ? requireValue(message(v, r), isMessage) : v];
        }));
        const v = Message.validate({...built.value, fields, ...overrides});
        return v.ok ? ok({ valid: true }) : v;
      }
      if (!Object.keys(i).every((k) => ['message', 'parameters', 'field_schemas'].includes(k)))
        return invalid();
      const m = message(i.message, r);
      if (!m.ok) return err(signatureBaseError('invalid_message'));
      const schemas = decoded(i.field_schemas ?? {}, r);
      return bytesResult(build(m.value, decoded(i.parameters, r), { fieldSchemas: schemas }));
    } catch (e) {
      if (isRequestSealError(e) && e.kind === 'message')
        return surface === 'signature_base.build'
          ? err(signatureBaseError('invalid_message'))
          : err(e);
      return invalid();
    }
  };
}
function bytesResult(result: Result<Uint8Array>): SurfaceResult {
  return result.ok ? ok({ bytes: result.value }) : result;
}

/** Execute one asserted release item; manifest pins are the only optional verdicts. */
export function wireBatchItem(item: BatchItem, manifest: Record<string, any>, r: CorpusResources): BatchCheck {
  const v = item.value;
  if (Object.hasOwn(manifest, 'overrides')) return {ok: false, expected: 'format without overrides', actual: 'unsupported_overrides'};
  try {
    if (manifest.batch.item_format === 'rfc9421-signature-bases/1') {
      const parent = item.parent ?? v, m = message(v.message, r);
      const expected = item.parent ? {base: parent.base, same_base: v.same_base} : parent.base;
      if (!m.ok) return {ok: false, expected, actual: {rule_id: ruleId(m.error)}};
      const transformed = item.parent ? {...parent, ...v} : v;
      const result = build(m.value, transformed.parameters);
      if (!result.ok) return {ok: false, expected, actual: {rule_id: ruleId(result.error)}};
      const actual = text(result.value);
      return {ok: item.parent ? (actual === parent.base) === v.same_base : actual === parent.base, expected, actual};
    }
    const options = {schema: {revision: 'rfc9651', type: v.header_type, itemTypes: ['integer','decimal','string','token','bytes','boolean','date','display_string'], innerLists: true}};
    const reject = v.must_fail === true || (v.can_fail === true && manifest.pins[item.id].outcome === 'reject');
    const canonical = (v.canonical ?? v.raw ?? []).join(', '), checks: BatchCheck[] = [];
    if (v.raw) {
      const parsed = parse(v.header_type, v.raw.join(', '), options);
      if (reject) checks.push({ok: !parsed.ok && parsed.error.kind === 'structured_fields', expected: 'reject', actual: parsed.ok ? 'accept' : {rule_id: ruleId(parsed.error)}});
      else if (!parsed.ok) checks.push({ok: false, expected: v.expected, actual: {rule_id: ruleId(parsed.error)}});
      else {
        const shape = isStructuredFieldsValue(parsed.value) && equivalent(parsed.value, expected(v.expected, v.header_type));
        const result = serialize(parsed.value);
        checks.push({ok: shape && result.ok && text(result.value) === canonical, expected: canonical, actual: result.ok ? text(result.value) : {rule_id: ruleId(result.error)}});
      }
    }
    if (v.expected) {
      const result = serialize(expected(v.expected, v.header_type), options);
      checks.push({ok: v.must_fail ? !result.ok && result.error.kind === 'structured_fields' : result.ok && text(result.value) === canonical, expected: v.must_fail ? 'reject' : canonical, actual: result.ok ? text(result.value) : {rule_id: ruleId(result.error)}});
    }
    return checks.find(c => !c.ok) ?? {ok: checks.length > 0, expected: 'valid', actual: 'valid'};
  } catch {return {ok: false, expected: 'supported item shape', actual: 'unexpected_item_shape'};}
}
