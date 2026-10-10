import {decodeUtf8Fatal, encodeUtf8} from '../runtime.ts';
import { isMessage, token, type Message } from '../message/index.ts';
import { byteString, decodeBase64, encodeBase64 } from '../bytes.ts';
import { snapshotOptions } from '../brand.ts';
import { STRUCTURED_FIELDS_LIMITS as CEILINGS, SF_MAX_INTEGER } from '../constants.ts';
import { parseDecimal, structuredInteger } from '../numbers.ts';
import { structuredFieldsError, messageError, isRequestSealError } from '../errors/types.ts';
import type { Reason } from '../errors/parity.ts';
import { err, ok, type Result } from '../result.ts';
export type Bare =
  | Readonly<{ kind: 'integer' | 'date'; value: number }>
  | Readonly<{ kind: 'decimal'; value: Readonly<{ scaled: number | bigint; scale: number }> }>
  | Readonly<{ kind: 'string' | 'token' | 'display_string'; value: string }>
  | Readonly<{ kind: 'bytes'; value: Uint8Array }>
  | Readonly<{ kind: 'boolean'; value: boolean }>;
// Exact parsed decimal text is internal provenance, separate from its numeric value.
const decimalSources = new WeakMap<object, string>();
export function decimalSource(value: Bare): string | undefined { return decimalSources.get(value); }
export function copyDecimalSource(from: Bare, to: Bare): void {
  const source = decimalSources.get(from);
  if (source !== undefined) decimalSources.set(to, source);
}
export type Parameters = readonly (readonly [string, Bare])[];
export type Item = Readonly<{ kind: 'item'; value: Bare; parameters: Parameters }>;
export type InnerList = Readonly<{
  kind: 'inner_list';
  value: readonly Item[];
  parameters: Parameters;
}>;
export type Member = Item | InnerList;
export type List = Readonly<{ kind: 'list'; value: readonly Member[] }>;
export type Dictionary = Readonly<{
  kind: 'dictionary';
  value: readonly (readonly [string, Member])[];
}>;
export type Value = Item | InnerList | List | Dictionary;
export type FieldType = 'item' | 'list' | 'dictionary';
export type Revision = 'rfc8941' | 'rfc9651';
export type Schema = Readonly<{
  revision: Revision;
  type: FieldType;
  itemTypes: readonly Bare['kind'][];
  parameterTypes: readonly Bare['kind'][];
  innerLists: boolean;
}>;
export type Limits = typeof CEILINGS;
export type Options = {
  schema: Revision | Schema;
  uniqueKeys?: 'all' | string[];
  uniqueParameters?: boolean;
  mode?: 'rfc' | 'unique';
  limits?: Partial<{ -readonly [K in keyof Limits]: number }>;
};
const baseTypes: readonly Bare['kind'][] = [
  'integer',
  'decimal',
  'string',
  'token',
  'bytes',
  'boolean',
];
const allTypes: readonly Bare['kind'][] = [...baseTypes, 'date', 'display_string'];
const schemas = new WeakMap<object, Schema>();
const values = new WeakSet<object>();
const schemaValues = new WeakSet<object>();
export function isStructuredFieldsValue(value: unknown): value is Value {
  return typeof value === 'object' && value !== null && values.has(value);
}
export function isStructuredFieldsSchema(value: unknown): value is Schema {
  return typeof value === 'object' && value !== null && schemaValues.has(value);
}

function fail(reason: Reason<'structured_fields'>): never {
  throw structuredFieldsError(reason);
}
function ensure(value: unknown, reason: Reason<'structured_fields'>): asserts value {
  if (!value) fail(reason);
}
export function createSchema(input: unknown): Result<Schema> {
  try {
    const s = snapshotOptions(input, [
      'revision',
      'type',
      'itemTypes',
      'parameterTypes',
      'innerLists',
    ]);
    ensure(s.ok, 'invalid_schema');
    const a = s.value;
    ensure(a.revision === 'rfc8941' || a.revision === 'rfc9651', 'invalid_schema');
    ensure(['item', 'list', 'dictionary'].includes(a.type as string), 'invalid_schema');
    const allowed = a.revision === 'rfc8941' ? baseTypes : allTypes;
    const list = (x: unknown, empty: boolean) =>
      Array.isArray(x) &&
      (empty || x.length > 0) &&
      x.length <= allowed.length &&
      new Set(x).size === x.length &&
      x.every((t) => allowed.includes(t));
    ensure(list(a.itemTypes, false), 'invalid_schema');
    const parameterTypes = Object.hasOwn(a, 'parameterTypes') ? a.parameterTypes : allowed;
    ensure(list(parameterTypes, true), 'invalid_schema');
    const innerLists = Object.hasOwn(a, 'innerLists') ? a.innerLists : false;
    ensure(typeof innerLists === 'boolean', 'invalid_schema');
    const value = Object.freeze({
      revision: a.revision,
      type: a.type as FieldType,
      itemTypes: Object.freeze([...(a.itemTypes as Bare['kind'][])]),
      parameterTypes: Object.freeze([...(parameterTypes as Bare['kind'][])]),
      innerLists,
    });
    schemaValues.add(value);
    return ok(value);
  } catch (e) {
    return err(error(e, 'invalid_schema'));
  }
}
function error(e: unknown, fallback: Reason<'structured_fields'>) {
  return isRequestSealError(e) && e.kind === 'structured_fields'
    ? (e as ReturnType<typeof structuredFieldsError>)
    : structuredFieldsError(fallback);
}
function setup(type: FieldType, options: unknown, retained?: Schema) {
  const s = snapshotOptions(options, ['schema', 'mode', 'limits', 'uniqueKeys', 'uniqueParameters']);
  ensure(s.ok, 'invalid_limits');
  const a = s.value;
  ensure(['item', 'list', 'dictionary'].includes(type), 'invalid_schema');
  const requested = Object.hasOwn(a, 'schema')
    ? a.schema
    : retained
      ? { ...retained, type }
      : undefined;
  const schemaResult =
    typeof requested === 'string'
      ? createSchema({
          revision: requested,
          type,
          itemTypes: requested === 'rfc8941' ? baseTypes : allTypes,
          innerLists: false,
        })
      : createSchema(requested);
  ensure(schemaResult.ok, 'invalid_schema');
  const schema = schemaResult.value;
  ensure(schema.type === type, 'schema_type');
  const mode = Object.hasOwn(a, 'mode') ? a.mode : 'rfc';
  ensure(mode === 'rfc' || mode === 'unique', 'invalid_limits');
  const lower = snapshotOptions(
    Object.hasOwn(a, 'limits') ? a.limits : {},
    Object.keys(CEILINGS) as (keyof Limits)[],
  );
  ensure(lower.ok, 'invalid_limits');
  const limits = Object.assign(Object.create(null), CEILINGS) as {
    -readonly [K in keyof Limits]: number;
  };
  for (const k of Object.keys(CEILINGS) as (keyof Limits)[])
    if (Object.hasOwn(lower.value, k)) {
      const n = lower.value[k];
      ensure(
        typeof n === 'number' && Number.isSafeInteger(n) && n > 0 && n <= CEILINGS[k],
        'invalid_limits',
      );
      limits[k] = n;
    }
  const uniqueKeys = Object.hasOwn(a, 'uniqueKeys') ? a.uniqueKeys : mode === 'unique' ? 'all' : [];
  ensure(
    uniqueKeys === 'all' ||
      (Array.isArray(uniqueKeys) && uniqueKeys.length <= limits.maxMembers &&
        uniqueKeys.every(k => typeof k === 'string' && k.length <= limits.maxKeyBytes &&
          /^[a-z*][a-z0-9_.*-]*$/.test(k))),
    'invalid_limits',
  );
  const uniqueParameters = Object.hasOwn(a, 'uniqueParameters') ? a.uniqueParameters : mode === 'unique';
  ensure(typeof uniqueParameters === 'boolean', 'invalid_limits');
  const selectedKeys = uniqueKeys === 'all' ? null : new Set(uniqueKeys as string[]);
  let nodes = 0;
  return {
    schema,
    limits,
    uniqueKey: (key: string) => selectedKeys === null || selectedKeys.has(key),
    listedUniqueKey: (key: string) => selectedKeys !== null && selectedKeys.has(key),
    uniqueParameters,
    node: () => ensure(++nodes <= limits.maxNodes, 'limit'),
  };
}
function byteText(b: Uint8Array): string {
  const chunks: string[] = [];
  for (let i = 0; i < b.length; i += 8192)
    chunks.push(String.fromCharCode(...b.subarray(i, i + 8192)));
  return chunks.join('');
}
/** A single cursor, bounded container depth, and encounter counts before deduplication. */
export function parse(
  fieldType: FieldType | unknown,
  raw: unknown,
  options: unknown = {},
): Result<Value> {
  try {
    const state = setup(fieldType as FieldType, options),
      { limits, schema } = state;
    if (typeof raw === 'string' || raw instanceof Uint8Array)
      ensure(raw.length <= limits.maxBytes, 'limit');
    const b = byteString(raw);
    ensure(b.ok, 'syntax');
    ensure(b.value.length <= limits.maxBytes, 'limit');
    const s = byteText(b.value);
    let i = 0,
      dupKey = false,
      dupParam = false;
    const sp = () => {
        while (s[i] === ' ') i++;
      },
      ows = () => {
        while (s[i] === ' ' || s[i] === '\t') i++;
      };
    const take = (re: RegExp, max: number) => {
      const start = i;
      while (i < s.length && re.test(s[i]!)) {
        ensure(i - start < max, 'limit');
        i++;
      }
      return s.slice(start, i);
    };
    const key = () => {
      ensure(/[a-z*]/.test(s[i] ?? '') && i < s.length, 'syntax');
      return take(/[a-z0-9_.*-]/, limits.maxKeyBytes);
    };
    const check = (v: Bare, param: boolean) => {
      ensure(
        (schema.revision === 'rfc8941' ? baseTypes : allTypes).includes(v.kind),
        'revision_type',
      );
      ensure((param ? schema.parameterTypes : schema.itemTypes).includes(v.kind), 'schema_type');
      return v;
    };
    function number(): Bare {
      const start = i;
      if (s[i] === '-') i++;
      const begin = i;
      while (/[0-9]/.test(s[i] ?? '') && i - begin < 16) i++;
      ensure(i - begin >= 1 && i - begin <= 15, 'syntax');
      if (s[i] === '.') {
        ensure(i - begin <= 12, 'syntax');
        i++;
        const f = i;
        while (/[0-9]/.test(s[i] ?? '') && i - f < 4) i++;
        ensure(i - f >= 1 && i - f <= 3, 'syntax');
        const d = parseDecimal(s.slice(start, i));
        ensure(d.ok, 'syntax');
        const value: Bare = { kind: 'decimal', value: d.value };
        decimalSources.set(value, s.slice(start, i));
        return value;
      }
      const n = Number(s.slice(start, i));
      return { kind: 'integer', value: n === 0 ? 0 : n };
    }
    function bare(param = false): Bare {
      let v: Bare;
      const c = s[i];
      if (c === '-' || /[0-9]/.test(c ?? '')) v = number();
      else if (c === '@') {
        i++;
        const n = number();
        ensure(n.kind === 'integer', 'syntax');
        v = { kind: 'date', value: n.value };
      } else if (c === '?') {
        i++;
        ensure(s[i] === '0' || s[i] === '1', 'syntax');
        v = { kind: 'boolean', value: s[i++] === '1' };
      } else if (c === '"' || s.slice(i, i + 2) === '%"') {
        const display = c === '%';
        i += display ? 2 : 1;
        const bytes: number[] = [];
        let closed = false;
        while (i < s.length) {
          let n = s.charCodeAt(i++);
          if (n === 34) {
            closed = true;
            break;
          }
          if (display && n === 37) {
            ensure(bytes.length < limits.maxValueBytes, 'limit');
            const hex = s.slice(i, i + 2);
            ensure(/^[0-9a-f]{2}$/.test(hex), 'syntax');
            i += 2;
            n = Number.parseInt(hex, 16);
          } else if (!display && n === 92) {
            n = s.charCodeAt(i++);
            ensure(n === 34 || n === 92, 'syntax');
          } else ensure(n >= 32 && n <= 126, 'syntax');
          ensure(bytes.length < limits.maxValueBytes, 'limit');
          bytes.push(n);
        }
        ensure(closed, 'syntax');
        v = display
          ? { kind: 'display_string', value: decodeUtf8Fatal(new Uint8Array(bytes)) }
          : { kind: 'string', value: byteText(new Uint8Array(bytes)) };
      } else if (c === ':') {
        i++;
        const encoded = take(/[^:]/, limits.maxBytes);
        ensure(s[i++] === ':', 'syntax');
        ensure(/^[A-Za-z0-9+/]*={0,2}$/.test(encoded), 'syntax');
        const b = decodeBase64(encoded + '='.repeat((4 - (encoded.length % 4)) % 4));
        ensure(b.ok, 'syntax');
        ensure(b.value.length <= limits.maxValueBytes, 'limit');
        const bytes = new Uint8Array(b.value);
        v = {
          kind: 'bytes',
          get value() { return new Uint8Array(bytes); },
        };
      } else {
        ensure(/[A-Za-z*]/.test(c ?? '') && i < s.length, 'syntax');
        v = { kind: 'token', value: take(/[A-Za-z0-9!#$%&'*+\-.^_`|~:/]/, limits.maxValueBytes) };
      }
      return check(v, param);
    }
    function params(): Parameters {
      const out: [string, Bare][] = [],
        indexes = new Map<string, number>();
      let count = 0;
      while (s[i] === ';') {
        ensure(++count <= limits.maxParameters, 'limit');
        state.node();
        i++;
        sp();
        const k = key();
        let v: Bare;
        if (s[i] === '=') {
          i++;
          v = bare(true);
        } else v = check({ kind: 'boolean', value: true }, true);
        const at = indexes.get(k);
        if (at !== undefined) {
          dupParam = true;
          out[at] = [k, v];
        } else {
          indexes.set(k, out.length);
          out.push([k, v]);
        }
      }
      return out;
    }
    function item(): Item {
      return { kind: 'item', value: bare(), parameters: params() };
    }
    function member(): Member {
      state.node();
      if (s[i] !== '(') return item();
      ensure(schema.innerLists, 'schema_type');
      i++;
      sp();
      const items: Item[] = [];
      while (s[i] !== ')') {
        ensure(items.length < limits.maxInnerItems, 'limit');
        state.node();
        items.push(item());
        ensure(s[i] === ')' || s[i] === ' ', 'syntax');
        sp();
      }
      i++;
      return { kind: 'inner_list', value: items, parameters: params() };
    }
    sp();
    state.node();
    let result: Value;
    if (fieldType === 'item') result = item();
    else {
      const members: Member[] = [],
        pairs: [string, Member][] = [],
        indexes = new Map<string, number>();
      let count = 0;
      while (i < s.length) {
        ensure(++count <= limits.maxMembers, 'limit');
        if (fieldType === 'dictionary') {
          const k = key();
          ensure(!state.listedUniqueKey(k) || !indexes.has(k), 'duplicate_key');
          let v: Member;
          if (s[i] === '=') {
            i++;
            v = member();
          } else {
            state.node();
            v = {
              kind: 'item',
              value: check({ kind: 'boolean', value: true }, false),
              parameters: params(),
            };
          }
          const at = indexes.get(k);
          if (at !== undefined) {
            dupKey ||= state.uniqueKey(k);
            pairs[at] = [k, v];
          } else {
            indexes.set(k, pairs.length);
            pairs.push([k, v]);
          }
        } else members.push(member());
        ows();
        if (i === s.length) break;
        ensure(s[i++] === ',', 'syntax');
        ows();
        ensure(i < s.length, 'syntax');
      }
      result =
        fieldType === 'dictionary'
          ? { kind: 'dictionary', value: pairs }
          : { kind: 'list', value: members };
    }
    sp();
    ensure(i === s.length, 'syntax');
    ensure(!dupKey, 'duplicate_key');
    ensure(!state.uniqueParameters || !dupParam, 'duplicate_parameter');
    // The parser owns this tree; preserve its copying byte getters while freezing containers.
    const freeze = (v: object) => {
      for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(v)))
        if ('value' in descriptor && descriptor.value && typeof descriptor.value === 'object')
          freeze(descriptor.value);
      Object.freeze(v);
    };
    freeze(result);
    const mark = (v: Value) => {
      values.add(v);
      schemas.set(v, schema);
      if (v.kind === 'list' || v.kind === 'inner_list') v.value.forEach(mark);
      else if (v.kind === 'dictionary') v.value.forEach(([, m]) => mark(m));
    };
    mark(result);
    return ok(result);
  } catch (e) {
    return err(error(e, 'syntax'));
  }
}
/** Validate direct trees while emitting; repeated names and nested inner lists reject. */
export function serialize(value: unknown, options: unknown = {}): Result<Uint8Array> {
  try {
    ensure(value && typeof value === 'object', 'invalid_value');
    // Cache each own accessor on first use, preserving per-entry validation order.
    const snapshots = new WeakMap<object, object>();
    function snapshot<T extends object>(source: T, knownKind?: string): T {
      ensure(!Array.isArray(source), 'invalid_value');
      const retained = snapshots.get(source);
      if (retained) return retained as T;
      const keys = Reflect.ownKeys(source);
      ensure(keys.length <= 3 && keys.every(key => Object.hasOwn(source, key)), 'invalid_value');
      const copy = Object.create(null);
      for (const key of keys) {
        let read = key === 'kind' && knownKind !== undefined;
        let current: unknown = read ? knownKind : undefined;
        Object.defineProperty(copy, key, { enumerable: true, get() {
          if (!read) {
            current = Reflect.get(source, key);
            read = true;
          }
          return current;
        } });
      }
      snapshots.set(source, copy);
      snapshots.set(copy, copy);
      return copy;
    }
    const kind = (value as Value).kind;
    ensure(['item', 'inner_list', 'list', 'dictionary'].includes(kind), 'invalid_value');
    const type = kind === 'inner_list' ? 'list' : kind;
    const state = setup(type, options, schemas.get(value as object));
    ensure(kind !== 'inner_list', 'schema_type');
    const root = snapshot(value as Value, kind);
    const { limits, schema } = state;
    let size = 0;
    const out: string[] = [];
    const emit = (s: string) => {
      size += s.length;
      ensure(size <= limits.maxBytes, 'limit');
      out.push(s);
    };
    const shape = (v: unknown, kind: string, keys: string[]) => {
      ensure(v && typeof v === 'object' && !Array.isArray(v), 'invalid_value');
      const captured = snapshot(v);
      ensure(
        (captured as { kind: unknown }).kind === kind &&
          Reflect.ownKeys(captured).length === keys.length &&
          keys.every((k) => Object.hasOwn(captured, k)),
        'invalid_value',
      );
    };
    const key = (s: unknown) => {
      ensure(typeof s === 'string', 'invalid_value');
      ensure(s.length <= limits.maxKeyBytes, 'limit');
      ensure(/^[a-z*][a-z0-9_.*-]*$/.test(s), 'invalid_value');
    };
    function bare(v: Bare, param: boolean) {
      ensure(v && typeof v === 'object', 'invalid_value');
      v = snapshot(v);
      shape(v, v.kind, ['kind', 'value']);
      ensure(allTypes.includes(v.kind), 'invalid_value');
      ensure(
        (schema.revision === 'rfc8941' ? baseTypes : allTypes).includes(v.kind),
        'revision_type',
      );
      ensure((param ? schema.parameterTypes : schema.itemTypes).includes(v.kind), 'schema_type');
      if (v.kind === 'integer' || v.kind === 'date') {
        ensure(structuredInteger(v.value === 0 ? 0 : v.value).ok, 'invalid_value');
        emit((v.kind === 'date' ? '@' : '') + String(v.value));
      } else if (v.kind === 'decimal') {
        const original = v.value;
        ensure(original && typeof original === 'object', 'invalid_value');
        const d = snapshot(original);
        ensure(
          d &&
            Reflect.ownKeys(d).length === 2 &&
            Object.hasOwn(d, 'scaled') &&
            Object.hasOwn(d, 'scale') &&
            (typeof d.scaled === 'bigint' || Number.isSafeInteger(d.scaled)) &&
            Number.isSafeInteger(d.scale) && d.scale >= 0 && d.scale <= 18,
          'invalid_value',
        );
        const coefficient = BigInt(d.scaled);
        const n = coefficient < 0n ? -coefficient : coefficient;
        ensure(n < 10n ** 30n, 'invalid_value');
        const divisor = 10n ** BigInt(Math.max(0, d.scale - 3));
        let scaled = d.scale <= 3 ? n * 10n ** BigInt(3 - d.scale) : n / divisor;
        const rem = n % divisor;
        if (d.scale > 3 && (rem * 2n > divisor || (rem * 2n === divisor && scaled % 2n === 1n)))
          scaled++;
        ensure(scaled <= BigInt(SF_MAX_INTEGER), 'invalid_value');
        const frac = String(scaled % 1000n).padStart(3, '0').replace(/0+$/, '') || '0';
        emit((coefficient < 0n && scaled !== 0n ? '-' : '') + String(scaled / 1000n) + '.' + frac);
      } else if (v.kind === 'boolean') {
        ensure(typeof v.value === 'boolean', 'invalid_value');
        emit(v.value ? '?1' : '?0');
      } else if (v.kind === 'bytes') {
        ensure(v.value instanceof Uint8Array, 'invalid_value');
        ensure(v.value.length <= limits.maxValueBytes, 'limit');
        emit(':' + encodeBase64(v.value) + ':');
      } else {
        ensure(typeof v.value === 'string', 'invalid_value');
        if (v.kind === 'display_string') {
          const bytes = encodeUtf8(v.value);
          ensure(bytes.length <= limits.maxValueBytes, 'limit');
          ensure(v.value.isWellFormed(), 'invalid_value');
          emit('%"');
          for (const b of bytes)
            emit(
              b === 37 || b === 34 || b < 32 || b > 126
                ? '%' + b.toString(16).padStart(2, '0')
                : String.fromCharCode(b),
            );
          emit('"');
        } else {
          ensure(v.value.length <= limits.maxValueBytes, 'limit');
          if (v.kind === 'token') {
            ensure(/^[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]*$/.test(v.value), 'invalid_value');
            emit(v.value);
          } else {
            ensure(/^[\x20-\x7e]*$/.test(v.value), 'invalid_value');
            emit('"' + v.value.replace(/["\\]/g, '\\$&') + '"');
          }
        }
      }
    }
    function params(p: Parameters) {
      ensure(Array.isArray(p), 'invalid_value');
      let count = 0;
      const seen = new Set<string>();
      for (const pair of p) {
        ensure(count++ < limits.maxParameters, 'limit');
        ensure(Array.isArray(pair) && pair.length === 2, 'invalid_value');
        const name = pair[0];
        key(name);
        ensure(!seen.has(name), 'invalid_value');
        seen.add(name);
        state.node();
        emit(';' + name);
        const original = pair[1];
        const v = original && typeof original === 'object' ? snapshot(original) : original;
        if (v?.kind === 'boolean' && v.value === true) {
          bareCheckBoolean(v);
        } else {
          emit('=');
          bare(v, true);
        }
      }
    }
    function bareCheckBoolean(v: Bare) {
      shape(v, 'boolean', ['kind', 'value']);
      ensure(schema.parameterTypes.includes('boolean'), 'schema_type');
    }
    function item(v: Item) {
      ensure(v && typeof v === 'object', 'invalid_value');
      v = snapshot(v);
      shape(v, 'item', ['kind', 'value', 'parameters']);
      bare(v.value, false);
      params(v.parameters);
    }
    function member(v: Member) {
      ensure(v && typeof v === 'object', 'invalid_value');
      v = snapshot(v);
      if (v?.kind === 'item') {
        shape(v, 'item', ['kind', 'value', 'parameters']);
        state.node();
        item(v);
      }
      else {
        shape(v, 'inner_list', ['kind', 'value', 'parameters']);
        state.node();
        ensure(schema.innerLists, 'schema_type');
        ensure(Array.isArray(v.value), 'invalid_value');
        emit('(');
        let count = 0;
        for (const x of v.value) {
          const i = count++;
          ensure(i < limits.maxInnerItems, 'limit');
          shape(x, 'item', ['kind', 'value', 'parameters']);
          if (i) emit(' ');
          state.node();
          item(x);
        }
        emit(')');
        params(v.parameters);
      }
    }
    state.node();
    if (root.kind === 'item') item(root);
    else {
      shape(root, root.kind, ['kind', 'value']);
      ensure(Array.isArray(root.value), 'invalid_value');
      const seen = new Set<string>();
      let count = 0;
      for (const entry of root.value) {
        const i = count++;
        ensure(i < limits.maxMembers, 'limit');
        if (i) emit(', ');
        if (root.kind === 'dictionary') {
          const pair = entry as readonly [string, Member];
          ensure(Array.isArray(pair) && pair.length === 2, 'invalid_value');
          const name = pair[0];
          key(name);
          ensure(!seen.has(name), 'invalid_value');
          seen.add(name);
          emit(name);
          const original = pair[1];
          const v = original && typeof original === 'object' ? snapshot(original) : original;
          const b = v?.kind === 'item' && v.value && typeof v.value === 'object' ? snapshot(v.value) : undefined;
          if (v?.kind === 'item' && b?.kind === 'boolean' && b.value === true) {
            shape(v, 'item', ['kind', 'value', 'parameters']);
            shape(b, 'boolean', ['kind', 'value']);
            ensure(schema.itemTypes.includes('boolean'), 'schema_type');
            state.node();
            params(v.parameters);
          } else {
            emit('=');
            member(v);
          }
        } else member(entry as Member);
      }
    }
    return byteString(out.join(''));
  } catch (e) {
    return err(error(e, 'invalid_value'));
  }
}
/** Select ordered occurrences, combine with comma-space, and parse under explicit policy. */
export function parseField(
  message: unknown,
  name: unknown,
  schema: Schema,
  section: 'headers' | 'trailers' = 'headers',
  options: unknown = {},
): Result<Value> {
  if (!isMessage(message)) return err(messageError('invalid_message'));
  try {
    const attrs = snapshotOptions(options, ['mode', 'limits', 'uniqueKeys', 'uniqueParameters']);
    ensure(attrs.ok, 'invalid_limits');
    const schemaResult = createSchema(schema);
    ensure(schemaResult.ok, 'invalid_schema');
    const opts = { ...attrs.value, schema: schemaResult.value };
    const { limits } = setup(schemaResult.value.type, opts);
    ensure(token(name) && (section === 'headers' || section === 'trailers'), 'invalid_field');
    const fields = section === 'headers' ? message.fields : message.trailers;
    ensure(Array.isArray(fields), 'unavailable_section');
    const selected: Uint8Array[] = [];
    let size = 0;
    const foldedName = name.toLowerCase();
    for (const f of fields as Message['fields']) {
      if (f.name.toLowerCase() !== foldedName) continue;
      const bytes = f.value;
      size += bytes.length + (selected.length ? 2 : 0);
      ensure(size <= limits.maxBytes, 'limit');
      selected.push(bytes);
    }
    ensure(selected.length, 'missing_field');
    return parse(schemaResult.value.type, selected.map(byteText).join(', '), { ...opts, limits });
  } catch (e) {
    return err(error(e, 'invalid_message'));
  }
}
export const StructuredFields = Object.freeze({ parse, parseField, serialize, createSchema });
