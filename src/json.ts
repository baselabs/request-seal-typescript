import {decodeUtf8Fatal, encodeUtf8} from './runtime.ts';
import { snapshotOptions } from './brand.ts';
import { JSON_LIMITS } from './constants.ts';
import { err, ok, type Result } from './result.ts';
import { joseError } from './errors/types.ts';
/** An ordered JSON tree that retains numeric source text. */
export type JsonNode = null | boolean | string | JsonNumber | JsonObject | JsonArray;
/** A JSON number represented by its original lexeme. */
export type JsonNumber = {readonly kind: 'number'; readonly lexeme: string};
/** A JSON object represented by ordered key-value pairs. */
export type JsonObject = {readonly kind: 'object'; readonly pairs: readonly (readonly [string, JsonNode])[]};
/** A JSON array represented by an ordered sequence of nodes. */
export type JsonArray = {readonly kind: 'array'; readonly items: readonly JsonNode[]};
/** Byte, depth, and container limits for JSON decoding. */
export type JsonLimits = {maxBytes: number; maxDepth: number; maxMembers: number; maxArrayLength: number; maxStringBytes: number};
/** JSON limits and explicit duplicate and noncharacter policies. */
export type JsonDecodeOptions = Partial<JsonLimits> & {rejectDuplicates?: boolean; acceptNoncharacters?: boolean};
/** A decoded JSON tree and its duplicate member names. */
export type DecodedJson = {readonly node: JsonNode; readonly duplicates: readonly string[]};
type Frame = {kind: 'object'; pairs: [string, JsonNode][]; keys: Set<string>; key: string; state: 'first' | 'key' | 'colon' | 'value' | 'end'} | {kind: 'array'; items: JsonNode[]; state: 'first' | 'value' | 'end'};
function fail(reason: 'invalid_header' | 'limit' | 'invalid_options' | 'duplicate_member'): never { throw reason; }
function noncharacter(cp: number): boolean { return cp >= 0xfdd0 && cp <= 0xfdef || (cp & 0xffff) >= 0xfffe; }
/** Single pass with an explicit container stack. Objects retain every ordered pair. */
export function decodeJson(input: unknown, options: JsonDecodeOptions = {}): Result<DecodedJson> {
  try {
    if (!(input instanceof Uint8Array)) fail('invalid_header');
    const captured = snapshotOptions(options, [...Object.keys(JSON_LIMITS), 'rejectDuplicates', 'acceptNoncharacters']);
    if (!captured.ok) fail('invalid_options');
    const opts = captured.value;
    const limits = Object.assign(Object.create(null), JSON_LIMITS) as JsonLimits;
    for (const key of ['rejectDuplicates', 'acceptNoncharacters']) {
      if (Object.hasOwn(opts, key) && typeof opts[key] !== 'boolean') fail('invalid_options');
    }
    for (const key of Object.keys(JSON_LIMITS) as (keyof JsonLimits)[]) {
      if (Object.hasOwn(opts, key)) limits[key] = opts[key] as number;
      if (!Number.isSafeInteger(limits[key]) || limits[key] <= 0) fail('invalid_options');
    }
    if (input.byteLength > limits.maxBytes) fail('limit');
    const text = decodeUtf8Fatal(input);
    let i = 0, root: JsonNode | undefined;
    const stack: Frame[] = [], duplicates: string[] = [];
    const space = () => { while (text[i] === ' ' || text[i] === '\t' || text[i] === '\r' || text[i] === '\n') i++; };
    function string(): string {
      if (text[i++] !== '"') fail('invalid_header');
      const parts: string[] = []; let size = 0;
      while (i < text.length) {
        if (text[i] === '"') { i++; return parts.join(''); }
        let cp = text.charCodeAt(i++);
        if (cp < 32) fail('invalid_header');
        if (cp === 92) {
          const escape = text[i++];
          const escaped: Record<string, number> = {'"': 34, '\\': 92, '/': 47, b: 8, f: 12, n: 10, r: 13, t: 9};
          if (escape === 'u') {
            const hex = text.slice(i, i + 4); if (!/^[0-9A-Fa-f]{4}$/.test(hex)) fail('invalid_header');
            cp = Number.parseInt(hex, 16); i += 4;
            if (cp >= 0xd800 && cp <= 0xdbff) {
              if (text.slice(i, i + 2) !== '\\u') fail('invalid_header');
              const lowHex = text.slice(i + 2, i + 6); if (!/^[0-9A-Fa-f]{4}$/.test(lowHex)) fail('invalid_header');
              const low = Number.parseInt(lowHex, 16); if (low < 0xdc00 || low > 0xdfff) fail('invalid_header');
              cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00; i += 6;
            } else if (cp >= 0xdc00 && cp <= 0xdfff) fail('invalid_header');
          } else if (escape !== undefined && Object.hasOwn(escaped, escape)) cp = escaped[escape]!;
          else fail('invalid_header');
        } else if (cp >= 0xd800 && cp <= 0xdbff) {
          const low = text.charCodeAt(i++); if (!(low >= 0xdc00 && low <= 0xdfff)) fail('invalid_header');
          cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00;
        } else if (cp >= 0xdc00 && cp <= 0xdfff) fail('invalid_header');
        if (!opts.acceptNoncharacters && noncharacter(cp)) fail('invalid_header');
        size += cp <= 127 ? 1 : cp <= 2047 ? 2 : cp <= 65535 ? 3 : 4;
        if (size > limits.maxStringBytes) fail('limit');
        parts.push(String.fromCodePoint(cp));
      }
      return fail('invalid_header');
    }
    function attach(value: JsonNode): void {
      const parent = stack.at(-1);
      if (!parent) { if (root !== undefined) fail('invalid_header'); root = value; }
      else if (parent.kind === 'array') {
        if (parent.items.length >= limits.maxArrayLength) fail('limit');
        parent.items.push(value); parent.state = 'end';
      } else {
        if (parent.pairs.length >= limits.maxMembers) fail('limit');
        if (parent.keys.has(parent.key)) {
          if (opts.rejectDuplicates) fail('duplicate_member');
          duplicates.push(parent.key);
        }
        parent.keys.add(parent.key); parent.pairs.push([parent.key, value]); parent.state = 'end';
      }
    }
    function value(): void {
      space(); const c = text[i];
      if (c === '{' || c === '[') {
        if (stack.length >= limits.maxDepth) fail('limit');
        i++;
        if (c === '{') { const pairs: [string, JsonNode][] = []; stack.push({kind: 'object', pairs, keys: new Set(), key: '', state: 'first'}); }
        else { const items: JsonNode[] = []; stack.push({kind: 'array', items, state: 'first'}); }
      } else if (c === '"') attach(string());
      else if (text.startsWith('true', i)) { i += 4; attach(true); }
      else if (text.startsWith('false', i)) { i += 5; attach(false); }
      else if (text.startsWith('null', i)) { i += 4; attach(null); }
      else {
        const start = i;
        while (i < text.length && /[0-9eE+.\-]/.test(text[i]!)) i++;
        const lexeme = text.slice(start, i);
        if (!/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/.test(lexeme)) fail('invalid_header');
        // OTP represents floating lexemes as finite IEEE-754 doubles. Integers remain exact.
        if (/[.eE]/.test(lexeme)) {
          const number = Number(lexeme);
          if (!Number.isFinite(number)) fail('invalid_header');
        }
        attach({kind: 'number', lexeme});
      }
    }
    value();
    while (stack.length) {
      space(); const frame = stack.at(-1)!; const c = text[i];
      if (frame.kind === 'array') {
        if (frame.state === 'first' && c === ']' || frame.state === 'end' && c === ']') { i++; stack.pop(); attach({kind: 'array', items: frame.items}); }
        else if (frame.state === 'end') { if (c !== ',') fail('invalid_header'); i++; frame.state = 'value'; }
        else value();
      } else {
        if (frame.state === 'first' && c === '}' || frame.state === 'end' && c === '}') { i++; stack.pop(); attach({kind: 'object', pairs: frame.pairs}); }
        else if (frame.state === 'end') { if (c !== ',') fail('invalid_header'); i++; frame.state = 'key'; }
        else if (frame.state === 'first' || frame.state === 'key') { frame.key = string(); frame.state = 'colon'; }
        else if (frame.state === 'colon') { if (c !== ':') fail('invalid_header'); i++; frame.state = 'value'; }
        else value();
      }
    }
    space(); if (i !== text.length || root === undefined) fail('invalid_header');
    return ok({node: root, duplicates});
  } catch (reason) { return err(joseError(reason === 'limit' || reason === 'invalid_options' || reason === 'duplicate_member' ? reason : 'invalid_header', 'input')); }
}
/** Encode a decoded tree, retaining pair order and exact numeric text. */
export function encodeJson(node: JsonNode, options: Pick<JsonDecodeOptions, 'acceptNoncharacters'> = {}): Result<Uint8Array<ArrayBuffer>> {
  try {
    type Task = {kind: 'value'; node: JsonNode; depth: number} | {kind: 'text'; text: string};
    const pending: Task[] = [{kind: 'value', node, depth: 0}], output: string[] = [];
    let size = 0;
    const emit = (text: string) => { size += text.length; if (size > JSON_LIMITS.maxBytes) fail('limit'); output.push(text); };
    while (pending.length) {
      const task = pending.pop()!;
      if (task.kind === 'text') { emit(task.text); continue; }
      const next = task.node;
      if (next === null || typeof next === 'boolean') emit(JSON.stringify(next));
      else if (typeof next === 'string') {
        if (next.length > JSON_LIMITS.maxStringBytes) fail('limit');
        emit(JSON.stringify(next));
      } else if (typeof next !== 'object' || !next) fail('invalid_header');
      else if (next.kind === 'number') {
        if (typeof next.lexeme !== 'string') fail('invalid_header');
        emit(next.lexeme);
      } else if (next.kind === 'object' || next.kind === 'array') {
        const array = next.kind === 'array';
        const items = array ? next.items : next.pairs;
        if (!Array.isArray(items)) fail('invalid_header');
        if (items.length > (array ? JSON_LIMITS.maxArrayLength : JSON_LIMITS.maxMembers) || task.depth >= JSON_LIMITS.maxDepth) fail('limit');
        emit(array ? '[' : '{'); pending.push({kind: 'text', text: array ? ']' : '}'});
        for (let n = items.length - 1; n >= 0; n--) {
          if (array) pending.push({kind: 'value', node: (items as readonly JsonNode[])[n]!, depth: task.depth + 1});
          else {
            const pair = (items as JsonObject['pairs'])[n]!;
            if (!Array.isArray(pair) || pair.length !== 2 || typeof pair[0] !== 'string') fail('invalid_header');
            pending.push({kind: 'value', node: pair[1], depth: task.depth + 1}, {kind: 'text', text: ':'}, {kind: 'value', node: pair[0], depth: task.depth + 1});
          }
          if (n > 0) pending.push({kind: 'text', text: ','});
        }
      } else fail('invalid_header');
    }
    const bytes = encodeUtf8(output.join(''));
    const valid = decodeJson(bytes, options);
    return valid.ok ? ok(bytes) : valid;
  } catch (reason) { return err(joseError(reason === 'limit' ? 'limit' : 'invalid_header', 'input')); }
}
