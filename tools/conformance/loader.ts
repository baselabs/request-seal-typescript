import {webBotAuthSurface} from './web-bot-auth.ts';
import {quorumSurface,acceptSignatureSurface} from './quorum-surfaces.ts';
import {replaySurface} from './replay-surfaces.ts';
import {joseSurface} from './jose-surfaces.ts';
import {signSurface,verifySurface,digestSurface} from './sign-surfaces.ts';
import {cryptoVerify, keyImport} from './crypto-surfaces.ts';
import {discoveryBody} from './discovery.ts';
import {selectRuntimeLimits, classifyRuntimeResult} from './runtime-limits.ts';
export {selectRuntimeLimits, classifyRuntimeResult} from './runtime-limits.ts';
import {prepareBatch, itemRegistry, count, type BatchItem} from './batch.ts';
import {wireSurface} from './wire.ts';
import { readdir, readFile, lstat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import {fileURLToPath} from 'node:url';
import { snapshotOptions } from '../../src/brand.ts';
import { decodeJson, type JsonNode } from '../../src/json.ts';
import { decodeBase64Url, encodeBase64Url } from '../../src/bytes.ts';
import { CORPUS_PIN, DIGEST_MAX_BYTES, DISCOVERY_MAX_BYTES } from '../../src/constants.ts';
import {RULE_IDS, type ErrorKind} from '../../src/errors/parity.ts';
import { ruleId, joseError } from '../../src/errors/types.ts';
import { ok, err, type Result } from '../../src/result.ts';
import { SMOKE_INDEX_SHA256 } from './smoke-pin.ts';
const digest = crypto.subtle.digest.bind(crypto.subtle);
export type CaseClass = 'byte_exact' | 'verify_only' | 'rejection';
export type CorpusCase = Readonly<{format: string; id: string; surface: string; class: CaseClass; evidence_class: string; source: Record<string, unknown>; inputs: Record<string, unknown>; expected: Record<string, unknown>; keys?: readonly Record<string, unknown>[]; policy?: Record<string, unknown>; now?: unknown; nonce?: unknown; derivation?: string; positive?: string; pin?: string}>;
export type Outcome = {fields: readonly (readonly [string,Uint8Array])[]} | {bytes: Uint8Array} | {valid: true; facts?: Record<string, unknown>} | {verification: unknown} | {facts: Record<string, unknown>};
export type CorpusResources = {read: (path: string) => Result<Uint8Array>; reference: (value: unknown) => Result<JsonNode>};
export type SurfaceResult = Result<Outcome> | {ok: false; loaderReason: 'invalid_manifest'};
export type Surface = ((manifest: CorpusCase, resources: CorpusResources) => SurfaceResult | Promise<SurfaceResult>) & {readonly errorKinds?: readonly ErrorKind[]};
export type CorpusReport = {ok: boolean; cases: number; listed: number; executed: number; not_applicable: number; runtime_limited: number; pending: {surface: string; item_format?: string; cases: number; items: number; ids: string[]}[]; known_positive_executed: boolean; failures: {id: string; reason: string; expected?: unknown; actual?: unknown}[]};
class LoaderFailure extends Error {}
const loaderFailure = (reason: string): never => {throw new LoaderFailure(reason);};
/** RFC 8785 ordering for the manifest's string/boolean/null and tagged-number model. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') return Number.isFinite(value) ? JSON.stringify(value) : loaderFailure('invalid_canonical_value');
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  if (typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return loaderFailure('invalid_canonical_value');
  const object = value as Record<string, unknown>;
  return '{' + Object.keys(object).sort().map(k => JSON.stringify(k) + ':' + canonicalJson(object[k])).join(',') + '}';
}
function record(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function plain(node: JsonNode): unknown {
  if (node === null || typeof node !== 'object') return node;
  if (node.kind === 'number') throw new Error('bare numeric manifest value');
  if (node.kind === 'array') return node.items.map(plain);
  const object = Object.create(null) as Record<string, unknown>;
  for (const [key, value] of node.pairs) object[key] = plain(value);
  return object;
}
function parse(bytes: Uint8Array, maxBytes: number): Record<string, unknown> {
  const decoded = decodeJson(bytes, {maxBytes, maxDepth: 64, maxMembers: 100_000, maxArrayLength: 100_000, maxStringBytes: maxBytes});
  if (!decoded.ok || decoded.value.duplicates.length) throw new Error('invalid manifest JSON');
  const value = plain(decoded.value.node);
  if (!record(value)) throw new Error('invalid manifest object');
  if (new TextDecoder().decode(bytes) !== canonicalJson(value)) throw new Error('noncanonical manifest JSON');
  return value;
}
function safePath(value: unknown): value is string {
  return typeof value === 'string' && /^(sources|cases)\/[A-Za-z0-9_.\/-]+$/.test(value) && value.split('/').every(p => p !== '' && p !== '.' && p !== '..');
}
async function hash(bytes: Uint8Array): Promise<string> {
  return Array.from(new Uint8Array(await digest('SHA-256', new Uint8Array(bytes))), b => b.toString(16).padStart(2, '0')).join('');
}
async function inventory(root: string, relative = ''): Promise<string[]> {
  const files: string[] = [];
  for (const entry of await readdir(join(root, relative), {withFileTypes: true})) {
    const path = relative ? `${relative}/${entry.name}` : entry.name;
    if (entry.isSymbolicLink()) loaderFailure('symbolic_link');
    if (relative === '' && !['index.json', 'sources', 'cases', '.DS_Store'].includes(entry.name) || entry.name === '.DS_Store' && !entry.isFile()) loaderFailure('unlisted_or_missing_file');
    if (entry.isDirectory()) files.push(...await inventory(root, path));
    else if (entry.isFile()) {
      const bytes = entry.name === '.DS_Store' ? await boundedRead(join(root, path), DIGEST_MAX_BYTES) : undefined;
      if (bytes !== undefined) {
        const finder = bytes.length === 0 || bytes.length >= 8 && [0,0,0,1,66,117,100,49].every((b, i) => bytes[i] === b);
        if (!finder) loaderFailure('unlisted_or_missing_file');
      } else files.push(path);
    }
    else throw new Error('nonregular corpus entry');
  }
  return files.sort();
}
async function boundedRead(path: string, max: number): Promise<Uint8Array> {
  const stat = await lstat(path).catch(e => {if (e.code === 'ENOENT') loaderFailure('missing_file'); throw e;});
  if (stat.isSymbolicLink()) loaderFailure('symbolic_link');
  if (!stat.isFile() || stat.size > max) throw new Error('invalid corpus file');
  const bytes = await readFile(path);
  if (bytes.length > max) throw new Error('oversized corpus file');
  return bytes;
}
/** Resolve an RFC 6901 pointer in an ordered source tree. Ambiguous members reject. */
export function resolvePointer(root: JsonNode, pointer: string): JsonNode {
  if (pointer === '') return root;
  if (!pointer.startsWith('/')) throw new Error('invalid source pointer');
  let node = root;
  for (const part of pointer.slice(1).split('/')) {
    if (/~(?:[^01]|$)/.test(part)) throw new Error('invalid source pointer');
    const key = part.replace(/~1/g, '/').replace(/~0/g, '~');
    if (node === null || typeof node !== 'object' || node.kind === 'number') throw new Error('invalid source pointer');
    if (node.kind === 'array') {
      if (!/^(0|[1-9][0-9]*)$/.test(key) || !Number.isSafeInteger(Number(key)) || Number(key) >= node.items.length) throw new Error('invalid source pointer');
      node = node.items[Number(key)]!;
    } else {
      const pairs = node.pairs.filter(([name]) => name === key);
      if (pairs.length !== 1) throw new Error('invalid source pointer');
      node = pairs[0]![1];
    }
  }
  return node;
}
function resourcesFor(files: ReadonlyMap<string, Uint8Array>): CorpusResources {
  return {
    read(path) {
      const bytes = safePath(path) && path.startsWith('sources/') ? files.get(path) : undefined;
      return bytes ? ok(new Uint8Array(bytes)) : err(joseError('invalid_options', 'input'));
    },
    reference(value) {
      try {
        if (!record(value) || !record(value.ref) || Object.keys(value).length !== 1 || Object.keys(value.ref).sort().join(',') !== 'file,pointer' || !safePath(value.ref.file) || !value.ref.file.startsWith('sources/') || typeof value.ref.pointer !== 'string') throw new Error('invalid source reference');
        const bytes = files.get(value.ref.file); if (!bytes) throw new Error('unlisted source reference');
        const parsed = decodeJson(bytes, {maxBytes: DIGEST_MAX_BYTES, maxDepth: 64, maxMembers: 100_000, maxArrayLength: 100_000, maxStringBytes: DIGEST_MAX_BYTES});
        if (!parsed.ok) return parsed;
        return ok(resolvePointer(parsed.value.node, value.ref.pointer));
      } catch { return err(joseError('invalid_options', 'input')); }
    }
  };
}
function referencesValid(value: unknown, resources: CorpusResources): boolean {
  if (Array.isArray(value)) return value.every(v => referencesValid(v, resources));
  if (!record(value)) return true;
  if (Object.hasOwn(value, 'ref')) return resources.reference(value).ok;
  return Object.values(value).every(v => referencesValid(v, resources));
}
const invalidManifest = (): SurfaceResult => ({ok: false, loaderReason: 'invalid_manifest'});
const smoke: Surface = (manifest, resources) => {
  const {operation, value} = manifest.inputs;
  if (Object.keys(manifest.inputs).sort().join(',') !== 'operation,value' || !record(value)) return invalidManifest();
  let encoded: unknown;
  if (Object.hasOwn(value, 'ref')) {
    const resolved = resources.reference(value); if (!resolved.ok) return invalidManifest(); encoded = resolved.value;
  } else {
    if (Object.keys(value).join(',') !== 'b64') return invalidManifest();
    encoded = value.b64;
  }
  if (typeof encoded !== 'string') return invalidManifest();
  if (operation === 'base64url.decode' || operation === 'json.decode') {
    const decoded = decodeBase64Url(encoded); if (!decoded.ok) return decoded;
    if (operation === 'base64url.decode') return ok({bytes: decoded.value});
    const parsed = decodeJson(decoded.value); return parsed.ok ? ok({valid: true}) : parsed;
  }
  return invalidManifest();
};
export function surfaceRegistry(): ReadonlyMap<string, Surface> {
  const entries: [string, Surface, readonly ErrorKind[]][] = [
    ['web_bot_auth.verify', webBotAuthSurface, ['core']],
    ['replay.claim', replaySurface, ['core','replay']], ['quorum.verify', quorumSurface, ['core','custody']],
    ['accept_signature.parse', acceptSignatureSurface, ['core']], ['smoke', smoke, ['jose']],
    ['sign', signSurface, ['core','custody']], ['verify', verifySurface, ['core','custody']],
    ['digest.content', digestSurface, ['digest']], ['crypto.verify', cryptoVerify, ['crypto','custody']],
    ['key.import', keyImport, ['crypto','custody']], ['discovery.body', discoveryBody, ['discovery']],
    ...['jws.sign','jws.verify','jwe.decrypt','nested.decrypt'].map(name => [name, joseSurface(name), ['jose']] as [string, Surface, ErrorKind[]]),
    ...['structured_fields.parse','structured_fields.serialize','message.validate','signature_base.build'].map(name =>
      [name, wireSurface(name), [name.split('.')[0] === 'message' ? 'message' : name.split('.')[0] as ErrorKind]] as [string, Surface, ErrorKind[]]),
  ];
  return new Map(entries.map(([name, surface, errorKinds]) => [name,
    Object.assign((m: CorpusCase, r: CorpusResources) => surface(m, r), {errorKinds: Object.freeze(errorKinds)})]));
}
function classValid(value: unknown): value is CaseClass { return value === 'byte_exact' || value === 'verify_only' || value === 'rejection'; }
function manifestValid(value: Record<string, unknown>): value is Record<string, unknown> & CorpusCase {
  if (value.format !== 'request-seal-conformance-case/1' || typeof value.id !== 'string' || typeof value.surface !== 'string' || !classValid(value.class) || !record(value.inputs) || !record(value.expected) || !record(value.source)) return false;
  if (value.evidence_class !== 'published_vector' && value.evidence_class !== 'reviewed_derivation') return false;
  if (value.evidence_class === 'reviewed_derivation' && (typeof value.derivation !== 'string' || !value.derivation.trim())) return false;
  const source = value.source;
  if (!['document', 'section', 'url'].every(k => typeof source[k] === 'string' && source[k] !== '')) return false;
  const fields = ['format', 'id', 'surface', 'class', 'evidence_class', 'source', 'inputs', 'keys', 'policy', 'now', 'nonce', 'expected', 'derivation', 'positive', 'pin'];
  if (!Object.keys(value).every(k => fields.includes(k))) return false;
  if (value.keys !== undefined && (!Array.isArray(value.keys) || !value.keys.every(k => record(k) && typeof k.name === 'string' && safePath(k.file) && k.file.startsWith('sources/') && (k.public === undefined || safePath(k.public) && k.public.startsWith('sources/'))))) return false;
  if (value.policy !== undefined && !record(value.policy)) return false;
  const expected = Object.keys(value.expected);
  if (value.class === 'byte_exact' && (Object.hasOwn(value.expected, 'bytes') || Object.hasOwn(value.expected, 'base'))) {
    const bytes = value.expected.bytes ?? value.expected.base;
    if (value.surface === 'sign' && Array.isArray(bytes)) return expected.length === 1 && bytes.every(pair => Array.isArray(pair) && pair.length === 2 && typeof pair[0] === 'string' && record(pair[1]) && Object.keys(pair[1]).join(',') === 'b64' && typeof pair[1].b64 === 'string' && decodeBase64Url(pair[1].b64).ok);
    return expected.length === 1 && record(bytes) && Object.keys(bytes).join(',') === 'b64' && typeof bytes.b64 === 'string' && decodeBase64Url(bytes.b64).ok;
  }
  if (value.class !== 'rejection') return expected.length === 1 && record(value.expected.verification) || value.expected.valid === true && expected.every(k => ['valid', 'payload', 'public'].includes(k)) || expected.length === 1 && Array.isArray(value.expected.keys) || expected.every(k => ['retain_until', 'row'].includes(k)) && record(value.expected.retain_until);
  return expected.length === 1 && typeof value.expected.rule_id === 'string' && RULE_IDS.has(value.expected.rule_id);
}
function rejectionKinds(registry: ReadonlyMap<string, Surface>): ReadonlyMap<string, readonly ErrorKind[]> {
  return new Map([...registry].map(([name, surface]) => [name, surface.errorKinds ?? []]));
}
const defaultRejectionKinds = rejectionKinds(surfaceRegistry());
export function matches(manifest: CorpusCase, result: Result<Outcome>, kindsBySurface = defaultRejectionKinds): boolean {
  if (manifest.class === 'rejection') {
    const kinds = kindsBySurface.get(manifest.surface);
    return !result.ok && !!kinds && kinds.includes(result.error.kind) && ruleId(result.error) === manifest.expected.rule_id;
  }
  if (!result.ok) return false;
  if (manifest.class === 'byte_exact' && (Object.hasOwn(manifest.expected, 'bytes') || Object.hasOwn(manifest.expected, 'base'))) {
    const expected = manifest.expected.bytes ?? manifest.expected.base;
    if(manifest.surface==='sign'&&Array.isArray(expected)) return 'fields' in result.value && canonicalJson(result.value.fields.map(([name,bytes])=>[name,{b64:encodeBase64Url(bytes)}]))===canonicalJson(expected);
    return record(expected) && Object.keys(expected).length === 1 && typeof expected.b64 === 'string' && decodeBase64Url(expected.b64).ok && 'bytes' in result.value && encodeBase64Url(result.value.bytes) === expected.b64;
  }
  if (Object.hasOwn(manifest.expected, 'verification')) return 'verification' in result.value && canonicalJson(result.value.verification) === canonicalJson(manifest.expected.verification);
  if (Object.hasOwn(manifest.expected, 'valid')) return 'valid' in result.value && result.value.valid === true && canonicalJson({valid: true, ...result.value.facts}) === canonicalJson(manifest.expected);
  return 'facts' in result.value && canonicalJson(result.value.facts) === canonicalJson(manifest.expected);
}
function batchManifestValid(m: Record<string, unknown>): boolean {
  return m.format === 'request-seal-conformance-batch/1' && m.class === 'mixed' && typeof m.id === 'string' && typeof m.surface === 'string' && record(m.source) && ['document','section','url'].every(k => typeof (m.source as Record<string, unknown>)[k] === 'string' && (m.source as Record<string, unknown>)[k] !== '') && (m.evidence_class === 'published_vector' || m.evidence_class === 'reviewed_derivation' && typeof m.derivation === 'string' && m.derivation.trim() !== '') && Object.keys(m).every(k => ['format','id','surface','class','evidence_class','source','batch','pins','overrides','derivation','positive'].includes(k));
}
export function parsePendingAllowlist(raw: string): CorpusReport["pending"] {
  let allowlist: unknown;
  try {allowlist = JSON.parse(raw);} catch {loaderFailure('invalid_pending_allowlist');}
  if (!Array.isArray(allowlist)) throw new LoaderFailure('invalid_pending_allowlist');
  if (!allowlist.every(p => record(p) && typeof p.surface === 'string' && (p.item_format === undefined || typeof p.item_format === 'string') && Number.isSafeInteger(p.cases) && Number(p.cases) > 0 && Number.isSafeInteger(p.items) && Number(p.items) >= 0 && Array.isArray(p.ids) && p.ids.every(id => typeof id === 'string') && p.ids.length === p.cases)) loaderFailure('invalid_pending_allowlist');
  return allowlist as CorpusReport["pending"];
}
export async function runCorpus(folder: string, options: {unpinned?: boolean; smoke?: boolean; pendingOk?: boolean; registry?: ReadonlyMap<string, Surface>} = {}): Promise<CorpusReport> {
  const report: CorpusReport = {ok: false, cases: 0, listed: 0, executed: 0, not_applicable: 0, runtime_limited: 0, pending: [], known_positive_executed: false, failures: []};
  const failure = (id: string, reason: string) => report.failures.push({id, reason});
  try {
    const snapshot = snapshotOptions(options, ['unpinned', 'smoke', 'pendingOk', 'registry']);
    if (!snapshot.ok) { failure('index', 'invalid_options'); return report; }
    const attrs = snapshot.value;
    for (const key of ['unpinned', 'smoke', 'pendingOk'] as const) if (Object.hasOwn(attrs, key) && typeof attrs[key] !== 'boolean') { failure('index', 'invalid_options'); return report; }
    if (Object.hasOwn(attrs, 'registry') && (!attrs.registry || typeof (attrs.registry as ReadonlyMap<string, Surface>).get !== 'function')) { failure('index', 'invalid_options'); return report; }
    const root = resolve(folder), rawIndex = await boundedRead(join(root, 'index.json'), DIGEST_MAX_BYTES);
    const pin = attrs.smoke ? SMOKE_INDEX_SHA256 : CORPUS_PIN.indexSha256;
    if ((attrs.smoke || !attrs.unpinned) && await hash(rawIndex) !== pin) { failure('index', 'index_pin_mismatch'); return report; }
    const index = parse(rawIndex, DIGEST_MAX_BYTES);
    if (index.format !== 'request-seal-conformance-corpus-index/1' || typeof index.elixir_release !== 'string' || !Array.isArray(index.files) || !Array.isArray(index.cases) || typeof index.known_positive !== 'string' || !index.known_positive || !index.cases.length) {failure('index', 'invalid_index'); return report;}
    if (!attrs.smoke && !attrs.unpinned && index.elixir_release !== CORPUS_PIN.tag) {failure('index', 'release_pin_mismatch'); return report;}
    report.cases = index.cases.length;
    const files = new Map<string, Uint8Array>(); let previous = ''; const folded = new Set<string>();
    for (const file of index.files) {
      if (!record(file) || Object.keys(file).sort().join(',') !== 'path,sha256' || !safePath(file.path) || typeof file.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(file.sha256) || file.path <= previous || folded.has(file.path.toLowerCase())) { failure('index', 'invalid_file_inventory'); return report; }
      previous = file.path; folded.add(file.path.toLowerCase());
    }
    // Walk before reads so no intermediate symlink can redirect a listed path.
    const observed = await inventory(root);
    for (const file of index.files as {path: string; sha256: string}[]) {
      const bytes = await boundedRead(join(root, file.path), DIGEST_MAX_BYTES);
      if (await hash(bytes) !== file.sha256) { failure(file.path, 'file_digest_mismatch'); return report; }
      files.set(file.path, bytes);
    }
    if (canonicalJson(observed) !== canonicalJson(['index.json', ...files.keys()].sort())) { failure('index', 'unlisted_or_missing_file'); return report; }
    const used = new Set<string>(), manifests = new Set<string>(), foldedManifests = new Set<string>();
    const registry = (attrs.registry as ReadonlyMap<string, Surface> | undefined) ?? surfaceRegistry(), resources = resourcesFor(files), formats = itemRegistry();
    const kindsBySurface = rejectionKinds(registry);
    const ready: {entry: Record<string, any>; manifest: Record<string, any>; items?: BatchItem[]; pendingLayout?: boolean; pendingItems?: number}[] = [];
    for (const entry of index.cases) {
      if (!record(entry) || Object.keys(entry).sort().join(',') !== (entry.class === 'mixed' ? 'class,count,id,manifest,not_applicable,surface' : 'class,id,manifest,surface') || typeof entry.id !== 'string' || !/^[a-z_]+\/[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(entry.id) || !safePath(entry.manifest) || !entry.manifest.startsWith('cases/') || typeof entry.surface !== 'string' || !(classValid(entry.class) || entry.class === 'mixed') || used.has(entry.id) || foldedManifests.has(entry.manifest.toLowerCase())) {failure('index', 'invalid_or_duplicate_case'); return report;}
      used.add(entry.id); manifests.add(entry.manifest); foldedManifests.add(entry.manifest.toLowerCase());
      const raw = files.get(entry.manifest);
      if (!raw) {failure(entry.id, 'unlisted_manifest'); continue;}
      let m: Record<string, any>;
      try {m = parse(raw, DISCOVERY_MAX_BYTES);} catch {failure(entry.id, 'invalid_manifest'); continue;}
      if (!(entry.class === 'mixed' ? batchManifestValid(m) : manifestValid(m)) || m.id !== entry.id || m.surface !== entry.surface || m.class !== entry.class) {failure(entry.id, 'invalid_manifest'); continue;}
      if (m.keys?.some((k: Record<string, any>) => !files.has(k.file) || k.public !== undefined && !files.has(k.public))) {failure(entry.id, 'unlisted_key'); continue;}
      if (!referencesValid(m, resources)) {failure(entry.id, 'invalid_source_reference'); continue;}
      if (entry.class === 'mixed') {
        const batch = prepareBatch(m, resources);
        if ('reason' in batch) {failure(entry.id, batch.reason); continue;}
        if (count(entry.count) !== count(m.batch.count) || count(entry.not_applicable) !== count(m.batch.not_applicable)) {failure(entry.id, 'batch_index_mismatch'); continue;}
        report.listed += batch.pending ? batch.listed : batch.items.length; report.not_applicable += batch.notApplicable;
        ready.push({entry, manifest: m, items: batch.items, ...(batch.pending ? {pendingLayout: true, pendingItems: batch.listed - batch.notApplicable} : {})});
      } else {report.listed++; ready.push({entry, manifest: m});}
    }
    if ([...files.keys()].some(path => path.startsWith('cases/') && !manifests.has(path))) failure('index', 'unconsumed_manifest');
    const byId = new Map(ready.map(r => [r.entry.id, r]));
    for (const {entry, manifest: m} of ready) if (Object.hasOwn(m, 'positive') && (typeof m.positive !== 'string' || m.positive === entry.id || !byId.has(m.positive) || m.evidence_class !== 'reviewed_derivation')) failure(entry.id, 'invalid_positive_reference');
    if (!['byte_exact', 'verify_only'].includes(byId.get(index.known_positive)?.manifest.class)) failure('index', 'invalid_known_positive');
    if (report.failures.length) return report;
    const pendingIds = new Set<string>();
    const limits = selectRuntimeLimits(JSON.parse(new TextDecoder().decode(await boundedRead(fileURLToPath(new URL('./runtime-limits.json', import.meta.url)), DIGEST_MAX_BYTES))), process.versions);
    for (const {entry, manifest: m, items, pendingLayout, pendingItems} of ready) {
      const surface = registry.get(entry.surface), format = items ? m.batch.item_format as string : undefined;
      const runner = format ? formats.get(format) : undefined;
      if (!surface || items && (!runner || pendingLayout)) {
        pendingIds.add(entry.id);
        let pending = report.pending.find(p => p.surface === entry.surface && p.item_format === format);
        if (!pending) {pending = {surface: entry.surface, ...(format ? {item_format: format} : {}), cases: 0, items: 0, ids: []}; report.pending.push(pending);}
        pending.cases++; pending.items += pendingItems ?? (items ? items.filter(i => !i.notApplicable).length : 1); pending.ids.push(entry.id);
        continue;
      }
      if (items) {
        let successful = true;
        const itemLimits = limits.filter(limit => limit.id === entry.id);
        for (const limit of itemLimits) for (const id of limit.items) if (!items.some(item => item.id === String(id) && !item.notApplicable)) failure(`${entry.id}/${id}`, 'stale_runtime_limitation');
        for (const item of items) {
          if (item.notApplicable) continue;
          const result = await runner!(item, m, resources);
          const status = classifyRuntimeResult(itemLimits, entry.id, item.id, result);
          if (status === 'runtime_limited') {report.runtime_limited++; successful = false;}
          else {
            report.executed++;
            if (status !== 'executed') {successful = false; report.failures.push({id: `${entry.id}/${item.position}:${item.id}`, reason: status, expected: result.expected, actual: result.actual});}
          }
        }
        if (entry.id === index.known_positive && successful) report.known_positive_executed = true;
      } else {
        const result = await surface!(m as CorpusCase, resources);
        if (!result.ok && 'loaderReason' in result) {failure(entry.id, result.loaderReason); continue;}
        report.executed++;
        const match = matches(m as CorpusCase, result, kindsBySurface);
        if (entry.id === index.known_positive && m.class !== 'rejection' && result.ok && match) report.known_positive_executed = true;
        if (!match) report.failures.push({id: entry.id, reason: 'outcome_mismatch', expected: m.expected, actual: result.ok ? ('bytes' in result.value ? {bytes: {b64: encodeBase64Url(result.value.bytes)}} : result.value) : {rule_id: ruleId(result.error)}});
      }
    }
    if (report.executed + report.not_applicable + report.runtime_limited + report.pending.reduce((n,p) => n + p.items, 0) !== report.listed) failure('index', 'execution_count_mismatch');
    if (!attrs.pendingOk && report.pending.length) failure('index', 'pending_surface');
    if (attrs.pendingOk) {
      const allowlist = parsePendingAllowlist(new TextDecoder().decode(await boundedRead(fileURLToPath(new URL('./pending.json', import.meta.url)), DIGEST_MAX_BYTES)));
      for (const entry of allowlist) if (!report.pending.some(p => p.surface === entry.surface && p.item_format === entry.item_format)) failure(entry.surface, 'stale_pending_allowlist');
      const registered = surfaceRegistry();
      for (const p of report.pending) {
        if (registered.has(p.surface) || registry.has(p.surface)) failure(p.surface, 'registered_surface_pending');
        if (p.item_format && formats.has(p.item_format)) failure(p.item_format, 'registered_item_format_pending');
        const expected = allowlist.find(e => e.surface === p.surface && e.item_format === p.item_format);
        if (!expected) failure(p.surface, 'pending_not_allowlisted');
        else if (canonicalJson(expected) !== canonicalJson(p)) failure(p.surface, 'pending_count_mismatch');
      }
    }
    if (!report.known_positive_executed && !(attrs.pendingOk && pendingIds.has(index.known_positive))) failure('index', 'known_positive_not_executed');
    report.ok = report.failures.length === 0;
  } catch (e) {failure('index', e instanceof LoaderFailure ? e.message : 'invalid_or_unavailable_corpus');}
  return report;
}
