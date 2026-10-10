import {joseBatchItem} from './jose-surfaces.ts';
import {cryptoBatchItem} from './crypto-surfaces.ts';
import {sourcePlain, wireBatchItem} from './wire.ts';
import type {CorpusResources} from './loader.ts';
import {RULE_IDS} from '../../src/errors/parity.ts';
export type BatchItem = {id: string; value: Record<string, any>; parent?: Record<string, any>; position: number; notApplicable: boolean};
export type BatchCheck = {notApplicable?: boolean; ok: boolean; expected: unknown; actual: unknown};
export type BatchRunner = (item: BatchItem, manifest: Record<string, any>, resources: CorpusResources) => BatchCheck | Promise<BatchCheck>;
export function itemRegistry(): ReadonlyMap<string, BatchRunner> {
  return new Map<string, BatchRunner>([...['httpwg-structured-fields/1', 'rfc9421-signature-bases/1'].map(format => [format, wireBatchItem] as const), ['wycheproof-ed25519/1', cryptoBatchItem], ['wycheproof-ecdsa/1', cryptoBatchItem], ['wycheproof-aes-gcm/1', joseBatchItem], ['wycheproof-rsa-oaep/1', joseBatchItem]]);
}
function record(x: unknown): x is Record<string, any> {return x !== null && typeof x === 'object' && !Array.isArray(x);}
export function count(x: unknown): number | undefined {
  if (!record(x) || Object.keys(x).join(',') !== 'int' || typeof x.int !== 'string' || !/^(0|[1-9][0-9]*)$/.test(x.int)) return;
  const n = Number(x.int); return Number.isSafeInteger(n) ? n : undefined;
}
export function prepareBatch(m: Record<string, any>, r: CorpusResources): {items: BatchItem[]; notApplicable: number; pending?: false} | {items: BatchItem[]; notApplicable: number; pending: true; listed: number} | {reason: string} {
  const b = m.batch;
  if (!record(b) || Object.keys(b).sort().join(',') !== 'count,file,item_format,not_applicable' || typeof b.file !== 'string' || !b.file.startsWith('sources/') || typeof b.item_format !== 'string' || count(b.count) === undefined || count(b.not_applicable) === undefined) return {reason: 'invalid_batch'};
  const surfaces: Record<string, readonly string[]> = {
    'httpwg-structured-fields/1': ['structured_fields.parse','structured_fields.serialize'],
    'rfc9421-signature-bases/1': ['signature_base.build'],
    'wycheproof-aes-gcm/1': ['jwe.decrypt'], 'wycheproof-rsa-oaep/1': ['jwe.decrypt'],
    'wycheproof-ed25519/1': ['crypto.verify'], 'wycheproof-ecdsa/1': ['crypto.verify'],
  };
  if (Object.hasOwn(surfaces, b.item_format) && !surfaces[b.item_format]!.includes(m.surface)) return {reason: 'invalid_batch_surface'};
  if (Object.hasOwn(m, 'overrides') && !['wycheproof-aes-gcm/1','wycheproof-rsa-oaep/1','wycheproof-ed25519/1','wycheproof-ecdsa/1'].includes(b.item_format)) return {reason: 'unsupported_overrides'};
  const source = r.reference({ref: {file: b.file, pointer: ''}});
  if (!source.ok) return {reason: 'invalid_source_reference'};
  const raw = sourcePlain(source.value), items: BatchItem[] = [];
  if (!Object.hasOwn(surfaces, b.item_format)) {
    const listed = count(b.count)!, notApplicable = count(b.not_applicable)!;
    if (notApplicable > listed) return {reason: 'not_applicable_count'};
    return {items, notApplicable, listed, pending: true};
  }
  const add = (value: Record<string, any>, id: string, parent?: Record<string, any>) => items.push({id, value, ...(parent ? {parent} : {}), position: items.length, notApplicable: false});
  if (b.item_format === 'rfc9421-signature-bases/1') {
    if (!Array.isArray(raw)) return {reason: 'unexpected_item_shape'};
    for (const v of raw) {
      if (!record(v) || typeof v.parameters !== 'string' || typeof v.base !== 'string' || (v.transformations !== undefined && !Array.isArray(v.transformations))) return {reason: 'unexpected_item_shape'};
      add(v, String(items.length));
      for (const t of v.transformations ?? []) {
        if (!record(t) || typeof t.same_base !== 'boolean') return {reason: 'unexpected_item_shape'};
        add(t, String(items.length), v);
      }
    }
  } else if (Array.isArray(raw)) {
    for (const v of raw) {
      if (!record(v) || typeof v.name !== 'string') return {reason: 'unexpected_item_shape'};
      add(v, v.name);
    }
  } else if (record(raw) && Array.isArray(raw.testGroups)) {
    for (const g of raw.testGroups) {
      if (!record(g) || !Array.isArray(g.tests)) return {reason: 'unexpected_item_shape'};
      for (const v of g.tests) {
        if (!record(v) || !record(v.tcId) || v.tcId.kind !== 'number' || !/^[1-9][0-9]*$/.test(v.tcId.lexeme)) return {reason: 'unexpected_item_shape'};
        add(v, v.tcId.lexeme, g);
      }
    }
  } else return {reason: 'unexpected_item_shape'};
  const upstreamTotal = record(raw) && 'numberOfTests' in raw ? raw.numberOfTests : undefined;
  if (b.item_format.startsWith('wycheproof-') && (!record(upstreamTotal) || upstreamTotal.kind !== 'number' || !/^(0|[1-9][0-9]*)$/.test(upstreamTotal.lexeme) || Number(upstreamTotal.lexeme) !== items.length)) return {reason: 'batch_count_mismatch'};
  if (items.length !== count(b.count)) return {reason: 'batch_count_mismatch'};
  const ids = new Set(items.map(i => i.id));
  if (ids.size !== items.length) return {reason: 'duplicate_batch_item'};
  const overrides = m.overrides ?? {};
  if (!record(overrides) || Object.keys(overrides).some(k => !ids.has(k))) return {reason: 'invalid_overrides'};
  for (const item of items) {
    const o = overrides[item.id];
    if (o === undefined) continue;
    if (!record(o)) return {reason: 'invalid_overrides'};
    if (o.outcome === 'not_applicable' && Object.keys(o).sort().join(',') === 'outcome,reason' && typeof o.reason === 'string' && o.reason.trim()) item.notApplicable = true;
    else if (!(o.outcome === 'reject' && Object.keys(o).sort().join(',') === 'clause,outcome,rule_id' && typeof o.clause === 'string' && o.clause.trim() && RULE_IDS.has(o.rule_id))) return {reason: 'invalid_overrides'};
  }
  const notApplicable = items.filter(i => i.notApplicable).length;
  if (notApplicable !== count(b.not_applicable)) return {reason: 'not_applicable_count'};
  if (b.item_format === 'httpwg-structured-fields/1') {
    const pins = m.pins;
    if (!record(pins)) return {reason: 'invalid_pins'};
    const optional = new Set(items.filter(i => i.value.can_fail === true).map(i => i.id));
    if (Object.keys(pins).length !== optional.size || Object.keys(pins).some(k => !optional.has(k))) return {reason: 'invalid_pins'};
    for (const p of Object.values(pins)) if (!record(p) || Object.keys(p).sort().join(',') !== 'outcome,reason' || !['accept','reject'].includes(p.outcome) || typeof p.reason !== 'string' || !p.reason.trim()) return {reason: 'invalid_pins'};
    if (items.some(i => !['item','list','dictionary'].includes(i.value.header_type) || (!Array.isArray(i.value.raw) && !Array.isArray(i.value.expected)))) return {reason: 'unexpected_item_shape'};
  }
  if (b.item_format.startsWith('wycheproof-')) {
    for (const i of items) if (!overrides[i.id] && !['valid','invalid'].includes(i.value.result)) return {reason: 'unexpected_item_shape'};
  }
  return {items, notApplicable};
}
