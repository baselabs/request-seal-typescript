import { ERROR_PARITY, ERROR_RETRYABLE, type ErrorKind, type Reason, type Layer } from './parity.ts';
/** The bounded detail vocabulary for core failures. */
export type CoreDetail = Reason<'core'> | Reason<'signature_base'> | 'legacy_string' | 'invalid_dictionary' | 'duplicate_member' | 'invalid_member' | 'missing_member' | 'unsupported_type' | 'not_an_origin' | 'untrusted_agent' | 'source_mismatch' | 'revoked_key' | 'source_unavailable' | 'timeout';
/** A core failure with layer, correlation, and optional bounded source. */
export type CoreError = Readonly<{ kind: 'core'; reason: Reason<'core'>; layer: Layer<'core'>; correlation: string; retryable: false; detail: CoreDetail | null; message: string | null; source: CustodyError | null }>;
/** Error families carrying only a reason. @inline */
type SimpleKind = 'message' | 'structured_fields' | 'signature_base' | 'digest' | 'crypto';
/** A reason-only error for message, field, digest, or crypto operations. */
export type SimpleError<K extends SimpleKind> = Readonly<{kind: K; reason: Reason<K>}>;
/** A custody failure with an explicit retryability flag. */
export type CustodyError = Readonly<{kind: 'custody'; reason: Reason<'custody'>; retryable: boolean}>;
/** A discovery failure with an explicit retryability flag. */
export type DiscoveryError = Readonly<{kind: 'discovery'; reason: Reason<'discovery'>; retryable: boolean}>;
/** A JOSE failure with layer and explicit retryability. */
export type JoseError = Readonly<{kind: 'jose'; reason: Reason<'jose'>; layer: Layer<'jose'>; correlation: null; retryable: boolean}>;
/** A nonretryable replay-store failure. */
export type ReplayError = Readonly<{kind: 'replay'; reason: Reason<'replay'>; retryable: false}>;
/** A bounded adapter failure with stage, attempt, and optional source. */
export type AdapterError = Readonly<{kind: 'adapter'; reason: Reason<'adapter'>; adapter: 'req' | 'finch' | 'plug' | 'node-http' | 'fetch'; stage: 'attach' | 'capture' | 'sign' | 'verify'; attempt: number; source: CoreError | CustodyError | SimpleError<'message'> | null; correlation: string; retryable: false}>;
/** The union of all branded, bounded public error families. */
export type RequestSealError = CoreError | { [K in SimpleKind]: SimpleError<K> }[SimpleKind] | CustodyError | DiscoveryError | JoseError | ReplayError | AdapterError;
const errors = new WeakSet<object>();
const addError = errors.add.bind(errors), hasError = errors.has.bind(errors);
const random = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
function correlation(): string { return Array.from(random(new Uint8Array(8)), b => b.toString(16).padStart(2, '0')).join(''); }
function freeze<T extends object>(error: T): T { addError(error); return Object.freeze(error); }
/** Check whether an error belongs to the private error brand. */
export function isRequestSealError(value: unknown): value is RequestSealError { return typeof value === 'object' && value !== null && hasError(value); }
function reasonFor<K extends ErrorKind>(kind: K, reason: Reason<K>): Reason<K> {
  if (!ERROR_PARITY.some(e => e.kind === kind && e.reason === reason)) throw new TypeError('Unknown error reason');
  return reason;
}
const signatureDetails = new Set<string>(['limit', 'wrong_message_kind', 'missing_request_context', 'unavailable_origin', 'unavailable_trailers', 'missing_field', 'non_ascii', 'unknown_field_schema', 'invalid_field_schema', 'invalid_structured_field', 'missing_dictionary_key', 'noncanonical_query_name', 'invalid_query_encoding', 'missing_query_parameter', 'ambiguous_query_parameter']);
const agentDetails = new Set<string>(['missing_member', 'unsupported_type', 'not_an_origin', 'untrusted_agent', 'source_mismatch', 'unknown_key', 'revoked_key', 'source_unavailable', 'timeout']);
const fieldDetails = new Set<string>(['legacy_string', 'invalid_dictionary', 'duplicate_member', 'invalid_member']);
export function coreError(reason: Reason<'core'>, layer: Layer<'core'>, detail: CoreDetail | null = null, source: CustodyError | null = null): CoreError {
  if (!ERROR_PARITY.some(e => e.kind === 'core' && e.layer === layer && e.reason === reason)) throw new TypeError('Unknown core error pair');
  if (source !== null && (reason !== 'signing_failed' || !isRequestSealError(source) || source.kind !== 'custody')) throw new TypeError('Invalid core source');
  const allowed = reason === 'signature_base_failed' ? signatureDetails : reason === 'agent_unresolved' ? agentDetails : reason === 'invalid_signature_agent' ? fieldDetails : reason === 'nonqualifying_signature' ? new Set(ERROR_PARITY.filter(e => e.kind === 'core').map(e => e.reason)) : new Set<string>();
  return freeze({kind: 'core', reason, layer, correlation: correlation(), retryable: false, source, message: reason === 'signer_algorithm_mismatch' ? 'signer algorithm does not match signature specification' : null, detail: typeof detail === 'string' && allowed.has(detail) ? detail : null});
}
function simple<K extends SimpleKind>(kind: K, reason: Reason<K>): SimpleError<K> {
  return freeze({ kind, reason: reasonFor(kind, reason) } as SimpleError<K>);
}
export const messageError = (reason: Reason<'message'>) => simple('message', reason);
export const structuredFieldsError = (reason: Reason<'structured_fields'>) => simple('structured_fields', reason);
export const signatureBaseError = (reason: Reason<'signature_base'>) => simple('signature_base', reason);
export const digestError = (reason: Reason<'digest'>) => simple('digest', reason);
export const cryptoError = (reason: Reason<'crypto'>) => simple('crypto', reason);
export function custodyError(reason: Reason<'custody'>): CustodyError {
  reason = reasonFor('custody', reason);
  return freeze({kind: 'custody', reason, retryable: reason === 'deadline_exceeded' || reason === 'custodian_unavailable'});
}
export function discoveryError(reason: Reason<'discovery'>, status?: number): DiscoveryError {
  reason = reasonFor('discovery', reason);
  const rule = ERROR_RETRYABLE.discovery[reason];
  const retryable = rule.kind === 'constant' ? rule.value : Number.isInteger(status) && status! >= rule.minimum && status! <= rule.maximum;
  return freeze({kind: 'discovery', reason, retryable});
}
export function joseError(reason: Reason<'jose'>, layer: Layer<'jose'>): JoseError {
  reason = reasonFor('jose', reason);
  if (!ERROR_PARITY.some(e => e.kind === 'jose' && e.layer === layer && e.reason === reason)) throw new TypeError('Unknown JOSE error pair');
  return freeze({kind: 'jose', reason, layer, correlation: null, retryable: reason === 'deadline_exceeded'});
}
export function replayError(reason: Reason<'replay'>): ReplayError { return freeze({kind: 'replay', reason: reasonFor('replay', reason), retryable: false}); }
export function adapterError(reason: Reason<'adapter'>, adapter: AdapterError['adapter'], stage: AdapterError['stage'], attempt: number, source: AdapterError['source'] = null): AdapterError {
  reason = reasonFor('adapter', reason);
  if (!['req', 'finch', 'plug', 'node-http', 'fetch'].includes(adapter)) throw new TypeError('Unknown adapter');
  if (!['attach', 'capture', 'sign', 'verify'].includes(stage)) throw new TypeError('Unknown adapter stage');
  if (!Number.isSafeInteger(attempt) || attempt < 0) throw new TypeError('Invalid adapter attempt');
  if (source !== null && (!isRequestSealError(source) || !['core', 'custody', 'message'].includes(source.kind))) throw new TypeError('Invalid adapter source');
  return freeze({kind: 'adapter', reason, adapter, stage, attempt, source, correlation: correlation(), retryable: false});
}
/** Format an error's family, layer when present, and reason as a rule ID. */
export function ruleId(error: RequestSealError): string { return 'layer' in error ? `${error.kind}/${error.layer}.${error.reason}` : `${error.kind}/${error.reason}`; }
