import { encodeUtf8 } from "./runtime.ts";
import { isMessage, Message } from "./message/index.ts";
import { isPolicy, normalizeFreshness } from "./policy.ts";
import { withDeadline, releaseContext } from "./context.ts";
import { SF_MAX_INTEGER, SIGNATURE_MAX_BYTES } from "./constants.ts";
import { dictionaries as parseDictionaries, validInner, inner, label, ensure } from "./signature-fields.ts";
import { verifyLabel as authenticateLabel, authenticationPreflight } from "./verify.ts";
import { coreError, isRequestSealError } from "./errors/types.ts";
import { ok, err, type Result } from "./result.ts";
import { decimalSource, type Bare, type InnerList, type Item, type Member } from "./structured-fields/index.ts";
import type { Verification, FreshnessFacts } from "./verification.ts";

/** Descriptive extension selection; source-specific enforcement belongs to the extension. */
export type ProfileStamp = Readonly<{
  name: readonly [packageName: string, kind: string];
  [key: string]: string | boolean | null | number | readonly [string, string];
}>;
export type SignatureDictionaries = readonly [
  readonly (readonly [string, InnerList])[],
  Readonly<Record<string, Item>>,
];
const reserved = new Set(["request_seal", "request-seal", "rfc9421", "web_bot_auth", "web-bot-auth"]);
function plain(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
/** Read the dynamic metadata vocabulary once, without retaining caller objects. */
function snapshotStamp(value: unknown): ProfileStamp {
  ensure(plain(value), "invalid_profile", "input");
  const keys = Reflect.ownKeys(value);
  ensure(keys.length <= 8 && keys.includes("name") && keys.every(k => typeof k === "string"), "invalid_profile", "input");
  const owned = Object.create(null) as Record<string, unknown>;
  for (const key of keys as string[]) owned[key] = value[key];
  const name = owned.name;
  ensure(Array.isArray(name), "invalid_profile", "input");
  const nameKeys = Reflect.ownKeys(name);
  ensure(nameKeys.length === 3 && nameKeys.includes("length") && nameKeys.includes("0") && nameKeys.includes("1") && name.length === 2, "invalid_profile", "input");
  const packageName: unknown = name[0], kind: unknown = name[1];
  ensure(typeof packageName === "string" && typeof kind === "string" && !reserved.has(packageName), "invalid_profile", "input");
  for (const key of keys as string[]) {
    if (key === "name") continue;
    const v = owned[key];
    ensure(v === null || typeof v === "boolean" ||
      (typeof v === "number" && Number.isSafeInteger(v) && Math.abs(v) <= SF_MAX_INTEGER) ||
      (typeof v === "string" && v.length <= 256 && encodeUtf8(v).length <= 256), "invalid_profile", "input");
  }
  owned.name = Object.freeze([packageName, kind]);
  return Object.freeze(owned) as ProfileStamp;
}
function protectedError(e: unknown) {
  return isRequestSealError(e) ? e : coreError("invalid_policy", "input");
}
/** The predicate checks signature semantics, not wire grammar or key trust. */
function validSignatureInput(input: unknown): boolean {
  try { return validInner(input as Member); } catch { return false; }
}
function dictionaries(message: unknown, max: number): Result<SignatureDictionaries> {
  try {
    const [inputs, signatures] = paired(message, max);
    const entries = Object.freeze([...inputs].map(([k, v]) => Object.freeze([k, v] as const)));
    const lookup = Object.create(null) as Record<string, Item>;
    for (const [key, value] of signatures) lookup[key] = value as Item;
    return ok(Object.freeze([entries, Object.freeze(lookup)] as const));
  } catch (e) { return err(protectedError(e)); }
}
function paired(message: unknown, max: number) {
  const values = parseDictionaries(message as Message, max);
  const [inputs, signatures] = values;
  ensure(inputs.size === signatures.size && [...inputs.keys()].every(k => signatures.has(k)), "label_mismatch", "fields");
  return values;
}
async function preflight(input: unknown, components: unknown, extra: "allow" | "reject", freshness: unknown): Promise<Result<FreshnessFacts | "not_evaluated">> {
  try {
    const required = inner(components);
    if (!required.ok) throw required.error;
    ensure(extra === "allow" || extra === "reject", "invalid_policy", "input");
    const context = withDeadline();
    if (!context.ok) throw context.error;
    try {
      return ok(await authenticationPreflight(input as InnerList, required.value, extra, () => normalizeFreshness(freshness), context.value));
    } finally { releaseContext(context.value); }
  } catch (e) { return err(protectedError(e)); }
}
/** Expected parser structure bounds traversal; unknown keys cannot hide extra values.
 * Ordered parameters/components and decoded byte equality mirror the reference values.
 * Each caller property is read once, independent of object insertion order or identity.
 */
function equalParsed(actual: unknown, expected: unknown): boolean {
  if (expected === null || typeof expected !== "object") return actual === expected;
  if (expected instanceof Uint8Array) {
    if (!(actual instanceof Uint8Array) || actual.length !== expected.length) return false;
    const bytes = new Uint8Array(actual);
    return bytes.every((b, i) => b === expected[i]);
  }
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual)) return false;
    const keys = Reflect.ownKeys(actual);
    if (actual.length !== expected.length || keys.length !== expected.length + 1 || !keys.includes("length")) return false;
    for (let i=0; i<expected.length; i++) if (!Object.hasOwn(actual, String(i)) || !equalParsed(actual[i], expected[i])) return false;
    return true;
  }
  if (!plain(actual)) return false;
  const keys = Reflect.ownKeys(actual), expectedKeys = Object.keys(expected);
  if (keys.length !== expectedKeys.length || !keys.every(k => typeof k === "string" && Object.hasOwn(expected, k))) return false;
  const fields = Object.create(null) as Record<string, unknown>;
  for (const key of expectedKeys) fields[key] = actual[key];
  const parsed = expected as Record<string, unknown>;
  if (parsed.kind === "decimal") {
    if (fields.kind !== "decimal") return false;
    const selected = decimalParts(actual as unknown as Bare, fields.value);
    const authoritative = decimalParts(expected as Bare, parsed.value);
    return selected !== null && authoritative !== null && selected[0] === authoritative[0] && selected[1] === authoritative[1];
  }
  for (const key of expectedKeys) if (!equalParsed(fields[key], parsed[key])) return false;
  return true;
}
/** Parsed decimals retain source coefficient/scale separately from numeric normalization.
 * Leading zero and negative-zero spellings do not change the reference integer coefficient.
 */
function decimalParts(node: Bare, value: unknown): readonly [bigint, number] | null {
  if (!plain(value)) return null;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== 2 || !keys.includes("scaled") || !keys.includes("scale")) return null;
  const scaled = value.scaled, scale = value.scale;
  if (!(typeof scaled === "bigint" || typeof scaled === "number" && Number.isSafeInteger(scaled)) || typeof scale !== "number" || !Number.isSafeInteger(scale) || scale < 1 || scale > 3) return null;
  const source = decimalSource(node);
  return source === undefined ? [BigInt(scaled), scale] : [BigInt(source.replace(".", "")), source.length - source.indexOf(".") - 1];
}
function signatureSnapshot(value: unknown): Item {
  ensure(plain(value), "invalid_signature_field", "fields");
  const keys = Reflect.ownKeys(value);
  ensure(keys.length === 3 && keys.every(k => typeof k === "string" && ["kind", "value", "parameters"].includes(k)), "invalid_signature_field", "fields");
  const kind = value.kind, bare = value.value, parameters = value.parameters;
  ensure(kind === "item" && plain(bare), "invalid_signature_field", "fields");
  const bareKeys = Reflect.ownKeys(bare);
  ensure(bareKeys.length === 2 && bareKeys.includes("kind") && bareKeys.includes("value"), "invalid_signature_field", "fields");
  const bareKind = bare.kind, bytes = bare.value;
  ensure(bareKind === "bytes" && bytes instanceof Uint8Array && bytes.length >= 1 && bytes.length <= SIGNATURE_MAX_BYTES, "invalid_signature_field", "fields");
  return {kind: "item", value: {kind: "bytes", value: new Uint8Array(bytes)}, parameters: parameters as Item["parameters"]};
}
async function verifyLabel(message: unknown, policy: unknown, selectedLabel: unknown, input: unknown, signature: unknown, stamp: unknown): Promise<Result<Verification>> {
  try {
    const profile = snapshotStamp(stamp);
    ensure(isPolicy(policy), "invalid_policy", "input");
    ensure(label(selectedLabel), "invalid_options", "input");
    ensure(isMessage(message), "invalid_message", "input");
    const validated = Message.create(message);
    ensure(validated.ok, "invalid_message", "input");
    const selectedSignature = signatureSnapshot(signature);
    const [inputs, signatures] = paired(validated.value, policy.maxSignatures);
    ensure(inputs.has(selectedLabel), "unknown_label", "fields");
    const selectedInput = inputs.get(selectedLabel)!;
    ensure(equalParsed(input, selectedInput), "invalid_signature_input", "fields");
    ensure(equalParsed(selectedSignature, signatures.get(selectedLabel)), "invalid_signature_field", "fields");
    return await authenticateLabel(validated.value, policy, {label: selectedLabel}, undefined,
      {input: selectedInput, signature: signatures.get(selectedLabel)! as Item, baseCache: new Map()}, profile);
  } catch (e) { return err(protectedError(e)); }
}
/** Unstable extension boundary. Pin the package exactly and keep profile names constant. */
export const Profile = Object.freeze({validSignatureInput, dictionaries, preflight, verifyLabel});
