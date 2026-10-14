import { snapshotOptions } from "./brand.ts";
import { inner, ensure, bounded } from "./signature-fields.ts";
import { resolveAlgorithm, selection, type SigningAlgorithm } from "./crypto/algorithm.ts";
import {
  createSchema,
  type Schema,
  type InnerList,
} from "./structured-fields/index.ts";
import { token } from "./message/index.ts";
import {
  QUORUM_MAX_SIGNATURES,
  CLOCK_MAX_SECONDS,
  FRESHNESS_MAX_SKEW_SECONDS,
  STRUCTURED_FIELDS_LIMITS,
  SIGNATURE_DEFAULT_MAX_MEMBERS,
  TIMEOUT_MAX_MS,
} from "./constants.ts";
import { ok, err, type Result } from "./result.ts";
import type { Context } from "./context.ts";
import type { KeyIdentity } from "./key_identity.ts";
import type { KeyHandle } from "./key_handle.ts";
import type { PublicKey } from "./public_key.ts";
import { boundedReplayBytes } from "./replay/claim.ts";
import { createReplayStore } from "./replay/store.ts";
import type { ReplayStore, ReplayFacts } from "./replay-port.ts";
/** A caller-owned signature verification callback receiving a bounded context. */
export type Verifier = (
  algorithm: SigningAlgorithm,
  base: Uint8Array,
  signature: Uint8Array,
  context: Context,
) => Result<boolean> | Promise<Result<boolean>>;
/** A resolved algorithm and key or verification capability with optional identity. */
export type ResolvedKey = Readonly<{
  algorithm: SigningAlgorithm;
  key?: PublicKey | KeyHandle | Verifier;
  verify?: Verifier;
  identity?: KeyIdentity;
}>;
/** Resolve a verification key from signature facts and an operation context. */
export type KeyResolver = (
  facts: Readonly<{ keyid: string | null; label: string; tag: string | null }>,
  context: Context,
) => Result<ResolvedKey | null> | Promise<Result<ResolvedKey | null>>;
/** Clock, age, skew, and expiration rules for signature freshness. */
export type Freshness = Readonly<{
  /** Return the current Unix time in seconds. */
  clock: () => number;
  maxAge: number | null;
  skew: number;
  requireExpires: boolean;
}>;
/** Digest algorithms and field section required for content verification. */
export type ContentPolicy = Readonly<{
  kind: "content" | "representation";
  algorithms: readonly string[];
  section: "headers" | "trailers";
}>;
/** Nonce namespace, commitment, atomic store, and timeout rules. */
export type ReplayPolicy = Readonly<{
  identifier: "nonce";
  namespace: Uint8Array;
  /** Derive caller-owned replay commitment bytes from verified facts. */
  commitment: (
    facts: ReplayFacts,
    context: Context,
  ) => Result<Uint8Array> | Promise<Result<Uint8Array>>;
  store: ReplayStore;
  timeoutMs: number;
}>;
/** A branded verification policy with explicit key, freshness, content, and replay rules. */
export type Policy = Readonly<{
  algorithms: readonly SigningAlgorithm[];
  components: InnerList;
  keyResolver: KeyResolver;
  freshness: "not_evaluated" | Freshness;
  content: "not_required" | ContentPolicy;
  replay: "not_required" | ReplayPolicy;
  fieldSchemas: Readonly<Record<string, Schema>>;
  extraComponents: "allow" | "reject";
  maxSignatures: number;
}>;
const policies = new WeakSet<object>();
const integer = (n: unknown, min: number, max: number): n is number =>
  typeof n === "number" && Number.isSafeInteger(n) && n >= min && n <= max;
function snapshot(
  input: unknown,
  keys: readonly string[],
): Readonly<Record<string, unknown>> {
  const r = snapshotOptions(input, keys);
  ensure(r.ok, "invalid_policy", "input");
  return r.value;
}
function list(
  input: unknown,
  pred: (v: unknown) => boolean,
): readonly string[] {
  ensure(Array.isArray(input), "invalid_policy", "input");
  const length = input.length;
  ensure(integer(length, 1, QUORUM_MAX_SIGNATURES), "invalid_policy", "input");
  const values = Array.from({ length }, (_, i) => input[i] as unknown);
  ensure(
    values.every(pred) && new Set(values).size === length,
    "invalid_policy",
    "input",
  );
  return Object.freeze(values as string[]);
}
function algorithmList(input: unknown): readonly SigningAlgorithm[] {
  ensure(Array.isArray(input), "invalid_policy", "input");
  const length = input.length;
  ensure(integer(length, 1, QUORUM_MAX_SIGNATURES), "invalid_policy", "input");
  const ids = new Set<string>(), choices: SigningAlgorithm[] = [];
  for (let i = 0; i < length; i++) {
    const r = resolveAlgorithm(input[i]);
    ensure(r.ok && !ids.has(r.value.id), "invalid_policy", "input");
    ids.add(r.value.id);
    choices.push(selection(r.value) as SigningAlgorithm);
  }
  return Object.freeze(choices);
}
export function fieldSchemas(
  input: unknown,
): Result<Readonly<Record<string, Schema>>> {
  try {
    ensure(
      input !== null && typeof input === "object" && !Array.isArray(input),
      "invalid_policy",
      "input",
    );
    const keys = Reflect.ownKeys(input);
    ensure(
      keys.length <= STRUCTURED_FIELDS_LIMITS.maxMembers &&
        keys.every(
          (k) => typeof k === "string" && token(k) && k === k.toLowerCase(),
        ),
      "invalid_policy",
      "input",
    );
    const attrs = snapshot(input, keys as string[]),
      schemas = Object.create(null) as Record<string, Schema>;
    for (const key of keys as string[]) {
      const r = createSchema(attrs[key]);
      ensure(r.ok, "invalid_policy", "input");
      schemas[key] = r.value;
    }
    return ok(Object.freeze(schemas));
  } catch (e) {
    return err(bounded(e, "invalid_policy", "input"));
  }
}
/** Check the private brand of a verification policy. */
export function isPolicy(value: unknown): value is Policy {
  return typeof value === "object" && value !== null && policies.has(value);
}
/** Internal shared freshness boundary for policies and extension preflight. */
export function normalizeFreshness(input: unknown): Freshness | "not_evaluated" {
  if (input === "not_evaluated") return input;
  const f = snapshot(input, [
    "clock",
    "maxAge",
    "skew",
    "requireExpires",
  ]);
  ensure(
    Object.keys(f).length === 4 &&
      typeof f.clock === "function" &&
      (f.maxAge === null || integer(f.maxAge, 1, CLOCK_MAX_SECONDS)) &&
      integer(f.skew, 0, FRESHNESS_MAX_SKEW_SECONDS) &&
      typeof f.requireExpires === "boolean",
    "invalid_policy",
    "input",
  );
  return Object.freeze({
    clock: f.clock as () => number,
    maxAge: f.maxAge as number | null,
    skew: f.skew,
    requireExpires: f.requireExpires,
  });
}
/** Snapshot, validate, and brand an explicit verification policy. */
export function createPolicy(input: unknown): Result<Policy> {
  try {
    const a = snapshot(input, [
      "algorithms",
      "components",
      "keyResolver",
      "freshness",
      "content",
      "replay",
      "fieldSchemas",
      "extraComponents",
      "maxSignatures",
    ]);
    ensure(
      [
        "algorithms",
        "components",
        "keyResolver",
        "freshness",
        "content",
        "replay",
      ].every((k) => Object.hasOwn(a, k)),
      "invalid_policy",
      "input",
    );
    const algorithms = algorithmList(a.algorithms),
      components = inner(a.components);
    ensure(
      components.ok && components.value.parameters.length === 0,
      "invalid_policy",
      "input",
    );
    ensure(typeof a.keyResolver === "function", "invalid_policy", "input");
    const freshness = normalizeFreshness(a.freshness);
    let content: Policy["content"] = "not_required";
    if (a.content !== "not_required") {
      const c = snapshot(a.content, ["kind", "algorithms", "section"]);
      ensure(
        Object.keys(c).length === 3 &&
          (c.kind === "content" || c.kind === "representation") &&
          (c.section === "headers" || c.section === "trailers"),
        "invalid_policy",
        "input",
      );
      content = Object.freeze({
        kind: c.kind,
        algorithms: list(
          c.algorithms,
          (v) => v === "sha-256" || v === "sha-512",
        ),
        section: c.section,
      });
    }
    let replay: Policy["replay"] = "not_required";
    if (a.replay !== "not_required") {
      ensure(a.replay !== null && typeof a.replay === "object", "invalid_policy", "input");
      const commitment = Object.getOwnPropertyDescriptor(a.replay, "commitment");
      ensure(commitment && Object.hasOwn(commitment, "value") && typeof commitment.value === "function", "invalid_policy", "input");
      const r = snapshot(a.replay, [
        "identifier",
        "namespace",
        "commitment",
        "store",
        "timeoutMs",
      ]);
      ensure(
        Object.keys(r).length === 5 &&
          r.identifier === "nonce" &&
          boundedReplayBytes(r.namespace) &&
          typeof r.commitment === "function" &&
          integer(r.timeoutMs, 1, TIMEOUT_MAX_MS) &&
          freshness !== "not_evaluated" &&
          (freshness.requireExpires || freshness.maxAge !== null),
        "invalid_policy",
        "input",
      );
      const store = createReplayStore(r.store);
      ensure(store.ok, "invalid_policy", "input");
      const ns = new Uint8Array(r.namespace);
      replay = Object.freeze({
        identifier: "nonce",
        get namespace() {
          return new Uint8Array(ns);
        },
        commitment: r.commitment as ReplayPolicy["commitment"],
        store: store.value,
        timeoutMs: r.timeoutMs,
      });
    }
    const schemas = fieldSchemas(
      Object.hasOwn(a, "fieldSchemas") ? a.fieldSchemas : {},
    );
    ensure(schemas.ok, "invalid_policy", "input");
    const extra = Object.hasOwn(a, "extraComponents")
        ? a.extraComponents
        : "allow",
      max = Object.hasOwn(a, "maxSignatures")
        ? a.maxSignatures
        : SIGNATURE_DEFAULT_MAX_MEMBERS;
    ensure(
      (extra === "allow" || extra === "reject") &&
        integer(max, 1, QUORUM_MAX_SIGNATURES),
      "invalid_policy",
      "input",
    );
    const p = Object.freeze({
      algorithms,
      components: components.value,
      keyResolver: a.keyResolver as KeyResolver,
      freshness,
      content,
      replay,
      fieldSchemas: schemas.value,
      extraComponents: extra,
      maxSignatures: max,
    });
    policies.add(p);
    return ok(p);
  } catch (e) {
    return err(bounded(e, "invalid_policy", "input"));
  }
}
/** Verification policy construction. */
export const Policy = Object.freeze({
  /**
   * Snapshot, validate, and brand an explicit verification policy.
   *
   * Six choices are required and none is defaulted: `algorithms`, `components`,
   * `keyResolver`, `freshness`, `content`, and `replay`. Optional members are
   * `extraComponents` (`"allow"` or `"reject"`), `maxSignatures` (1 through 64, default 16),
   * and `fieldSchemas`.
   *
   * @returns `ok(policy)`, or `core` `input.invalid_policy` when any choice is missing,
   *   unknown, or malformed.
   * @see [Signing and verifying guide](https://github.com/baselabs/request-seal-typescript/blob/main/docs/guides/signing-and-verifying.md#verify) and
   *   [reference](https://github.com/baselabs/request-seal-typescript/blob/main/docs/reference/sign-and-verify.md).
   */
  create: createPolicy });
