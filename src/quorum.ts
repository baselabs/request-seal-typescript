import {encodeUtf8} from './runtime.ts';
import { snapshotOptions } from "./brand.ts";
import { isPolicy, type Policy } from "./policy.ts";
import { label, ensure, bounded } from "./signature-fields.ts";
import { ok, err, type Result } from "./result.ts";
import {
  SIGNATURE_DEFAULT_MAX_MEMBERS,
  QUORUM_MAX_SIGNATURES,
} from "./constants.ts";
/** Require all, any, or a threshold number of successful signers. */
export type QuorumMode = "all" | "any" | Readonly<{ threshold: number }>;
/** Count quorum satisfaction by keys, principals, or roles. */
export type QuorumUnit = "keys" | "principals" | "roles";
/** A named quorum slot with a policy and optional signature and principal selectors. */
export type SignerSlot = Readonly<{
  id: string;
  policy: Policy;
  required: boolean;
  label: string | null;
  tag: string | null;
  principal: string | null;
  role: string | null;
}>;
/** A same-component or same-parameter constraint across quorum slots. */
export type QuorumBinding =
  | Readonly<{ kind: "nested"; outer: string; inner: string }>
  | Readonly<{
      kind: "same_parameter";
      name: "nonce" | "tag" | "created";
      slots: readonly string[];
    }>;
/** A branded policy for bounded multi-signature verification. */
export type Quorum = Readonly<{
  mode: QuorumMode;
  unit: QuorumUnit;
  sharedPrincipal: boolean | null;
  slots: readonly SignerSlot[];
  unexpected: "reject" | "ignore";
  invalid: "reject" | "ignore";
  bindings: readonly QuorumBinding[];
  maxSignatures: number;
}>;
const quorums = new WeakSet<object>();
const text = (v: unknown): v is string =>
  typeof v === "string" &&
  encodeUtf8(v).length >= 1 &&
  encodeUtf8(v).length <= 256;
/** Check the private brand of a quorum policy. */
export function isQuorum(v: unknown): v is Quorum {
  return typeof v === "object" && v !== null && quorums.has(v);
}
function snapshot(
  v: unknown,
  keys: readonly string[],
): Readonly<Record<string, unknown>> {
  const r = snapshotOptions(v, keys);
  ensure(r.ok, "invalid_quorum", "input");
  return r.value;
}
/** Snapshot, validate, and brand a quorum policy. */
export function createQuorum(input: unknown): Result<Quorum> {
  try {
    const a = snapshot(input, [
      "mode",
      "unit",
      "sharedPrincipal",
      "slots",
      "unexpected",
      "invalid",
      "bindings",
      "maxSignatures",
    ]);
    ensure(
      ["mode", "unit", "slots", "unexpected", "invalid"].every((k) =>
        Object.hasOwn(a, k),
      ),
      "invalid_quorum",
      "input",
    );
    const max = Object.hasOwn(a, "maxSignatures")
      ? a.maxSignatures
      : SIGNATURE_DEFAULT_MAX_MEMBERS;
    ensure(
      typeof max === "number" &&
        Number.isInteger(max) &&
        max >= 1 &&
        max <= QUORUM_MAX_SIGNATURES,
      "invalid_quorum",
      "input",
    );
    let mode: QuorumMode;
    if (a.mode === "all" || a.mode === "any") mode = a.mode;
    else {
      const m = snapshot(a.mode, ["threshold"]);
      ensure(
        typeof m.threshold === "number" &&
          Number.isInteger(m.threshold) &&
          m.threshold >= 1 &&
          m.threshold <= max,
        "invalid_quorum",
        "input",
      );
      mode = Object.freeze({ threshold: m.threshold });
    }
    ensure(
      a.unit === "keys" || a.unit === "principals" || a.unit === "roles",
      "invalid_quorum",
      "input",
    );
    ensure(
      a.unit === "roles"
        ? typeof a.sharedPrincipal === "boolean"
        : !Object.hasOwn(a, "sharedPrincipal"),
      "invalid_quorum",
      "input",
    );
    ensure(
      (a.unexpected === "ignore" || a.unexpected === "reject") &&
        (a.invalid === "ignore" || a.invalid === "reject"),
      "invalid_quorum",
      "input",
    );
    ensure(
      Array.isArray(a.slots) && a.slots.length >= 1 && a.slots.length <= 16,
      "invalid_quorum",
      "input",
    );
    const slots: SignerSlot[] = Array.from(a.slots, (raw) => {
      const s = snapshot(raw, [
        "id",
        "policy",
        "required",
        "label",
        "tag",
        "principal",
        "role",
      ]);
      ensure(
        text(s.id) && isPolicy(s.policy) && typeof s.required === "boolean",
        "invalid_quorum",
        "input",
      );
      ensure(
        (s.policy.content === "not_required" ||
            s.policy.content.kind === "content"),
        "invalid_quorum",
        "input",
      );
      const l = s.label ?? null,
        t = s.tag ?? null,
        p = s.principal ?? null,
        r = s.role ?? null;
      ensure(
        (l === null || label(l)) &&
          (t === null || text(t)) &&
          (p === null || text(p)) &&
          (r === null || text(r)),
        "invalid_quorum",
        "input",
      );
      ensure(
        (a.unit === "keys" || p !== null) && (a.unit !== "roles" || r !== null),
        "invalid_quorum",
        "input",
      );
      return Object.freeze({
        id: s.id,
        policy: s.policy,
        required: s.required,
        label: l,
        tag: t,
        principal: p,
        role: r,
      }) as SignerSlot;
    });
    const ids = new Set(slots.map((s) => s.id));
    ensure(
      ids.size === slots.length &&
        (mode !== "all" || slots.some((s) => s.required)),
      "invalid_quorum",
      "input",
    );
    const rawBindings = Object.hasOwn(a, "bindings") ? a.bindings : [];
    ensure(
      Array.isArray(rawBindings) && rawBindings.length <= 64,
      "invalid_quorum",
      "input",
    );
    const bindings: QuorumBinding[] = Array.from(rawBindings, (raw) => {
      const b = snapshot(raw, ["kind", "outer", "inner", "name", "slots"]);
      if (b.kind === "nested") {
        ensure(
          Object.keys(b).length === 3 &&
            typeof b.outer === "string" &&
            typeof b.inner === "string" &&
            ids.has(b.outer) &&
            ids.has(b.inner) &&
            b.outer !== b.inner,
          "invalid_quorum",
          "input",
        );
        return Object.freeze({
          kind: "nested",
          outer: b.outer,
          inner: b.inner,
        });
      }
      ensure(
        b.kind === "same_parameter" &&
          Object.keys(b).length === 3 &&
          (b.name === "nonce" || b.name === "tag" || b.name === "created") &&
          Array.isArray(b.slots) &&
          b.slots.length >= 1 &&
          b.slots.length <= 16,
        "invalid_quorum",
        "input",
      );
      const selected = Array.from(b.slots) as unknown[];
      ensure(
        selected.every((s) => typeof s === "string" && ids.has(s)) &&
          new Set(selected).size === selected.length,
        "invalid_quorum",
        "input",
      );
      return Object.freeze({
        kind: "same_parameter",
        name: b.name,
        slots: Object.freeze(selected as string[]),
      });
    });
    ensure(
      new Set(bindings.map((b) => JSON.stringify(b))).size === bindings.length,
      "invalid_quorum",
      "input",
    );
    const q = {
      mode,
      unit: a.unit,
      sharedPrincipal:
        a.unit === "roles" ? (a.sharedPrincipal as boolean) : null,
      slots: Object.freeze(slots),
      unexpected: a.unexpected,
      invalid: a.invalid,
      bindings: Object.freeze(bindings),
      maxSignatures: max,
    } as Quorum;
    const facts = () => ({mode: q.mode, unit: q.unit, maxSignatures: q.maxSignatures});
    const inspect = () => JSON.stringify(facts());
    Object.defineProperty(q, "toJSON", {value: facts});
    for (const name of ["nodejs.util.inspect.custom", "Deno.customInspect"]) Object.defineProperty(q, Symbol.for(name), {value: inspect});
    Object.freeze(q);
    quorums.add(q);
    return ok(q);
  } catch (e) {
    return err(bounded(e, "invalid_quorum", "input"));
  }
}
/** Quorum policy construction. */
export const Quorum = Object.freeze({
  /** Snapshot, validate, and brand a bounded quorum policy. */
  create: createQuorum });
