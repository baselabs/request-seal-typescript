import { ok, err, type Result } from "../result.ts";
import { coreError } from "../errors/types.ts";
import { verificationFacts, type Verification } from "../verification.ts";
import type { QuorumMode, QuorumUnit, QuorumBinding } from "../quorum.ts";
import type { Layer, Reason } from "../errors/parity.ts";
export type QuorumVerification = Readonly<{
  profile: Readonly<{ name: "rfc9421" }>;
  mode: QuorumMode;
  unit: QuorumUnit;
  sharedPrincipal: boolean | null;
  required: readonly string[];
  satisfied: readonly string[];
  count: number;
  qualifying: readonly Readonly<{
    label: string;
    slot: string;
    principal: string | null;
    role: string | null;
  }>[];
  signatures: Readonly<Record<string, Verification>>;
  nonqualifying: readonly Readonly<{
    label: string;
    slot: string | null;
    reason: Reason<"core">;
    layer: Layer<"core">;
  }>[];
  bindings: "not_required" | readonly (readonly [QuorumBinding, "satisfied"])[];
  negotiation: "not_requested" | "fulfilled";
  replay: "not_required";
  principal: "unattributed";
  authorization: "not_evaluated";
}>;
const results = new WeakSet<object>();
export function isQuorumVerification(v: unknown): v is QuorumVerification {
  return typeof v === "object" && v !== null && results.has(v);
}
export function completeQuorum(
  value: QuorumVerification,
): Result<QuorumVerification> {
  const result = {
    ...value,
    profile: Object.freeze({ ...value.profile }),
    required: Object.freeze([...value.required]),
    satisfied: Object.freeze([...value.satisfied]),
    qualifying: Object.freeze(
      value.qualifying.map((r) => Object.freeze({ ...r })),
    ),
    signatures: Object.freeze(
      Object.assign(
        Object.create(null) as Record<string, Verification>,
        value.signatures,
      ),
    ),
    nonqualifying: Object.freeze(
      value.nonqualifying.map((r) => Object.freeze({ ...r })),
    ),
    bindings:
      value.bindings === "not_required"
        ? ("not_required" as const)
        : Object.freeze(
            value.bindings.map((b) => Object.freeze([...b] as const)),
          ),
  };
  const inspect = () =>
    JSON.stringify({
      profile: result.profile,
      mode: result.mode,
      unit: result.unit,
      required: result.required,
      satisfied: result.satisfied,
      count: result.count,
      replay: result.replay,
      principal: result.principal,
      authorization: result.authorization,
    });
  for (const name of ["nodejs.util.inspect.custom", "Deno.customInspect"])
    Object.defineProperty(result, Symbol.for(name), { value: inspect });
  Object.defineProperty(result, "toJSON", {value: () => JSON.parse(inspect()) as unknown});
  Object.freeze(result);
  results.add(result);
  return ok(result);
}
export function quorumFacts(value: unknown): Result<unknown> {
  if (!isQuorumVerification(value))
    return err(coreError("invalid_verification", "binding"));
  const signatures = Object.create(null) as Record<string, unknown>;
  for (const label of Object.keys(value.signatures).sort()) {
    const r = verificationFacts(value.signatures[label]);
    if (!r.ok) return r;
    signatures[label] = r.value;
  }
  return ok({
    profile: value.profile,
    mode:
      typeof value.mode === "string"
        ? value.mode
        : ["threshold", { int: String(value.mode.threshold) }],
    unit:
      value.unit === "keys"
        ? "key"
        : value.unit === "principals"
          ? "principal"
          : ["role", [["shared_principal", value.sharedPrincipal]]],
    required: value.required,
    satisfied: value.satisfied,
    count: { int: String(value.count) },
    qualifying: value.qualifying,
    signatures,
    nonqualifying: value.nonqualifying,
    bindings:
      value.bindings === "not_required"
        ? "not_required"
        : value.bindings.map(([b, status]) => [
            b.kind === "nested"
              ? [
                  "nested",
                  [
                    ["outer", b.outer],
                    ["inner", b.inner],
                  ],
                ]
              : ["same_parameter", b.name, b.slots],
            status,
          ]),
    negotiation: value.negotiation,
    replay: value.replay,
    principal: value.principal,
    authorization: value.authorization,
  });
}
