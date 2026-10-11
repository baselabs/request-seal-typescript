import {isWebBotAuthVerification, webBotAuthFacts} from './web-bot-auth/verification.ts';
import {isQuorumVerification,quorumFacts} from './quorum/verification.ts';
import { deepFreeze, inspection } from "./brand.ts";
import { encodeUtf8 } from "./runtime.ts";
import { decimalSource, copyDecimalSource, type Bare, type Parameters } from "./structured-fields/index.ts";
import type { DigestFacts } from "./digest.ts";
import { isReplayReceipt } from "./replay/receipt.ts";
import { coreError } from "./errors/types.ts";
import { ok, err, type Result } from "./result.ts";
export type FreshnessFacts = Readonly<{
  now: number;
  created: number | null;
  expires: number | null;
  maxAge: number | null;
  skew: number;
}>;
export type Verification = Readonly<{
  label: string;
  signature: Readonly<{
    algorithm: import("./crypto/algorithm.ts").SigningAlgorithm;
    covered: readonly (readonly [string, Parameters])[];
    parameters: Parameters;
    keyid: string | null;
    crypto: "valid";
  }>;
  profile: Readonly<{ name: "rfc9421" }> | import("./web-bot-auth/verification.ts").WebBotAuthProfile | import("./profile.ts").ProfileStamp;
  content: "not_required" | DigestFacts;
  freshness: "not_evaluated" | FreshnessFacts;
  replay:
    | "not_required"
    | import("./replay-port.ts").ReplayReceipt;
  principal: "unattributed" | import("./web-bot-auth/verification.ts").AgentPrincipal | import("./web-bot-auth/verification.ts").HeldPrincipal;
  authorization: "not_evaluated";
}>;
const verifications = new WeakSet<object>();
export function isVerification(value: unknown): value is Verification {
  return (
    typeof value === "object" && value !== null && verifications.has(value)
  );
}
/** Internal pipeline constructor; callers receive verifications only through verify. */
function ownedBare(v: Bare): Bare {
  if (v.kind === "bytes") {
    const bytes = new Uint8Array(v.value);
    return Object.freeze({
      kind: "bytes",
      get value() {
        return new Uint8Array(bytes);
      },
    });
  }
  const owned = Object.freeze(v.kind === "decimal" ? { ...v, value: Object.freeze({ ...v.value }) } : { ...v });
  copyDecimalSource(v, owned);
  return owned;
}
function ownedParameters(params: Parameters): Parameters {
  return Object.freeze(
    params.map(([key, v]) => Object.freeze([key, ownedBare(v)] as const)),
  );
}
export function completed(value: Verification): Result<Verification> {
  const signature = Object.freeze({
    ...value.signature,
    covered: Object.freeze(
      value.signature.covered.map(([name, params]) =>
        Object.freeze([name, ownedParameters(params)] as const),
      ),
    ),
    parameters: ownedParameters(value.signature.parameters),
  });
  const snapshot = deepFreeze({
    ...value,
    signature: null,
    replay: "not_required",
  });
  if (!snapshot.ok) return snapshot;
  let replay: Verification["replay"] = "not_required";
  if (value.replay !== "not_required") {
    if (!isReplayReceipt(value.replay)) return err(coreError("invalid_verification", "binding"));
    replay = value.replay;
  }
  const result = {
    ...snapshot.value,
    signature,
    replay,
  } as Verification;
  const inspect = () => Object.freeze({
    label: result.label,
    profile: result.profile,
    replay: result.replay,
    authorization: result.authorization,
  });
  Object.defineProperties(result, {
    toJSON: { value: inspect },
    ...inspection(inspect),
  });
  Object.freeze(result);
  verifications.add(result);
  return ok(result);
}
function tagged(v: Bare): unknown {
  if (v.kind === "integer" || v.kind === "date")
    return { int: v.value.toString() };
  if (v.kind === "bytes") return { b64: base64url(v.value) };
  if (v.kind === "decimal") {
    const source = decimalSource(v);
    if (source !== undefined) return {dec: source};
    const n = BigInt(v.value.scaled),
      digits = (n < 0n ? -n : n).toString().padStart(v.value.scale + 1, "0"),
      scale = v.value.scale;
    const decimal = scale
      ? digits.slice(0, -scale) + "." + digits.slice(-scale).replace(/0+$/, "")
      : digits + ".";
    return {
      dec: (n < 0n ? "-" : "") + decimal + (decimal.endsWith(".") ? "0" : ""),
    };
  }
  return v.value;
}

function wire(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return value.map(wire);
  const o = value as Record<string, unknown>;
  return Object.fromEntries(
    Object.entries(o).map(([key, v]) => [
      key === "maxAge"
        ? "max_age"
        : key === "retainUntil"
          ? "retain_until"
          : key,
      typeof v === "number" ? { int: v.toString() } : wire(v),
    ]),
  );
}
/** Ordered language-neutral facts; cryptographic material is never serialized. */
export function verificationFacts(value: unknown): Result<unknown> {
  if (isWebBotAuthVerification(value)) return webBotAuthFacts(value);
  if (isQuorumVerification(value)) return quorumFacts(value);
  if (!isVerification(value))
    return err(coreError("invalid_verification", "binding"));
  const number = (n: number | null) =>
    n === null ? null : { int: n.toString() };
  return ok({
    label: value.label,
    signature: {
      algorithm: typeof value.signature.algorithm === "string" ? value.signature.algorithm : ["jws", value.signature.algorithm.jws],
      covered: value.signature.covered.map(([name, params]) => [
        name,
        params.map(([k, v]) => [k, tagged(v)]),
      ]),
      parameters: value.signature.parameters.map(([k, v]) => [k, tagged(v)]),
      keyid: value.signature.keyid,
      crypto: "valid",
    },
    profile: Array.isArray(value.profile.name)
      ? Object.fromEntries(Object.entries(value.profile).map(([k, v]) => [k, typeof v === "boolean" ? String(v) : v === null ? "" : v]))
      : value.profile,
    content:
      value.content === "not_required"
        ? "not_required"
        : { ...value.content, bytes: number(value.content.bytes) },
    freshness: wire(value.freshness),
    replay: value.replay === "not_required" ? "not_required" : {store: "store", retain_until: number(value.replay.retainUntil)},
    principal: value.principal === 'unattributed' ? 'unattributed' : value.principal.kind === 'key' ? {thumbprint:value.principal.thumbprint} : {agent:value.principal.origin,source:value.principal.type,thumbprint:value.principal.thumbprint},
    authorization: value.authorization,
  });
}
export function serializeVerification(value: unknown): Result<Uint8Array> {
  const r = verificationFacts(value);
  if (!r.ok) return r;
  // Metadata values retain their Structured Fields type; extension byte parameters
  // use the corpus byte tag rather than JSON's typed-array property enumeration.
  const encode = (v: unknown): unknown =>
    v instanceof Uint8Array
      ? { b64: base64url(v) }
      : Array.isArray(v)
        ? v.map(encode)
        : v && typeof v === "object"
          ? Object.fromEntries(
              Object.entries(v).map(([k, x]) => [k, encode(x)]),
            )
          : v;
  return ok(encodeUtf8(JSON.stringify(encode(r.value))));
}
import { encodeBase64Url as base64url } from "./bytes.ts";
