import { snapshotOptions } from "./brand.ts";
import { byteString } from "./bytes.ts";
import { decodeUtf8FatalBom } from "./runtime.ts";
import {
  parse,
  serialize,
  type Dictionary,
  type InnerList,
  type Parameters,
} from "./structured-fields/index.ts";
import {
  signatureSchema,
  inner,
  label,
  ensure,
  bounded,
} from "./signature-fields.ts";
import {Message, isMessage, type Message as HttpMessage} from "./message/index.ts";
import {sign, type Signer} from "./sign.ts";
import {isKeyHandle} from "./key_handle.ts";
import {fieldSchemas} from "./policy.ts";
import {SF_MAX_INTEGER} from "./constants.ts";
import {isContext, withDeadline, run} from "./context.ts";
import {isRequestSealError} from "./errors/types.ts";
import { Crypto } from "./crypto/index.ts";
import { ok, err, type Result } from "./result.ts";
export type SignatureRequest = Readonly<{
  label: string;
  components: InnerList;
  parameters: Readonly<Record<string, string | true>>;
}>;
export type AcceptSignature = readonly SignatureRequest[];
const requestsBrand = new WeakSet<object>();
const names = ["keyid", "alg", "created", "expires", "nonce", "tag"] as const;
const requestDerived = [
  "@method",
  "@target-uri",
  "@authority",
  "@scheme",
  "@request-target",
  "@path",
  "@query",
  "@query-param",
];
export function isAcceptSignature(v: unknown): v is AcceptSignature {
  return typeof v === "object" && v !== null && requestsBrand.has(v);
}
export function applicable(
  requests: AcceptSignature,
  target: "request" | "response",
): Result<AcceptSignature> {
  try {
    for (const r of requests)
      for (const item of r.components.value) {
        const name = item.value.value as string,
          req = item.parameters.some(([k]) => k === "req");
        ensure(
          target === "request"
            ? name !== "@status" && !req
            : (name !== "@status" || !req) &&
                (!requestDerived.includes(name) || req),
          "inapplicable_component",
          "negotiation",
        );
      }
    return ok(requests);
  } catch (e) {
    return err(bounded(e, "invalid_accept_signature", "negotiation"));
  }
}
export function parseAcceptSignature(
  wire: unknown,
  options: unknown,
): Result<AcceptSignature> {
  try {
    const a = snapshotOptions(options, ["target"]);
    ensure(
      a.ok && (a.value.target === "request" || a.value.target === "response"),
      "invalid_options",
      "input",
    );
    const fields = Array.isArray(wire) ? Array.from(wire) : [wire];
    ensure(fields.length <= 1024, "invalid_accept_signature", "negotiation");
    const parts = fields.map((v) => {
      const r = byteString(v);
      ensure(
        (typeof v === "string" || v instanceof Uint8Array) && r.ok,
        "invalid_accept_signature",
        "negotiation",
      );
      return r.value;
    });
    const size = parts.reduce(
      (n, v) => n + v.length,
      Math.max(0, parts.length - 1) * 2,
    );
    ensure(size <= 65536, "limit", "input");
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (let i = 0; i < parts.length; i++) {
      if (i) {
        bytes[offset++] = 44;
        bytes[offset++] = 32;
      }
      bytes.set(parts[i]!, offset);
      offset += parts[i]!.length;
    }
    const parsed = parse("dictionary", bytes, {
      schema: { ...signatureSchema, type: "dictionary" },
      mode: "unique",
      limits: { maxMembers: 16 },
    });
    if (!parsed.ok) {
      const reason = parsed.error.reason;
      ensure(reason !== "duplicate_key", "duplicate_label", "fields");
      ensure(reason !== "duplicate_parameter", "duplicate_parameter", "fields");
      ensure(reason !== "limit", "limit", "input");
      ensure(false, "invalid_accept_signature", "negotiation");
    }
    const requests: SignatureRequest[] = (parsed.value as Dictionary).value.map(
      ([l, member]) => {
        ensure(
          label(l) && member.kind === "inner_list",
          "invalid_accept_signature",
          "negotiation",
        );
        const c = inner({ ...member, parameters: [] });
        ensure(c.ok, "invalid_accept_signature", "negotiation");
        const params = Object.create(null) as Record<string, string | true>;
        for (const [k, v] of member.parameters) {
          ensure(
            names.includes(k as (typeof names)[number]) &&
              (k === "created" || k === "expires"
                ? v.kind === "boolean" && v.value === true
                : v.kind === "string" || v.kind === "token" || v.kind === "bytes"),
            "invalid_accept_signature",
            "negotiation",
          );
          const decoded = v.kind === "bytes" ? decodeUtf8FatalBom(v.value) : v.value;
          if (k !== "created" && k !== "expires") {
            const encoded = serialize({kind: "item", value: {kind: "string", value: decoded as string}, parameters: []}, {schema: {...signatureSchema, type: "item"}});
            ensure(encoded.ok, "invalid_accept_signature", "negotiation");
          }
          if (k === "alg") {
            const algorithms = Crypto.algorithms();
            ensure(
              algorithms.ok && algorithms.value.includes(decoded as never),
              "invalid_accept_signature",
              "negotiation",
            );
          }
          params[k] = decoded as string | true;
        }
        const request = Object.freeze({
          label: l,
          components: c.value,
          parameters: Object.freeze(params),
        });
        const allowed = applicable([request], a.value.target as "request" | "response");
        if (!allowed.ok) throw allowed.error;
        return request;
      },
    );
    const result = Object.freeze(requests);
    requestsBrand.add(result);
    return applicable(result, a.value.target);
  } catch (e) {
    return err(bounded(e, "invalid_accept_signature", "negotiation"));
  }
}
export function serializeAcceptSignature(
  requests: unknown,
): Result<Uint8Array> {
  try {
    ensure(
      isAcceptSignature(requests),
      "invalid_accept_signature",
      "negotiation",
    );
    const value: Dictionary = {
      kind: "dictionary",
      value: requests.map((r) => [
        r.label,
        {
          ...r.components,
          parameters: names
            .filter((k) => Object.hasOwn(r.parameters, k))
            .map((k) => [
              k,
              r.parameters[k] === true
                ? { kind: "boolean", value: true }
                : { kind: "string", value: r.parameters[k] as string },
            ]) as Parameters,
        },
      ]),
    };
    const result = serialize(value, {
      schema: { ...signatureSchema, type: "dictionary" },
      mode: "unique",
      limits: { maxMembers: 16 },
    });
    ensure(
      result.ok,
      result.ok
        ? "invalid_accept_signature"
        : result.error.reason === "limit"
          ? "limit"
          : "invalid_accept_signature",
      result.ok
        ? "negotiation"
        : result.error.reason === "limit"
          ? "input"
          : "negotiation",
    );
    return result;
  } catch (e) {
    return err(bounded(e, "invalid_accept_signature", "negotiation"));
  }
}
export type SignatureChoice = Readonly<{algorithm: string; created: number | null; expires: number | null}>;
export type SignatureChooser = (request: SignatureRequest) => Result<SignatureChoice> | Promise<Result<SignatureChoice>>;
/** Fulfill atomically through caller-owned selection and the single-signature API. */
export async function fulfillAcceptSignature(
  message: unknown,
  requests: unknown,
  chooser: unknown,
  signer: unknown,
  options: unknown = {},
): Promise<Result<HttpMessage>> {
  try {
    const a = snapshotOptions(options, ["fieldSchemas", "context"]);
    ensure(a.ok && (typeof chooser === "function") && (typeof signer === "function" || isKeyHandle(signer)), "invalid_options", "input");
    const schemas = fieldSchemas(Object.hasOwn(a.value, "fieldSchemas") ? a.value.fieldSchemas : {});
    ensure(schemas.ok, "invalid_options", "input");
    const context = Object.hasOwn(a.value, "context")
      ? (isContext(a.value.context) ? ok(a.value.context) : err(bounded(null, "invalid_options", "input")))
      : withDeadline();
    ensure(context.ok, "invalid_options", "input");
    ensure(isMessage(message) && Message.create(message).ok, "invalid_message", "input");
    ensure(isAcceptSignature(requests), "invalid_accept_signature", "negotiation");
    const allowed = applicable(requests, message.kind);
    if (!allowed.ok) return allowed;
    const selectedSigner: Signer = (algorithm, bytes) => isKeyHandle(signer)
      ? signer.sign(algorithm, bytes, context.value)
      : (signer as Signer)(algorithm, bytes, context.value);
    let current = message;
    for (const request of requests) {
      const selected = await run(context.value, async () => {
        try { return ok(await (chooser as SignatureChooser)(request)); }
        catch { return err(bounded(null, "negotiation_unfulfillable", "negotiation")); }
      });
      if (!selected.ok && isRequestSealError(selected.error) && selected.error.kind === "custody") return selected;
      ensure(selected.ok, "negotiation_unfulfillable", "negotiation");
      const result = snapshotOptions(selected.value, ["ok", "value", "error"]);
      ensure(result.ok && result.value.ok === true && Object.hasOwn(result.value, "value"), "negotiation_unfulfillable", "negotiation");
      const choice = snapshotOptions(result.value.value, ["algorithm", "created", "expires"]);
      const time = (v: unknown) => v === null || (typeof v === "number" && Number.isSafeInteger(v) && Math.abs(v) <= SF_MAX_INTEGER);
      const algorithms = Crypto.algorithms();
      ensure(choice.ok && Object.keys(choice.value).length === 3 && algorithms.ok && algorithms.value.includes(choice.value.algorithm as never) && time(choice.value.created) && time(choice.value.expires), "negotiation_unfulfillable", "negotiation");
      const picked = choice.value;
      ensure(!Object.hasOwn(request.parameters, "alg") || request.parameters.alg === picked.algorithm, "negotiation_unfulfillable", "negotiation");
      const params: Parameters = names.filter(k => Object.hasOwn(request.parameters, k)).map(k => {
        const requested = request.parameters[k];
        if (requested === true) {
          const value = picked[k as "created" | "expires"];
          ensure(typeof value === "number" && Number.isSafeInteger(value), "negotiation_unfulfillable", "negotiation");
          return [k, {kind: "integer", value}];
        }
        return [k, {kind: "string", value: requested as string}];
      });
      const signed = await run(context.value, () => sign(current, {label: request.label, signatureInput: {...request.components, parameters: params}, algorithm: picked.algorithm}, selectedSigner, {fieldSchemas: schemas.value, context: context.value}));
      if (!signed.ok && signed.error.kind === "custody" && signed.error.reason === "deadline_exceeded") return signed;
      ensure(signed.ok, "negotiation_unfulfillable", "negotiation");
      current = signed.value;
    }
    return ok(current);
  } catch (e) { return err(bounded(e, "negotiation_unfulfillable", "negotiation")); }
}
export const AcceptSignature = Object.freeze({
  parse: parseAcceptSignature,
  serialize: serializeAcceptSignature,
  fulfill: fulfillAcceptSignature,
});
