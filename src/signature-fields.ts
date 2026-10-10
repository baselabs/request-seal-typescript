import {
  parse,
  parseField,
  serialize,
  type Schema,
  type InnerList,
  type Member,
  type Bare,
  type Dictionary,
} from "./structured-fields/index.ts";
import { byteString } from "./bytes.ts";
import { token, type Message } from "./message/index.ts";
import {
  coreError,
  isRequestSealError,
  type CoreDetail,
} from "./errors/types.ts";
import { type Reason, type Layer } from "./errors/parity.ts";
import { ok, err, type Result } from "./result.ts";
import {
  SIGNATURE_MAX_BYTES,
  SIGNATURE_BASE_MAX_COMPONENTS,
  MESSAGE_MAX_TOKEN_BYTES,
  STRUCTURED_FIELDS_LIMITS,
} from "./constants.ts";
export function fail(
  reason: Reason<"core">,
  layer: Layer<"core">,
  detail: CoreDetail | null = null,
): never {
  throw coreError(reason, layer, detail);
}
export function ensure(
  value: unknown,
  reason: Reason<"core">,
  layer: Layer<"core">,
): asserts value {
  if (!value) fail(reason, layer);
}
export function bounded(
  e: unknown,
  reason: Reason<"core">,
  layer: Layer<"core">,
) {
  return isRequestSealError(e) && e.kind === "core"
    ? e
    : coreError(reason, layer);
}
export function label(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MESSAGE_MAX_TOKEN_BYTES &&
    /^[a-z*][a-z0-9_.*-]*$/.test(value)
  );
}
export const signatureSchema: Schema = Object.freeze({
  revision: "rfc8941",
  type: "list",
  itemTypes: Object.freeze(["string"] as const),
  parameterTypes: Object.freeze([
    "integer",
    "decimal",
    "string",
    "token",
    "bytes",
    "boolean",
  ] as const),
  innerLists: true,
});
const derived = [
  "@method",
  "@target-uri",
  "@authority",
  "@scheme",
  "@request-target",
  "@path",
  "@query",
  "@query-param",
  "@status",
];
export function identities(value: InnerList): string[] {
  return value.value.map((item) =>
    JSON.stringify([
      item.value.value,
      [...item.parameters].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
    ]),
  );
}
export function validInner(input: Member): input is InnerList {
  if (
    input.kind !== "inner_list" ||
    input.value.length > SIGNATURE_BASE_MAX_COMPONENTS
  )
    return false;
  if (
    !input.value.every((item) => {
      if (item.value.kind !== "string") return false;
      const name = item.value.value;
      const allowed = derived.includes(name)
        ? name === "@query-param"
          ? ["req", "name"]
          : ["req"]
        : ["sf", "key", "bs", "tr", "req"];
      return (
        (derived.includes(name) ||
          (token(name) && name === name.toLowerCase())) &&
        item.parameters.every(
          ([key, v]) =>
            allowed.includes(key) &&
            ((v.kind === "boolean" &&
              v.value === true &&
              ["sf", "bs", "tr", "req"].includes(key)) ||
              (v.kind === "string" && ["key", "name"].includes(key))),
        ) &&
        (name !== "@query-param" ||
          item.parameters.some(([key]) => key === "name")) &&
        !(
          item.parameters.some(([key]) => key === "bs") &&
          item.parameters.some(([key]) => key === "sf" || key === "key")
        )
      );
    })
  )
    return false;
  return (
    new Set(identities(input)).size === input.value.length &&
    input.parameters.every(([key, v]) =>
      ["created", "expires"].includes(key)
        ? v.kind === "integer"
        : ["nonce", "alg", "keyid", "tag"].includes(key)
          ? v.kind === "string"
          : true,
    )
  );
}
export function inner(value: unknown): Result<InnerList> {
  try {
    const wire =
      typeof value === "string" || value instanceof Uint8Array
        ? byteString(value)
        : serialize(
            { kind: "list", value: [value as InnerList] },
            { schema: signatureSchema },
          );
    if (!wire.ok) return wire;
    const parsed = parse("list", wire.value, {
      schema: signatureSchema,
    });
    if (!parsed.ok) return parsed;
    const list = parsed.value as { value: readonly Member[] };
    if (list.value.length !== 1 || !validInner(list.value[0]!))
      return err(coreError("invalid_signature_input", "fields"));
    return ok(list.value[0]!);
  } catch {
    return err(coreError("invalid_signature_input", "fields"));
  }
}
export function dictionaries(
  message: Message,
  max: number,
  required = true,
): [Map<string, InnerList>, Map<string, Member>] {
  const read = (name: "signature-input" | "signature"): Dictionary => {
    const signature = name === "signature";
    const parsed = parseField(
      message,
      name,
      {
        ...signatureSchema,
        type: "dictionary",
        ...(signature ? { itemTypes: ["bytes"], innerLists: false } : {}),
      },
      "headers",
      {
        uniqueKeys: "all",
        uniqueParameters: true,
        limits: {
          maxMembers: max,
          maxValueBytes: signature
            ? SIGNATURE_MAX_BYTES
            : STRUCTURED_FIELDS_LIMITS.maxValueBytes,
        },
      },
    );
    if (!parsed.ok) {
      const reason = parsed.error.reason;
      if (reason === "missing_field" && !required)
        return { kind: "dictionary", value: [] };
      if (reason === "limit") fail("limit", "input");
      if (reason === "duplicate_key") fail("duplicate_label", "fields");
      if (reason === "duplicate_parameter")
        fail("duplicate_parameter", "fields");
      fail(
        reason === "missing_field"
          ? signature
            ? "missing_signature"
            : "missing_signature_input"
          : signature
            ? "invalid_signature_field"
            : "invalid_signature_input",
        "fields",
      );
    }
    const d = parsed.value as Dictionary;
    if (!signature)
      ensure(
        d.value.every(([, v]) => v.kind === "inner_list"),
        "invalid_signature_input",
        "fields",
      );
    return d;
  };
  return [
    new Map(read("signature-input").value) as Map<string, InnerList>,
    new Map(read("signature").value),
  ];
}
export function parameters(
  input: InnerList,
): Readonly<Record<string, Bare["value"]>> {
  return Object.freeze(
    Object.fromEntries(input.parameters.map(([k, v]) => [k, v.value])),
  );
}
export function wireInner(input: InnerList): Result<Uint8Array> {
  return serialize(
    { kind: "list", value: [input] },
    { schema: signatureSchema },
  );
}
