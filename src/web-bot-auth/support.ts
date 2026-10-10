import {
  StructuredFields,
  type Schema,
  type InnerList,
  type Item,
  type Dictionary,
} from "../structured-fields/index.ts";
import {
  signatureSchema,
  inner,
  identities,
  fail,
  ensure,
} from "../signature-fields.ts";
import type { Message } from "../message/index.ts";
import { sourceOrigin } from "../discovery/source.ts";
export const agentSchema: Schema = Object.freeze({
  ...signatureSchema,
  type: "dictionary",
  itemTypes: Object.freeze(["string"] as const),
  innerLists: false,
});
export const schemas = (extra: Readonly<Record<string, Schema>>) =>
  Object.freeze(
    Object.assign(Object.create(null), extra, {
      "signature-agent": agentSchema,
      "signature-input": Object.freeze({
        ...signatureSchema,
        type: "dictionary",
      }),
      signature: Object.freeze({
        ...signatureSchema,
        type: "dictionary",
        itemTypes: Object.freeze(["bytes"] as const),
        innerLists: false,
      }),
    }),
  );
export type Agent = Readonly<{
  location: string;
  type: "directory" | "jwks_uri" | "cimd" | "unsupported";
}>;
export function agentMember(member: Item): Agent {
  if (
    member.value.kind !== "string" ||
    !member.parameters.every(([, v]) => v.kind === "token")
  )
    fail("invalid_signature_agent", "fields", "invalid_member");
  const location = member.value.value;
  let url: URL;
  try {
    url = new URL(location);
  } catch {
    fail("invalid_signature_agent", "fields", "invalid_member");
  }
  if (
    location.length < 1 ||
    location.length > 2048 ||
    !/^[\x21-\x7e]+$/.test(location) ||
    !/^https:\/\/[^/?#]+/i.test(location) ||
    url.protocol !== "https:" ||
    !url.hostname ||
    url.username ||
    url.password ||
    location.includes("\\") ||
    /%(?![a-fA-F0-9]{2})/.test(location) ||
    Number(url.port || 443) < 1
  )
    fail("invalid_signature_agent", "fields", "invalid_member");
  const type =
    member.parameters.find(([k]) => k === "type")?.[1].value ?? "directory";
  return Object.freeze({
    location,
    type:
      type === "directory" || type === "jwks_uri" || type === "cimd"
        ? type
        : "unsupported",
  });
}
export function agents(message: Message): Map<string, Agent> {
  const fields = message.fields.filter(
    (f) => f.name.toLowerCase() === "signature-agent",
  );
  if (!fields.length) return new Map();
  if (
    fields.some((f) =>
      new TextDecoder().decode(f.value).trimStart().startsWith('"'),
    )
  )
    fail("invalid_signature_agent", "fields", "legacy_string");
  const parsed = StructuredFields.parseField(
    message,
    "signature-agent",
    agentSchema,
    "headers",
    { uniqueKeys: "all", uniqueParameters: true },
  );
  if (!parsed.ok) {
    if (parsed.error.reason === "duplicate_key")
      fail("invalid_signature_agent", "fields", "duplicate_member");
    if (parsed.error.reason === "limit") fail("limit", "input");
    fail("invalid_signature_agent", "fields", "invalid_dictionary");
  }
  return new Map(
    (parsed.value as Dictionary).value.map(([label, m]) => {
      if (m.kind !== "item")
        fail("invalid_signature_agent", "fields", "invalid_member");
      return [label, agentMember(m)];
    }),
  );
}
export function asciiOrigin(location: string): string {
  const u = new URL(location);
  return "https://" + u.hostname.toLowerCase() + (u.port ? ":" + u.port : "");
}
export function originAgent(location: string): boolean {
  return location === asciiOrigin(location);
}
export function identifier(agent: Agent): string {
  const url = new URL(agent.location);
  if (agent.type === "directory")
    return sourceOrigin(url) + "/.well-known/http-message-signatures-directory";
  const path = url.pathname.replace(/%[a-fA-F0-9]{2}/g, (e) => {
    const c = String.fromCharCode(parseInt(e.slice(1), 16));
    return /^[a-zA-Z0-9._~-]$/.test(c) ? c : e.toUpperCase();
  });
  // WHATWG removes literal dot segments; decoding unreserved escapes may add more.
  const parts: string[] = [];
  for (const part of path.split("/")) {
    if (part === ".") continue;
    if (part === "..") {
      if (parts.length > 1) parts.pop();
    } else parts.push(part);
  }
  let normalized = parts.join("/");
  if (/\/(?:\.|\.\.)$/.test(path) && !normalized.endsWith("/"))
    normalized += "/";
  return sourceOrigin(url) + (normalized || "/");
}
export function component(name: string, key?: string): Item {
  return {
    kind: "item",
    value: { kind: "string", value: name },
    parameters:
      key === undefined ? [] : [["key", { kind: "string", value: key }]],
  };
}
export function required(input: unknown, added: readonly Item[]): InnerList {
  const r = inner(input);
  ensure(r.ok && r.value.parameters.length === 0, "invalid_options", "input");
  const seen = new Set<string>();
  const values = [...added, ...r.value.value].filter((item) => {
    const id = identities({
      kind: "inner_list",
      value: [item],
      parameters: [],
    })[0]!;
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
  return { kind: "inner_list", value: values, parameters: [] };
}
export function nested(
  selected: readonly (readonly [string, InnerList])[],
  all: Map<string, InnerList>,
): Record<string, readonly string[]> {
  const evidence = Object.create(null) as Record<string, readonly string[]>;
  for (const [label, input] of selected) {
    const ids = new Set(identities(input));
    const covered: string[] = [];
    for (const item of input.value) {
      if (item.value.value !== "signature") continue;
      const key = item.parameters.find(
        ([k, v]) => k === "key" && v.kind === "string",
      )?.[1].value;
      if (typeof key !== "string") continue;
      const target = all.get(key);
      const id = identities({
        kind: "inner_list",
        value: [component("signature-input", key)],
        parameters: [],
      })[0]!;
      ensure(
        item.parameters.length === 1 &&
          target &&
          ids.has(id) &&
          identities(target).every((id) => ids.has(id)),
        "nested_coverage_incomplete",
        "policy",
      );
      covered.push(key);
    }
    evidence[label] = Object.freeze(covered.sort());
  }
  return evidence;
}
