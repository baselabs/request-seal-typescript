import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as Seal from "../../src/index.ts";
export const value = <T>(r: Seal.Result<T>): T => {
  assert.equal(r.ok, true, JSON.stringify(r));
  return r.value;
};
export const now = 1735689600;
export const requests = JSON.parse(
  readFileSync("conformance/sources/web-bot-auth/requests.json", "utf8"),
) as {
  name: string;
  target: string;
  fields: [string, string][];
  algorithm: string;
  base: string;
}[];
export const directory = JSON.parse(
  readFileSync("conformance/sources/web-bot-auth/directory.json", "utf8"),
) as { body: string; fields: [string, string][] };
export const published = JSON.parse(
  readFileSync("conformance/sources/web-bot-auth/protocol-00.json", "utf8"),
) as {
  section: string;
  fields: [string, string][];
  base: string;
  algorithm: string;
}[];
export async function request(name = "directory") {
  const r = requests.find((r) => r.name === name)!;
  return value(await Seal.Message.request("GET", r.target, r.fields, ""));
}
export async function trust(a: Seal.AgentRequest) {
  const source = value(
    Seal.DiscoverySource.create({
      type: a.type,
      location: a.location.split("#")[0],
      requireSignedDirectory: false,
    }),
  );
  const body =
    a.type === "cimd"
      ? JSON.stringify({
          client_id: source.location,
          jwks: JSON.parse(directory.body),
        })
      : directory.body;
  return Seal.Discovery.resolver.fromSnapshot(
    source,
    new TextEncoder().encode(body),
    now,
    [
      ["cache-control", "max-age=7200"],
      [
        "content-type",
        a.type === "directory"
          ? "application/http-message-signatures-directory+json"
          : "application/json",
      ],
    ],
  );
}
export function policy(extra: Record<string, unknown> = {}) {
  return value(
    Seal.WebBotAuth.Policy.create({
      algorithms: ["ed25519", "rsa-pss-sha512"],
      agents: trust,
      cache: null,
      freshness: { clock: () => now, maxAge: null, skew: 0 },
      content: "not_required",
      replay: "not_required",
      testKeys: "allow",
      ...extra,
    }),
  );
}
export function rewrite(
  m: Seal.Message,
  f: (name: string, wire: string) => string,
) {
  return value(
    Seal.Message.create({
      ...m,
      fields: m.fields.map((field) =>
        value(
          Seal.FieldOccurrence.create({
            name: field.name,
            section: "headers",
            value: f(
              field.name.toLowerCase(),
              new TextDecoder().decode(field.value),
            ),
          }),
        ),
      ),
    }),
  );
}
export function agentField(m: Seal.Message, wire: string) {
  return value(
    Seal.Message.create({
      ...m,
      fields: [
        ...m.fields.filter((f) => f.name.toLowerCase() !== "signature-agent"),
        value(
          Seal.FieldOccurrence.create({
            name: "Signature-Agent",
            value: wire,
            section: "headers",
          }),
        ),
      ],
    }),
  );
}
export async function custody() {
  return value(
    await Seal.Custody.local(
      "ed25519",
      readFileSync(
        "conformance/sources/rfc9421/keys/ed25519_private.pem",
        "utf8",
      ),
    ),
  );
}
export function rejection(
  r: Seal.Result<unknown>,
  reason: string,
  detail: string | null = null,
) {
  assert.equal(r.ok, false);
  if (!r.ok) {
    assert.equal(r.error.reason, reason);
    assert.equal(r.error.kind, "core");
    if (r.error.kind === "core") {
      assert.equal(r.error.detail, detail);
      assert.equal(r.error.retryable, false);
    }
    assert.equal(JSON.stringify(r.error).includes("https://"), false);
  }
}
