import { remainingMs, type Context } from "../context.ts";
import {
  StructuredFields,
  type InnerList,
  type Bare,
  type Dictionary,
  type Member,
} from "../structured-fields/index.ts";
import {
  Message,
  Body,
  TransportFacts,
  type FieldOccurrence,
  type Message as HttpMessage,
} from "../message/index.ts";
import { SignatureBase } from "../signature-base/index.ts";
import { Crypto } from "../crypto/index.ts";
import { digest } from "../crypto/subtle.ts";
import { algorithms } from "../crypto/algorithm.ts";
import { encodeBase64 } from "../bytes.ts";
import type { DiscoverySource } from "./source.ts";
import { sourceAuthority, sourceUrl, thumbprintId } from "./source.ts";
import type { Resolution, Proof } from "./body.ts";
import { ensure, unwrap } from "./support.ts";
import { values } from "./headers.ts";
const inputSchema = unwrap(
  StructuredFields.createSchema({
    revision: "rfc8941",
    type: "dictionary",
    itemTypes: ["string"],
    parameterTypes: [
      "integer",
      "decimal",
      "string",
      "token",
      "bytes",
      "boolean",
    ],
    innerLists: true,
  }),
  "invalid_options",
);
const signatureSchema = unwrap(
  StructuredFields.createSchema({
    revision: "rfc8941",
    type: "dictionary",
    itemTypes: ["bytes"],
    parameterTypes: [
      "integer",
      "decimal",
      "string",
      "token",
      "bytes",
      "boolean",
    ],
    innerLists: false,
  }),
  "invalid_options",
);
function params(member: Member): Map<string, Bare> {
  return new Map(member.parameters);
}
function textParam(p: Map<string, Bare>, name: string): string | null {
  const b = p.get(name);
  return b?.kind === "string" ? b.value : null;
}
function integerParam(p: Map<string, Bare>, name: string): number | null {
  const b = p.get(name);
  return b?.kind === "integer" ? b.value : null;
}
function dictionary(raw: string, schema: typeof inputSchema): Dictionary {
  const parsed = unwrap(
    StructuredFields.parse("dictionary", raw, {
      schema,
      mode: "unique",
      limits: { maxMembers: 64, maxValueBytes: 1024 },
    }),
    "directory_signature_invalid",
  );
  ensure(parsed.kind === "dictionary", "directory_signature_invalid");
  return parsed;
}
export async function proofMessage(
  location: string,
  fs: readonly FieldOccurrence[],
  encoded: Uint8Array,
  type: DiscoverySource["type"],
): Promise<HttpMessage> {
  const url = sourceUrl(location),
    authority = sourceAuthority(url);
  const req = unwrap(
    await Message.request(
      "GET",
      `https://${authority}${url.pathname}${url.search}`,
      [
        ["Host", authority],
        [
          "Accept",
          type === "directory"
            ? "application/http-message-signatures-directory+json"
            : "application/json, application/jwk-set+json",
        ],
        ["Accept-Encoding", "gzip"],
        ["Connection", "close"],
      ],
      null,
    ),
    "directory_signature_invalid",
  );
  return unwrap(
    Message.create({
      kind: "response",
      status: 200,
      fields: fs,
      trailers: [],
      relatedRequest: req,
      body: unwrap(
        Body.create({ state: "retained", bytes: encoded, maxBytes: 1048576 }),
        "directory_signature_invalid",
      ),
      transport: unwrap(
        TransportFacts.create({}),
        "directory_signature_invalid",
      ),
    }),
    "directory_signature_invalid",
  );
}
export async function possessionProof(
  source: DiscoverySource,
  keys: Readonly<Record<string, Resolution>>,
  location: string,
  fs: readonly FieldOccurrence[],
  encoded: Uint8Array,
  now: number,
  context?: Context,
): Promise<{ proof: Proof; expiresAt: number }> {
  ensure(!context || remainingMs(context) > 0, "deadline_exceeded");
  const inputs = values(fs, "signature-input"),
    signatures = values(fs, "signature");
  if (!inputs.length && !signatures.length) {
    ensure(!source.requireSignedDirectory, "directory_unsigned");
    return { proof: "unsigned", expiresAt: now + source.maxTtl };
  }
  const input = dictionary(inputs.join(", "), inputSchema),
    signature = dictionary(signatures.join(", "), signatureSchema);
  ensure(
    input.value.length >= 1 && input.value.length <= 64,
    "directory_signature_invalid",
  );
  const selected = input.value.filter(
    ([label, m]) =>
      label === "directory" ||
      (textParam(params(m), "tag") === "http-message-signatures-directory" &&
        Object.hasOwn(keys, textParam(params(m), "keyid") ?? "")),
  );
  ensure(selected.length > 0, "directory_signature_invalid");
  const message = await proofMessage(location, fs, encoded, source.type);
  ensure(!context || remainingMs(context) > 0, "deadline_exceeded");
  const rawDigest = values(fs, "content-digest");
  ensure(rawDigest.length > 0, "directory_signature_invalid");
  const dig = unwrap(
    StructuredFields.parse("dictionary", rawDigest.join(", "), {
      schema: signatureSchema,
      mode: "unique",
    }),
    "directory_signature_invalid",
  );
  ensure(dig.kind === "dictionary", "directory_signature_invalid");
  let recognized = false;
  for (const [algorithm, item] of dig.value) {
    ensure(!context || remainingMs(context) > 0, "deadline_exceeded");
    if (algorithm !== "sha-256" && algorithm !== "sha-512") continue;
    ensure(
      item.kind === "item" && item.value.kind === "bytes",
      "directory_signature_invalid",
    );
    const actual = new Uint8Array(
      await digest(
        algorithm === "sha-256" ? "SHA-256" : "SHA-512",
        new Uint8Array(encoded),
      ),
    );
    ensure(!context || remainingMs(context) > 0, "deadline_exceeded");
    ensure(
      encodeBase64(actual) === encodeBase64(item.value.value),
      "directory_signature_invalid",
    );
    recognized = true;
  }
  ensure(recognized, "directory_signature_invalid");
  let expiresAt = now + source.maxTtl;
  for (const [label, m] of selected) {
    ensure(m.kind === "inner_list", "directory_signature_invalid");
    const p = params(m);
    const kid = textParam(p, "keyid"),
      created = integerParam(p, "created"),
      expires = integerParam(p, "expires");
    ensure(
      thumbprintId(kid) &&
        textParam(p, "tag") === "http-message-signatures-directory" &&
        created !== null &&
        created <= now &&
        expires !== null &&
        expires > now &&
        expires >= created,
      "directory_signature_invalid",
    );
    const entry = Object.hasOwn(keys, kid) ? keys[kid] : undefined;
    ensure(entry, "directory_signature_invalid");
    const sig = signature.value.find(([n]) => n === label)?.[1];
    ensure(
      sig?.kind === "item" &&
        sig.value.kind === "bytes" &&
        sig.parameters.length === 0,
      "directory_signature_invalid",
    );
    const mandatory = (name: string, req: boolean) =>
      m.value.some(
        (i) =>
          i.value.kind === "string" &&
          i.value.value === name &&
          i.parameters.length === (req ? 1 : 0) &&
          (!req ||
            (i.parameters[0]![0] === "req" &&
              i.parameters[0]![1].kind === "boolean" &&
              i.parameters[0]![1].value)),
      );
    ensure(
      mandatory("@authority", true) && mandatory("content-digest", false),
      "directory_signature_invalid",
    );
    const base = unwrap(
      SignatureBase.build(message, m as InnerList),
      "directory_signature_invalid",
    );
    let valid = false;
    for (const algorithm of unwrap(algorithms(), "directory_signature_invalid")) {
      ensure(!context || remainingMs(context) > 0, "deadline_exceeded");
      if (
        (entry.assertedAlgorithm === null ||
          entry.assertedAlgorithm === algorithm) &&
        entry.key.bind(algorithm).ok &&
        (!p.has("alg") || textParam(p, "alg") === algorithm)
      ) {
        if (
          (await Crypto.verify(algorithm, entry.key, sig.value.value, base)).ok
        ) {
          valid = true;
          break;
        }
      }
    }
    ensure(!context || remainingMs(context) > 0, "deadline_exceeded");
    ensure(valid, "directory_signature_invalid");
    expiresAt = Math.min(expiresAt, expires);
  }
  return { proof: "signed", expiresAt };
}
