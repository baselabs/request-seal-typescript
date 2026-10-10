import { snapshotOptions } from "../brand.ts";
import {
  isMessage,
  Message,
  FieldOccurrence,
  type Message as HttpMessage,
} from "../message/index.ts";
import { isPublicKey } from "../public_key.ts";
import { validSigner } from "../signer.ts";
import { resolveAlgorithm, selection } from "../crypto/algorithm.ts";
import { sign } from "../sign.ts";
import { fieldSchemas } from "../policy.ts";
import {
  StructuredFields,
  type Bare,
  type Item,
} from "../structured-fields/index.ts";
import { SF_MAX_INTEGER } from "../constants.ts";
import { err, type Result } from "../result.ts";
import { isRequestSealError } from "../errors/types.ts";
import {
  ensure,
  bounded,
  label,
  dictionaries,
  inner,
} from "../signature-fields.ts";
import {
  agentMember,
  agents,
  originAgent,
  component,
  required,
  nested,
  schemas,
  agentSchema,
} from "./support.ts";
export async function signWebBotAuth(
  message: unknown,
  spec: unknown,
  signer: unknown,
  options: unknown = {},
): Promise<Result<HttpMessage>> {
  try {
    const o = snapshotOptions(options, ["fieldSchemas", "context"]);
    ensure(o.ok, "invalid_options", "input");
    ensure(
      isMessage(message) && message.kind === "request",
      "invalid_message",
      "input",
    );
    const checked = Message.create(message);
    ensure(checked.ok, "invalid_message", "input");
    let m = checked.value;
    const s = snapshotOptions(spec, [
      "label",
      "agent",
      "key",
      "algorithm",
      "created",
      "expires",
      "nonce",
      "components",
    ]);
    ensure(
      s.ok &&
        [
          "label",
          "agent",
          "key",
          "algorithm",
          "created",
          "expires",
          "nonce",
        ].every((k) => Object.hasOwn(s.value, k)),
      "invalid_options",
      "input",
    );
    const a = s.value;
    const algorithm = resolveAlgorithm(a.algorithm);
    ensure(
      label(a.label) &&
        algorithm.ok &&
        algorithm.value.family !== "hmac" &&
        validSigner(signer),
      "invalid_options",
      "input",
    );
    ensure(
      typeof a.created === "number" &&
        Number.isSafeInteger(a.created) &&
        a.created >= 0 &&
        a.created <= SF_MAX_INTEGER &&
        typeof a.expires === "number" &&
        Number.isSafeInteger(a.expires) &&
        a.expires <= SF_MAX_INTEGER &&
        a.expires > a.created &&
        a.expires - a.created <= 86400 &&
        (a.nonce === null ||
          (typeof a.nonce === "string" &&
            a.nonce.length >= 1 &&
            a.nonce.length <= 1024)),
      "invalid_options",
      "input",
    );
    ensure(isPublicKey(a.key), "invalid_options", "input");
    const keyid = await a.key.thumbprint();
    ensure(
      keyid.ok && a.key.bind(selection(algorithm.value)).ok,
      "invalid_options",
      "input",
    );
    const agent = snapshotOptions(a.agent, ["location", "type"]);
    ensure(
      agent.ok &&
        Object.keys(agent.value).length === 2 &&
        ["directory", "jwks_uri", "cimd"].includes(agent.value.type as string),
      "invalid_options",
      "input",
    );
    const member: Item = {
      kind: "item",
      value: { kind: "string", value: agent.value.location as string },
      parameters: [
        ["type", { kind: "token", value: agent.value.type as string }],
      ],
    };
    const parsed = agentMember(member);
    ensure(
      parsed.type !== "directory" || originAgent(parsed.location),
      "invalid_options",
      "input",
    );
    const existing = agents(m);
    const old = existing.get(a.label);
    ensure(
      !old || (old.type === parsed.type && old.location === parsed.location),
      "invalid_options",
      "input",
    );
    if (!old) {
      const wire = StructuredFields.serialize(
        { kind: "dictionary", value: [[a.label, member]] },
        { schema: agentSchema },
      );
      ensure(wire.ok, "invalid_options", "input");
      const f = FieldOccurrence.create({
        name: "Signature-Agent",
        value: wire.value,
        section: "headers",
      });
      ensure(f.ok, "invalid_options", "input");
      const next = Message.create({ ...m, fields: [...m.fields, f.value] });
      ensure(next.ok, "invalid_message", "input");
      m = next.value;
    }
    const items = required(
      Object.hasOwn(a, "components") ? a.components : "()",
      [component("@authority"), component("signature-agent", a.label)],
    );
    const params: [string, Bare][] = [
      ["created", { kind: "integer", value: a.created }],
      ["keyid", { kind: "string", value: keyid.value }],
    ];
    const chosen = selection(algorithm.value);
    if (typeof chosen === "string")
      params.push(["alg", { kind: "string", value: chosen }]);
    params.push(["expires", { kind: "integer", value: a.expires }]);
    if (a.nonce !== null)
      params.push(["nonce", { kind: "string", value: a.nonce }]);
    params.push(["tag", { kind: "string", value: "web-bot-auth" }]);
    const input = inner({ ...items, parameters: params });
    ensure(input.ok, "invalid_options", "input");
    const [inputs] = dictionaries(m, 16, false);
    nested([[a.label, input.value]], inputs);
    const fs = fieldSchemas(
      Object.hasOwn(o.value, "fieldSchemas") ? o.value.fieldSchemas : {},
    );
    ensure(fs.ok, "invalid_options", "input");
    return await sign(
      m,
      { label: a.label, signatureInput: input.value, algorithm: chosen },
      signer,
      {
        fieldSchemas: schemas(fs.value),
        ...(Object.hasOwn(o.value, "context")
          ? { context: o.value.context }
          : {}),
      },
    );
  } catch (e) {
    return err(
      isRequestSealError(e) ? e : bounded(e, "invalid_options", "input"),
    );
  }
}
