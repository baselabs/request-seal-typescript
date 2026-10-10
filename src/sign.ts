import { snapshotOptions } from "./brand.ts";
import { byteString, encodeBase64Url } from "./bytes.ts";
import { isContext, withDeadline, releaseContext, run, type Context } from "./context.ts";
import {
  SIGNATURE_MAX_BYTES,
  SIGNATURE_DEFAULT_MAX_MEMBERS,
  SF_MAX_INTEGER,
  CLOCK_MAX_SECONDS,
  SIGNING_NONCE_BYTES,
} from "./constants.ts";
import { random } from "./crypto/subtle.ts";
import { resolveAlgorithm, selection, type SigningAlgorithm } from "./crypto/algorithm.ts";
import { isKeyHandle } from "./key_handle.ts";
import { validSigner, custodySign } from "./signer.ts";
import {
  Message,
  isMessage,
  FieldOccurrence,
  type Message as HttpMessage,
} from "./message/index.ts";
import { build } from "./signature-base/index.ts";
import {
  serialize,
  type InnerList,
  type Parameters,
  type Bare,
} from "./structured-fields/index.ts";
import { checkDigest, digest } from "./digest.ts";
import { fieldSchemas } from "./policy.ts";
import {
  inner,
  label,
  dictionaries,
  signatureSchema,
  parameters,
  fail,
  ensure,
  bounded,
} from "./signature-fields.ts";
import { coreError, isRequestSealError } from "./errors/types.ts";
import { timeoutMs } from "./numbers.ts";
import { ok, err, type Result } from "./result.ts";
export type Signer = (
  algorithm: SigningAlgorithm,
  base: Uint8Array,
  context: Context,
) => Result<Uint8Array> | Promise<Result<Uint8Array>>;
export type SignatureSpec = Readonly<{
  label: string;
  signatureInput: string | Uint8Array | InnerList;
  algorithm: SigningAlgorithm;
}>;
export type SigningParameters = Readonly<{
  created?: boolean;
  expiresIn: number | null;
  nonce?: "random" | null;
  alg?: boolean;
  keyid?: string | null;
  tag?: string | null;
}>;
export type SigningSpec = Readonly<{
  label: string;
  components: string;
  algorithm: SigningAlgorithm;
  parameters?: SigningParameters;
  expiresIn?: number;
  created?: boolean;
  nonce?: "random" | null;
  alg?: boolean;
  keyid?: string | null;
  tag?: string | null;
  digest?: readonly string[] | null;
  fieldSchemas?: unknown;
}>;
function take(
  input: unknown,
  keys: readonly string[],
): Readonly<Record<string, unknown>> {
  const r = snapshotOptions(input, keys);
  ensure(r.ok, "invalid_options", "input");
  return r.value;
}
function result<T>(r: Result<T>): T {
  if (!r.ok) throw r.error;
  return r.value;
}
function changed(m: HttpMessage, fields: HttpMessage["fields"]): HttpMessage {
  const r = Message.create({ ...m, fields });
  ensure(r.ok, "invalid_message", "input");
  return r.value;
}
function append(m: HttpMessage, name: string, bytes: unknown): HttpMessage {
  return changed(m, [
    ...m.fields,
    result(FieldOccurrence.create({ name, value: bytes, section: "headers" })),
  ]);
}
export async function sign(
  message: unknown,
  spec: unknown,
  signer: unknown,
  options: unknown = {},
): Promise<Result<HttpMessage>> {
  try {
    const s = take(spec, [
      "label",
      "signatureInput",
      "algorithm",
      "components",
      "parameters",
      "created",
      "expiresIn",
      "nonce",
      "alg",
      "keyid",
      "tag",
      "digest",
      "fieldSchemas",
    ]);
    const generated = Object.hasOwn(s, "components");
    const o = take(
      options,
      generated
        ? ["clock", "nonce", "signingTimeout", "context"]
        : ["fieldSchemas", "signingTimeout", "context"],
    );
    const selected = resolveAlgorithm(s.algorithm);
    const algorithm = selected.ok ? selection(selected.value) as SigningAlgorithm : null;
    const validateSigner = () => {
      ensure(validSigner(signer), "invalid_options", "input");
      if (isKeyHandle(signer)) ensure(JSON.stringify(signer.algorithm) === JSON.stringify(algorithm), generated ? "invalid_options" : "signer_algorithm_mismatch", "input");
    };
    const unusedLabel = (m: HttpMessage) => {
      const [inputs, signatures] = dictionaries(m, SIGNATURE_DEFAULT_MAX_MEMBERS, false);
      ensure(!inputs.has(s.label as string) && !signatures.has(s.label as string), "label_in_use", "fields");
      ensure(JSON.stringify([...inputs.keys()].sort()) === JSON.stringify([...signatures.keys()].sort()), "label_mismatch", "fields");
      ensure(inputs.size < SIGNATURE_DEFAULT_MAX_MEMBERS, "limit", "input");
    };
    const fs = fieldSchemas(Object.hasOwn(generated ? s : o, "fieldSchemas") ? (generated ? s : o).fieldSchemas : {});
    let signingTimeout = 5000;
    if (!generated) {
      ensure(fs.ok, "invalid_options", "input");
      const timeout = timeoutMs(Object.hasOwn(o, "signingTimeout") ? o.signingTimeout : 5000);
      ensure(timeout.ok, "invalid_options", "input");
      signingTimeout = timeout.value;
      ensure(Object.keys(s).length === 3 && Object.hasOwn(s, "signatureInput"), "invalid_options", "input");
      ensure(label(s.label) && algorithm !== null, "invalid_options", "input");
      validateSigner();
    }
    const parameterKeys = [
      "created", "expiresIn", "nonce", "alg", "keyid", "tag",
    ];
    let p: Readonly<Record<string, unknown>> = Object.create(null);
    let full = false;
    if (generated) {
      ensure(
        ["label", "algorithm", "components"].every(k => Object.hasOwn(s, k)),
        "invalid_options", "input",
      );
      const nested = Object.hasOwn(s, "parameters");
      ensure(
        !Object.hasOwn(s, "signatureInput") &&
          (!nested || !parameterKeys.some(k => Object.hasOwn(s, k))),
        "invalid_options", "input",
      );
      p = nested
        ? take(s.parameters, parameterKeys)
        : Object.assign(Object.create(null), Object.fromEntries(
            parameterKeys.filter(k => Object.hasOwn(s, k)).map(k => [k, s[k]]),
          ));
      full = nested && parameterKeys.every(k => Object.hasOwn(p, k)) &&
        Object.hasOwn(s, "digest") && Object.hasOwn(s, "fieldSchemas");
      ensure(
        full || (typeof p.expiresIn === "number" &&
          Number.isSafeInteger(p.expiresIn) && p.expiresIn > 0 &&
          p.expiresIn <= SF_MAX_INTEGER),
        "invalid_options", "input",
      );
    }
    ensure(isMessage(message), "invalid_message", "input");
    const validated = Message.create(message);
    ensure(validated.ok, "invalid_message", "input");
    let m = validated.value;
    let input: InnerList;
    let c: Result<Context> | undefined;
    if (!generated) {
      unusedLabel(m);
      const r = inner(s.signatureInput);
      if (!r.ok) {
        if (r.error.reason === "limit") fail("limit", "input");
        fail("invalid_signature_input", "fields");
      }
      input = r.value;
      if (Object.hasOwn(o, "context") || !isKeyHandle(signer)) {
        c = Object.hasOwn(o, "context") ? (isContext(o.context) ? ok(o.context) : err(bounded(null, "invalid_options", "input"))) : withDeadline({timeoutMs: 5000});
        ensure(c.ok, "invalid_options", "input");
      }
    } else {
      ensure(
        !Object.hasOwn(s, "signatureInput") && typeof s.components === "string",
        "invalid_options",
        "input",
      );
      ensure(label(s.label) && algorithm !== null && fs.ok, "invalid_options", "input");
      const created = Object.hasOwn(p, "created") ? p.created : true,
        age = p.expiresIn,
        nonce = Object.hasOwn(p, "nonce") ? p.nonce : "random",
        alg = Object.hasOwn(p, "alg") ? p.alg : typeof algorithm === "string",
        keyid = Object.hasOwn(p, "keyid") ? p.keyid : null,
        tag = Object.hasOwn(p, "tag") ? p.tag : null;
      ensure(
        typeof created === "boolean" &&
          typeof alg === "boolean" &&
          (nonce === null || nonce === "random") &&
          ((full && age === null) ||
            (typeof age === "number" &&
              Number.isSafeInteger(age) &&
              age > 0 &&
              age <= SF_MAX_INTEGER)) &&
          (age === null || created) && (typeof algorithm === "string" || !alg),
        "invalid_options",
        "input",
      );
      const string = (v: unknown) =>
        v === null ||
        (typeof v === "string" &&
          v.length <= SIGNATURE_MAX_BYTES &&
          /^[\x20-\x7e]*$/.test(v));
      ensure(string(keyid) && string(tag), "invalid_options", "input");
      ensure(s.digest == null || (Array.isArray(s.digest) && s.digest.length >= 1 && s.digest.length <= 2 && new Set(s.digest).size === s.digest.length && s.digest.every(v => v === "sha-256" || v === "sha-512")), "invalid_options", "input");
      const parsed = inner(s.components);
      ensure(
        parsed.ok && parsed.value.parameters.length === 0,
        "invalid_options",
        "input",
      );
      input = parsed.value;
      ensure(
        input.value.every(
          (item) =>
            item.value.value !== "host" &&
            !item.parameters.some(
              ([k]) => k === "tr" || (k === "req" && m.kind !== "response"),
            ),
        ),
        "unsupported_component",
        "input",
      );
      const timeout = timeoutMs(Object.hasOwn(o, "signingTimeout") ? o.signingTimeout : 5000);
      ensure(timeout.ok, "invalid_options", "input");
      signingTimeout = timeout.value;
      ensure(
        !Object.hasOwn(o, "clock") || typeof o.clock === "function",
        "invalid_options",
        "input",
      );
      ensure(
        !Object.hasOwn(o, "nonce") ||
          (o.nonce instanceof Uint8Array &&
            o.nonce.length === SIGNING_NONCE_BYTES),
        "invalid_options",
        "input",
      );
      const entropy =
        o.nonce instanceof Uint8Array ? new Uint8Array(o.nonce) : undefined;
      c = Object.hasOwn(o, "context") ? (isContext(o.context) ? ok(o.context) : err(bounded(null, "invalid_options", "input"))) : withDeadline({timeoutMs: timeout.value});
      ensure(c.ok, "invalid_options", "input");
      validateSigner();
      const bodyRequired =
        s.digest != null ||
        input.value.some(
          (v) =>
            ["content-digest", "repr-digest", "content-length"].includes(
              v.value.value as string,
            ) && !v.parameters.some(([k]) => k === "req"),
        );
      ensure(
        !bodyRequired || m.body.state === "retained",
        "body_unavailable",
        "content",
      );
      if (Object.hasOwn(s, "digest") && s.digest !== null) {
        const existing = m.fields.filter(
          (f) => f.name.toLowerCase() === "content-digest",
        );
        const computed = await digest(m.body.bytes, s.digest);
        if (!computed.ok) {
          if (computed.error.reason === "limit") fail("limit", "input");
          fail("invalid_options", "input");
        }
        if (existing.length) {
          const checked = await checkDigest(m, "content");
          ensure(
            checked.ok &&
              JSON.stringify([...checked.value.checked].sort()) ===
                JSON.stringify([...(s.digest as string[])].sort()),
            "digest_mismatch",
            "content",
          );
        } else m = append(m, "content-digest", computed.value);
      }
      if (
        input.value.some(
          (v) =>
            v.value.value === "content-length" &&
            !v.parameters.some(([k]) => k === "req"),
        )
      ) {
        const fs = m.fields.filter(
            (f) => f.name.toLowerCase() === "content-length",
          ),
          length = m.body.bytes!.length.toString();
        ensure(
          fs.length === 0 ||
            (fs.length === 1 &&
              (fs[0]!.value.length === length.length && fs[0]!.value.every((b, i) => b === length.charCodeAt(i)))),
          "invalid_request",
          "input",
        );
        if (!fs.length) m = append(m, "content-length", length);
      }
      let now: unknown = null;
      if (created) {
        const clock = await run(c.value, () => {
          try { return ok(Object.hasOwn(o, "clock") ? (o.clock as () => unknown)() : Math.floor(Date.now() / 1000)); }
          catch { return err(bounded(null, "invalid_options", "input")); }
        });
        if (!clock.ok) {
          if (clock.error.kind === "custody" && clock.error.reason === "deadline_exceeded") throw clock.error;
          fail("invalid_options", "input");
        }
        now = clock.value;
      }
      ensure(
        (now === null && !created) ||
          (typeof now === "number" &&
            Number.isSafeInteger(now) &&
            now >= 0 &&
            now <= CLOCK_MAX_SECONDS),
        "invalid_options",
        "input",
      );
      const expires = age === null ? null : (now as number) + (age as number);
      ensure(
        expires === null ||
          (Number.isSafeInteger(expires) &&
            expires >= 0 &&
            expires <= SF_MAX_INTEGER),
        "invalid_options",
        "input",
      );
      const params: [string, Bare][] = [];
      if (now !== null)
        params.push(["created", { kind: "integer", value: now as number }]);
      if (expires !== null)
        params.push(["expires", { kind: "integer", value: expires }]);
      if (nonce !== null)
        params.push([
          "nonce",
          {
            kind: "string",
            value: encodeBase64Url(
              entropy ?? random(new Uint8Array(SIGNING_NONCE_BYTES)),
            ),
          },
        ]);
      if (alg) params.push(["alg", { kind: "string", value: algorithm as string }]);
      if (keyid !== null)
        params.push(["keyid", { kind: "string", value: keyid as string }]);
      if (tag !== null)
        params.push(["tag", { kind: "string", value: tag as string }]);
      input = result(inner({ ...input, parameters: params as Parameters }));
    }
    ensure(fs.ok && algorithm !== null, "invalid_options", "input");
    const params = parameters(input);
    ensure(
      !Object.hasOwn(params, "alg") || (typeof algorithm === "string" && params.alg === algorithm),
      "algorithm_mismatch",
      "input",
    );
    const base = build(m, input, { fieldSchemas: fs.value });
    if (!base.ok) {
      if (generated)
        fail(
          base.error.reason === "limit" ? "limit" : "unsupported_component",
          "input",
        );
      fail("signature_base_failed", "crypto", base.error.reason as "limit");
    }
    let ownedSigningContext: Context | undefined;
    if (isKeyHandle(signer)) {
      const parent = Object.hasOwn(o, "context") && c?.ok ? c.value : undefined;
      c = withDeadline(parent ? {parent, timeoutMs: signingTimeout} : {timeoutMs: signingTimeout});
      ensure(c.ok, "invalid_options", "input");
      ownedSigningContext = c.value;
    }
    ensure(c?.ok, "invalid_options", "input");
    let signed: Result<Uint8Array>;
    try {
      signed = isKeyHandle(signer)
        ? await custodySign(signer, algorithm, base.value, c.value)
        : await run(c.value, async (context) => {
            try {
              const r = await (signer as Signer)(algorithm, new Uint8Array(base.value), context);
              if (
                !r ||
                !r.ok ||
                !(r.value instanceof Uint8Array) ||
                r.value.length < 1 ||
                r.value.length > SIGNATURE_MAX_BYTES
              )
                return err(bounded(null, "signer_failed", "crypto"));
              return ok(new Uint8Array(r.value));
            } catch {
              return err(bounded(null, "signer_failed", "crypto"));
            }
          });
    } finally {
      if (ownedSigningContext) releaseContext(ownedSigningContext);
    }
    if (!signed.ok) {
      if (isKeyHandle(signer)) throw coreError("signing_failed", "crypto", null,
        isRequestSealError(signed.error) && signed.error.kind === "custody" ? signed.error : null);
      fail("signer_failed", "crypto");
    }
    if (generated) unusedLabel(m);
    const inputWire = result(
      serialize(
        { kind: "dictionary", value: [[s.label, input]] },
        { schema: { ...signatureSchema, type: "dictionary" } },
      ),
    );
    const signatureWire = result(
      serialize(
        {
          kind: "dictionary",
          value: [
            [
              s.label,
              {
                kind: "item",
                value: { kind: "bytes", value: signed.value },
                parameters: [],
              },
            ],
          ],
        },
        {
          schema: {
            ...signatureSchema,
            type: "dictionary",
            itemTypes: ["bytes"],
            innerLists: false,
          },
        },
      ),
    );
    m = append(
      append(m, "Signature-Input", inputWire),
      "Signature",
      signatureWire,
    );
    dictionaries(m, SIGNATURE_DEFAULT_MAX_MEMBERS);
    return ok(m);
  } catch (e) {
    if (isRequestSealError(e) && e.kind === "custody" && e.reason === "deadline_exceeded") return err(e);
    return err(bounded(e, "invalid_options", "input"));
  }
}
