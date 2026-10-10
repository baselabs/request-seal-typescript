import { message, decoded, resolve } from "./wire.ts";
import {
  Custody,
  PublicKey,
  Policy,
  sign,
  verify,
  digest,
  Message,
  FieldOccurrence,
  ok,
  err,
  decodeBase64,
  createMemoryStore,
  type KeyHandle,
  type SigningAlgorithm,
  type Context,
  type Result,
} from "../../src/index.ts";
import { coreError, isRequestSealError } from "../../src/errors/types.ts";
import { serializeVerification } from "../../src/verification.ts";
import type {
  Surface,
  SurfaceResult,
  CorpusCase,
  CorpusResources,
} from "./loader.ts";
const invalid = (): SurfaceResult => ({
  ok: false,
  loaderReason: "invalid_manifest",
});
const names: Record<string, string> = {
  "rsa-pss-sha512": "rsa_pss",
  "rsa-v1_5-sha256": "rsa",
  "ecdsa-p256-sha256": "p256",
  ed25519: "ed25519",
  "hmac-sha256": "hmac",
};
function value<T>(r: Result<T>): T {
  if (!r.ok) throw r.error;
  return r.value;
}
export function mapped(value: any): any {
  if (Array.isArray(value)) return value.map(mapped);
  if (
    value === null ||
    typeof value !== "object" ||
    value instanceof Uint8Array
  )
    return value;
  const names: Record<string, string> = {
    max_lifetime: "maxLifetime",
    test_keys: "testKeys",
    signature_input: "signatureInput",
    shared_principal: "sharedPrincipal",
    accept_signature: "acceptSignature",
    expires_in: "expiresIn",
    field_schemas: "fieldSchemas",
    key_resolver: "keyResolver",
    max_age: "maxAge",
    require_expires: "requireExpires",
    extra_components: "extraComponents",
    max_signatures: "maxSignatures",
    digest_state: "digestState",
    signing_timeout: "signingTimeout",
    timeout: "timeoutMs",
    raw_target: "rawTarget",
    target_form: "targetForm",
    related_request: "relatedRequest",
  };
  return Object.fromEntries(
    Object.entries(value).map(([k, v]) => [names[k] ?? k, mapped(v)]),
  );
}
export function built(m: CorpusCase, r: CorpusResources): Result<Message> {
  const base = resolve(m.inputs.message, r);
  const input = message(base, r);
  if (!input.ok) return err(coreError("invalid_message", "input"));
  const fields = [
    ...input.value.fields,
    ...((m.inputs.append_fields ?? []) as any[]).map((pair) =>
      value(
        FieldOccurrence.create({
          name: pair[0],
          value: decoded(pair[1], r),
          section: "headers",
        }),
      ),
    ),
  ];
  const overrides = mapped(decoded(m.inputs.message_override ?? {}, r));
  const result = Message.create({ ...input.value, fields, ...overrides });
  return result.ok ? result : err(coreError("invalid_message", "input"));
}
async function key(
  m: CorpusCase,
  r: CorpusResources,
  algorithm: any,
  privateKey: boolean,
): Promise<Result<PublicKey | KeyHandle>> {
  const reference = m.keys?.find((k) => k.name === algorithm),
    name = names[algorithm];
  const path = reference
    ? privateKey
      ? reference.file
      : (reference.public ?? reference.file)
    : name
      ? `sources/rfc9421/keys/${name}${name === "hmac" ? ".txt" : privateKey ? "_private.pem" : "_public.pem"}`
      : undefined;
  if (typeof path !== "string") throw new Error("Invalid key reference");
  const raw = value(r.read(path));
  if (algorithm === "hmac-sha256")
    return Custody.local(algorithm, {
      hmac: value(decodeBase64(new TextDecoder().decode(raw).trim())),
    });
  return privateKey
    ? Custody.local(algorithm, new TextDecoder().decode(raw))
    : PublicKey.import(new TextDecoder().decode(raw), "pem");
}
export const signSurface: Surface = async (m, r) => {
  let handle: KeyHandle | undefined;
  let verificationHandle: KeyHandle | undefined;
  try {
    if (
      !Object.keys(m.inputs).every((k) =>
        [
          "message",
          "message_override",
          "append_fields",
          "spec",
          "key",
          "signer",
          "options",
        ].includes(k),
      )
    )
      return invalid();
    const input = built(m, r);
    if (!input.ok) return input;
    const s = mapped(decoded(m.inputs.spec, r)),
      k = await key(m, r, m.inputs.key, true);
    if (!k.ok) return k;
    handle = k.value as KeyHandle;
    const opts = mapped(decoded(m.inputs.options ?? {}, r));
    if (Object.hasOwn(opts, "clock")) {
      const now = opts.clock;
      opts.clock = () => now;
    } else if (m.now !== undefined) {
      const now = decoded(m.now, r);
      opts.clock = () => now;
    }
    if (m.nonce !== undefined) opts.nonce = decoded(m.nonce, r);
    const signer =
      m.inputs.signer === "raise"
        ? (_algorithm: unknown, _base: unknown) => {
            throw new Error("Signer fault");
          }
        : Object.hasOwn(s, "components")
          ? handle
          : (
              algorithm: SigningAlgorithm,
              base: Uint8Array,
              ...[context]: [Context]
            ) => handle!.sign(algorithm, base, context);
    const signed = await sign(input.value, s, signer, opts);
    if (!signed.ok) return signed;
    if (m.class === "verify_only") {
      const publicKey = await key(m, r, m.inputs.key, false);
      if (!publicKey.ok) return publicKey;
      if (m.inputs.key === "hmac-sha256")
        verificationHandle = publicKey.value as KeyHandle;
      const p = Policy.create({
        algorithms: [s.algorithm],
        components: "()",
        keyResolver: async () =>
          ok({ algorithm: s.algorithm, key: publicKey.value }),
        freshness: "not_evaluated",
        content: "not_required",
        replay: "not_required",
      });
      if (!p.ok) return p;
      const checked = await verify(signed.value, p.value, { label: s.label });
      return checked.ok ? ok({ valid: true }) : checked;
    }
    return ok({
      fields: signed.value.fields
        .slice(input.value.fields.length)
        .map((f) => [f.name, f.value] as const),
    });
  } catch (e) {
    return isRequestSealError(e) ? err(e) : invalid();
  } finally {
    if (verificationHandle) await verificationHandle.release();
    if (handle) await handle.release();
  }
};
export async function manifestPolicy(
  m: CorpusCase,
  r: CorpusResources,
  handles: KeyHandle[],
): Promise<Result<import("../../src/policy.ts").Policy>> {
  const p = mapped(decoded(m.policy, r));
  if (!p || typeof p !== "object")
    return err(coreError("invalid_policy", "input"));
  const resolver = p.keyResolver;
  if (resolver?.behavior === "raise")
    p.keyResolver = async () =>
      ok({
        algorithm: "ed25519",
        verify: () => {
          throw new Error("Verifier fault");
        },
      });
  else {
    const imported = await key(m, r, resolver?.key, false);
    if (!imported.ok) return imported;
    if (resolver.key === "hmac-sha256")
      handles.push(imported.value as KeyHandle);
    p.keyResolver = async () =>
      ok({ algorithm: resolver.key, key: imported.value });
  }
  if (typeof p.freshness === "object" && p.freshness) {
    const now = decoded(m.now, r);
    p.freshness.clock = () => now;
  }
  if (typeof p.replay === "object" && p.replay) {
    if (p.replay.commitment !== "identifier" || p.replay.store !== "ets")
      throw new Error("Invalid manifest");
    p.replay.commitment = async (facts: { identifier: string }) =>
      ok(new TextEncoder().encode(facts.identifier));
    p.replay.store = value(createMemoryStore({maxEntries: 64}));
  }

  return Policy.create(p);
}
export const verifySurface: Surface = async (m, r) => {
  const handles: KeyHandle[] = [];
  try {
    if (
      !Object.keys(m.inputs).every((k) =>
        [
          "message",
          "message_override",
          "append_fields",
          "label",
          "options",
        ].includes(k),
      )
    )
      return invalid();
    const input = built(m, r);
    const policy = await manifestPolicy(m, r, handles);
    const opts = {
      label: m.inputs.label,
      ...mapped(decoded(m.inputs.options ?? {}, r)),
    };
    if (!policy.ok) return policy;
    if (!input.ok) return input;
    const checked = await verify(input.value, policy.value, opts);
    if (!checked.ok) return checked;
    const serialized = serializeVerification(checked.value);
    return serialized.ok
      ? ok({
          verification: JSON.parse(new TextDecoder().decode(serialized.value)),
        })
      : serialized;
  } catch (e) {
    return isRequestSealError(e) ? err(e) : invalid();
  } finally {
    for (const handle of handles) await handle.release();
  }
};
export const digestSurface: Surface = async (m, r) => {
  try {
    if (
      !Object.keys(m.inputs).every((k) =>
        ["content", "algorithms", "kind", "field", "max_bytes"].includes(k),
      )
    )
      return invalid();
    const i = decoded(m.inputs, r),
      field = i.field ?? i.kind ?? "content-digest";
    if (
      !["content-digest", "repr-digest", "content", "representation"].includes(
        field,
      )
    )
      return err(
        (await import("../../src/errors/types.ts")).digestError("invalid_kind"),
      );
    const result = await digest(
      i.content,
      i.algorithms,
      Object.hasOwn(i, "max_bytes") ? { maxBytes: i.max_bytes } : {},
    );
    return result.ok ? ok({ bytes: result.value }) : result;
  } catch (e) {
    return isRequestSealError(e) ? err(e) : invalid();
  }
};
