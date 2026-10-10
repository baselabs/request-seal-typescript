import { built, mapped, manifestPolicy } from "./sign-surfaces.ts";
import { decoded } from "./wire.ts";
import {
  Quorum,
  verifyQuorum,
  AcceptSignature,
  serializeVerification,
  ok,
  err,
  type KeyHandle,
} from "../../src/index.ts";
import { isRequestSealError } from "../../src/errors/types.ts";
import type { Surface } from "./loader.ts";
export const quorumSurface: Surface = async (m, r) => {
  const handles: KeyHandle[] = [];
  try {
    if (
      !Object.keys(m.inputs).every((k) =>
        [
          "message",
          "message_override",
          "append_fields",
          "label",
          "quorum",
          "options",
        ].includes(k),
      )
    )
      return { ok: false, loaderReason: "invalid_manifest" };
    const policy = await manifestPolicy(m, r, handles);
    if (!policy.ok) return policy;
    // The released manifests describe a single named required signer plus mode.
    // Expanded manifests supply explicit slots whose policies use the same decoder.
    const attrs = mapped(decoded(m.inputs.quorum, r));
    if (Array.isArray(attrs.slots))
      for (const slot of attrs.slots) {
        const p = await manifestPolicy(
          { ...m, policy: slot.policy },
          r,
          handles,
        );
        if (!p.ok) return p;
        slot.policy = p.value;
      }
    const q = Quorum.create({
      unit: "principals",
      slots: [
        {
          id: "signer",
          principal: "published",
          label: m.inputs.label,
          policy: policy.value,
          required: true,
        },
      ],
      unexpected: "reject",
      invalid: "reject",
      ...attrs,
    });
    if (!q.ok) return q;
    const input = built(m, r);
    if (!input.ok) return input;
    const opts = mapped(decoded(m.inputs.options ?? {}, r));
    if (Object.hasOwn(opts, "acceptSignature")) {
      const requests = AcceptSignature.parse(opts.acceptSignature, {
        target: input.value.kind,
      });
      if (!requests.ok) return requests;
      opts.acceptSignature = requests.value;
    }
    const result = await verifyQuorum(input.value, q.value, opts);
    if (!result.ok) return result;
    const serialized = serializeVerification(result.value);
    return serialized.ok
      ? ok({
          valid: true,
          verification: JSON.parse(new TextDecoder().decode(serialized.value)),
        })
      : serialized;
  } catch (e) {
    return isRequestSealError(e)
      ? err(e)
      : { ok: false, loaderReason: "invalid_manifest" };
  } finally {
    for (const handle of handles) await handle.release();
  }
};
export const acceptSignatureSurface: Surface = (m, r) => {
  try {
    if (!Object.keys(m.inputs).every((k) => ["raw", "target"].includes(k)))
      return { ok: false, loaderReason: "invalid_manifest" };
    const requests = AcceptSignature.parse(decoded(m.inputs.raw, r), {
      target: m.inputs.target ?? "request",
    });
    if (!requests.ok) return requests;
    const bytes = AcceptSignature.serialize(requests.value);
    return bytes.ok ? ok({ bytes: bytes.value }) : bytes;
  } catch (e) {
    return isRequestSealError(e)
      ? err(e)
      : { ok: false, loaderReason: "invalid_manifest" };
  }
};
