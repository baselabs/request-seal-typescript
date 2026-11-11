import { decoded } from "./wire.ts";
import { AcceptSignature, ok, err } from "../../src/index.ts";
import { isRequestSealError } from "../../src/errors/types.ts";
import type { Surface } from "./loader.ts";
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
