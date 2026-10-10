import { parseBody } from "../../src/discovery/body.ts";
import {
  Discovery,
  DiscoverySource,
  decodeBase64Url,
  ok,
} from "../../src/index.ts";
import type { Surface, SurfaceResult } from "./loader.ts";
function record(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}
const invalid = (): SurfaceResult => ({
  ok: false,
  loaderReason: "invalid_manifest",
});
export const discoveryBody: Surface = async (m, r) => {
  try {
    const i = m.inputs;
    if (
      !Object.keys(i).every((k) =>
        ["body", "kind", "limits", "location"].includes(k),
      ) ||
      !["jwks", "directory", "cimd"].includes(i.kind as string) ||
      !record(i.limits) ||
      typeof i.location !== "string"
    )
      return invalid();
    if (
      !record(m.now) ||
      Object.keys(m.now).join(",") !== "int" ||
      typeof m.now.int !== "string" ||
      !/^-?(0|[1-9][0-9]*)$/.test(m.now.int)
    )
      return invalid();
    const now = Number(m.now.int);
    if (!Number.isSafeInteger(now)) return invalid();
    let body: Uint8Array;
    if (record(i.body) && Object.keys(i.body).join(",") === "b64") {
      const decoded = decodeBase64Url(i.body.b64);
      if (!decoded.ok) return invalid();
      body = decoded.value;
    } else if (
      record(i.body) &&
      Object.keys(i.body).join(",") === "file" &&
      typeof i.body.file === "string"
    ) {
      const bytes = r.read(i.body.file);
      if (!bytes.ok) return invalid();
      body = bytes.value;
    } else if (record(i.body) && Object.keys(i.body).join(",") === "ref") {
      const ref = r.reference(i.body);
      if (!ref.ok || typeof ref.value !== "string") return invalid();
      body = new TextEncoder().encode(ref.value);
    } else return invalid();
    const mapping: Record<string, string> = {
      max_bytes: "maxBytes",
      max_decoded_bytes: "maxDecodedBytes",
      max_keys: "maxKeys",
    };
    const limits: Record<string, number> = Object.create(null);
    for (const [key, n] of Object.entries(i.limits)) {
      if (
        !Object.hasOwn(mapping, key) ||
        !record(n) ||
        Object.keys(n).join(",") !== "int" ||
        typeof n.int !== "string" ||
        !/^-?(0|[1-9][0-9]*)$/.test(n.int)
      )
        return invalid();
      const value = Number(n.int);
      if (!Number.isSafeInteger(value)) return invalid();
      limits[mapping[key]!] = value;
    }
    const source = DiscoverySource.create({
      type: i.kind === "jwks" ? "jwks_uri" : i.kind,
      location: i.location,
      requireSignedDirectory: false,
      limits,
    });
    if (!source.ok) return source;
    if (i.kind === "cimd") {
      const set = await Discovery.resolver.fromSnapshot(
        source.value,
        body,
        now,
        [["content-type", "application/json"]],
      );
      return set.ok
        ? ok({
            facts: {
              keys: Object.values(set.value.keys)
                .map((k) => k.thumbprint)
                .sort(),
            },
          })
        : set;
    }
    const parsed = await parseBody(body, source.value, now);
    return parsed.ok
      ? ok({
          facts: {
            keys: Object.values(parsed.value)
              .map((k) => k.thumbprint)
              .sort(),
          },
        })
      : parsed;
  } catch {
    return invalid();
  }
};
