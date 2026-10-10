import { Discovery } from "../../src/index.ts";
export function snapshotWithMedia(config: unknown, bytes: unknown, now: unknown, headers: unknown = []) {
  const type = config && typeof config === "object" && "type" in config ? config.type : "jwks_uri";
  const media = type === "directory" ? "application/http-message-signatures-directory+json" : "application/json";
  // Preserve hostile collection probes intact; only ordinary test headers gain media.
  const complete = Array.isArray(headers) && !Object.hasOwn(headers, Symbol.iterator) && !headers.some(p => Array.isArray(p) && String(p[0]).toLowerCase() === "content-type")
    ? [["content-type", media], ...headers] : headers;
  return Discovery.resolver.fromSnapshot(config, bytes, now, complete);
}
