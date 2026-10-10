import { ok, type Result } from "../result.ts";
import { decodeBase64Url, encodeBase64Url } from "../bytes.ts";
import { certificate } from "./certificate.ts";
import { parseAddress } from "./address.ts";
import { ensure, failure, options, inspectable, list } from "./support.ts";
export type SourceType = "directory" | "jwks_uri" | "cimd";
export type DiscoverySource = Readonly<{
  type: SourceType;
  location: string;
  keyId: "thumbprint" | "directory";
  cacerts: "os" | readonly Uint8Array[];
  permittedAddresses: readonly string[];
  revoked: readonly string[];
  requireSignedDirectory: boolean;
  maxRedirects: number;
  redirectScope: "same_origin" | "any_https";
  maxBytes: number;
  maxDecodedBytes: number;
  maxKeys: number;
  timeoutMs: number;
  minTtl: number;
  maxTtl: number;
  negativeTtl: number;
}>;
const sources = new WeakMap<object, string>();
const directoryPath = "/.well-known/http-message-signatures-directory";
const limits = Object.freeze({
  maxRedirects: 0,
  maxBytes: 65536,
  maxDecodedBytes: 65536,
  maxKeys: 32,
  timeoutMs: 5000,
  minTtl: 300,
  maxTtl: 86400,
  negativeTtl: 30,
});
export function isDiscoverySource(s: unknown): s is DiscoverySource {
  return !!s && typeof s === "object" && sources.has(s);
}
export function sourceIdentity(s: DiscoverySource): string {
  return sources.get(s)!;
}
export function thumbprintId(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== 43) return false;
  const b = decodeBase64Url(value);
  return b.ok && b.value.length === 32 && encodeBase64Url(b.value) === value;
}
function validDirectoryId(v: unknown): v is string {
  return (
    typeof v === "string" &&
    v.length >= 1 &&
    v.length <= 256 &&
    /^[\x20-\x7e]+$/.test(v)
  );
}
export function directoryId(value: unknown): Result<boolean> {
  return ok(validDirectoryId(value));
}
export function keyIdValid(s: DiscoverySource, v: unknown): v is string {
  return s.keyId === "thumbprint" ? thumbprintId(v) : validDirectoryId(v);
}
/** Validate raw spelling before WHATWG normalization can erase a dot segment. */
export function sourceUrl(location: unknown): URL {
  ensure(
    typeof location === "string" &&
      location.length >= 1 &&
      location.length <= 2048 &&
      /^[\x21-\x7e]+$/.test(location),
    "invalid_source",
  );
  ensure(
    !location.includes("\\") &&
      !location.includes("#") &&
      !/%(?![a-fA-F0-9]{2})/.test(location),
    "invalid_source",
  );
  const raw = /^https:\/\/([^/?#]+)([^?#]*)(?:\?[^#]*)?$/i.exec(location);
  ensure(raw, "invalid_source");
  ensure(
    /^(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?$/.test(raw[1]!),
    "invalid_source",
  );
  const path = raw[2]!;
  for (const segment of path.split("/"))
    ensure(
      ![".", ".."].includes(decodeURIComponent(segment)),
      "invalid_source",
    );
  ensure(!/[\r\n\\]/.test(decodeURIComponent(path)), "invalid_source");
  const u = new URL(location);
  ensure(
    u.protocol === "https:" &&
      u.hostname &&
      !u.username &&
      !u.password &&
      Number(u.port || 443) >= 1 &&
      Number(u.port || 443) <= 65535,
    "invalid_source",
  );
  return u;
}
export function normalizedHost(url: URL): string {
  return url.hostname
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "")
    .toLowerCase();
}
export function sourceOrigin(url: URL): string {
  const host = normalizedHost(url);
  return (
    "https://" +
    (host.includes(":") ? "[" + host + "]" : host) +
    (url.port ? ":" + url.port : "")
  );
}
export function sourceAuthority(url: URL): string {
  return sourceOrigin(url).slice(8);
}
export function createSource(input: unknown): Result<DiscoverySource> {
  try {
    if (isDiscoverySource(input)) return ok(input);
    const a = options(
      input,
      [
        "type",
        "location",
        "keyId",
        "cacerts",
        "permittedAddresses",
        "revoked",
        "requireSignedDirectory",
        "redirectScope",
        "limits",
        ...Object.keys(limits),
      ] as const,
      "invalid_source",
    );
    ensure(
      a.type === "directory" || a.type === "jwks_uri" || a.type === "cimd",
      "invalid_source",
    );
    const url = sourceUrl(a.location);
    const rawPath = /^https:\/\/[^/?]+([^?]*)/i.exec(a.location as string)![1]!;
    ensure(a.type !== "cimd" || rawPath.length > 0, "invalid_source");
    let location = a.location as string;
    if (a.type === "directory" && ["", "/"].includes(rawPath))
      location = sourceOrigin(url) + directoryPath;
    ensure(
      a.type !== "directory" ||
        (!(a.location as string).includes("?") &&
          url.search === "" &&
          !location.includes("?") &&
          sourceUrl(location).pathname === directoryPath),
      "invalid_source",
    );
    const keyId = Object.hasOwn(a, "keyId") ? a.keyId : "thumbprint";
    ensure(keyId === "thumbprint" || keyId === "directory", "invalid_source");
    ensure(a.type !== "directory" || keyId === "thumbprint", "invalid_source");
    const signed = Object.hasOwn(a, "requireSignedDirectory")
      ? a.requireSignedDirectory
      : true;
    ensure(typeof signed === "boolean", "invalid_source");
    const numeric = Object.assign(Object.create(null), limits) as Record<
      keyof typeof limits,
      number
    >;
    const nested = Object.hasOwn(a, "limits")
      ? options(
          a.limits,
          Object.keys(limits) as (keyof typeof limits)[],
          "invalid_source",
        )
      : {};
    for (const key of Object.keys(limits) as (keyof typeof limits)[]) {
      ensure(
        !(Object.hasOwn(nested, key) && Object.hasOwn(a, key)),
        "invalid_source",
      );
      const v = Object.hasOwn(a, key)
        ? a[key]
        : Object.hasOwn(nested, key)
          ? nested[key]
          : limits[key];
      const lo = ["maxRedirects", "minTtl", "maxTtl", "negativeTtl"].includes(
        key,
      )
        ? 0
        : 1;
      const hi =
        key === "maxRedirects"
          ? 3
          : key === "maxKeys"
            ? 256
            : key === "timeoutMs"
              ? 300000
              : key === "negativeTtl"
                ? 300
                : ["minTtl", "maxTtl"].includes(key)
                  ? 604800
                  : 1048576;
      ensure(
        Number.isSafeInteger(v) && (v as number) >= lo && (v as number) <= hi,
        key === "negativeTtl" ? "invalid_options" : "invalid_source",
      );
      numeric[key] = v as number;
    }
    ensure(numeric.minTtl <= numeric.maxTtl, "invalid_source");
    const scope = Object.hasOwn(a, "redirectScope")
      ? a.redirectScope
      : "same_origin";
    ensure(scope === "same_origin" || scope === "any_https", "invalid_source");
    const addresses = Object.hasOwn(a, "permittedAddresses")
      ? a.permittedAddresses
      : [];
    const permittedAddresses = Object.freeze(
      Array.from(list(addresses, 16, 0, "invalid_source"), (ip) => {
        const p = parseAddress(ip);
        ensure(p, "invalid_source");
        return p.canonical;
      }),
    );
    const revocations = Object.hasOwn(a, "revoked") ? a.revoked : [];
    const revoked = Object.freeze(
      Array.from(list(revocations, 256, 0, "invalid_source"), (v) => {
        ensure(thumbprintId(v), "invalid_source");
        return v;
      }),
    );
    const roots = Object.hasOwn(a, "cacerts") ? a.cacerts : "os";
    let ca: "os" | readonly Uint8Array[] = "os";
    if (roots !== "os") {
      ca = Object.freeze(
        Array.from(list(roots, 256, 1, "invalid_source"), certificate),
      );
    }
    const data = {
      type: a.type,
      location,
      keyId,
      permittedAddresses,
      revoked,
      requireSignedDirectory: signed,
      redirectScope: scope,
      ...numeric,
    };
    const identity = JSON.stringify({
      ...data,
      cacerts: ca === "os" ? "os" : ca.map(encodeBase64Url),
    });
    const out = Object.assign(Object.create(null), data) as DiscoverySource;
    Object.defineProperty(out, "cacerts", {
      enumerable: true,
      get: () =>
        ca === "os"
          ? "os"
          : Object.freeze(ca.map((der) => new Uint8Array(der))),
    });
    sources.set(out, identity);
    return ok(inspectable(out, { kind: "DiscoverySource", type: a.type }));
  } catch (e) {
    return failure(e, "invalid_source");
  }
}
export const DiscoverySource = Object.freeze({
  create: createSource,
  directoryId,
});
