import {
  FieldOccurrence,
  type FieldOccurrence as Field,
} from "../message/index.ts";
import { ensure, unwrap, list } from "./support.ts";
import type { DiscoverySource } from "./source.ts";
/** Ordered discovery response header names and string or byte values. */
export type Headers = readonly (readonly [string, string | Uint8Array])[];
export function fields(headers: unknown): readonly Field[] {
  let total = 0;
  return Object.freeze(
    Array.from(list(headers, 16384, 0, "invalid_response"), (p) => {
      ensure(Array.isArray(p) && p.length === 2, "invalid_response");
      const name = p[0],
        value = p[1];
      const f = unwrap(
        FieldOccurrence.create({
          name,
          value,
          section: "headers",
          provenance: "http1",
        }),
        "invalid_response",
      );
      total += f.name.length + f.value.length + 4;
      ensure(total <= 16384, "limit");
      return f;
    }),
  );
}
export function values(fs: readonly Field[], name: string): string[] {
  return fs
    .filter((f) => f.name.toLowerCase() === name)
    .map((f) => String.fromCharCode(...f.value).trim());
}
export function header(fs: readonly Field[], name: string): string | null {
  const all = values(fs, name);
  ensure(all.length <= 1, "invalid_response");
  return all[0] ?? null;
}
export function httpDate(input: string | null, now: number): number | null {
  if (input === null) return null;
  let parts =
    /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), ([0-9]{2}) ([A-Z][a-z]{2}) ([0-9]{4}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) GMT$/
      .exec(input)
      ?.slice(1);
  if (!parts) {
    parts =
      /^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), ([0-9]{2})-([A-Z][a-z]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) GMT$/
        .exec(input)
        ?.slice(1);
    if (parts) {
      const current = new Date(now * 1000).getUTCFullYear();
      let year = Math.floor(current / 100) * 100 + Number(parts[2]);
      if (year > current + 50) year -= 100;
      parts[2] = String(year);
    } else {
      const p =
        /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) ([A-Z][a-z]{2}) ( [0-9]|[0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) ([0-9]{4})$/.exec(
          input,
        );
      if (p) parts = [p[2]!.trim(), p[1]!, p[6]!, p[3]!, p[4]!, p[5]!];
    }
  }
  if (!parts) return null;
  const [day, month, year, hour, minute, second] = parts;
  const m = [
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
  ].indexOf(month!);
  const d = Number(day),
    y = Number(year),
    h = Number(hour),
    min = Number(minute),
    s = Number(second);
  if (m < 0 || d < 1 || d > 31 || h > 23 || min > 59 || s > 59) return null;
  const date = new Date(0);
  date.setUTCFullYear(y, m, d);
  date.setUTCHours(h, min, s, 0);
  return date.getUTCFullYear() === y &&
    date.getUTCMonth() === m &&
    date.getUTCDate() === d
    ? date.getTime() / 1000
    : null;
}
export function expiry(
  fs: readonly Field[],
  source: DiscoverySource,
  now: number,
): number {
  const controls = values(fs, "cache-control")
    .join(",")
    .toLowerCase()
    .split(",")
    .map((v) => v.trim());
  return expiryFromControls(fs, source, now, controls);
}
/** RFC 9111 Section 4.3.4: whether a response carries freshness directives of its own. */
export function hasFreshness(fs: readonly Field[]): boolean {
  if (header(fs, "expires") !== null) return true;
  const controls = values(fs, "cache-control")
    .join(",")
    .toLowerCase()
    .split(",")
    .map((v) => v.trim());
  // Only freshness-changing names count: max-age, no-cache, no-store. A
  // directive like `public` leaves the stored lifetime in force.
  return controls.some((v) => {
    const name = v.split("=", 1)[0]!.trim();
    return name === "no-store" || name === "no-cache" || name === "max-age";
  });
}
function expiryFromControls(
  fs: readonly Field[],
  source: DiscoverySource,
  now: number,
  controls: readonly string[],
): number {
  const ages = controls
    .filter((v) => v.startsWith("max-age="))
    .map((v) => v.slice(8).replace(/^"+|"+$/g, ""));
  ensure(ages.length <= 1, "invalid_response");
  const date = httpDate(header(fs, "date"), now) ?? now;
  let ttl = source.minTtl;
  if (ages.length) {
    ensure(/^[0-9]{1,10}$/.test(ages[0]!), "invalid_response");
    ttl = Number(ages[0]);
  } else {
    const expires = header(fs, "expires");
    if (expires !== null)
      ttl = Math.max((httpDate(expires, now) ?? date) - date, 0);
  }
  const age = header(fs, "age") ?? "0";
  ensure(/^[0-9]{1,10}$/.test(age), "invalid_response");
  // RFC 9111 Sections 5.2.2.3 and 5.2.2.4: no-store and no-cache also arrive
  // qualified, as in no-cache="content-type" (and the RFC 7234 quoted form whose
  // member can itself contain commas). Match the directive name before any "=",
  // so every spelling still forces revalidation.
  return (
    now +
    (controls.some((v) => {
      const name = v.split("=", 1)[0]!.trim();
      return name === "no-store" || name === "no-cache";
    })
      ? 0
      : Math.max(
          Math.min(ttl, source.maxTtl) - Math.max(Number(age), now - date, 0),
          0,
        ))
  );
}
export function mediaType(
  fs: readonly Field[],
  type: DiscoverySource["type"],
): void {
  const media = header(fs, "content-type");
  ensure(media !== null, "unexpected_media_type");
  const allowed =
    type === "directory"
      ? ["application/http-message-signatures-directory+json"]
      : type === "cimd"
        ? ["application/json"]
        : ["application/json", "application/jwk-set+json"];
  ensure(
    allowed.includes(media.split(";")[0]!.trim().toLowerCase()),
    "unexpected_media_type",
  );
}
