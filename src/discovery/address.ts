import { ok, type Result } from "../result.ts";
import { ensure, failure } from "./support.ts";
// Pinned RequestSeal v0.4.0 Discovery.Address conservative IANA policy.
// https://www.iana.org/assignments/iana-ipv4-special-registry/
// https://www.iana.org/assignments/iana-ipv6-special-registry/
const v4 = [
  [0x00000000n, 8], // 0.0.0.0/8; https://www.rfc-editor.org/rfc/rfc791.html
  [0x0a000000n, 8], // 10.0.0.0/8; https://www.rfc-editor.org/rfc/rfc1918.html
  [0x64400000n, 10], // 100.64.0.0/10; https://www.rfc-editor.org/rfc/rfc6598.html
  [0x7f000000n, 8], // 127.0.0.0/8; https://www.rfc-editor.org/rfc/rfc1122.html
  [0xa9fe0000n, 16], // 169.254.0.0/16; https://www.rfc-editor.org/rfc/rfc3927.html
  [0xac100000n, 12], // 172.16.0.0/12; https://www.rfc-editor.org/rfc/rfc1918.html
  [0xc0000000n, 24], // 192.0.0.0/24; https://www.rfc-editor.org/rfc/rfc6890.html
  [0xc0000200n, 24], // 192.0.2.0/24; https://www.rfc-editor.org/rfc/rfc5737.html
  [0xc01fc400n, 24], // 192.31.196.0/24; https://www.rfc-editor.org/rfc/rfc7535.html
  [0xc034c100n, 24], // 192.52.193.0/24; https://www.rfc-editor.org/rfc/rfc7450.html
  [0xc0586300n, 24], // 192.88.99.0/24; https://www.rfc-editor.org/rfc/rfc7526.html
  [0xc0a80000n, 16], // 192.168.0.0/16; https://www.rfc-editor.org/rfc/rfc1918.html
  [0xc0af3000n, 24], // 192.175.48.0/24; https://www.rfc-editor.org/rfc/rfc7534.html
  [0xc6120000n, 15], // 198.18.0.0/15; https://www.rfc-editor.org/rfc/rfc2544.html
  [0xc6336400n, 24], // 198.51.100.0/24; https://www.rfc-editor.org/rfc/rfc5737.html
  [0xcb007100n, 24], // 203.0.113.0/24; https://www.rfc-editor.org/rfc/rfc5737.html
  [0xe0000000n, 4], // 224.0.0.0/4; https://www.rfc-editor.org/rfc/rfc5771.html#section-3
  [0xf0000000n, 4], // 240.0.0.0/4; https://www.rfc-editor.org/rfc/rfc1112.html
] as const;
const v6 = [
  [0x20010000000000000000000000000000n, 23],
  [0x20010db8000000000000000000000000n, 32],
  [0x2620004f800000000000000000000000n, 48],
  [0x3fff0000000000000000000000000000n, 20],
] as const;
type Address = { family: 4 | 6; number: bigint; canonical: string };
export function parseAddress(input: unknown): Address | undefined {
  if (typeof input !== "string" || input.length > 45 || input.includes("%"))
    return;
  if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(input)) {
    const parts = input.split(".");
    if (parts.some((s) => !/^(0|[1-9][0-9]*)$/.test(s) || Number(s) > 255))
      return;
    return {
      family: 4,
      number: parts.reduce((a, p) => a * 256n + BigInt(p), 0n),
      canonical: input,
    };
  }
  if (!input.includes(":") || !/^[0-9A-Fa-f:.]+$/.test(input)) return;
  try {
    const canonical = new URL(`https://[${input}]/`).hostname.slice(1, -1);
    const halves = canonical.split("::");
    if (halves.length > 2) return;
    const left = halves[0] ? halves[0].split(":") : [],
      right = halves[1] ? halves[1].split(":") : [];
    const parts =
      halves.length === 2
        ? [
            ...left,
            ...Array<string>(8 - left.length - right.length).fill("0"),
            ...right,
          ]
        : left;
    if (parts.length !== 8) return;
    return {
      family: 6,
      number: parts.reduce((a, p) => a * 65536n + BigInt("0x" + p), 0n),
      canonical,
    };
  } catch {
    return;
  }
}
const prefix = (n: bigint, b: bigint, bits: number, width: number) =>
  n >> BigInt(width - bits) === b >> BigInt(width - bits);
function publicV4(n: bigint): boolean {
  return !v4.some(([b, bits]) => prefix(n, b, bits, 32));
}
export function addressAllowed(
  input: unknown,
  permitted: readonly string[] = [],
): Result<boolean> {
  try {
    const a = parseAddress(input);
    ensure(a, "invalid_source");
    ensure(
      Array.isArray(permitted) &&
        permitted.length <= 16 &&
        permitted.every((ip) => parseAddress(ip)),
      "invalid_source",
    );
    if (
      permitted.some((ip) => {
        const p = parseAddress(ip)!;
        return p.family === a.family && p.number === a.number;
      })
    )
      return ok(true);
    if (a.family === 4) return ok(publicV4(a.number));
    if (
      a.number >> 32n === 0xffffn ||
      a.number >> 32n === 0x64ff9b0000000000000000n
    )
      return ok(publicV4(a.number & 0xffffffffn));
    if (a.number >> 112n === 0x2002n)
      return ok(publicV4((a.number >> 80n) & 0xffffffffn));
    return ok(
      prefix(a.number, 0x20000000000000000000000000000000n, 3, 128) &&
        !v6.some(([b, bits]) => prefix(a.number, b, bits, 128)),
    );
  } catch (e) {
    return failure(e, "invalid_source");
  }
}
export function sameAddress(a: unknown, b: unknown): boolean {
  const x = parseAddress(a),
    y = parseAddress(b);
  return !!x && !!y && x.family === y.family && x.number === y.number;
}
