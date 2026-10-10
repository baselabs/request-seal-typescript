import { ensure } from "./support.ts";
import { remainingMs, type Context } from "../context.ts";

// RFC 1951 Sections 3.2.5–3.2.7. This walks framing and counts output; the
// runtime remains the inflater. https://www.rfc-editor.org/rfc/rfc1951
type Tree = { codes: Map<number, number>; max: number };
function tree(lengths: readonly number[]): Tree {
  const counts = Array<number>(16).fill(0),
    next = Array<number>(16).fill(0);
  for (const length of lengths) {
    ensure(length >= 0 && length <= 15, "invalid_response");
    if (length) counts[length] = counts[length]! + 1;
  }
  let code = 0;
  for (let bits = 1; bits <= 15; bits++) {
    code = (code + counts[bits - 1]!) * 2;
    next[bits] = code;
    ensure(code + counts[bits]! <= 2 ** bits, "invalid_response");
  }
  const codes = new Map<number, number>();
  let max = 0;
  for (let symbol = 0; symbol < lengths.length; symbol++) {
    const bits = lengths[symbol]!;
    if (!bits) continue;
    let value = next[bits]!,
      reversed = 0;
    next[bits] = value + 1;
    for (let i = 0; i < bits; i++) {
      reversed = reversed * 2 + (value & 1);
      value >>= 1;
    }
    codes.set(2 ** bits + reversed, symbol);
    max = Math.max(max, bits);
  }
  return { codes, max };
}
const fixedLiterals = tree(
  Array.from({ length: 288 }, (_, i) =>
    i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8,
  ),
);
const fixedDistances = tree(Array<number>(32).fill(5));
const order = [
  16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
] as const;
const lengthBase = [
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67,
  83, 99, 115, 131, 163, 195, 227, 258,
] as const;
const lengthExtra = [
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5,
  5, 5, 0,
] as const;
const distanceBase = [
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
  1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
] as const;
const distanceExtra = [
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11,
  11, 12, 12, 13, 13,
] as const;

/** Require the final block to end at the gzip trailer, including byte padding.
 * Count output without allocating it, reject impossible backward distances,
 * and bound both expansion and work by the caller's byte cap and Context. */
export function deflateSize(
  bytes: Uint8Array,
  start: number,
  end: number,
  cap: number,
  context?: Context,
): number {
  let bit = start * 8,
    size = 0,
    steps = 0;
  const deadline = () =>
    ensure(!context || remainingMs(context) > 0, "deadline_exceeded");
  function read(n: number): number {
    ensure(bit + n <= end * 8, "invalid_response");
    let value = 0;
    for (let i = 0; i < n; i++, bit++)
      value |= ((bytes[bit >>> 3]! >>> (bit & 7)) & 1) << i;
    return value;
  }
  function symbol(t: Tree): number {
    let code = 0;
    for (let n = 1; n <= t.max; n++) {
      code |= read(1) << (n - 1);
      const value = t.codes.get(2 ** n + code);
      if (value !== undefined) return value;
    }
    ensure(false, "invalid_response");
  }
  function dynamic(): [Tree, Tree] {
    const literals = read(5) + 257,
      distances = read(5) + 1,
      count = read(4) + 4;
    ensure(literals <= 286 && distances <= 30, "invalid_response");
    const codes = Array<number>(19).fill(0);
    for (let i = 0; i < count; i++) codes[order[i]!] = read(3);
    const codeTree = tree(codes),
      lengths: number[] = [];
    while (lengths.length < literals + distances) {
      const s = symbol(codeTree);
      if (s < 16) lengths.push(s);
      else {
        ensure(s <= 18 && (s !== 16 || lengths.length > 0), "invalid_response");
        const repeat =
          s === 16 ? read(2) + 3 : s === 17 ? read(3) + 3 : read(7) + 11;
        const value = s === 16 ? lengths.at(-1)! : 0;
        ensure(
          lengths.length + repeat <= literals + distances,
          "invalid_response",
        );
        for (let i = 0; i < repeat; i++) lengths.push(value);
      }
    }
    ensure(lengths[256] !== 0, "invalid_response");
    return [tree(lengths.slice(0, literals)), tree(lengths.slice(literals))];
  }
  let final: number;
  do {
    deadline();
    final = read(1);
    const kind = read(2);
    ensure(kind !== 3, "invalid_response");
    if (kind === 0) {
      bit = Math.ceil(bit / 8) * 8;
      const count = read(16),
        complement = read(16);
      ensure(
        (count ^ complement) === 65535 && bit + count * 8 <= end * 8,
        "invalid_response",
      );
      bit += count * 8;
      size += count;
      ensure(size <= cap, "limit");
    } else {
      const [literals, distances] =
        kind === 1 ? [fixedLiterals, fixedDistances] : dynamic();
      while (true) {
        if ((++steps & 1023) === 0) deadline();
        const value = symbol(literals);
        if (value === 256) break;
        if (value < 256) size++;
        else {
          ensure(value >= 257 && value <= 285, "invalid_response");
          const i = value - 257,
            length = lengthBase[i]! + read(lengthExtra[i]!);
          const d = symbol(distances);
          ensure(d < 30, "invalid_response");
          const distance = distanceBase[d]! + read(distanceExtra[d]!);
          ensure(distance <= size, "invalid_response");
          size += length;
        }
        ensure(size <= cap, "limit");
      }
    }
  } while (!final);
  deadline();
  ensure(Math.ceil(bit / 8) === end, "invalid_response");
  return size;
}
