import { ensure } from "./support.ts";
import type { Context } from "../context.ts";
import { deflateSize } from "./deflate.ts";
const crcTable = Array.from({ length: 256 }, (_, n) => {
  for (let i = 0; i < 8; i++) n = n & 1 ? 0xedb88320 ^ (n >>> 1) : n >>> 1;
  return n >>> 0;
});
function crc(bytes: Uint8Array): number {
  let n = 0xffffffff;
  for (const b of bytes) n = crcTable[(n ^ b) & 255]! ^ (n >>> 8);
  return (n ^ 0xffffffff) >>> 0;
}
function little(bytes: Uint8Array, at: number): number {
  return (
    (bytes[at]! |
      (bytes[at + 1]! << 8) |
      (bytes[at + 2]! << 16) |
      (bytes[at + 3]! << 24)) >>>
    0
  );
}
/** One gzip member only. The runtime performs DEFLATE; this code owns framing. */
export async function decodeBody(
  bytes: Uint8Array,
  coding: string | null,
  cap: number,
  context?: Context,
): Promise<Uint8Array> {
  coding = coding?.trim().toLowerCase() ?? "identity";
  if (coding === "identity") {
    ensure(bytes.length <= cap, "limit");
    return new Uint8Array(bytes);
  }
  ensure(coding === "gzip" || coding === "x-gzip", "invalid_response");
  ensure(
    bytes.length >= 18 &&
      bytes[0] === 31 &&
      bytes[1] === 139 &&
      bytes[2] === 8 &&
      (bytes[3]! & 224) === 0,
    "invalid_response",
  );
  const flags = bytes[3]!;
  let start = 10;
  const end = bytes.length - 8;
  if (flags & 4) {
    ensure(start + 2 <= end, "invalid_response");
    start += 2 + bytes[start]! + (bytes[start + 1]! << 8);
    ensure(start <= end, "invalid_response");
  }
  for (const flag of [8, 16])
    if (flags & flag) {
      while (start < end && bytes[start] !== 0) start++;
      ensure(start < end, "invalid_response");
      start++;
    }
  if (flags & 2) {
    ensure(
      start + 2 <= end &&
        (bytes[start]! | (bytes[start + 1]! << 8)) ===
          (crc(bytes.subarray(0, start)) & 65535),
      "invalid_response",
    );
    start += 2;
  }
  ensure(start < end, "invalid_response");
  const expected = deflateSize(bytes, start, end, cap, context);
  const stream = new DecompressionStream("deflate-raw"),
    writer = stream.writable.getWriter(),
    reader = stream.readable.getReader();
  const aborted = () => {
    void reader.cancel().catch(() => {});
    void writer.abort().catch(() => {});
  };
  context?.signal.addEventListener("abort", aborted, { once: true });
  const writing = (async () => {
    await writer.write(new Uint8Array(bytes.subarray(start, end)));
    await writer.close();
  })();
  writing.catch(() => {});
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      ensure(!context?.signal.aborted, "deadline_exceeded");
      const next = await reader.read();
      if (next.done) break;
      size += next.value.length;
      ensure(size <= cap, "limit");
      chunks.push(next.value);
    }
    await writing;
    ensure(!context?.signal.aborted, "deadline_exceeded");
    const decoded = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      decoded.set(chunk, offset);
      offset += chunk.length;
    }
    ensure(
      size === expected &&
        little(bytes, end + 4) === size &&
        little(bytes, end) === crc(decoded),
      "invalid_response",
    );
    return decoded;
  } finally {
    context?.signal.removeEventListener("abort", aborted);
    aborted();
  }
}
