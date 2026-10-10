import { decodeBase64Url } from "../../bytes.ts";
import { custodyError } from "../../errors/types.ts";
import type { PublicKey } from "../../public_key.ts";
import type { Spec } from "../../crypto/algorithm.ts";
export const MAX_FRAME = 1_048_576;
export function ensure(value: unknown): asserts value {
  if (!value) throw custodyError("custodian_protocol");
}
export function uint32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
}
export function string(value: Uint8Array | string): Buffer {
  const b = typeof value === "string" ? Buffer.from(value) : Buffer.from(value);
  return Buffer.concat([uint32(b.length), b]);
}
export class Reader {
  #bytes: Buffer;
  #offset = 0;
  constructor(bytes: Uint8Array) {
    this.#bytes = Buffer.from(bytes);
  }
  byte(): number {
    ensure(this.#offset < this.#bytes.length);
    return this.#bytes[this.#offset++]!;
  }
  number(): number {
    ensure(this.#offset + 4 <= this.#bytes.length);
    const n = this.#bytes.readUInt32BE(this.#offset);
    this.#offset += 4;
    return n;
  }
  string(max: number): Buffer {
    const n = this.number();
    ensure(n <= max && n <= this.#bytes.length - this.#offset);
    const b = this.#bytes.subarray(this.#offset, this.#offset + n);
    this.#offset += n;
    return b;
  }
  end(): void {
    ensure(this.#offset === this.#bytes.length);
  }
}
function component(value: unknown): Buffer {
  const r = decodeBase64Url(value);
  ensure(r.ok);
  return Buffer.from(r.value);
}
function mpint(bytes: Buffer): Buffer {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  bytes = bytes.subarray(i);
  return string(
    bytes[0]! >= 128 ? Buffer.concat([Buffer.from([0]), bytes]) : bytes,
  );
}
export function keyBlob(publicKey: PublicKey): Buffer {
  const r = publicKey.jwk();
  if (!r.ok) throw custodyError("key_mismatch");
  const j = r.value;
  if (j.kty === "OKP")
    return Buffer.concat([string("ssh-ed25519"), string(component(j.x))]);
  if (j.kty === "RSA")
    return Buffer.concat([
      string("ssh-rsa"),
      mpint(component(j.e)),
      mpint(component(j.n)),
    ]);
  const curve = j.crv === "P-256" ? "nistp256" : "nistp384";
  return Buffer.concat([
    string("ecdsa-sha2-" + curve),
    string(curve),
    string(Buffer.concat([Buffer.from([4]), component(j.x), component(j.y)])),
  ]);
}
export function identities(bytes: Uint8Array): readonly Buffer[] {
  const r = new Reader(bytes),
    type = r.byte();
  if (type === 5) {
    r.end();
    throw custodyError("custodian_rejected");
  }
  ensure(type === 12);
  const n = r.number();
  ensure(n <= 256);
  const out: Buffer[] = [];
  for (let i = 0; i < n; i++) {
    out.push(r.string(16_384));
    r.string(16_384);
  }
  r.end();
  return out;
}
function fixed(bytes: Buffer, width: number): Buffer {
  ensure(bytes.length > 0);
  if (bytes[0] === 0) {
    ensure(bytes.length > 1 && bytes[1]! >= 128);
    bytes = bytes.subarray(1);
  } else ensure(bytes[0]! < 128);
  ensure(bytes.length <= width);
  const out = Buffer.alloc(width);
  bytes.copy(out, width - bytes.length);
  return out;
}
export function signature(
  bytes: Uint8Array,
  spec: Spec,
  publicKey: PublicKey,
): Uint8Array<ArrayBuffer> {
  const r = new Reader(bytes),
    type = r.byte();
  if (type === 5) {
    r.end();
    throw custodyError("custodian_rejected");
  }
  ensure(type === 14);
  const packet = new Reader(r.string(16_384));
  r.end();
  const name = packet.string(64).toString("ascii"),
    raw = packet.string(16_384);
  packet.end();
  let out: Buffer;
  if (spec.jose === "EdDSA") {
    ensure(name === "ssh-ed25519" && raw.length === 64);
    out = raw;
  } else if (spec.jose === "RS256") {
    ensure(name === "rsa-sha2-256");
    const j = publicKey.jwk();
    ensure(j.ok);
    const width = component(j.value.n).length;
    ensure(raw.length > 0 && raw.length <= width);
    out = Buffer.alloc(width);
    raw.copy(out, width - raw.length);
  } else {
    const width = spec.jose === "ES256" ? 32 : 48;
    ensure(name === "ecdsa-sha2-" + (width === 32 ? "nistp256" : "nistp384"));
    const ec = new Reader(raw);
    const a = fixed(ec.string(width + 1), width),
      b = fixed(ec.string(width + 1), width);
    ec.end();
    out = Buffer.concat([a, b]);
  }
  return new Uint8Array(out);
}
