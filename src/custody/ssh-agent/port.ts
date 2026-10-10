import {CRYPTO_MAX_BYTES_CEILING} from "../../constants.ts";
import {boundedBinary} from "../../crypto/primitive.ts";
import { connect, type Socket } from "node:net";
import { snapshotOptions } from "../../brand.ts";
import { withDeadline, isContext, run, type Context } from "../../context.ts";
import { custodyError, isRequestSealError } from "../../errors/types.ts";
import {
  createKeyHandle,
  type KeyHandle,
  type Custodian,
} from "../../key_handle.ts";
import { KeyIdentity } from "../../key_identity.ts";
import {
  isPublicKey,
  bindPublicKey,
  verifyPublicKey,
  type PublicKey,
} from "../../public_key.ts";
import {
  resolveAlgorithm,
  selection,
  type Spec,
} from "../../crypto/algorithm.ts";
import { ok, err, type Result } from "../../result.ts";
import {
  MAX_FRAME,
  uint32,
  string,
  identities,
  signature,
  keyBlob,
} from "./wire.ts";
export function failure<T>(e: unknown): Result<T> {
  return err(
    isRequestSealError(e) && e.kind === "custody"
      ? e
      : custodyError("custodian_protocol"),
  );
}
/** @internal Direct custodian implementation; use the public factory for handles. */
export class AgentPort implements Custodian {
  #path: string;
  #public: PublicKey;
  #spec: Spec;
  #blob: Buffer;
  #live = true;
  #sockets = new Set<Socket>();
  constructor(path: string, publicKey: PublicKey, spec: Spec) {
    this.#path = path;
    this.#public = publicKey;
    this.#spec = spec;
    this.#blob = keyBlob(publicKey);
    Object.freeze(this);
  }
  async #connect(c: Context): Promise<Result<Socket>> {
    return new Promise((resolve) => {
      const s = connect(this.#path);
      this.#sockets.add(s);
      let settled = false;
      const done = (r: Result<Socket>) => {
        if (settled) return;
        settled = true;
        s.removeListener("error", error);
        c.signal.removeEventListener("abort", abort);
        resolve(r);
      };
      const abort = () => {
        s.destroy();
        done(err(custodyError("deadline_exceeded")));
      };
      const error = (e: NodeJS.ErrnoException) => {
        s.destroy();
        done(
          err(
            custodyError(
              ["ENOENT", "ECONNREFUSED", "ECONNRESET"].includes(e.code ?? "")
                ? "custodian_unavailable"
                : "custodian_failure",
            ),
          ),
        );
      };
      // A write error can arrive after an exchange has settled; keep it contained until close.
      s.on("error", () => s.destroy());
      s.once("close", () => this.#sockets.delete(s));
      s.once("error", error);
      s.once("connect", () => done(ok(s)));
      c.signal.addEventListener("abort", abort, { once: true });
      if (c.signal.aborted) abort();
    });
  }
  async #exchange(
    socket: Socket,
    request: Buffer,
    c: Context,
  ): Promise<Result<Uint8Array>> {
    return new Promise((resolve) => {
      let buffer = Buffer.alloc(0),
        settled = false;
      const done = (r: Result<Uint8Array>) => {
        if (settled) return;
        settled = true;
        socket.removeListener("data", data);
        socket.removeListener("error", error);
        socket.removeListener("end", error);
        socket.removeListener("close", error);
        c.signal.removeEventListener("abort", abort);
        resolve(r);
      };
      const error = () => done(err(custodyError("custodian_protocol")));
      const abort = () => {
        socket.destroy();
        done(err(custodyError("deadline_exceeded")));
      };
      const data = (chunk: Buffer) => {
        if (buffer.length + chunk.length > MAX_FRAME + 4) {
          socket.destroy();
          error();
          return;
        }
        buffer = Buffer.concat([buffer, chunk]);
        if (buffer.length < 4) return;
        const length = buffer.readUInt32BE(0);
        if (length < 1 || length > MAX_FRAME || buffer.length > length + 4) {
          socket.destroy();
          error();
          return;
        }
        if (buffer.length === length + 4)
          done(ok(new Uint8Array(buffer.subarray(4))));
      };
      socket.on("data", data);
      socket.once("error", error);
      socket.once("end", error);
      socket.once("close", error);
      c.signal.addEventListener("abort", abort, { once: true });
      if (c.signal.aborted) {
        abort();
        return;
      }
      socket.write(Buffer.concat([uint32(request.length), request]), (e) => {
        if (e) error();
      });
    });
  }
  async possession(
    c: Context,
    initial = false,
  ): Promise<Result<Uint8Array<ArrayBuffer>>> {
    return this.#sign(new Uint8Array(), c, initial);
  }
  async #sign(
    data: Uint8Array,
    c: Context,
    initial = false,
  ): Promise<Result<Uint8Array<ArrayBuffer>>> {
    return run(c, async () => {
      if (!this.#live) return err(custodyError("key_not_found"));
      const connected = await this.#connect(c);
      if (!connected.ok) return connected;
      const socket = connected.value;
      try {
        const reply = await this.#exchange(socket, Buffer.from([11]), c);
        if (!reply.ok) return reply;
        const keys = identities(reply.value);
        if (!keys.some((k) => k.equals(this.#blob)))
          return err(
            custodyError(initial ? "custodian_rejected" : "key_not_found"),
          );
        const signed = await this.#exchange(
          socket,
          Buffer.concat([
            Buffer.from([13]),
            string(this.#blob),
            string(data),
            uint32(this.#spec.jose === "RS256" ? 2 : 0),
          ]),
          c,
        );
        if (!signed.ok) return signed;
        const raw = signature(signed.value, this.#spec, this.#public);
        const checked = await verifyPublicKey(
          this.#public,
          selection(this.#spec),
          raw,
          data,
          CRYPTO_MAX_BYTES_CEILING,
        );
        if (!checked.ok) {
          raw.fill(0);
          return err(custodyError("custodian_rejected"));
        }
        return ok(raw);
      } catch (e) {
        return failure(e);
      } finally {
        socket.destroy();
      }
    });
  }
  async sign(
    _algorithm: unknown,
    data: unknown,
    c: Context,
  ): Promise<Result<Uint8Array<ArrayBuffer>>> {
    if (!boundedBinary(data, CRYPTO_MAX_BYTES_CEILING)) return err(custodyError("invalid_data"));
    return this.#sign(new Uint8Array(data), c);
  }
  async verify(
    algorithm: unknown,
    sig: unknown,
    data: unknown,
    _c: Context,
  ): Promise<Result<true>> {
    if (!boundedBinary(data, CRYPTO_MAX_BYTES_CEILING)) return err(custodyError("invalid_data"));
    return verifyPublicKey(this.#public, algorithm, sig, data, CRYPTO_MAX_BYTES_CEILING);
  }
  async publicKey(): Promise<Result<PublicKey>> {
    return ok(this.#public);
  }
  async identity() {
    return KeyIdentity.fromPublic(this.#public);
  }
  async unwrap(): Promise<
    ReturnType<Custodian["unwrap"]> extends Promise<infer T> ? T : never
  > {
    return err(custodyError("unsupported_operation"));
  }
  async release(): Promise<Result<true>> {
    this.#live = false;
    for (const s of this.#sockets) s.destroy();
    return ok(true);
  }
}
