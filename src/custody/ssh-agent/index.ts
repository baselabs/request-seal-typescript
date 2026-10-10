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
function failure<T>(e: unknown): Result<T> {
  return err(
    isRequestSealError(e) && e.kind === "custody"
      ? e
      : custodyError("custodian_protocol"),
  );
}
class AgentPort implements Custodian {
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
      if (request.length > MAX_FRAME) {
        done(err(custodyError("limit")));
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
    if (!(data instanceof Uint8Array)) return err(custodyError("invalid_data"));
    return this.#sign(new Uint8Array(data), c);
  }
  async verify(
    algorithm: unknown,
    sig: unknown,
    data: unknown,
    _c: Context,
  ): Promise<Result<true>> {
    return verifyPublicKey(this.#public, algorithm, sig, data);
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
/** Caller-selected local socket and trusted public components; no environment discovery. */
export async function createSshAgent(
  algorithm: unknown,
  socketPath: unknown,
  publicKey: unknown,
  options: unknown = {},
): Promise<Result<KeyHandle>> {
  try {
    const a = snapshotOptions(options, ["context", "timeoutMs"]);
    if (!a.ok) return err(custodyError("invalid_options"));
    const spec = resolveAlgorithm(algorithm);
    if (
      !spec.ok ||
      !["EdDSA", "RS256", "ES256", "ES384"].includes(spec.value.jose)
    )
      return err(custodyError("unsupported_algorithm"));
    if (
      typeof socketPath !== "string" ||
      socketPath.length < 1 ||
      !socketPath.startsWith("/") ||
      new TextEncoder().encode(socketPath).length > 103 ||
      socketPath.includes("\0")
    )
      return err(custodyError("invalid_options"));
    if (!isPublicKey(publicKey)) return err(custodyError("invalid_key"));
    if (!bindPublicKey(publicKey, algorithm).ok)
      return err(custodyError("key_mismatch"));
    if (
      Object.hasOwn(a.value, "context") &&
      Object.hasOwn(a.value, "timeoutMs")
    )
      return err(custodyError("invalid_options"));
    const c = Object.hasOwn(a.value, "context")
      ? isContext(a.value.context)
        ? ok(a.value.context)
        : err(custodyError("invalid_options"))
      : withDeadline(
          Object.hasOwn(a.value, "timeoutMs")
            ? { timeoutMs: a.value.timeoutMs }
            : {},
        );
    if (!c.ok) return c;
    const port = new AgentPort(socketPath, publicKey, spec.value);
    const proof = await port.possession(c.value, true);
    if (!proof.ok) {
      await port.release();
      return proof;
    }
    proof.value.fill(0);
    return createKeyHandle(selection(spec.value), port, ["sign", "verify"]);
  } catch (e) {
    return failure(e);
  }
}
export const SSHAgent = Object.freeze({ create: createSshAgent });
