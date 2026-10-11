import {snapshotOptions} from "../../brand.ts";
import {withDeadline, isContext} from "../../context.ts";
import {custodyError} from "../../errors/types.ts";
import {createKeyHandle, type KeyHandle} from "../../key_handle.ts";
import {isPublicKey, bindPublicKey} from "../../public_key.ts";
import {resolveAlgorithm, selection} from "../../crypto/algorithm.ts";
import {ok, err, type Result} from "../../result.ts";
import {AgentPort, failure} from "./port.ts";
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
/** Caller-selected OpenSSH agent custody construction. */
export const SSHAgent = Object.freeze({
  /** Bind an algorithm and public key to a caller-selected OpenSSH agent socket. */
  create: createSshAgent });
