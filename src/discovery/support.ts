import { snapshotOptions, deepFreeze } from "../brand.ts";
import { discoveryError, isRequestSealError, type DiscoveryError } from "../errors/types.ts";
import type { Reason } from "../errors/parity.ts";
import { err, type Result } from "../result.ts";
export function ensure(
  value: unknown,
  reason: Reason<"discovery">,
): asserts value {
  if (!value) throw discoveryError(reason);
}
export function unwrap<T>(r: Result<T>, reason: Reason<"discovery">): T {
  if (!r.ok) throw discoveryError(reason);
  return r.value;
}
export function failure<T>(
  error: unknown,
  fallback: Reason<"discovery"> = "invalid_response",
): Result<T> {
  return err(
    isRequestSealError(error) && error.kind === "discovery"
      ? error
      : discoveryError(fallback),
  );
}
export function options<K extends string>(
  input: unknown,
  keys: readonly K[],
  reason: Reason<"discovery"> = "invalid_options",
) {
  return unwrap(snapshotOptions(input, keys), reason);
}
export function list(
  input: unknown,
  max: number,
  min = 0,
  reason: Reason<"discovery"> = "invalid_options",
): readonly unknown[] {
  ensure(Array.isArray(input), reason);
  const size = input.length;
  ensure(Number.isSafeInteger(size) && size >= min && size <= max, reason);
  const owned = unwrap(deepFreeze(input), reason);
  ensure(owned.length >= min && owned.length <= max, reason);
  for (let i = 0; i < owned.length; i++)
    ensure(Object.hasOwn(owned, i), reason);
  return owned;
}
export function clockSeconds(value: unknown): value is number {
  return (
    Number.isSafeInteger(value) &&
    (value as number) >= 0 &&
    (value as number) <= 253_402_300_799
  );
}
export function clockValue(clock: unknown): number {
  ensure(typeof clock === "function", "invalid_options");
  try {
    const n: unknown = clock();
    ensure(clockSeconds(n), "invalid_options");
    return n;
  } catch {
    throw discoveryError("invalid_options");
  }
}
export const systemClock = () => Math.floor(Date.now() / 1000);
export function inspectable<T extends object>(value: T, facts: object): T {
  const inspect = () => Object.freeze({ ...facts });
  Object.defineProperties(value, {
    toJSON: { value: inspect },
    [Symbol.for("nodejs.util.inspect.custom")]: { value: inspect },
    [Symbol.for("Deno.customInspect")]: { value: inspect },
  });
  return Object.freeze(value);
}

export function sslError(error: unknown): DiscoveryError {
  const code = error && typeof error === "object" && "code" in error ? error.code : null;
  const connectFailure = typeof code === "string" &&
    ["ECONNREFUSED", "ENETUNREACH", "EHOSTUNREACH", "ECONNRESET", "EPIPE", "EADDRNOTAVAIL"].includes(code.toUpperCase());
  return discoveryError(connectFailure ? "connect_failed" : "tls_failed");
}
