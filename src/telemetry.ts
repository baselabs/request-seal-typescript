import { err, ok, type Result } from "./result.ts";
import { coreError, isRequestSealError, ruleId } from "./errors/types.ts";

/** The versioned event names (v1), mirroring the reference telemetry contract. */
export type TelemetryEventName =
  | "verify"
  | "verifyQuorum"
  | "webBotAuthVerify"
  | "replayClaim"
  | "custodySign";
/** What an event reports: the operation's outcome within a closed vocabulary. */
export type TelemetryOutcome = "ok" | "error" | "claimed" | "already_claimed";
/** One bounded, low-cardinality observation of a RequestSeal operation. */
export type TelemetryEvent = Readonly<{
  event: TelemetryEventName;
  outcome: TelemetryOutcome;
  reason: string | null;
  layer: string | null;
  detail: string | null;
  durationMs: number;
}>;
/** A caller-owned subscriber; handlers own storage and aggregation. */
export type TelemetrySubscriber = (event: TelemetryEvent) => void;
/** A caller-owned attachment; `detach` stops delivery and is idempotent. */
export type TelemetryHandle = Readonly<{
  /** Stop delivering events to this attachment; calling it again does nothing. */
  detach(): void;
}>;
const names: readonly TelemetryEventName[] = Object.freeze([
  "verify",
  "verifyQuorum",
  "webBotAuthVerify",
  "replayClaim",
  "custodySign",
]);
const MAX_SUBSCRIBERS = 16;
const handles = new WeakSet<object>();
let subscribers: readonly TelemetrySubscriber[] = Object.freeze([]);
// A captured monotonic clock: replacing the global later cannot change a duration.
const now = performance.now.bind(performance);
/**
 * Emit one event to every attached subscriber. Telemetry is an optional path:
 * a throwing subscriber degrades silently and never fails the operation it
 * observes. Payloads carry closed vocabulary only — never labels, key IDs,
 * URLs, principals, nonces, bytes, or exception text.
 */
export function emit(
  event: TelemetryEventName,
  durationMs: number,
  outcome: TelemetryOutcome,
  error?: unknown,
): void {
  if (subscribers.length === 0) return;
  const payload: TelemetryEvent = Object.freeze({
    event,
    outcome,
    reason: isRequestSealError(error) ? ruleId(error) : null,
    layer: isRequestSealError(error) && "layer" in error ? error.layer : null,
    detail: isRequestSealError(error) && "detail" in error && typeof error.detail === "string" ? error.detail : null,
    durationMs,
  });
  for (const subscriber of subscribers) {
    try {
      subscriber(payload);
    } catch {
      // Degrade: a defective observer is not the observed operation's failure.
    }
  }
}
/** Measure an operation and emit its stop event with the result's metadata. */
export async function span<T>(
  event: TelemetryEventName,
  work: () => Promise<T>,
  outcome: (result: T) => TelemetryOutcome,
  errorOf: (result: T) => unknown,
): Promise<T> {
  const start = now();
  const result = await work();
  emit(event, now() - start, outcome(result), errorOf(result));
  return result;
}
/** The captured monotonic clock used for event durations, in milliseconds. */
export function monotonicMs(): number { return now(); }

/** Attach a telemetry subscriber; at most sixteen run at once. */
export function attach(input: unknown): Result<TelemetryHandle> {
  if (typeof input !== "function")
    return err(coreError("invalid_options", "input"));
  if (subscribers.length >= MAX_SUBSCRIBERS)
    return err(coreError("invalid_options", "input"));
  const subscriber = input as TelemetrySubscriber;
  subscribers = Object.freeze([...subscribers, subscriber]);
  let live = true;
  const handle = Object.freeze({
    detach(): void {
      if (!live) return;
      live = false;
      // Remove exactly one occurrence: two attachments of one function are
      // independently detachable, mirroring the reference's handler ids.
      const index = subscribers.indexOf(subscriber);
      if (index >= 0)
        subscribers = Object.freeze(
          subscribers.slice(0, index).concat(subscribers.slice(index + 1)),
        );
    },
  });
  handles.add(handle);
  return ok(handle);
}
/** The v1 event names, as documented in the observability reference. */
export const Telemetry = Object.freeze({
  /** The v1 event names. */
  events(): readonly TelemetryEventName[] {
    return names;
  },
  /** Attach a telemetry subscriber; the handle's `detach` stops delivery. */
  attach,
  /** Check the private brand of a telemetry attachment handle. */
  isHandle(value: unknown): value is TelemetryHandle {
    return !!value && typeof value === "object" && handles.has(value);
  },
});
