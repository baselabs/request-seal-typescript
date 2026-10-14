import { ok, type Result } from "../result.ts";
import { snapshotOptions } from "../brand.ts";
import { isKeySet, algorithmList, type KeySet } from "./body.ts";
import { isDiscoverySource, type DiscoverySource } from "./source.ts";
import { isDiscoveryCache, type DiscoveryCache } from "./cache.ts";
import { fromSnapshot } from "./snapshot.ts";
import { type Resolution } from "./body.ts";
import { ensure, unwrap, failure } from "./support.ts";
/** A discovery-backed signature key resolver. @inline */
export type KeyResolver = (
  request: unknown,
) => Promise<
  Result<
    Readonly<{ algorithm: Resolution["algorithm"]; key: Resolution["key"] }>
  >
>;
/** Create a resolver over a branded key set or caller-owned discovery cache. */
function resolver(input: unknown, opts: unknown): Result<KeyResolver> {
  try {
    const a = unwrap(snapshotOptions(opts, ["algorithms", "clock"]), "invalid_options");
    const allowed = algorithmList(a.algorithms);
    // An explicit clock, usually the policy's freshness clock; system time otherwise.
    const clock = Object.hasOwn(a, "clock") ? a.clock : undefined;
    ensure(clock === undefined || typeof clock === "function", "invalid_options");
    let set: KeySet | undefined,
      cache: DiscoveryCache | undefined,
      source: DiscoverySource | undefined;
    if (isKeySet(input)) set = input;
    else {
      const tuple = unwrap(
        snapshotOptions(input, ["cache", "source"]),
        "invalid_options",
      );
      ensure(
        isDiscoveryCache(tuple.cache) && isDiscoverySource(tuple.source),
        "invalid_options",
      );
      cache = tuple.cache;
      source = tuple.source;
    }
    const fn: KeyResolver = async (request) => {
      try {
        ensure(
          request &&
            typeof request === "object" &&
            Object.hasOwn(request, "keyid"),
          "unknown_key",
        );
        const kid = (request as { keyid: unknown }).keyid;
        const result = set
          ? clock === undefined
            ? await set.lookup(kid, allowed)
            : await set.lookup(kid, allowed, (clock as () => number)())
          : await cache!.resolve(
              source!,
              kid,
              clock === undefined ? { algorithms: allowed } : { algorithms: allowed, clock },
            );
        return result.ok
          ? ok(
              Object.freeze({
                algorithm: result.value.algorithm,
                key: result.value.key,
              }),
            )
          : result;
      } catch (e) {
        return failure(e, "unknown_key");
      }
    };
    return ok(Object.freeze(fn));
  } catch (e) {
    return failure(e, "invalid_options");
  }
}
const Resolver = Object.freeze(Object.assign(resolver, {
  /** Parse a caller-supplied discovery snapshot without fetching it. */
  fromSnapshot }));
/** Snapshot resolution and explicit discovery operations. */
export const Discovery = Object.freeze({
  /**
   * Create a resolver over a branded key set or caller-owned discovery cache.
   * Options are `algorithms` and an optional `clock` (integer Unix seconds); pass the
   * policy's freshness clock so key freshness and signature freshness agree. Without
   * `clock`, a key set uses system time and a cache uses its own clock.
   */
  resolver: Resolver });
export { DiscoverySource, isDiscoverySource, directoryId } from "./source.ts";
export {
  isKeySet,
  isResolution,
  type KeySet,
  type Resolution,
} from "./body.ts";
export {
  createCache,
  isDiscoveryCache,
  type DiscoveryCache,
  type DiscoveryFetch,
} from "./cache.ts";
export type { Headers } from "./snapshot.ts";
