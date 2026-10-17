import { ok, err, type Result } from "../result.ts";
import { discoveryError } from "../errors/types.ts";
import {
  withDeadline,
  run,
  isContext,
  remainingMs,
  type Context,
} from "../context.ts";
import {
  isDiscoverySource,
  sourceIdentity,
  keyIdValid,
  thumbprintId,
  type DiscoverySource,
} from "./source.ts";
import {
  algorithmList,
  isKeySet,
  keySet,
  lookup,
  type KeySet,
  type NotModified,
  type Resolution,
} from "./body.ts";
import { algorithms } from "../crypto/algorithm.ts";
import {
  ensure,
  unwrap,
  failure,
  options,
  clockValue,
  systemClock,
  inspectable,
} from "./support.ts";
/** A caller-owned discovery transport callback. With `validators`, an unchanged source answers 304 and the callback returns a `NotModified` outcome instead of a key set (RFC 9111 Section 4.3.4). */
export type DiscoveryFetch = (
  source: DiscoverySource,
  options: {
    clock: () => number;
    context: Context;
    validators?: Readonly<{etag: string; lifetime: number}>;
  },
) => Promise<Result<KeySet | NotModified>>;
/** A caller-owned bounded cache of discovery key sets and failures. */
export type DiscoveryCache = Readonly<{
  /** Refresh a source from an explicit snapshot or configured fetch callback. */
  refresh: (source: unknown, snapshot?: unknown) => Promise<Result<KeySet>>;
  /** Resolve an eligible key through the bounded discovery cache. */
  resolve: (
    source: unknown,
    keyId: unknown,
    options?: unknown,
  ) => Promise<Result<Resolution>>;
  /** Remove a key by thumbprint from a cached source. */
  remove: (source: unknown, thumbprint: unknown) => Result<true>;
  /** Invalidate a source's cached key set. */
  invalidate: (source: unknown) => Result<true>;
  /** Close this capability and release its retained state. */
  close: () => Result<true>;
}>;
const caches = new WeakSet<object>();
type DecidedResolve = (s: unknown, kid: unknown, input: unknown, decision: () => number) => Promise<Result<Resolution>>;
const decided = new WeakMap<object, DecidedResolve>();
/**
 * Internal to the resolver bridge, not exported from the package: resolve with the
 * cache's own clock for fetching, storing, negative caching, and entry freshness, and
 * decide the key's freshness on `decision`.
 */
export function resolveOnClock(cache: DiscoveryCache, s: unknown, kid: unknown, input: unknown, decision: () => number): Promise<Result<Resolution>> {
  return decided.get(cache)!(s, kid, input, decision);
}
/** Check the private brand of a discovery cache. */
export function isDiscoveryCache(v: unknown): v is DiscoveryCache {
  return !!v && typeof v === "object" && caches.has(v);
}
type Enrollment = {
  source: DiscoverySource;
  set?: KeySet;
  fetchedAtHighWater?: number;
  failureUntil?: number;
  removed: Set<string>;
  generation: number;
};
type Flight = {
  controller: AbortController;
  work: Promise<Result<KeySet>>;
  waiters: number;
};
/** Validate cache options and create a branded discovery cache. */
export function createCache(input: unknown = {}): Result<DiscoveryCache> {
  try {
    const a = options(input, ["clock", "maxSources", "maxInFlight", "fetch"]);
    const clock = Object.hasOwn(a, "clock") ? a.clock : systemClock;
    clockValue(clock);
    const clockFn = clock as () => number;
    const maxSources = Object.hasOwn(a, "maxSources") ? a.maxSources : 64,
      maxInFlight = Object.hasOwn(a, "maxInFlight") ? a.maxInFlight : 8;
    ensure(
      Number.isSafeInteger(maxSources) &&
        (maxSources as number) >= 1 &&
        (maxSources as number) <= 4096 &&
        Number.isSafeInteger(maxInFlight) &&
        (maxInFlight as number) >= 1 &&
        (maxInFlight as number) <= 256,
      "invalid_options",
    );
    ensure(
      !Object.hasOwn(a, "fetch") || typeof a.fetch === "function",
      "invalid_options",
    );
    const fetcher = a.fetch as DiscoveryFetch | undefined;
    const enrolled = new Map<string, Enrollment>(),
      flights = new Map<string, Flight>();
    let closed = false,
      waiters = 0;
    function enroll(s: unknown): Enrollment {
      ensure(!closed, "source_unavailable");
      ensure(isDiscoverySource(s), "invalid_source");
      const id = sourceIdentity(s);
      let e = enrolled.get(id);
      if (!e) {
        ensure(enrolled.size < (maxSources as number), "cache_overloaded");
        e = { source: s, removed: new Set(), generation: 0 };
        enrolled.set(id, e);
      }
      return e;
    }
    function filter(set: KeySet, e: Enrollment): KeySet {
      const keys = Object.assign(Object.create(null), set.keys) as Record<
        string,
        Resolution
      >;
      for (const [kid, key] of Object.entries(keys))
        if (e.removed.has(key.thumbprint)) delete keys[kid];
      return keySet({ ...set, keys: Object.freeze(keys) });
    }
    function store(e: Enrollment, result: Result<KeySet | NotModified>, clock: () => number, snapshot = false): Result<KeySet> {
      const now = clockValue(clock);
      if (result.ok && "notModified" in result.value && result.value.notModified === true) {
        // RFC 9111 Section 4.3.4: the stored representation stays; the 304's
        // own freshness directives and validator replace the stored ones. The
        // set never claims freshness beyond its earliest still-live key.
        const current = e.set;
        if (
          !current ||
          sourceIdentity(current.source) !== sourceIdentity(e.source)
        )
          return err(discoveryError("source_unavailable"));
        const fresh = result.value;
        const set = filter(current, e);
        const earliest = Object.values(set.keys).reduce(
          (bound, key) => Math.min(bound, key.expiresAt),
          Infinity,
        );
        const merged = keySet({
          ...set,
          etag: fresh.etag,
          fetchedAt: fresh.fetchedAt,
          expiresAt: Math.min(fresh.expiresAt, earliest),
        });
        e.fetchedAtHighWater = Math.max(
          e.fetchedAtHighWater ?? merged.fetchedAt,
          merged.fetchedAt,
        );
        delete e.failureUntil;
        if (merged.expiresAt > now) e.set = merged;
        else delete e.set;
        return ok(merged);
      }
      if (result.ok) {
        ensure(
          isKeySet(result.value) &&
            sourceIdentity(result.value.source) === sourceIdentity(e.source),
          "source_unavailable",
        );
        ensure(result.value.fetchedAt <= now, snapshot ? "invalid_options" : "source_unavailable");
        if (snapshot) ensure(
          (e.fetchedAtHighWater === undefined || result.value.fetchedAt >= e.fetchedAtHighWater), "invalid_options");
        // Freshness may be discarded, but successful observation of a rotation persists.
        e.fetchedAtHighWater = Math.max(e.fetchedAtHighWater ?? result.value.fetchedAt, result.value.fetchedAt);
        const set = filter(result.value, e);
        delete e.failureUntil;
        if (set.expiresAt > now) e.set = set;
        else delete e.set;
        return ok(set);
      }
      if (e.source.type !== "cimd" && e.source.negativeTtl > 0)
        e.failureUntil = now + e.source.negativeTtl;
      else delete e.failureUntil;
      return result;
    }
    async function load(
      e: Enrollment,
      clock: () => number,
      context?: Context,
    ): Promise<Result<KeySet>> {
      const id = sourceIdentity(e.source);
      let flight = flights.get(id);
      ensure(waiters < (maxInFlight as number) * 32, "cache_overloaded");
      if (!flight) {
        ensure(flights.size < (maxInFlight as number), "cache_overloaded");
        ensure(fetcher, "source_unavailable");
        const controller = new AbortController();
        const c = unwrap(
          withDeadline({
            timeoutMs: e.source.timeoutMs,
            signal: controller.signal,
          }),
          "invalid_options",
        );
        const generation = e.generation;
        // A stored validator makes the revalidation conditional: an unchanged
        // source answers 304 and its key set stays put. A CIMD document is not
        // the key set itself — its 304 says nothing about the nested JWKS it
        // names — so CIMD sources always revalidate unconditionally.
        let validators: Readonly<{etag: string; lifetime: number}> | undefined;
        const stored = e.set;
        if (stored && stored.etag !== null && e.source.type !== "cimd") {
          const now = clockValue(clock);
          // A 304 keeps the stored keys, so it can only renew a set whose
          // every key is still inside its own expiry; any dead key forces a
          // full fetch.
          const alive =
            Object.keys(stored.keys).length > 0 &&
            Object.values(stored.keys).every((key) => now < key.expiresAt);
          if (alive)
            validators = Object.freeze({
              etag: stored.etag,
              lifetime: Math.max(stored.expiresAt - stored.fetchedAt, 0),
            });
        }
        flight = {
          controller,
          waiters: 0,
          work: Promise.resolve().then(async () => {
            let result: Result<KeySet | NotModified>;
            try {
              const r = await run(c, () =>
                fetcher(e.source, {
                  clock,
                  context: c,
                  ...(validators ? {validators} : {}),
                }),
              );
              result =
                !r.ok && r.error.kind !== "discovery"
                  ? err(
                      discoveryError(
                        r.error.reason === "deadline_exceeded"
                          ? "deadline_exceeded"
                          : "source_unavailable",
                      ),
                    )
                  : r;
              if (
                closed ||
                generation !== e.generation ||
                controller.signal.aborted
              )
                return err(discoveryError("source_unavailable"));
              return store(e, result, clock);
            } catch (error) {
              return failure(error, "source_unavailable");
            } finally {
              if (flights.get(id) === flight) flights.delete(id);
            }
          }),
        };
        flights.set(id, flight);
      }
      const active = flight;
      active.waiters++;
      waiters++;
      const c =
        context ??
        unwrap(
          withDeadline({ timeoutMs: e.source.timeoutMs }),
          "invalid_options",
        );
      try {
        const r = await run(c, () => active.work);
        return !r.ok && r.error.kind === "custody"
          ? err(
              discoveryError(
                r.error.reason === "deadline_exceeded"
                  ? "deadline_exceeded"
                  : "source_unavailable",
              ),
            )
          : r;
      } finally {
        active.waiters--;
        waiters--;
        if (active.waiters === 0 && flights.get(id) === active) {
          active.controller.abort();
          flights.delete(id);
        }
      }
    }
    async function resolveWith(s: unknown, kid: unknown, input: unknown, decision?: () => number): Promise<Result<Resolution>> {
        try {
          ensure(isDiscoverySource(s), "invalid_source");
          const a = options(input, ["algorithms", "clock", "context", "timeoutMs"]);
          const choices = algorithmList(
            Object.hasOwn(a, "algorithms")
              ? a.algorithms
              : unwrap(algorithms(), "invalid_options"),
          );
          ensure(keyIdValid(s, kid), "unknown_key");
          ensure(s.keyId === "directory" || !s.revoked.includes(kid), "revoked_key");
          // With a decision clock (the resolver bridge), the cache's own clock fetches, stores,
          // and judges entry freshness; the decision clock judges only the key returned.
          const selectedClock = decision === undefined && Object.hasOwn(a, "clock") ? a.clock : clockFn;
          const now = clockValue(selectedClock);
          const decisionNow = decision === undefined ? now : clockValue(decision);
          ensure(
            !Object.hasOwn(a, "context") || isContext(a.context),
            "invalid_options",
          );
          let context = a.context as Context | undefined;
          if (Object.hasOwn(a, "timeoutMs")) {
            ensure(
              Number.isSafeInteger(a.timeoutMs) &&
                (a.timeoutMs as number) >= 1 &&
                (a.timeoutMs as number) <= 300000,
              "invalid_options",
            );
            context = unwrap(
              withDeadline({
                timeoutMs: Math.min(a.timeoutMs as number, s.timeoutMs),
                ...(context ? { parent: context } : {}),
              }),
              "invalid_options",
            );
          }
          ensure(!context || remainingMs(context) > 0, "deadline_exceeded");
          const e = enroll(s);
          ensure(e.source.keyId === "directory" ||
            (!e.removed.has(kid) && !e.source.revoked.includes(kid)), "revoked_key");
          if (e.set && now < e.set.expiresAt)
            return await lookup(e.set, kid, choices, decisionNow);
          ensure(
            e.failureUntil === undefined || now >= e.failureUntil,
            "source_unavailable",
          );
          const fetched = await load(e, selectedClock as () => number, context);
          if (!fetched.ok) return fetched;
          ensure(
            e.source.keyId === "directory" || !e.removed.has(kid),
            "revoked_key",
          );
          return await lookup(
            filter(fetched.value, e),
            kid,
            choices,
            decision === undefined ? clockValue(selectedClock) : clockValue(decision),
            fetched.value.expiresAt === fetched.value.fetchedAt,
          );
        } catch (e) {
          return failure(e, "source_unavailable");
        }
    }
    const out: DiscoveryCache = {
      async refresh(s, snapshot) {
        try {
          const e = enroll(s);
          if (snapshot !== undefined) {
            ensure(isKeySet(snapshot), "invalid_options");
            ensure(!flights.has(sourceIdentity(e.source)), "cache_overloaded");
            return store(e, ok(snapshot), clockFn, true);
          }
          return await load(e, clockFn);
        } catch (e) {
          return failure(e, "source_unavailable");
        }
      },
      resolve(s, kid, input = {}) {
        return resolveWith(s, kid, input);
      },
      remove(s, kid) {
        try {
          const e = enroll(s);
          ensure(thumbprintId(kid), "unknown_key");
          ensure(e.removed.has(kid) || e.removed.size < 256, "limit");
          e.removed.add(kid);
          if (e.set) e.set = filter(e.set, e);
          return ok(true);
        } catch (e) {
          return failure(e, "source_unavailable");
        }
      },
      invalidate(s) {
        try {
          const e = enroll(s);
          e.generation++;
          delete e.set;
          delete e.failureUntil;
          const id = sourceIdentity(e.source);
          flights.get(id)?.controller.abort();
          flights.delete(id);
          return ok(true);
        } catch (e) {
          return failure(e, "source_unavailable");
        }
      },
      close() {
        closed = true;
        for (const flight of flights.values()) flight.controller.abort();
        flights.clear();
        enrolled.clear();
        return ok(true);
      },
    };
    caches.add(out);
    decided.set(out, (src, kid, input, decision) => resolveWith(src, kid, input, decision));
    return ok(inspectable(out, { kind: "DiscoveryCache" }));
  } catch (e) {
    return failure(e, "invalid_options");
  }
}
