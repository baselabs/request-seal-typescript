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
export type DiscoveryFetch = (
  source: DiscoverySource,
  options: { clock: () => number; context: Context },
) => Promise<Result<KeySet>>;
export type DiscoveryCache = Readonly<{
  refresh: (source: unknown, snapshot?: unknown) => Promise<Result<KeySet>>;
  resolve: (
    source: unknown,
    keyId: unknown,
    options?: unknown,
  ) => Promise<Result<Resolution>>;
  remove: (source: unknown, thumbprint: unknown) => Result<true>;
  invalidate: (source: unknown) => Result<true>;
  close: () => Result<true>;
}>;
const caches = new WeakSet<object>();
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
    function store(e: Enrollment, result: Result<KeySet>, clock: () => number, snapshot = false): Result<KeySet> {
      const now = clockValue(clock);
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
        flight = {
          controller,
          waiters: 0,
          work: Promise.resolve().then(async () => {
            let result: Result<KeySet>;
            try {
              const r = await run(c, () =>
                fetcher(e.source, { clock, context: c }),
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
      async resolve(s, kid, input = {}) {
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
          const selectedClock = Object.hasOwn(a, "clock") ? a.clock : clockFn;
          const now = clockValue(selectedClock);
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
            return await lookup(e.set, kid, choices, now);
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
            clockValue(selectedClock),
            fetched.value.expiresAt === fetched.value.fetchedAt,
          );
        } catch (e) {
          return failure(e, "source_unavailable");
        }
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
    return ok(inspectable(out, { kind: "DiscoveryCache" }));
  } catch (e) {
    return failure(e, "invalid_options");
  }
}
