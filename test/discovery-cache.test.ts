import { snapshotWithMedia } from "./support/discovery-snapshot.ts";
import test from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import {
  Discovery,
  DiscoverySource,
  createCache,
  isDiscoveryCache,
  withDeadline,
  type Result,
} from "../src/index.ts";
const jwk = {
  kty: "OKP",
  crv: "Ed25519",
  x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
};
const kid = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
const bytes = (s: string) => new TextEncoder().encode(s);
function value<T>(r: Result<T>): T {
  assert.equal(r.ok, true, JSON.stringify(r));
  return (r as { ok: true; value: T }).value;
}
function reason(r: Result<unknown>, expected: string) {
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.error.reason, expected);
}
test("fresh cache keys respect caller cancellation and expired deadlines", async () => {
  const source = value(
    DiscoverySource.create({
      type: "jwks_uri",
      location: "https://agent.example",
    }),
  );
  const snapshot = value(
    await snapshotWithMedia(
      source,
      bytes(JSON.stringify({ keys: [jwk] })),
      100,
      [],
    ),
  );
  const cache = value(createCache({ clock: () => 100 }));
  value(await cache.refresh(source, snapshot));
  const controller = new AbortController();
  const canceled = value(withDeadline({ signal: controller.signal }));
  controller.abort();
  reason(
    await cache.resolve(source, kid, { context: canceled }),
    "deadline_exceeded",
  );
  const expired = value(withDeadline({ timeoutMs: 1 }));
  await new Promise((done) => setTimeout(done, 10));
  reason(
    await cache.resolve(source, kid, { context: expired }),
    "deadline_exceeded",
  );
  value(await cache.resolve(source, kid));
  value(cache.close());
});
test("snapshot cache removals persist through replacement and invalidation", async () => {
  const source = value(
    DiscoverySource.create({
      type: "jwks_uri",
      location: "https://agent.example",
    }),
  );
  const set = value(
    await snapshotWithMedia(
      source,
      bytes(JSON.stringify({ keys: [jwk] })),
      100,
      [["cache-control", "max-age=30"]],
    ),
  );
  const cache = value(createCache({ clock: () => 100 }));
  assert.ok(isDiscoveryCache(cache));
  assert.equal(isDiscoveryCache({ ...cache }), false);
  assert.ok(Object.isFrozen(cache));
  value(await cache.refresh(source, set));
  value(await cache.resolve(source, kid));
  value(cache.remove(source, kid));
  reason(await cache.resolve(source, kid), "revoked_key");
  assert.equal(
    Object.keys(value(await cache.refresh(source, set)).keys).length,
    0,
  );
  value(cache.invalidate(source));
  value(await cache.refresh(source, set));
  reason(await cache.resolve(source, kid), "revoked_key");
  assert.equal(Object.keys(set.keys).length, 1);
  value(cache.close());
  reason(await cache.resolve(source, kid), "source_unavailable");
});
test("directory IDs cannot transfer another key thumbprint revocation", async () => {
  const source = value(
    DiscoverySource.create({
      type: "jwks_uri",
      location: "https://agent.example",
      keyId: "directory",
    }),
  );
  const other = value(
    await snapshotWithMedia(
      source,
      bytes(JSON.stringify({ keys: [{ ...jwk, kid: "Alias" }] })),
      100,
      [],
    ),
  );
  const cache = value(createCache({ clock: () => 100 }));
  value(await cache.refresh(source, other));
  value(cache.remove(source, kid));
  reason(await cache.resolve(source, "Alias"), "unknown_key");
  value(cache.invalidate(source));
  value(await cache.refresh(source, other));
  reason(await cache.resolve(source, "Alias"), "unknown_key");
});
test("cache rejects stale snapshots and bounds source enrollment without eviction", async () => {
  let now = 100;
  const cache = value(createCache({ clock: () => now, maxSources: 1 }));
  const source = value(
    DiscoverySource.create({
      type: "jwks_uri",
      location: "https://agent.example",
    }),
  );
  value(
    await cache.refresh(
      source,
      value(
        await snapshotWithMedia(
          source,
          bytes(JSON.stringify({ keys: [jwk] })),
          100,
          [["cache-control", "max-age=1"]],
        ),
      ),
    ),
  );
  now = 101;
  reason(await cache.resolve(source, kid), "source_unavailable");
  const other = value(
    DiscoverySource.create({
      type: "jwks_uri",
      location: "https://other.example",
    }),
  );
  reason(cache.invalidate(other), "cache_overloaded");
  for (const options of [
    { maxSources: 0 },
    { maxInFlight: 257 },
    { clock: () => -1 },
    { unknown: true },
  ])
    reason(createCache(options), "invalid_options");
});
test(
  "cache operations are deterministic for generated directives, clocks and operation sequences",
  { timeout: 15000 },
  async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 0, max: 300 }),
        fc.integer({ min: 100, max: 10000 }),
        fc.array(
          fc.constantFrom("refresh", "invalidate", "remove", "resolve"),
          { maxLength: 20 },
        ),
        async (ttl, now, ops) => {
          const source = value(
            DiscoverySource.create({
              type: "jwks_uri",
              location: "https://agent.example",
            }),
          );
          const set = value(
            await snapshotWithMedia(
              source,
              bytes(JSON.stringify({ keys: [jwk] })),
              now,
              [["cache-control", `max-age=${ttl}`]],
            ),
          );
          const caches = [
            value(createCache({ clock: () => now })),
            value(createCache({ clock: () => now })),
          ];
          for (const op of ops) {
            const outcomes = [];
            for (const cache of caches) {
              const result =
                op === "refresh"
                  ? await cache.refresh(source, set)
                  : op === "invalidate"
                    ? cache.invalidate(source)
                    : op === "remove"
                      ? cache.remove(source, kid)
                      : await cache.resolve(source, kid);
              outcomes.push(
                result.ok
                  ? {
                      ok: true,
                      value:
                        op === "refresh"
                          ? Object.keys((result.value as typeof set).keys)
                          : op === "resolve"
                            ? (result.value as { thumbprint: string })
                                .thumbprint
                            : true,
                    }
                  : { ok: false, reason: result.error.reason },
              );
            }
            assert.deepEqual(outcomes[0], outcomes[1]);
          }
          for (const cache of caches) value(cache.close());
        },
      ),
      { seed: 9111, numRuns: 40 },
    );
  },
);
