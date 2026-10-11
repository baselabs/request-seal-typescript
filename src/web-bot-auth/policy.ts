import { inspection, snapshotOptions } from "../brand.ts";
import {
  Policy,
  type Policy as GenericPolicy,
  type KeyResolver,
  type ReplayPolicy,
} from "../policy.ts";
import { isDiscoveryCache, type DiscoveryCache } from "../discovery/cache.ts";
import type { DiscoverySource } from "../discovery/source.ts";
import type { KeySet } from "../discovery/body.ts";
import type { Context } from "../context.ts";
import type { Result } from "../result.ts";
import { ok, err } from "../result.ts";
import { ensure, bounded } from "../signature-fields.ts";
import { resolveAlgorithm } from "../crypto/algorithm.ts";
import type { WebBotAuthReplayFacts } from "./verification.ts";
export type AgentRequest = Readonly<{
  identifier: string;
  location: string;
  type: DiscoverySource["type"];
}>;
export type AgentTrust = (
  agent: AgentRequest,
) =>
  | Result<DiscoverySource | KeySet | null>
  | Promise<Result<DiscoverySource | KeySet | null>>;
export type WebBotAuthReplayPolicy = Omit<ReplayPolicy, "commitment"> &
  Readonly<{
    commitment: (
      facts: WebBotAuthReplayFacts,
      context: Context,
    ) => Result<Uint8Array> | Promise<Result<Uint8Array>>;
  }>;
export type WebBotAuthPolicy = Omit<
  GenericPolicy,
  "keyResolver" | "replay" | "freshness"
> &
  Readonly<{
    agents: AgentTrust;
    cache: DiscoveryCache | null;
    freshness: Exclude<GenericPolicy["freshness"], "not_evaluated">;
    replay: "not_required" | WebBotAuthReplayPolicy;
    maxLifetime: number;
    unresolved: "reject" | Readonly<{ heldKeys: KeyResolver }>;
    testKeys: "reject" | "allow";
    untagged: "reject" | "ignore";
  }>;
const policies = new WeakSet<object>();
export function isWebBotAuthPolicy(v: unknown): v is WebBotAuthPolicy {
  return !!v && typeof v === "object" && policies.has(v);
}
export function createPolicy(input: unknown): Result<WebBotAuthPolicy> {
  try {
    const r = snapshotOptions(input, [
      "algorithms",
      "agents",
      "cache",
      "freshness",
      "content",
      "replay",
      "components",
      "maxLifetime",
      "unresolved",
      "testKeys",
      "untagged",
      "maxSignatures",
      "fieldSchemas",
    ]);
    ensure(r.ok, "invalid_policy", "input");
    const a = r.value;
    ensure(
      ["algorithms", "agents", "cache", "freshness", "content", "replay"].every(
        (k) => Object.hasOwn(a, k),
      ),
      "invalid_policy",
      "input",
    );
    ensure(
      typeof a.agents === "function" &&
        (a.cache === null || isDiscoveryCache(a.cache)),
      "invalid_policy",
      "input",
    );
    const f = snapshotOptions(a.freshness, [
      "clock",
      "skew",
      "maxAge",
      "requireExpires",
    ]);
    ensure(
      f.ok &&
        ["clock", "skew", "maxAge"].every((k) => Object.hasOwn(f.value, k)),
      "invalid_policy",
      "input",
    );
    const generic = Policy.create({
      algorithms: a.algorithms,
      components: Object.hasOwn(a, "components") ? a.components : "()",
      keyResolver: async () => ok(null),
      freshness: { ...f.value, requireExpires: true },
      content: a.content,
      replay: a.replay,
      ...(Object.hasOwn(a, "maxSignatures")
        ? { maxSignatures: a.maxSignatures }
        : {}),
      ...(Object.hasOwn(a, "fieldSchemas")
        ? { fieldSchemas: a.fieldSchemas }
        : {}),
    });
    ensure(
      generic.ok && generic.value.freshness !== "not_evaluated",
      "invalid_policy",
      "input",
    );
    ensure(
      generic.value.algorithms.every((v) => {
        const r = resolveAlgorithm(v);
        return r.ok && r.value.family !== "hmac";
      }),
      "invalid_policy",
      "input",
    );
    const maxLifetime = Object.hasOwn(a, "maxLifetime") ? a.maxLifetime : 86400;
    const testKeys = Object.hasOwn(a, "testKeys") ? a.testKeys : "reject",
      untagged = Object.hasOwn(a, "untagged") ? a.untagged : "ignore";
    ensure(
      typeof maxLifetime === "number" &&
        Number.isInteger(maxLifetime) &&
        maxLifetime >= 1 &&
        maxLifetime <= 604800 &&
        (testKeys === "reject" || testKeys === "allow") &&
        (untagged === "reject" || untagged === "ignore"),
      "invalid_policy",
      "input",
    );
    let unresolved: WebBotAuthPolicy["unresolved"] = "reject";
    if (Object.hasOwn(a, "unresolved") && a.unresolved !== "reject") {
      const u = snapshotOptions(a.unresolved, ["heldKeys"]);
      ensure(
        u.ok && typeof u.value.heldKeys === "function",
        "invalid_policy",
        "input",
      );
      unresolved = Object.freeze({ heldKeys: u.value.heldKeys as KeyResolver });
    }
    const { keyResolver: _resolver, ...base } = generic.value;
    const p: WebBotAuthPolicy = {
      ...base,
      freshness: generic.value.freshness,
      replay: base.replay as WebBotAuthPolicy["replay"],
      agents: a.agents as AgentTrust,
      cache: a.cache as DiscoveryCache | null,
      maxLifetime,
      testKeys,
      untagged,
      unresolved,
    };
    const inspect = () =>
      Object.freeze({
        algorithms: p.algorithms,
        maxLifetime: p.maxLifetime,
        testKeys: p.testKeys,
        untagged: p.untagged,
        maxSignatures: p.maxSignatures,
      });
    Object.defineProperties(p, {
      toJSON: { value: inspect },
      ...inspection(inspect),
    });
    Object.freeze(p);
    policies.add(p);
    return ok(p);
  } catch (e) {
    return err(bounded(e, "invalid_policy", "input"));
  }
}
export const WebBotAuthPolicy = Object.freeze({ create: createPolicy });
