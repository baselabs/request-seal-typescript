import { snapshotOptions } from "./brand.ts";
import { isContext, withDeadline, run, remainingMs, releaseContext, type Context } from "./context.ts";
import {
  CLOCK_MAX_SECONDS,
  SIGNATURE_MAX_BYTES,
  KEY_IDENTITY_MAX_BYTES,
} from "./constants.ts";
import {
  isMessage,
  isBody,
  Message,
  type Message as HttpMessage,
} from "./message/index.ts";
import {
  isPolicy,
  type Policy,
  type Freshness,
  type ResolvedKey,
  type Verifier,
} from "./policy.ts";
import { resolveAlgorithm, selection, type SigningAlgorithm } from "./crypto/algorithm.ts";
import { Crypto } from "./crypto/index.ts";
import { isKeyHandle } from "./key_handle.ts";
import { isPublicKey } from "./public_key.ts";
import { isKeyIdentity, KeyIdentity } from "./key_identity.ts";
import { build } from "./signature-base/index.ts";
import { digestField, checkDigest, isDigestState } from "./digest.ts";
import {
  label,
  dictionaries,
  validInner,
  parameters,
  identities,
  ensure,
  fail,
  bounded,
} from "./signature-fields.ts";
import {
  completed,
  type Verification,
  type FreshnessFacts,
} from "./verification.ts";
import type { InnerList, Item } from "./structured-fields/index.ts";
import type { ReplayFacts } from "./replay-port.ts";
import { createClaim, retainUntil as retention } from "./replay/claim.ts";
import { createReceipt } from "./replay/receipt.ts";
import { claim as submitClaim } from "./replay/store.ts";
import { coreError, custodyError, isRequestSealError } from "./errors/types.ts";
import { ok, err, type Result } from "./result.ts";
async function freshness(
  params: Readonly<Record<string, unknown>>,
  policy: Freshness | "not_evaluated",
  context: Context,
): Promise<Verification["freshness"]> {
  if (policy === "not_evaluated") return policy;
  const clock = await run(context, async () => {
    try {
      return ok(policy.clock());
    } catch {
      return err(coreError("invalid_clock", "freshness"));
    }
  });
  if (!clock.ok && clock.error.kind === "custody" && clock.error.reason === "deadline_exceeded") throw clock.error;
  ensure(
    clock.ok &&
      typeof clock.value === "number" &&
      Number.isSafeInteger(clock.value) &&
      clock.value >= 0 &&
      clock.value <= CLOCK_MAX_SECONDS,
    "invalid_clock",
    "freshness",
  );
  const now = clock.value,
    created = (params.created ?? null) as number | null,
    expires = (params.expires ?? null) as number | null;
  ensure(
    policy.maxAge === null || created !== null,
    "missing_created",
    "freshness",
  );
  ensure(
    !policy.requireExpires || expires !== null,
    "missing_expires",
    "freshness",
  );
  ensure(
    created === null || created <= now + policy.skew,
    "created_in_future",
    "freshness",
  );
  const earliest = Math.max(now - policy.skew, created ?? now - policy.skew);
  ensure(expires === null || expires > earliest, "expired", "freshness");
  ensure(
    policy.maxAge === null || earliest <= created! + policy.maxAge,
    "too_old",
    "freshness",
  );
  return Object.freeze({
    now,
    created,
    expires,
    maxAge: policy.maxAge,
    skew: policy.skew,
  });
}
/** Internal coverage/freshness pipeline shared by selected verification and preflight. */
export async function authenticationPreflight(input: InnerList, components: InnerList, extra: Policy["extraComponents"], freshnessPolicy: Policy["freshness"] | (() => Policy["freshness"]), context: Context): Promise<Verification["freshness"]> {
    const covered = new Set(identities(input)),
      needed = new Set(identities(components));
    ensure(
      [...needed].every((id) => covered.has(id)),
      "missing_required_component",
      "policy",
    );
    ensure(
      extra === "allow" ||
        [...covered].every((id) => needed.has(id)),
      "unexpected_component",
      "policy",
    );
    return freshness(parameters(input), typeof freshnessPolicy === "function" ? freshnessPolicy() : freshnessPolicy, context);

}
async function content(
  m: HttpMessage,
  input: InnerList,
  policy: Policy["content"],
  options: Readonly<Record<string, unknown>>,
): Promise<Verification["content"]> {
  if (policy === "not_required") return policy;
  const name = policy.kind === "content" ? "content-digest" : "repr-digest";
  ensure(
    input.value.some(
      (item) =>
        item.value.value === name &&
        item.parameters.every(
          ([k, v]) =>
            (policy.section === "trailers" ? ["tr", "sf"] : ["sf"]).includes(
              k,
            ) &&
            v.kind === "boolean" &&
            v.value === true,
        ) &&
        item.parameters.some(([k]) => k === "tr") ===
          (policy.section === "trailers"),
    ),
    "digest_not_covered",
    "content",
  );
  const expected = digestField(m, policy.kind, policy.section);
  if (!expected.ok) {
    if (expected.error.reason === "limit") fail("limit", "input");
    fail("digest_unsupported", "content");
  }
  const names = expected.value.value
    .filter(([k]) => k === "sha-256" || k === "sha-512")
    .map(([k]) => k);
  ensure(
    names.length > 0 && names.every((k) => policy.algorithms.includes(k)),
    "digest_unsupported",
    "content",
  );
  const checked = await checkDigest(m, policy.kind, {
    section: policy.section,
    ...(Object.hasOwn(options, "representation")
      ? { representation: options.representation }
      : {}),
    ...(Object.hasOwn(options, "digestState")
      ? { digestState: options.digestState }
      : {}),
  });
  if (!checked.ok) {
    if (checked.error.reason === "mismatch") fail("digest_mismatch", "content");
    if (
      ["invalid_body", "body_unavailable", "representation_required"].includes(
        checked.error.reason,
      )
    )
      fail("body_unavailable", "content");
    if (checked.error.reason === "limit") fail("limit", "input");
    fail("digest_unsupported", "content");
  }
  return checked.value;
}
async function replay(
  params: Readonly<Record<string, unknown>>,
  algorithm: SigningAlgorithm,
  fresh: Verification["freshness"],
  policy: Policy["replay"],
  context: Context,
  profile: ReplayFacts["profile"],
): Promise<Verification["replay"]> {
  if (policy === "not_required") return policy;
  ensure(
    typeof params.nonce === "string" && params.nonce.length > 0,
    "missing_replay_identifier",
    "replay",
  );
  ensure(fresh !== "not_evaluated", "invalid_policy", "input");
  const f = fresh as FreshnessFacts;
  const retained = retention({created: f.created, expires: f.expires, maxAge: f.maxAge, skew: f.skew});
  if (!retained.ok) {
    if (retained.error.kind === "core") throw retained.error;
    // Unreachable: branded Policy and authenticated freshness already validate
    // every retention option; the only remaining rejection is core retention_exceeded.
    fail("invalid_policy", "input");
  }
  const retainUntil = retained.value;
  const facts: ReplayFacts = Object.freeze({
    identifier: params.nonce,
    algorithm,
    keyid: (params.keyid ?? null) as string | null,
    tag: (params.tag ?? null) as string | null,
    created: f.created,
    expires: f.expires,
    profile,
  });
  return commitReplay(facts, retainUntil, policy, context);
}
/** Internal shared commit boundary; profile facts are supplied only after authentication. */
export async function commitReplay<F>(
  facts: F,
  retainUntil: number,
  policy: Omit<import('./policy.ts').ReplayPolicy, 'commitment'> & {commitment: (facts: F, context: Context) => Result<Uint8Array> | Promise<Result<Uint8Array>>},
  context: Context,
): Promise<Verification['replay']> {
  const child = withDeadline({ parent: context, timeoutMs: policy.timeoutMs });
  ensure(child.ok, "store_timeout", "replay");
  try {
    const receipt = await run(child.value, async (c) => {
      if (remainingMs(c) <= 0) return err(coreError("store_timeout", "replay"));
      let key: Uint8Array;
      try {
        const raw = await policy.commitment(facts, c);
        const result = snapshotOptions(raw, ["ok", "value", "error"]);
        if (!result.ok || Object.keys(result.value).length !== 2 || result.value.ok !== true || !(result.value.value instanceof Uint8Array) || result.value.value.length < 1 || result.value.value.length > KEY_IDENTITY_MAX_BYTES)
          return err(coreError("commitment_failed", "replay"));
        key = new Uint8Array(result.value.value);
      } catch {
        return err(coreError("commitment_failed", "replay"));
      }
      // Awaited caller work can settle after run has returned a deadline rejection.
      // Check again before the external commit point, including caller-owned ports.
      if (remainingMs(c) <= 0) return err(coreError("store_timeout", "replay"));
      const claim = createClaim({namespace: policy.namespace, key, retainUntil});
      if (!claim.ok) return err(coreError("commitment_failed", "replay"));
      try {
        const r = await submitClaim(policy.store, claim.value, c);
        if (!r?.ok)
          return err(
            coreError(
              r &&
                !r.ok &&
                r.error.kind === "replay" &&
                ["store_timeout", "store_unavailable"].includes(r.error.reason)
                ? (r.error.reason as "store_timeout")
                : "store_failed",
              "replay",
            ),
          );
        if (r.value === "already_claimed")
          return err(coreError("replayed", "replay"));
        if (r.value !== "claimed")
          return err(coreError("store_failed", "replay"));
        return createReceipt({store: policy.store.identity ?? "caller", retainUntil});
      } catch {
        return err(coreError("store_failed", "replay"));
      }
    });
    if (!receipt.ok) {
      if (receipt.error.kind === "custody") fail("store_timeout", "replay");
      throw receipt.error;
    }
    return receipt.value;
  } finally {
    releaseContext(child.value);
  }
}
/** Per-label cache; schemas remain part of the key so slot policies stay independent. */
export type BaseCache = Map<string, ReturnType<typeof build>>;
type ParsedCandidate = Readonly<{input: InnerList; signature: Item; baseCache: BaseCache}>;
export async function verifyLabel(
  message: unknown,
  policy: unknown,
  options: unknown,
  observeIdentity?: (identity: KeyIdentity) => void,
  parsed?: ParsedCandidate,
  profile: ReplayFacts["profile"] = Object.freeze({name: "rfc9421"}),
): Promise<Result<Verification>> {
  try {
    // Reserved stamps have their own bounded reason even when other options reject.
    ensure(options !== null && typeof options === "object" && !Array.isArray(options), "invalid_options", "input");
    const keys = Reflect.ownKeys(options);
    // Read all own values once before applying the reference's reserved-key order.
    const own = Object.create(null) as Record<PropertyKey, unknown>;
    for (const key of keys) own[key] = Reflect.get(options, key);
    const a = Object.freeze(own);
    ensure(!Object.hasOwn(a, "profile") && !Object.hasOwn(a, "principal"), "invalid_profile", "input");
    ensure(keys.every(k => typeof k === "string" && ["label", "representation", "digestState", "context"].includes(k)), "invalid_options", "input");
    ensure(label(a.label), "invalid_options", "input");
    ensure(isPolicy(policy), "invalid_policy", "input");
    ensure(
      !(Object.hasOwn(a, "representation") && Object.hasOwn(a, "digestState")),
      "invalid_options",
      "input",
    );
    if (Object.hasOwn(a, "representation"))
      ensure(
        policy.content !== "not_required" &&
          policy.content.kind === "representation" &&
          isBody(a.representation),
        "invalid_options",
        "input",
      );
    if (Object.hasOwn(a, "digestState"))
      ensure(
        policy.content !== "not_required" &&
          isDigestState(a.digestState) &&
          a.digestState.kind === policy.content.kind,
        "invalid_options",
        "input",
      );
    const c = Object.hasOwn(a, "context")
      ? isContext(a.context)
        ? ok(a.context)
        : err(coreError("invalid_options", "input"))
      : withDeadline();
    ensure(c.ok, "invalid_options", "input");
    ensure(isMessage(message), "invalid_message", "input");
    const validated = parsed ? ok(message) : Message.create(message);
    ensure(validated.ok, "invalid_message", "input");
    const m = validated.value;
    let input: InnerList, signature: Item;
    if (parsed) { input = parsed.input; signature = parsed.signature; }
    else {
      const [inputs, signatures] = dictionaries(m, policy.maxSignatures);
      ensure(JSON.stringify([...inputs.keys()].sort()) === JSON.stringify([...signatures.keys()].sort()), "label_mismatch", "fields");
      ensure(inputs.has(a.label), "unknown_label", "fields");
      input = inputs.get(a.label)!; signature = signatures.get(a.label)! as Item;
    }
    ensure(validInner(input), "invalid_signature_input", "fields");
    const params = parameters(input);
    ensure(
      params.nonce === undefined ||
        (typeof params.nonce === "string" &&
          params.nonce.length <= SIGNATURE_MAX_BYTES),
      "limit",
      "input",
    );
    const fresh = await authenticationPreflight(input, policy.components, policy.extraComponents, policy.freshness, c.value);
    ensure(
      !Object.hasOwn(params, "alg") ||
        policy.algorithms.some(a => typeof a === "string" && a === params.alg),
      "algorithm_not_permitted",
      "policy",
    );
    const resolution = await run(c.value, async (context) => {
      try {
        return ok(await policy.keyResolver(
          Object.freeze({
            keyid: (params.keyid ?? null) as string | null,
            label: a.label as string,
            tag: (params.tag ?? null) as string | null,
          }),
          context,
        ));
      } catch {
        return err(coreError("key_resolver_failed", "key"));
      }
    });
    if (!resolution.ok) {
      if (resolution.error.kind === "custody" && resolution.error.reason === "deadline_exceeded") throw resolution.error;
      fail("key_resolver_failed", "key");
    }
    // Callback failures are data. Only run's own cancellation may carry a deadline.
    const resolved = snapshotOptions(resolution.value, ["ok", "value", "error"]);
    ensure(resolved.ok && resolved.value.ok === true && Object.hasOwn(resolved.value, "value"), "key_resolver_failed", "key");
    ensure(resolved.value.value !== null, "unknown_key", "key");
    const r = snapshotOptions(resolved.value.value, ["algorithm", "key", "verify", "identity"]);
    ensure(r.ok, "key_resolver_failed", "key");
    const binding = r.value,
      selected = resolveAlgorithm(binding.algorithm),
      algorithm = selected.ok ? selection(selected.value) as SigningAlgorithm : null,
      key = Object.hasOwn(binding, "verify") ? binding.verify : binding.key;
    ensure(
      algorithm !== null &&
        Object.hasOwn(binding, "algorithm") &&
        Object.hasOwn(binding, "key") !== Object.hasOwn(binding, "verify") &&
        (typeof key === "function" || isPublicKey(key) || isKeyHandle(key)),
      "key_resolver_failed",
      "key",
    );
    ensure(selected.ok && (selected.value.family !== "hmac" || typeof key === "function" || isKeyHandle(key)), "key_resolver_failed", "key");
    let canonicalIdentity: KeyIdentity | undefined;
    if (isPublicKey(key) || (isKeyHandle(key) && selected.ok && selected.value.family !== "hmac" && (observeIdentity !== undefined || Object.hasOwn(binding, "identity")))) {
      const id = isPublicKey(key) ? KeyIdentity.fromPublic(key) : await key.identity(c.value);
      if (!id.ok && id.error.kind === "custody" && id.error.reason === "deadline_exceeded") throw id.error;
      ensure(id.ok && isKeyIdentity(id.value), "key_resolver_failed", "key");
      canonicalIdentity = id.value;
    }
    if (Object.hasOwn(binding, "identity")) {
      ensure(isKeyIdentity(binding.identity), "key_resolver_failed", "key");
      if (canonicalIdentity) {
        const same = KeyIdentity.same(canonicalIdentity, binding.identity);
        ensure(same.ok && same.value, "key_resolver_failed", "key");
      }
    }
    ensure(
      !Object.hasOwn(params, "alg") || (typeof algorithm === "string" && params.alg === algorithm),
      "algorithm_mismatch",
      "policy",
    );
    ensure(
      policy.algorithms.some(a => JSON.stringify(a) === JSON.stringify(algorithm)),
      "algorithm_not_permitted",
      "policy",
    );
    const cacheKey = JSON.stringify(policy.fieldSchemas);
    const base = parsed?.baseCache.get(cacheKey) ?? build(m, input, { fieldSchemas: policy.fieldSchemas });
    parsed?.baseCache.set(cacheKey, base);
    if (!base.ok)
      fail("signature_base_failed", "crypto", base.error.reason as "limit");
    const checked = await run(c.value, async (context) => {
      try {
        const sig = new Uint8Array(signature.value.value as Uint8Array),
          data = new Uint8Array(base.value);
        const r =
          typeof key === "function"
            ? await (key as Verifier)(algorithm, data, sig, context)
            : isKeyHandle(key)
              ? await key.verify(algorithm, sig, data, context)
              : await Crypto.verify(algorithm, key, sig, data);
        if (typeof key === "function") {
          const result = snapshotOptions(r, ["ok", "value", "error"]);
          if (result.ok && Object.keys(result.value).length === 2) {
            const v = result.value;
            if (v.ok === true && Object.hasOwn(v, "value")) {
              if (v.value === true) return ok(true as const);
              if (v.value === false) return err(coreError("invalid_signature", "crypto"));
            }
            if (v.ok === false && Object.hasOwn(v, "error")) return err(coreError("invalid_signature", "crypto"));
          }
        } else {
          if (r && r.ok === true && r.value === true) return ok(true as const);
          if (r && r.ok === false && r.error && (r.error.kind === "crypto" || r.error.kind === "custody") && r.error.reason === "invalid_signature")
            return err(coreError("invalid_signature", "crypto"));
        }
        return err(coreError("verifier_failed", "crypto"));
      } catch {
        return err(coreError("verifier_failed", "crypto"));
      }
    });
    if (!checked.ok) {
      if (checked.error.kind === "core" || (checked.error.kind === "custody" && checked.error.reason === "deadline_exceeded")) throw checked.error;
      fail("verifier_failed", "crypto");
    }
    if (remainingMs(c.value) <= 0) throw custodyError("deadline_exceeded");
    const contentResult = policy.content === "not_required" ? ok("not_required" as const) : await run(c.value, async () => {
      try { return ok(await content(m, input, policy.content, a)); }
      catch (e) { return err(bounded(e, "digest_unsupported", "content")); }
    });
    if (!contentResult.ok) {
      if (contentResult.error.kind === "custody" && contentResult.error.reason === "deadline_exceeded") throw contentResult.error;
      if (contentResult.error.kind === "core") throw contentResult.error;
      fail("digest_unsupported", "content");
    }
    const replayFacts = await replay(params, algorithm, fresh, policy.replay, c.value, profile);
    let identity: KeyIdentity | undefined;
    if (observeIdentity) {
      const id = await run(c.value, async () => {
        if (canonicalIdentity) return ok(canonicalIdentity);
        if (isKeyIdentity(binding.identity)) return ok(binding.identity);
        if (isPublicKey(key)) return KeyIdentity.fromPublic(key);
        if (isKeyHandle(key)) return key.identity(c.value);
        return KeyIdentity.unknown();
      });
      if (!id.ok && id.error.kind === "custody" && id.error.reason === "deadline_exceeded") throw id.error;
      ensure(id.ok && isKeyIdentity(id.value), "key_resolver_failed", "key");
      identity = id.value;
    }
    const result = completed({
      label: a.label as string,
      signature: {
        algorithm,
        covered: input.value.map(item => [item.value.value as string, item.parameters] as const),
        parameters: input.parameters,
        keyid: (params.keyid ?? null) as string | null,
        crypto: "valid",
      },
      profile, content: contentResult.value, freshness: fresh,
      replay: replayFacts, principal: "unattributed", authorization: "not_evaluated",
    });
    if (result.ok && identity) observeIdentity!(identity);
    return result;
  } catch (e) {
    if (isRequestSealError(e) && e.kind === "custody" && e.reason === "deadline_exceeded") return err(e);
    return err(bounded(e, typeof profile.name === "string" ? "invalid_options" : "invalid_policy", "input"));
  }
}

export function verify(message: unknown, policy: unknown, options: unknown): Promise<Result<Verification>> {
  return verifyLabel(message, policy, options);
}
/** Internal composition of the single-label pipeline; identities stay private. */
export async function verifyCandidate(message: unknown, policy: Policy, options: unknown, parsed?: ParsedCandidate): Promise<Result<Readonly<{verification: Verification; identity: KeyIdentity}>>> {
  let identity: KeyIdentity | undefined;
  const result = await verifyLabel(message, policy, options, id => {identity = id;}, parsed);
  return result.ok ? ok(Object.freeze({verification: result.value, identity: identity!})) : result;
}
