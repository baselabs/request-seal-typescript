import { snapshotOptions } from "../brand.ts";
import { ok, err, type Result } from "../result.ts";
import {
  isContext,
  withDeadline,
  run,
  remainingMs,
  releaseContext,
  type Context,
} from "../context.ts";
import {
  isMessage,
  Message,
} from "../message/index.ts";
import { Policy } from "../policy.ts";
import { verify, commitReplay } from "../verify.ts";
import { completed } from "../verification.ts";
import { isWebBotAuthPolicy, type WebBotAuthPolicy } from "./policy.ts";
import {
  isDiscoverySource,
  sourceOrigin,
  thumbprintId,
} from "../discovery/source.ts";
import { isKeySet, isResolution, type Resolution } from "../discovery/body.ts";
import { isPublicKey } from "../public_key.ts";
import {
  coreError,
  isRequestSealError,
  type CoreDetail,
} from "../errors/types.ts";
import {
  dictionaries,
  validInner,
  parameters,
  identities,
  ensure,
  fail,
  bounded,
  envelope,
} from "../signature-fields.ts";
import { CLOCK_MAX_SECONDS } from "../constants.ts";
import { retentionEnd } from "../replay/claim.ts";
import {
  agents,
  identifier,
  originAgent,
  component,
  required,
  nested,
  schemas,
  type Agent,
} from "./support.ts";
import {
  WEB_BOT_AUTH_PROFILE,
  completedEnvelope,
  type WebBotAuthVerification,
  type WebBotAuthSignature,
  type AgentPrincipal,
  type WebBotAuthReplayFacts,
} from "./verification.ts";
const testKeys = new Set([
  "BHj8s0GPnMEQtkaULIM-PLgEhLBbuGUQ1vMxmBWZzEo",
  "oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA",
  "ydQXMtvbsOsZyFir-Y7A8t7fKEM1gbKPvyFkdpu4fvI",
  "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U",
]);
function unresolved(detail: CoreDetail): never {
  return fail("agent_unresolved", "key", detail);
}
function clock(p: WebBotAuthPolicy): number {
  let n: unknown;
  try {
    n = p.freshness.clock();
  } catch {
    n = null;
  }
  ensure(
    typeof n === "number" &&
      Number.isSafeInteger(n) &&
      n >= 0 &&
      n <= CLOCK_MAX_SECONDS,
    "invalid_clock",
    "freshness",
  );
  return n;
}
async function callback<T>(
  context: Context,
  fn: () => Promise<Result<T>> | Result<T>,
  failureDetail: CoreDetail = "untrusted_agent",
): Promise<T> {
  const r = await run(context, async () => {
    try {
      return ok(await fn());
    } catch {
      return err(coreError("agent_unresolved", "key", "source_unavailable"));
    }
  });
  if (!r.ok)
    unresolved(
      r.error.reason === "deadline_exceeded" ? "timeout" : "source_unavailable",
    );
  const s = snapshotOptions(r.value, ["ok", "value", "error"]);
  if (
    !s.ok ||
    Object.keys(s.value).length !== 2 ||
    s.value.ok !== true ||
    !Object.hasOwn(s.value, "value")
  )
    unresolved(failureDetail);
  return s.value.value as T;
}
async function associated(
  agent: Agent | undefined,
  params: Readonly<Record<string, unknown>>,
  p: WebBotAuthPolicy,
  c: Context,
): Promise<
  Readonly<{
    algorithm: Resolution["algorithm"];
    key: Resolution["key"];
    principal: AgentPrincipal;
  }>
> {
  if (!agent) unresolved("missing_member");
  if (agent.type === "unsupported") unresolved("unsupported_type");
  if (agent.type === "directory" && !originAgent(agent.location))
    unresolved("not_an_origin");
  const id = identifier(agent);
  const configured = await callback(c, () =>
    p.agents(
      Object.freeze({
        identifier: id,
        location: agent.location,
        type: agent.type as "directory" | "jwks_uri" | "cimd",
      }),
    ),
  );
  if (!isKeySet(configured) && !isDiscoverySource(configured))
    unresolved("untrusted_agent");
  const source = isKeySet(configured) ? configured.source : configured;
  if (
    source.type !== agent.type ||
    identifier({ location: source.location, type: source.type }) !== id ||
    (agent.type !== "directory" &&
      source.location !== agent.location.split("#")[0]) ||
    source.maxRedirects !== 0
  )
    unresolved("source_mismatch");
  if (source.revoked.includes(params.keyid as string))
    unresolved("revoked_key");
  const now = clock(p);
  let resolved: Result<Resolution>;
  if (isKeySet(configured))
    resolved = await run(c, () =>
      configured.lookup(params.keyid, p.algorithms, now),
    );
  else {
    if (!p.cache) unresolved("source_unavailable");
    resolved = await p.cache.resolve(source, params.keyid, {
      algorithms: p.algorithms,
      clock: () => now,
      context: c,
    });
  }
  if (!resolved.ok)
    unresolved(
      resolved.error.reason === "deadline_exceeded"
        ? "timeout"
        : isKeySet(configured) || resolved.error.reason === "unknown_key"
          ? "unknown_key"
          : resolved.error.reason === "revoked_key"
            ? "revoked_key"
            : "source_unavailable",
    );
  const r = resolved.value;
  if (
    !isResolution(r) ||
    r.sourceType !== source.type ||
    r.location !== source.location ||
    r.origin !== sourceOrigin(new URL(source.location))
  )
    unresolved("source_mismatch");
  const thumb = await run(c, () => r.key.thumbprint());
  if (!thumb.ok) {
    if (thumb.error.reason === "deadline_exceeded") unresolved("timeout");
    unresolved("source_mismatch");
  }
  if (thumb.value !== params.keyid) unresolved("source_mismatch");
  if (
    source.type === "directory" &&
    source.requireSignedDirectory &&
    r.proof !== "signed"
  )
    unresolved("source_unavailable");
  return Object.freeze({
    algorithm: r.algorithm,
    key: r.key,
    principal: Object.freeze({
      kind: "agent",
      identifier:
        agent.type === "directory" ? id : agent.location.split("#")[0]!,
      type: agent.type,
      origin: r.origin,
      thumbprint: thumb.value,
      provenance: Object.freeze({
        sourceType: r.sourceType,
        proof: r.proof,
        fetchedAt: r.fetchedAt,
        revision: r.revision,
      }),
    }),
  });
}
async function resolve(
  agent: Agent | undefined,
  label: string,
  params: Readonly<Record<string, unknown>>,
  p: WebBotAuthPolicy,
  c: Context,
) {
  try {
    return await associated(agent, params, p, c);
  } catch (e) {
    if (
      !isRequestSealError(e) ||
      e.kind !== "core" ||
      e.reason !== "agent_unresolved" ||
      p.unresolved === "reject" ||
      ["revoked_key", "source_mismatch", "not_an_origin"].includes(e.detail!)
    )
      throw e;
    const result = await callback(
      c,
      () =>
        p.unresolved !== "reject"
          ? p.unresolved.heldKeys(
              Object.freeze({
                label,
                keyid: params.keyid as string,
                tag: params.tag as string,
              }),
              c,
            )
          : ok(null),
      "unknown_key",
    );
    const r = snapshotOptions(result, ["algorithm", "key"]);
    if (
      !r.ok ||
      !isPublicKey(r.value.key) ||
      !p.algorithms.some(
        (a) => JSON.stringify(a) === JSON.stringify(r.value.algorithm),
      )
    )
      unresolved("unknown_key");
    const key = r.value.key;
    const thumb = await run(c, () => key.thumbprint());
    if (!thumb.ok) {
      if (thumb.error.reason === "deadline_exceeded") unresolved("timeout");
      unresolved("unknown_key");
    }
    if (thumb.value !== params.keyid) unresolved("unknown_key");
    return {
      algorithm: r.value.algorithm as Resolution["algorithm"],
      key: r.value.key,
      principal: Object.freeze({
        kind: "key" as const,
        thumbprint: thumb.value,
      }),
    };
  }
}
export async function verifyWebBotAuth(
  message: unknown,
  policy: unknown,
  options: unknown = {},
): Promise<Result<WebBotAuthVerification>> {
  let owned: Context | undefined;
  try {
    ensure(isWebBotAuthPolicy(policy), "invalid_policy", "input");
    const p = policy;
    const o = snapshotOptions(options, [
      "representation",
      "digestState",
      "timeoutMs",
      "context",
    ]);
    ensure(o.ok, "invalid_options", "input");
    const timeout = Object.hasOwn(o.value, "timeoutMs")
      ? o.value.timeoutMs
      : 5000;
    ensure(
      typeof timeout === "number" &&
        Number.isInteger(timeout) &&
        timeout >= 1 &&
        timeout <= 300000,
      "invalid_options",
      "input",
    );
    ensure(
      !Object.hasOwn(o.value, "context") || isContext(o.value.context),
      "invalid_options",
      "input",
    );
    const child = withDeadline({
      timeoutMs: timeout,
      ...(isContext(o.value.context) ? { parent: o.value.context } : {}),
    });
    ensure(child.ok, "invalid_options", "input");
    const c = (owned = child.value);
    ensure(
      isMessage(message) && message.kind === "request",
      "invalid_message",
      "input",
    );
    const checked = Message.create(message);
    ensure(checked.ok, "invalid_message", "input");
    const m = checked.value;
    const [inputs, signatures] = dictionaries(m, p.maxSignatures);
    ensure(
      JSON.stringify([...inputs.keys()].sort()) ===
        JSON.stringify([...signatures.keys()].sort()),
      "label_mismatch",
      "fields",
    );
    const selected = [...inputs].filter(
        ([, v]) => parameters(v).tag === "web-bot-auth",
      ),
      ignored = [...inputs]
        .filter(([, v]) => parameters(v).tag !== "web-bot-auth")
        .map(([k]) => k);
    ensure(
      p.untagged !== "reject" || !ignored.length,
      "unexpected_signature",
      "policy",
    );
    ensure(selected.length > 0, "no_web_bot_auth_signature", "fields");
    const members = agents(m),
      present = m.fields.some(
        (f) => f.name.toLowerCase() === "signature-agent",
      );
    const results = Object.create(null) as Record<string, WebBotAuthSignature>;
    for (const [label, input] of selected) {
      if (remainingMs(c) <= 0) unresolved("timeout");
      ensure(validInner(input), "invalid_signature_input", "fields");
      const params = parameters(input);
      ensure(thumbprintId(params.keyid), "invalid_keyid", "policy");
      ensure(
        p.testKeys === "allow" || !testKeys.has(params.keyid),
        "test_key_rejected",
        "policy",
      );
      const ids = new Set(identities(input));
      const has = (name: string, key?: string) =>
        ids.has(
          identities({
            kind: "inner_list",
            value: [component(name, key)],
            parameters: [],
          })[0]!,
        );
      ensure(
        has("@authority") || has("@target-uri"),
        "missing_required_component",
        "policy",
      );
      const agent = members.get(label);
      if (!agent && present) unresolved("missing_member");
      ensure(
        !agent || has("signature-agent", label),
        "missing_required_component",
        "policy",
      );
      ensure(
        typeof params.created === "number",
        "missing_created",
        "freshness",
      );
      ensure(
        typeof params.expires === "number",
        "missing_expires",
        "freshness",
      );
      ensure(
        params.expires > params.created &&
          params.expires - params.created <= p.maxLifetime,
        "lifetime_exceeded",
        "freshness",
      );
      const now = clock(p);
      ensure(
        params.created <= now + p.freshness.skew,
        "created_in_future",
        "freshness",
      );
      ensure(now < params.expires + p.freshness.skew, "expired", "freshness");
      ensure(
        p.freshness.maxAge === null ||
          now - p.freshness.skew <= params.created + p.freshness.maxAge,
        "too_old",
        "freshness",
      );
      const resolved = await resolve(agent, label, params, p, c);
      const generic = Policy.create({
        algorithms: p.algorithms,
        components: required(
          p.components,
          agent ? [component("signature-agent", label)] : [],
        ),
        keyResolver: async () =>
          ok({ algorithm: resolved.algorithm, key: resolved.key }),
        freshness: p.freshness,
        content: p.content,
        replay: "not_required",
        maxSignatures: p.maxSignatures,
        fieldSchemas: schemas(p.fieldSchemas),
      });
      ensure(generic.ok, "invalid_policy", "input");
      const v = await verify(m, generic.value, {
        label,
        context: c,
        ...(Object.hasOwn(o.value, "representation")
          ? { representation: o.value.representation }
          : {}),
        ...(Object.hasOwn(o.value, "digestState")
          ? { digestState: o.value.digestState }
          : {}),
      });
      if (!v.ok) throw v.error;
      const stamped = completed({
        ...v.value,
        profile: WEB_BOT_AUTH_PROFILE,
        principal: resolved.principal,
      });
      if (!stamped.ok) throw stamped.error;
      results[label] = stamped.value as WebBotAuthSignature;
    }
    const evidence = nested(selected, inputs);
    let replay: WebBotAuthVerification["replay"] = "not_required";
    if (p.replay !== "not_required") {
      const facts: WebBotAuthReplayFacts["signatures"][number][] = [];
      const ends: number[] = [];
      for (const [label, v] of Object.entries(results)) {
        const params = Object.fromEntries(
          v.signature.parameters.map(([k, b]) => [k, b.value]),
        );
        ensure(
          typeof params.nonce === "string" && params.nonce.length > 0,
          "missing_replay_identifier",
          "replay",
        );
        ensure(v.freshness !== "not_evaluated", "invalid_policy", "input");
        const f = v.freshness;
        const end = retentionEnd({
          created: f.created,
          expires: f.expires,
          maxAge: f.maxAge,
          skew: f.skew,
        });
        if (!end.ok) throw end.error;
        ends.push(end.value);
        const principal = v.principal;
        const agent =
          principal.kind === "key"
            ? principal
            : Object.freeze({
                kind: principal.kind,
                identifier: principal.identifier,
                type: principal.type,
                origin: principal.origin,
                thumbprint: principal.thumbprint,
              });
        facts.push(
          Object.freeze({
            label,
            identifier: params.nonce,
            algorithm: v.signature.algorithm,
            keyid: params.keyid as string,
            agent,
            created: params.created as number,
            expires: params.expires as number,
          }),
        );
      }
      ensure(
        Math.min(...ends) <= CLOCK_MAX_SECONDS,
        "retention_exceeded",
        "replay",
      );
      replay = await commitReplay(
        Object.freeze({
          profile: WEB_BOT_AUTH_PROFILE,
          signatures: Object.freeze(facts),
        }),
        Math.min(...ends),
        p.replay,
        c,
      );
      for (const [label, v] of Object.entries(results)) {
        const stamped = completed({ ...v, replay });
        if (!stamped.ok) throw stamped.error;
        results[label] = stamped.value as WebBotAuthSignature;
      }
    }
    return completedEnvelope(results, evidence, ignored, replay);
  } catch (e) {
    if (isRequestSealError(e)) return err(e);
    return err(envelope(e));
  } finally {
    if (owned) releaseContext(owned);
  }
}
