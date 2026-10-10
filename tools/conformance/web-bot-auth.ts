import {
  WebBotAuth,
  Discovery,
  DiscoverySource,
  ok,
  isRequestSealError,
  serializeVerification,
  type AgentRequest,
} from "../../src/index.ts";
import { built, mapped } from "./sign-surfaces.ts";
import { decoded } from "./wire.ts";
import type { Surface } from "./loader.ts";
/** Offline source-bound execution; directory bytes and trust are explicit corpus inputs. */
export const webBotAuthSurface: Surface = async (m, r) => {
  try {
    if (
      !Object.keys(m.inputs).every((k) =>
        [
          "message",
          "message_override",
          "append_fields",
          "directory",
          "agents",
          "options",
        ].includes(k),
      )
    )
      return { ok: false, loaderReason: "invalid_manifest" };
    const input = built(m, r);
    if (!input.ok) return input;
    const a = decoded(m.inputs, r),
      p = mapped(decoded(m.policy, r)),
      now = decoded(m.now, r);
    if (
      typeof a.directory !== "string" ||
      !Array.isArray(a.agents) ||
      !a.agents.every((v: unknown) => typeof v === "string")
    )
      return { ok: false, loaderReason: "invalid_manifest" };
    const body = new TextEncoder().encode(a.directory),
      trusted = new Set(a.agents as string[]);
    const agents = async (agent: AgentRequest) => {
      if (!trusted.has(agent.location)) return ok(null);
      const source = DiscoverySource.create({
        type: agent.type,
        location: agent.location,
        requireSignedDirectory: false,
      });
      if (!source.ok) return source;
      return Discovery.resolver.fromSnapshot(source.value, body, now, [
        [
          "content-type",
          agent.type === "directory"
            ? "application/http-message-signatures-directory+json"
            : "application/json",
        ],
        ["cache-control", "max-age=7200"],
      ]);
    };
    const policy = WebBotAuth.Policy.create({
      ...p,
      agents,
      cache: null,
      freshness: { ...p.freshness, clock: () => now },
    });
    if (!policy.ok) return policy;
    const checked = await WebBotAuth.verify(
      input.value,
      policy.value,
      mapped(decoded(m.inputs.options ?? {}, r)),
    );
    if (!checked.ok) return checked;
    const serialized = serializeVerification(checked.value);
    return serialized.ok
      ? ok({
          verification: JSON.parse(new TextDecoder().decode(serialized.value)),
        })
      : serialized;
  } catch (e) {
    return isRequestSealError(e)
      ? { ok: false, error: e }
      : { ok: false, loaderReason: "invalid_manifest" };
  }
};
