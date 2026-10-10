import type { Verification } from "../verification.ts";
import type { ReplayReceipt } from "../replay-port.ts";
import type { SigningAlgorithm } from "../crypto/algorithm.ts";
import type { Proof } from "../discovery/body.ts";
export const WEB_BOT_AUTH_PROFILE = Object.freeze({
  name: "web_bot_auth" as const,
  revision: "draft-ietf-webbotauth-httpsig-protocol-00" as const,
});
export type WebBotAuthProfile = typeof WEB_BOT_AUTH_PROFILE;
export type AgentPrincipal = Readonly<{
  kind: "agent";
  identifier: string;
  type: "directory" | "jwks_uri" | "cimd";
  origin: string;
  thumbprint: string;
  provenance: Readonly<{
    sourceType: "directory" | "jwks_uri" | "cimd";
    proof: Proof;
    fetchedAt: number;
    revision: string | null;
  }>;
}>;
export type HeldPrincipal = Readonly<{ kind: "key"; thumbprint: string }>;
export type WebBotAuthSignature = Omit<Verification, "profile" | "principal"> &
  Readonly<{
    profile: WebBotAuthProfile;
    principal: AgentPrincipal | HeldPrincipal;
  }>;
export type WebBotAuthReplayFacts = Readonly<{
  profile: WebBotAuthProfile;
  signatures: readonly Readonly<{
    label: string;
    identifier: string;
    algorithm: SigningAlgorithm;
    keyid: string;
    agent: Omit<AgentPrincipal, "provenance"> | HeldPrincipal;
    created: number;
    expires: number;
  }>[];
}>;
export type WebBotAuthVerification = Readonly<{
  profile: WebBotAuthProfile;
  signatures: Readonly<Record<string, WebBotAuthSignature>>;
  evidence: Readonly<Record<string, readonly string[]>>;
  ignored: readonly string[];
  replay: "not_required" | ReplayReceipt;
  authorization: "not_evaluated";
}>;
import { ok, err, type Result } from "../result.ts";
import { coreError } from "../errors/types.ts";
import { verificationFacts, isVerification } from "../verification.ts";
import { isReplayReceipt } from "../replay/receipt.ts";
const envelopes = new WeakSet<object>();
export function isWebBotAuthVerification(
  v: unknown,
): v is WebBotAuthVerification {
  return !!v && typeof v === "object" && envelopes.has(v);
}
/** Internal constructor; single-label facts retain their independent brands. */
export function completedEnvelope(
  signatures: Record<string, WebBotAuthSignature>,
  evidence: Record<string, readonly string[]>,
  ignored: readonly string[],
  replay: WebBotAuthVerification["replay"],
): Result<WebBotAuthVerification> {
  if (
    !Object.values(signatures).every(isVerification) ||
    (replay !== "not_required" && !isReplayReceipt(replay))
  )
    return err(coreError("invalid_verification", "binding"));
  const result: WebBotAuthVerification = Object.assign(Object.create(null), {
    profile: WEB_BOT_AUTH_PROFILE,
    signatures: Object.freeze(signatures),
    evidence: Object.freeze(evidence),
    ignored: Object.freeze([...ignored]),
    replay,
    authorization: "not_evaluated",
  });
  const inspect = () =>
    Object.freeze({
      profile: result.profile,
      labels: Object.freeze(Object.keys(result.signatures).sort()),
      replay: result.replay,
      authorization: result.authorization,
    });
  Object.defineProperties(result, {
    toJSON: { value: inspect },
    [Symbol.for("nodejs.util.inspect.custom")]: { value: inspect },
    [Symbol.for("Deno.customInspect")]: { value: inspect },
  });
  envelopes.add(result);
  return ok(Object.freeze(result));
}
/** The pinned corpus canonical form is the sorted map of per-label facts. */
export function webBotAuthFacts(
  value: WebBotAuthVerification,
): Result<unknown> {
  const facts = Object.create(null) as Record<string, unknown>;
  for (const label of Object.keys(value.signatures).sort()) {
    const r = verificationFacts(value.signatures[label]);
    if (!r.ok) return r;
    facts[label] = r.value;
  }
  return ok(facts);
}
