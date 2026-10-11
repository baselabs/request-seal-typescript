import type { Verification } from "../verification.ts";
import type { ReplayReceipt } from "../replay-port.ts";
import type { SigningAlgorithm } from "../crypto/algorithm.ts";
import type { Proof } from "../discovery/body.ts";
import { inspection } from "../brand.ts";
/** Pinned Web Bot Auth profile metadata. */
export const WEB_BOT_AUTH_PROFILE = Object.freeze({
  name: "web_bot_auth" as const,
  revision: "draft-ietf-webbotauth-httpsig-protocol-00" as const,
});
/** Profile name `web_bot_auth` and revision `draft-ietf-webbotauth-httpsig-protocol-00`. */
export type WebBotAuthProfile = typeof WEB_BOT_AUTH_PROFILE;
/** A verified agent identity with discovery provenance and key thumbprint. */
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
/** A verified held-key principal identified by its thumbprint. */
export type HeldPrincipal = Readonly<{ kind: "key"; thumbprint: string }>;
/** Single-signature verification facts narrowed to Web Bot Auth principals. */
export type WebBotAuthSignature = Omit<Verification, "profile" | "principal"> &
  Readonly<{
    profile: WebBotAuthProfile;
    principal: AgentPrincipal | HeldPrincipal;
  }>;
/** Verified Web Bot Auth envelope facts supplied to a replay commitment callback. */
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
/** A branded Web Bot Auth envelope with per-label facts, evidence, and replay status. */
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
/** Check the private brand of a Web Bot Auth verification envelope. */
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
    ...inspection(inspect),
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
