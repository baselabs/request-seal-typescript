import { WebBotAuthPolicy } from "./policy.ts";
import { verifyWebBotAuth } from "./verify.ts";
import { signWebBotAuth } from "./sign.ts";
/** Web Bot Auth policy construction, signing, and verification operations. */
export const WebBotAuth = Object.freeze({
  Policy: WebBotAuthPolicy,
  /** Verify an agent signature envelope under explicit trust, freshness, and replay rules. */
  verify: verifyWebBotAuth,
  /** Add a Web Bot Auth signature using explicit agent and freshness parameters. */
  sign: signWebBotAuth,
});
export { isWebBotAuthVerification } from "./verification.ts";
export { isWebBotAuthPolicy } from "./policy.ts";
export type {
  WebBotAuthPolicy,
  AgentRequest,
  AgentTrust,
  WebBotAuthReplayPolicy,
} from "./policy.ts";
export type {
  WebBotAuthProfile,
  WebBotAuthSignature,
  WebBotAuthVerification,
  WebBotAuthReplayFacts,
  AgentPrincipal,
  HeldPrincipal,
} from "./verification.ts";
