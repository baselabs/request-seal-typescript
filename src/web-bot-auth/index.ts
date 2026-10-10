import { WebBotAuthPolicy } from "./policy.ts";
import { verifyWebBotAuth } from "./verify.ts";
import { signWebBotAuth } from "./sign.ts";
export const WebBotAuth = Object.freeze({
  Policy: WebBotAuthPolicy,
  verify: verifyWebBotAuth,
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
