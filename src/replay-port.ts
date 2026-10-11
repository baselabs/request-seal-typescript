import type { Context } from "./context.ts";
import type { Result } from "./result.ts";
/** A caller-owned atomic store. Cancellation cannot undo an already committed claim. */
export type ReplayClaim = Readonly<{
  namespace: Uint8Array;
  key: Uint8Array;
  retainUntil: number | bigint;
}>;
/** Bounded callback vocabulary; normalized by Replay.claim and Replay.sweep. */
export type ReplayStoreFailure = "unavailable" | "timeout" | "full" | "failure";
/** A store result with branded errors or the bounded callback failure vocabulary. */
export type ReplayStoreResult<T> = Result<T> | Readonly<{ok: false; error: ReplayStoreFailure}>;
/** A caller-owned atomic claim and expiration-sweep port. */
export type ReplayStore = Readonly<{
  /** Public adapter identity; unnamed caller implementations use "caller". */
  identity?: string;
  /** Atomically reserve the claim or report that it was already claimed. */
  claim: (
    claim: ReplayClaim,
    context: Context,
  ) =>
    | ReplayStoreResult<"claimed" | "already_claimed">
    | Promise<ReplayStoreResult<"claimed" | "already_claimed">>;
  /** Remove expired replay claims and return the removal count. */
  sweep: (
    now: number,
    context: Context,
  ) => ReplayStoreResult<number> | Promise<ReplayStoreResult<number>>;
}>;
/** Verified signature and profile facts supplied to a replay commitment callback. */
export type ReplayFacts = Readonly<{
  identifier: string;
  algorithm: import("./crypto/algorithm.ts").SigningAlgorithm;
  keyid: string | null;
  tag: string | null;
  created: number | null;
  expires: number | null;
  profile: Readonly<{ name: "rfc9421" }> | import("./profile.ts").ProfileStamp;
}>;

/** Successful atomic claim; contains only public adapter identity and retention. */
export type ReplayReceipt = Readonly<{store: string; retainUntil: number}>;
