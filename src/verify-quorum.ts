import { snapshotOptions } from "./brand.ts";
import { isMessage, Message } from "./message/index.ts";
import { isQuorum } from "./quorum.ts";
import { isContext, withDeadline, remainingMs } from "./context.ts";
import {
  isAcceptSignature,
  applicable,
  type AcceptSignature,
} from "./accept-signature.ts";
import {
  dictionaries,
  parameters,
  identities,
  ensure,
  fail,
  bounded,
  envelope,
} from "./signature-fields.ts";
import { verifyCandidate } from "./verify.ts";
import { span } from "./telemetry.ts";
import { evaluateQuorum, type Candidate } from "./quorum/evaluation.ts";
import {
  completeQuorum,
  type QuorumVerification,
} from "./quorum/verification.ts";
import { custodyError, isRequestSealError } from "./errors/types.ts";
import type { Verification } from "./verification.ts";
import { ok, err, type Result } from "./result.ts";
/** Verify bounded HTTP signatures and evaluate the configured quorum policy. */
export function verifyQuorum(
  message: unknown,
  quorum: unknown,
  options: unknown,
): Promise<Result<QuorumVerification>> {
  return span("verifyQuorum", () => verifyQuorumSpanned(message, quorum, options), r => r.ok ? "ok" : "error", r => r.ok ? undefined : r.error);
}
async function verifyQuorumSpanned(
  message: unknown,
  quorum: unknown,
  options: unknown,
): Promise<Result<QuorumVerification>> {
  try {
    const a = snapshotOptions(options, ["acceptSignature", "context"]);
    ensure(a.ok, "invalid_options", "input");
    ensure(isQuorum(quorum), "invalid_quorum", "input");
    ensure(quorum.slots.every(s => s.policy.replay === "not_required"), "invalid_policy", "input");
    ensure(isMessage(message), "invalid_message", "input");
    const validated = Message.create(message);
    ensure(validated.ok, "invalid_message", "input");
    const m = validated.value;
    const c = Object.hasOwn(a.value, "context")
      ? isContext(a.value.context)
        ? ok(a.value.context)
        : err(custodyError("invalid_options"))
      : withDeadline();
    ensure(c.ok, "invalid_options", "input");
    const requests: AcceptSignature = Object.hasOwn(a.value, "acceptSignature")
      ? (a.value.acceptSignature as AcceptSignature)
      : Object.freeze([]);
    ensure(
      !Object.hasOwn(a.value, "acceptSignature") || isAcceptSignature(requests),
      "invalid_accept_signature",
      "negotiation",
    );
    const allowed = applicable(requests, m.kind);
    if (!allowed.ok) return allowed;
    const [inputs, signatures] = dictionaries(m, quorum.maxSignatures);
    ensure(
      JSON.stringify([...inputs.keys()].sort()) ===
        JSON.stringify([...signatures.keys()].sort()),
      "label_mismatch",
      "fields",
    );
    const candidates: Candidate[] = [],
      facts: QuorumVerification["nonqualifying"][number][] = [],
      verified = new Map<Candidate, Verification>();
    for (const l of [...inputs.keys()].sort()) {
      if (remainingMs(c.value) <= 0) throw custodyError("deadline_exceeded");
      const input = inputs.get(l)!,
        params = parameters(input),
        slots = [...quorum.slots]
          .filter(
            (s) =>
              (s.label === null || s.label === l) &&
              (s.tag === null || s.tag === params.tag),
          );
      if (slots.length === 0) {
        facts.push({
          label: l,
          slot: null,
          reason: "unexpected_signature",
          layer: "quorum",
        });
        ensure(
          quorum.unexpected === "ignore",
          "unexpected_signature",
          "quorum",
        );
        continue;
      }
      let qualified = false,
        last: QuorumVerification["nonqualifying"][number] | undefined;
      const baseCache: import("./verify.ts").BaseCache = new Map();
      for (const slot of slots) {
        let r: Awaited<ReturnType<typeof verifyCandidate>>;
        try {
          r = await verifyCandidate(m, slot.policy, {
            label: l,
            context: c.value,
          }, {input, signature: signatures.get(l)! as import("./structured-fields/index.ts").Item, baseCache});
        } catch (fault) {
          // Per-label rescue isolates a defective label as its own
          // nonqualifying internal fact, never a whole-call failure.
          if (isRequestSealError(fault) && fault.kind === "custody") return err(fault);
          const faulted = envelope(fault);
          if (faulted.kind !== "core") throw fault;
          last = {
            label: l,
            slot: slot.id,
            reason: faulted.reason,
            layer: faulted.layer,
          };
          facts.push(last);
          continue;
        }
        if (r.ok) {
          const record = Object.freeze({
            slot,
            label: l,
            identity: r.value.identity,
            input,
          });
          candidates.push(record);
          verified.set(record, r.value.verification);
          qualified = true;
        } else {
          if (
            r.error.kind === "custody" &&
            r.error.reason === "deadline_exceeded"
          )
            return r;
          ensure(r.error.kind === "core", "invalid_quorum", "input");
          last = {
            label: l,
            slot: slot.id,
            reason: r.error.reason,
            layer: r.error.layer,
          };
          facts.push(last);
        }
      }
      if (!qualified && quorum.invalid === "reject")
        fail("nonqualifying_signature", "quorum", last!.reason);
    }
    const assignment = await evaluateQuorum(candidates, quorum, requests, c.value);
    if (!assignment.ok) return assignment;
    for (const request of requests) {
      const needed = [...identities(request.components)].sort();
      ensure(
        assignment.value.pool.some(
          (r) =>
            r.label === request.label &&
            JSON.stringify([...identities(r.input)].sort()) ===
              JSON.stringify(needed) &&
            Object.entries(request.parameters).every(([k, v]) => {
              const actual = parameters(r.input)[k];
              return v === true
                ? typeof actual === "number" && Number.isInteger(actual)
                : actual === v;
            }),
        ),
        "negotiation_unfulfilled",
        "negotiation",
      );
    }
    const chosen = [...assignment.value.chosen].sort(
        (a, b) => quorum.slots.indexOf(a.slot) - quorum.slots.indexOf(b.slot),
      ),
      results = Object.create(null) as Record<string, Verification>;
    for (const r of chosen) {
      const original = candidates.find(
        (c) => c.slot === r.slot && c.label === r.label,
      )!;
      results[r.label] = verified.get(original)!;
    }
    // The wall-clock bound lives in the assignment search: an accepted
    // assignment, including one accepted at deadline exhaustion, completes.
    // The remaining work here is synchronous and bounded.
    return completeQuorum({
      profile: { name: "rfc9421" },
      mode: quorum.mode,
      unit: quorum.unit,
      sharedPrincipal: quorum.sharedPrincipal,
      required: quorum.slots.filter((s) => s.required).map((s) => s.id),
      satisfied: quorum.slots
        .filter((s) => chosen.some((r) => r.slot === s))
        .map((s) => s.id),
      count: assignment.value.count,
      qualifying: chosen.map((r) => ({
        label: r.label,
        slot: r.slot.id,
        principal: r.slot.principal,
        role: r.slot.role,
      })),
      signatures: results,
      nonqualifying: facts,
      bindings: quorum.bindings.length
        ? quorum.bindings.map((b) => [b, "satisfied"] as const)
        : "not_required",
      negotiation: requests.length ? "fulfilled" : "not_requested",
      replay: "not_required",
      principal: "unattributed",
      authorization: "not_evaluated",
    });
  } catch (e) {
    if (isRequestSealError(e) && e.kind === "custody") return err(e);
    return err(envelope(e));
  }
}
