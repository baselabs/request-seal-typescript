**Status:** maintained · **Kind:** reference · **Updated:** October 17, 2026 ·
**Governed by:** the versioned telemetry contract v1, mirroring RequestSeal for Elixir ·
**Review when:** the event surface, outcomes, or emission sites change

# Telemetry

`Telemetry.attach(subscriber)` observes verification, replay, and custody operations with bounded, low-cardinality events. Handlers own storage and aggregation; the library keeps no history. The surface is opt-in, has zero dependencies, and never changes what an operation returns — a subscriber that throws is silently skipped, and the operation it observes still completes.

```ts
import assert from "node:assert/strict";
import { Custody, Message, Policy, Telemetry, ok, sign, verify, withDeadline } from "@request-seal/core";

// At most sixteen subscribers run at once; the handle's detach() stops delivery.
const seen: string[] = [];
const attached = Telemetry.attach((event) => seen.push(`${event.event} ${event.outcome}${event.reason ? " " + event.reason : ""}`));
assert.ok(attached.ok);
const handle = attached.value;

// One real signing key; the same events would fire for any custody algorithm.
const h = await Custody.local("hmac-sha256", {hmac: crypto.getRandomValues(new Uint8Array(32)), identity: "telemetry-example"});
assert.ok(h.ok);
const message = await Message.request("POST", "https://partner.example/charge", [], '{"order":"A-1"}');
assert.ok(message.ok);
const signed = await sign(message.value, {label: "sig", algorithm: "hmac-sha256", signatureInput: '("@method");keyid="telemetry-example"'},
  (a, d, c = withDeadline().value) => h.value.sign(a, d, c));
assert.ok(signed.ok);
const policy = Policy.create({algorithms: ["hmac-sha256"], components: '("@method")',
  keyResolver: () => ok({algorithm: "hmac-sha256", key: h.value}), freshness: "not_evaluated", content: "not_required", replay: "not_required"});
assert.ok(policy.ok);
const verified = await verify(signed.value, policy.value, {label: "sig"});
assert.ok(verified.ok);
// The public verify entry emitted one event; the shared custody signing path
// emitted its own. Internal per-label work emits nothing.
assert.deepEqual(seen.filter((line) => line.startsWith("verify ")), ["verify ok"]);
assert.ok(seen.includes("custodySign ok"));
handle.detach();
await h.value.release();
```

## Events (v1)

| Event | Emitted by | Outcomes |
| --- | --- | --- |
| `verify` | `verify` | `ok`, `error` |
| `verifyQuorum` | `verifyQuorum` | `ok`, `error` |
| `webBotAuthVerify` | `WebBotAuth.verify` | `ok`, `error` |
| `replayClaim` | the required-replay commit every profile shares | `claimed`, `already_claimed`, `error` |
| `custodySign` | the shared custody signing path of both `sign` forms | `ok`, `error` |

`Telemetry.events()` lists the names. Internal per-label work inside `verifyQuorum` emits nothing; the quorum event covers the whole call.

## Payload

Every event is a frozen object with exactly six fields:

| Field | Meaning |
| --- | --- |
| `event` | one of the v1 names |
| `outcome` | the closed outcome vocabulary above |
| `reason` | the parity rule id exactly as the caller receives it (`core/fields.unknown_label`, `custody/deadline_exceeded`), or `null` on success |
| `layer` | the error's layer (`fields`, `quorum`, `internal`, …), or `null` |
| `detail` | the error's bounded detail (an exception class for `core/internal.internal`), or `null` |
| `durationMs` | monotonic milliseconds covering the emitting call |

No signature label, key ID, header name or value, URL, principal, nonce, body or base bytes, exception message, or any other attacker-controlled or high-cardinality value ever appears in an event. A rejected verification reports its bounded `reason` and `layer` exactly as returned to the caller, so resource exhaustion (`core/input.limit`, the retryable `core/quorum.deadline`) and internal faults (`core/internal.internal`) are countable without reading anything else.

## Attachment

`Telemetry.attach` accepts one function and returns `ok(handle)` or a `core/input.invalid_options` error. At most sixteen subscribers run at once; a seventeenth attaches only after a slot is freed by `detach`. `detach` is idempotent. Attachment and dispatch are synchronous and O(subscribers); there is no global state beyond the subscriber list itself.

The event names, outcomes, and payload fields are a versioned public contract: additive events and fields may arrive in minor releases; renames and removals require a major version. The Elixir package's `:telemetry` contract carries the same five events with the same closed metadata vocabulary.
