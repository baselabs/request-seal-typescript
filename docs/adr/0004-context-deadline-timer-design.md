**Status:** accepted · **Kind:** record · **Updated:** October 11, 2026 · **Governed by:** src/context.ts and the Context lifetime tests · **Review when:** timer, abort-signal, or promise handling in src/context.ts changes

# ADR 0004: A referenced timer exists only while a run is active

- Status: Accepted
- Date: October 11, 2026

## Context

Every operation that can wait, such as custody, discovery, replay, a callback, or an adapter exchange, shares an absolute deadline through a `Context`. Three failure modes are possible for a timer-based deadline:

- A callback that never settles must still end with `deadline_exceeded`. If the only pending work is that callback and the timer does not keep the process alive, Node can exit with the run dropped and no result.
- A `Context` that nobody is running must not keep a process alive for its remaining lifetime, or a short script hangs for minutes after its last call.
- A caller or parent `AbortSignal` listener must not leak when a `Context` is created and never used.

A deadline also has to survive being shared: a child `Context` never outlives its parent, and a settled `Context` can be reused.

## Decision

`withDeadline({ timeoutMs, signal, parent })` creates a frozen, branded `Context` holding an absolute `deadline` and an `AbortSignal`. The deadline is the smaller of `now + timeoutMs` and the parent's deadline.

- **Each `run(context, fn)` arms its own referenced timer** and clears it when the run settles or the deadline passes. A hung callback therefore ends with `deadline_exceeded` on Node, Deno, and Bun, and the run is settled by the timer rather than dropped.
- **An idle or settled `Context` keeps no referenced timer.** A `Context` with caller or parent signals keeps one unreferenced timer so those listeners are released at the deadline; it never holds the process open. A `Context` with no external signals keeps none.
- **Settlement leaves the `Context` reusable.** Internal release of a settled child does not release its parent and does not drop an outer run's hold.
- **A run that ends at its deadline abandons its callback; it cannot stop it.** Callbacks should honor `context.signal`. Native operations already submitted to WebCrypto cannot be interrupted, and their late results are discarded.
- **The race that decides a run uses an owned promise receiver**, so replacing `Promise.race` or `Promise.resolve` after load cannot forge the outcome.

## Strongest alternatives

1. **`AbortSignal.timeout(ms)` per call.** It is built in and simple. It cannot express a shared absolute deadline with a parent, its timer semantics differ across runtimes, and it gives no control over whether a pending timer holds the process open.
2. **One referenced timer for the lifetime of each `Context`.** The simplest way to guarantee the deadline fires. It keeps the process alive for up to the full timeout after the last use, even when everything has settled.
3. **Only unreferenced timers.** An idle `Context` costs nothing. A never-settling callback then lets the process exit with no result, which hides the failure instead of reporting it.
4. **Polling the clock when work completes.** No timers at all. A callback that never completes would never be checked.

## Deciding evidence and deletion test

`src/context.ts` arms a referenced timer during `run` and releases it when the run settles. `test/context-deadline-hold.test.ts` runs real child processes with hung callbacks and asserts `deadline_exceeded`; its idle cases assert process exit. `test/context-lifetime.test.ts` checks listener release for idle and never-run contexts. These tests observe lifecycle behavior. No removal of either timer is claimed to have been executed.

## Consequences

Callers can create many `Context` values cheaply. Code that wraps a callback must pass `context.signal` to its own I/O to stop real work; the deadline only stops the wait. Timers are the one global resource this module touches, so a change to timer handling needs the child-process tests on all three runtimes. The one test that makes timer reference methods throw skips Deno, whose timer functions the library captures at load, and it prints the reason.

## Acceptance

- `src/context.ts` implements `withDeadline`, `run`, `remainingMs`, and the internal release.
- `test/context.test.ts`, `test/context-lifetime.test.ts`, `test/context-deadline-hold.test.ts`, `test/context-deadline-in-process.test.ts`, and the Context cases in `test/foundation-fixes.test.ts` exercise Context behavior on Node, Deno, and Bun.
- `CHANGELOG.md` records the hold-only-while-running change.
