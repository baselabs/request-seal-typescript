# 0004 — A referenced timer exists only while a run is active

## Context

A hung callback must reach its deadline while idle contexts let the process exit. Shared contexts preserve parent deadlines, release external signal listeners, and remain reusable after settlement.

## Decision

`withDeadline({ timeoutMs, signal, parent })` creates a frozen, branded `Context` holding an absolute `deadline` and an `AbortSignal`. The deadline is the smaller of `now + timeoutMs` and the parent's deadline.

- **Each `run(context, fn)` arms its own referenced timer** and clears it when the run settles or the deadline passes. A hung callback therefore ends with `deadline_exceeded` on Node, Deno, and Bun, and the run is settled by the timer rather than dropped.
- **An idle or settled `Context` keeps no referenced timer.** A `Context` with caller or parent signals keeps one unreferenced timer so those listeners are released at the deadline; it never holds the process open. A `Context` with no external signals keeps none.
- **Settlement leaves the `Context` reusable.** Internal release of a settled child does not release its parent and does not drop an outer run's hold.
- **A run that ends at its deadline abandons its callback; it cannot stop it.** Callbacks should honor `context.signal`. Native operations already submitted to WebCrypto cannot be interrupted, and their late results are discarded.
- **The race that decides a run uses an owned promise receiver**, so replacing `Promise.race` or `Promise.resolve` after load cannot forge the outcome.

## Consequences

Callers can create many `Context` values cheaply. Code that wraps a callback must pass `context.signal` to its own I/O to stop real work; the deadline only stops the wait. Timers are the one global resource this module touches, so a change to timer handling needs the child-process tests on all three runtimes. The one test that makes timer reference methods throw skips Deno, whose timer functions the library captures at load, and it prints the reason.
