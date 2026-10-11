import {now, unrefTimer} from './runtime.ts';
import { snapshotOptions } from './brand.ts';
import { timeoutMs } from './numbers.ts';
import { TIMEOUT_DEFAULT_MS } from './constants.ts';
import { custodyError, isRequestSealError } from './errors/types.ts';
import { err, ok, type Result } from './result.ts';
// Promise.race reads its receiver's resolve at dispatch time. Use an owned
// receiver so replacing either global static after load cannot forge a result.
const promiseResolve = Promise.resolve.bind(Promise);
class RacePromise<T> extends Promise<T> {}
Object.defineProperty(RacePromise, 'resolve', {value: promiseResolve});
Object.freeze(RacePromise);
const promiseRace = Promise.race.bind(RacePromise);
const apply = Reflect.apply;
const promiseThen = Promise.prototype.then;
const removeAbortListener = AbortSignal.prototype.removeEventListener;
function then<T, U>(promise: Promise<T>, fulfilled: (value: T) => U | PromiseLike<U>, rejected?: (reason: unknown) => U | PromiseLike<U>): Promise<U> {
  return apply(promiseThen, promise, [fulfilled, rejected]) as Promise<U>;
}
/** A branded deadline and cancellation signal for an operation. */
export type Context = Readonly<{deadline: number; signal: AbortSignal}>;
const contexts = new WeakSet<object>();
const lifetimes = new WeakMap<Context, {attach: () => void; hold: () => () => void; abort: () => void; dispose: () => void}>();
/** Check the private brand of an operation context. */
export function isContext(value: unknown): value is Context {
  return typeof value === 'object' && value !== null && contexts.has(value);
}
/** Create a bounded context from timeout, parent, and cancellation options. */
export function withDeadline(options: unknown = {}): Result<Context> {
  try {
    const snapshot = snapshotOptions(options, ['signal', 'timeoutMs', 'parent']);
    if (!snapshot.ok) return err(custodyError('invalid_options'));
    const attrs = snapshot.value;
    const timeout = timeoutMs(Object.hasOwn(attrs, 'timeoutMs') ? attrs.timeoutMs : TIMEOUT_DEFAULT_MS);
    if (!timeout.ok) return timeout;
    const caller = attrs.signal, parent = attrs.parent;
    if (Object.hasOwn(attrs, 'signal') && !(caller instanceof AbortSignal) || Object.hasOwn(attrs, 'parent') && !isContext(parent)) return err(custodyError('invalid_options'));
    const controller = new AbortController();
    const deadline = Math.min(now() + timeout.value, isContext(parent) ? parent.deadline : Infinity);
    const context = Object.freeze({deadline, signal: controller.signal}); contexts.add(context);
    const signals = new Set<AbortSignal>();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let attached = false;
    const clearTimer = () => {
      if (timer !== undefined) { clearTimeout(timer); timer = undefined; }
    };
    const dispose = () => {
      clearTimer();
      for (const signal of signals) apply(removeAbortListener, signal, ['abort', abort]);
      // Keep signals for reuse after internal release; abort clears terminal references.
      attached = false;
    };
    const abort = () => {
      dispose();
      signals.clear();
      controller.abort();
    };
    const schedule = () => {
      const remaining = deadline - now();
      if (remaining <= 0) { abort(); return; }
      timer = setTimeout(schedule, remaining);
      // Supported hosts release their timer reference; browser timers need no hook.
      unrefTimer(timer);
    };
    const resume = () => {
      if (controller.signal.aborted) return;
      if (!attached) {
        // Mark before reading caller properties: they may reenter run().
        attached = true;
        if ([...signals].some(signal => signal.aborted)) { abort(); return; }
        for (const signal of signals) signal.addEventListener('abort', abort, Object.assign(Object.create(null), {once: true}));
      }
      if (timer === undefined && signals.size > 0) schedule();
    };
    // A referenced per-run timer holds only live work, independently of disposal.
    const hold = () => {
      let held: ReturnType<typeof setTimeout> | undefined;
      const tick = () => {
        held = undefined;
        const remaining = deadline - now();
        if (remaining <= 0) abort(); else held = setTimeout(tick, remaining);
      };
      tick();
      return () => { if (held !== undefined) { clearTimeout(held); held = undefined; } };
    };
    lifetimes.set(context, {attach: resume, hold, abort, dispose});
    if (caller instanceof AbortSignal) signals.add(caller);
    if (isContext(parent)) signals.add(parent.signal);
    if (deadline <= now()) abort();
    else {
      try { resume(); } catch (error) { abort(); throw error; }
    }
    return ok(context);
  } catch { return err(custodyError('invalid_options')); }
}
/** Internal ownership release for a settled child; never releases its parent. */
export function releaseContext(context: Context): void {
  lifetimes.get(context)?.dispose();
}
/** Return the context's remaining time, or zero after cancellation. */
export function remainingMs(context: Context): number {
  return isContext(context) && !context.signal.aborted ? Math.max(0, context.deadline - now()) : 0;
}
/** Runs share the absolute deadline. Each run holds a referenced timer until it
 * settles or the deadline passes, so a callback that never settles still ends with
 * `deadline_exceeded`; outside a run the Context keeps nothing alive. A Context
 * with caller or parent signals keeps one unreferenced timer that releases those
 * listeners at the deadline. Settlement leaves the Context reusable. A run that
 * ends at its deadline abandons, not stops, its callback; callbacks should honor
 * `context.signal`. A caller or parent signal whose state cannot be read returns
 * `custodian_failure`. */
export async function run<T>(context: Context, fn: (context: Context) => Result<T> | Promise<Result<T>>): Promise<Result<T>> {
  if (!isContext(context)) return err(custodyError('invalid_options'));
  if (remainingMs(context) <= 0) { lifetimes.get(context)!.abort(); return err(custodyError('deadline_exceeded')); }
  const lifetime = lifetimes.get(context)!;
  try { lifetime.attach(); } catch {
    lifetime.abort();
    return err(custodyError('custodian_failure'));
  }
  if (remainingMs(context) <= 0) return err(custodyError('deadline_exceeded'));
  let cancel: (() => void) | undefined;
  const canceled = then(new Promise<Result<T>>(resolve => {
    cancel = () => resolve(err(custodyError('deadline_exceeded')));
    context.signal.addEventListener('abort', cancel, Object.assign(Object.create(null), {once: true}));
    if (context.signal.aborted) cancel();
  }), result => result, () => err<T>(custodyError('custodian_failure')));
  const work = then(then(promiseResolve(), () => fn(context)), result => {
    if (!result || typeof result !== 'object') return err<T>(custodyError('custodian_failure'));
    if (result.ok === true && Object.hasOwn(result, 'value')) return ok(result.value);
    if (result.ok === false && isRequestSealError(result.error)) return err<T>(result.error);
    return err<T>(custodyError('custodian_failure'));
  }, () => err<T>(custodyError('custodian_failure')));
  const boundedWork = then(work, result => result, () => err<T>(custodyError('custodian_failure')));
  let releaseHold: (() => void) | undefined;
  try {
    releaseHold = lifetime.hold();
    const result = await promiseRace([boundedWork, canceled]);
    return remainingMs(context) > 0 ? result : err(custodyError('deadline_exceeded'));
  } catch {
    lifetime.abort();
    return err(custodyError('custodian_failure'));
  } finally {
    releaseHold?.();
    if (cancel) apply(removeAbortListener, context.signal, ['abort', cancel]);
  }
}
