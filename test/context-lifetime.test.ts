import test from 'node:test';
import assert from 'node:assert/strict';
import {getEventListeners} from 'node:events';
import * as api from '../src/index.ts';
import {releaseContext} from '../src/context.ts';
const value = <T>(r: api.Result<T>): T => {assert.ok(r.ok); return r.value;};
test('idle Context expires and removes caller and parent listeners', async () => {
  const caller = new AbortController();
  const parent = value(api.withDeadline({timeoutMs: 5000}));
  const child = value(api.withDeadline({signal: caller.signal, parent, timeoutMs: 30}));
  assert.equal(getEventListeners(caller.signal, 'abort').length, 1);
  assert.equal(getEventListeners(parent.signal, 'abort').length, 1);
  assert.deepEqual(await api.run(child, () => api.ok(true)), api.ok(true));
  await new Promise(resolve => setTimeout(resolve, 70));
  assert.equal(getEventListeners(caller.signal, 'abort').length, 0);
  assert.equal(getEventListeners(parent.signal, 'abort').length, 0);
  assert.equal(child.signal.aborted, true);
});
test('Context lifetime is registered before a hostile signal observes it', async () => {
  const originalFreeze = Object.freeze;
  let observed: api.Context | undefined, result: Promise<api.Result<true>> | undefined;
  const signal = new AbortController().signal;
  Object.defineProperty(signal, 'aborted', {get() {assert.ok(observed && api.isContext(observed)); result = api.run(observed, () => api.ok(true)); return false;}});
  Object.freeze = ((object: object) => { if ('deadline' in object && 'signal' in object) observed = object as api.Context; return originalFreeze(object); }) as typeof Object.freeze;
  try {assert.ok(api.withDeadline({signal, timeoutMs: 5000}).ok);} finally {Object.freeze = originalFreeze;}
  assert.deepEqual(await result, api.ok(true));
});
test('a settled internal child can resume without losing its deadline', async () => {
  const child = value(api.withDeadline({timeoutMs: 30}));
  assert.deepEqual(await api.run(child, () => api.ok(true)), api.ok(true));
  releaseContext(child);
  let unblock!: () => void;
  const barrier = new Promise<void>(resolve => {unblock = resolve;});
  const running = api.run(child, async () => {await barrier; return api.ok(true);});
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([running, new Promise<undefined>(resolve => {timer = setTimeout(() => resolve(undefined), 150);})]);
    assert.ok(result, 'released child lost its deadline timer');
    assert.equal(result.ok, false); assert.equal(!result.ok && result.error.reason, 'deadline_exceeded');
  } finally {if (timer) clearTimeout(timer); unblock(); await running;}
});

test('contexts without external signals retain no idle deadline timers', async () => {
  // Count real timers, including unreferenced ones; forward every call unchanged.
  const originalSet = globalThis.setTimeout, originalClear = globalThis.clearTimeout;
  const active = new Set<ReturnType<typeof setTimeout>>();
  globalThis.setTimeout = ((...args: Parameters<typeof setTimeout>) => {
    const timer = originalSet(...args); active.add(timer); return timer;
  }) as typeof setTimeout;
  globalThis.clearTimeout = ((timer: ReturnType<typeof setTimeout>) => {
    active.delete(timer); originalClear(timer);
  }) as typeof clearTimeout;
  const contexts: api.Context[] = [];
  try {
    const positive = setTimeout(() => {}, 5000);
    assert.equal(active.size, 1, 'timer counter observes an actual timer'); clearTimeout(positive);
    for (let i = 0; i < 2000; i++) contexts.push(value(api.withDeadline({timeoutMs: 5000})));
    assert.equal(active.size, 0, 'signal-free idle contexts must not arm timers');
    for (const c of contexts.slice(0, 100)) assert.deepEqual(await api.run(c, () => api.ok(true)), api.ok(true));
    assert.equal(active.size, 0, 'settled signal-free contexts must release timers');
  } finally {
    for (const c of contexts) releaseContext(c);
    for (const timer of active) originalClear(timer);
    globalThis.setTimeout = originalSet; globalThis.clearTimeout = originalClear;
  }
});
test('never-run contexts release external listeners at their creation deadline', async () => {
  const caller = new AbortController();
  const parent = value(api.withDeadline({timeoutMs: 5000}));
  const child = value(api.withDeadline({signal: caller.signal, parent, timeoutMs: 30}));
  try {
    assert.equal(getEventListeners(caller.signal, 'abort').length, 1);
    assert.equal(getEventListeners(parent.signal, 'abort').length, 1);
    await new Promise(resolve => setTimeout(resolve, 80));
    assert.equal(child.signal.aborted, true);
    assert.equal(getEventListeners(caller.signal, 'abort').length, 0);
    assert.equal(getEventListeners(parent.signal, 'abort').length, 0);
  } finally {releaseContext(child); releaseContext(parent);}
});
for (const cancelWhen of ['before reuse', 'during reuse'] as const) test('released contexts honor caller cancellation ' + cancelWhen, async () => {
  const caller = new AbortController();
  const child = value(api.withDeadline({signal: caller.signal, timeoutMs: 5000}));
  releaseContext(child);
  let unblock!: () => void, notify!: () => void;
  const barrier = new Promise<void>(resolve => {unblock = resolve;});
  const entered = new Promise<void>(resolve => {notify = resolve;});
  if (cancelWhen === 'before reuse') caller.abort();
  const running = api.run(child, async () => {notify(); await barrier; return api.ok(true);});
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    if (cancelWhen === 'during reuse') {await entered; caller.abort();}
    const result = await Promise.race([running, new Promise<undefined>(resolve => {timer = setTimeout(() => resolve(undefined), 150);})]);
    assert.ok(result, 'released context lost caller cancellation');
    assert.equal(!result.ok && result.error.reason, 'deadline_exceeded');
  } finally {if (timer) clearTimeout(timer); unblock(); await running; releaseContext(child);}
});

for (const property of ['aborted', 'addEventListener'] as const) test(`released Context contains a throwing caller signal ${property}`, async () => {
  const caller = new AbortController();
  const context = value(api.withDeadline({signal: caller.signal, timeoutMs: 5000}));
  releaseContext(context);
  const fail = () => {throw new Error('private signal diagnostic');};
  if (property === 'aborted') Object.defineProperty(caller.signal, property, {get: fail});
  else Object.defineProperty(caller.signal, property, {value: fail});
  let called = false;
  const result = await api.run(context, () => {called = true; return api.ok(true);});
  assert.deepEqual(result, api.err((await import('../src/errors/types.ts')).custodyError('custodian_failure')));
  assert.equal(called, false);
  assert.equal(context.signal.aborted, true);
  assert.equal(getEventListeners(caller.signal, 'abort').length, 0);
});
