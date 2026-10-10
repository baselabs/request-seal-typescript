import test from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import * as api from "../src/index.ts";
import { signatureSchema } from "../src/signature-fields.ts";
import { evaluateQuorum } from "../src/quorum/evaluation.ts";
const A = { ...api, evaluateQuorum } as any;
const value = (r: any): any => {
  assert.equal(r.ok, true, JSON.stringify(r));
  return r.value;
};
// Independent exhaustive enumeration: no product matching, merging, counting, or binding helpers.
function brute(slots: any[], edges: any[], unit: string, shared: boolean) {
  let best = [-1, -1];
  function walk(i: number, chosen: any[]) {
    if (i === slots.length) {
      if (
        slots.some((s) => s.required && !chosen.some((c) => c.slot.id === s.id))
      )
        return;
      let count = chosen.length;
      if (unit === "principals")
        count = new Set(chosen.map((c) => c.slot.principal)).size;
      if (unit === "roles") {
        if (shared) count = new Set(chosen.map((c) => c.slot.role)).size;
        else {
          count = 0;
          function roles(
            j: number,
            principals: Set<string>,
            selectedRoles: Set<string>,
          ) {
            if (j === chosen.length) {
              count = Math.max(count, selectedRoles.size);
              return;
            }
            rolesSkip(j, principals, selectedRoles);
            const s = chosen[j].slot;
            if (!principals.has(s.principal) && !selectedRoles.has(s.role))
              roles(
                j + 1,
                new Set([...principals, s.principal]),
                new Set([...selectedRoles, s.role]),
              );
          }
          function rolesSkip(j: number, p: Set<string>, r: Set<string>) {
            roles(j + 1, p, r);
          }
          roles(0, new Set(), new Set());
        }
      }
      if (count > best[0]! || (count === best[0] && chosen.length > best[1]!))
        best = [count, chosen.length];
      return;
    }
    if (!slots[i].required) walk(i + 1, chosen);
    for (const c of edges.filter((e) => e.slot.id === slots[i].id))
      if (!chosen.some((e) => e.label === c.label || e.identity === c.identity))
        walk(i + 1, [...chosen, c]);
  }
  walk(0, []);
  return best;
}
test(
  "bounded assignment agrees with independent exhaustive enumeration",
  { timeout: 30_000 },
  async (t) => {
    assert.equal(
      typeof A.evaluateQuorum,
      "function",
      "evaluateQuorum must be available for differential testing",
    );
    const policy = value(
      api.Policy.create({
        algorithms: ["ed25519"],
        components: "()",
        keyResolver: () => api.ok(null),
        freshness: "not_evaluated",
        content: "not_required",
        replay: "not_required",
      }),
    );
    const ids = Array.from({ length: 5 }, (_, i) =>
      value(api.KeyIdentity.symmetric(`key${i}`)),
    );
    const input = value(
      api.parseStructuredField("list", "()", { schema: signatureSchema }),
    ).value[0];
    let instances = 0;
    await fc.assert(
      fc.asyncProperty(
        fc.array(
          fc.record({
            required: fc.boolean(),
            principal: fc.integer({ min: 0, max: 2 }),
            role: fc.integer({ min: 0, max: 2 }),
            keys: fc.uniqueArray(fc.integer({ min: 0, max: 4 }), {
              maxLength: 5,
            }),
          }),
          { minLength: 1, maxLength: 5 },
        ),
        fc.constantFrom("keys", "principals", "roles"),
        fc.boolean(),
        async (raw, unit, shared) => {
          const slots = raw.map((s, i) => ({
            id: `s${i}`,
            policy,
            required: s.required,
            principal: `p${s.principal}`,
            role: `r${s.role}`,
          }));
          const q = value(
            A.Quorum.create({
              mode: "any",
              unit,
              ...(unit === "roles" ? { sharedPrincipal: shared } : {}),
              slots,
              unexpected: "ignore",
              invalid: "ignore",
            }),
          );
          const edges = raw.flatMap((s, i) =>
            s.keys.map((k) => ({
              slot: q.slots[i],
              label: `k${k}`,
              identity: ids[k],
              input,
            })),
          );
          const expected = brute(q.slots, edges, unit, shared);
          const actual = await A.evaluateQuorum(edges, q, []);
          if (expected[0]! <= 0) assert.equal(actual.ok, false);
          else {
            assert.equal(
              actual.ok,
              true,
              JSON.stringify({ raw, unit, shared, expected, actual }),
            );
            assert.deepEqual(
              [actual.value.count, actual.value.chosen.length],
              expected,
            );
          }
          instances++;
        },
      ),
      { numRuns: 2160, seed: 9421 },
    );
    t.diagnostic(`DIFFERENTIAL instances=${instances} disagreements=0`);
  },
);

test('matching search preserves reference pruning and canonical signers', async () => {
  const {policy, quorum, input} = await import('./support/quorum.ts');
  const p = policy();
  const slots = Array.from({length: 16}, (_, i) => ({id: `s${String(i).padStart(2, '0')}`, policy: p, required: true, principal: 'one', role: `r${i}`}));
  const ids = Array.from({length: 16}, (_, i) => value(api.KeyIdentity.symmetric(`key${i}`)));
  const edges = (q: any) => q.slots.flatMap((slot: any) => ids.map((identity, i) => ({slot, identity, label: `k${String(i).padStart(2, '0')}`, input: input()})));
  const q1 = quorum(slots, {unit: 'roles', sharedPrincipal: false, mode: {threshold: 1}});
  const r = value(await A.evaluateQuorum(edges(q1), q1, []));
  assert.equal(r.nodes, 17);
  assert.equal(r.exhausted, false);
  assert.equal(r.chosen.find((c: any) => c.slot.id === 's00').label, 'k15');
  const q2 = quorum(slots, {unit: 'roles', sharedPrincipal: false, mode: {threshold: 2}});
  assert.equal((await A.evaluateQuorum(edges(q2), q2, [])).error.reason, 'quorum_not_met');
  const q3 = quorum(slots.map((s, i) => ({...s, required: false, principal: i === 15 ? 'P2' : 'P1', role: i === 15 ? 'R2' : 'R1'})), {unit: 'roles', sharedPrincipal: false, mode: {threshold: 2}});
  const e3 = edges(q3).filter((c: any) => c.slot.id === 's15' ? c.label === 'k00' : c.label !== 'k15');
  const r3 = value(await A.evaluateQuorum(e3, q3, []));
  assert.equal(r3.count, 2); assert.equal(r3.nodes, 34);
  const q4 = quorum(slots.map(s => ({...s, required: false})), {mode: {threshold: 16}, bindings: [{kind: 'same_parameter', name: 'nonce', slots: ['s15']}]});
  assert.equal((await A.evaluateQuorum(edges(q4), q4, [])).error.reason, 'binding_unsatisfied');
});

test('selector-free nonce binding reaches the reference node bound', {timeout: 30_000}, async (t) => {
  const {policy, quorum, input} = await import('./support/quorum.ts');
  const p = policy();
  const slots = Array.from({length: 16}, (_, i) => ({id: `s${String(i).padStart(2, '0')}`, policy: p, required: true}));
  const ids = Array.from({length: 64}, (_, i) => value(api.KeyIdentity.symmetric(`key${i}`)));
  for (const size of [16, 4]) {
    const q = quorum(slots.slice(0, size), {maxSignatures: 64, bindings: [{kind: 'same_parameter', name: 'nonce', slots: slots.slice(0, size).map(s => s.id)}]});
    const edges = q.slots.flatMap((slot: any) => ids.map((identity, i) => ({slot, identity, label: `k${String(i).padStart(2, '0')}`, input: input(`();nonce="${i < 15 ? 0 : 1 + (i - 15) % 15}"`)})));
    const start = performance.now();
    const r = await A.evaluateQuorum(edges, q, []);
    const elapsed = performance.now() - start;
    t.diagnostic(`BOUND_SEARCH slots=${size} ms=${elapsed.toFixed(1)}`);
    assert.ok(elapsed < 2500, `bounded search took ${elapsed.toFixed(1)} ms`);
    if (size === 16) { assert.equal(r.ok, false); assert.equal(r.error.reason, 'limit'); assert.equal(r.error.layer, 'input'); }
    else { assert.equal(value(r).count, 4); }
  }
  t.diagnostic('NODE_BUDGET bound=131072 reference nonce pool=64 slots=16; four slots succeed');
});

test('maximum signatures with a shared nonce binding reaches the limit within the default deadline', {timeout: 15_000}, async (t) => {
  const {policy, quorum} = await import('./support/quorum.ts');
  const base = value(await api.Message.request('POST', 'https://example.com/', [], ''));
  const handles: api.KeyHandle[] = [];
  const fields = [...base.fields];
  try {
    for (let i = 0; i < 64; i++) {
      const h = value(await api.Custody.local('hmac-sha256', {hmac: crypto.getRandomValues(new Uint8Array(32)), identity: `key${i}`}));
      handles.push(h);
      const nonce = i < 15 ? 0 : 1 + (i - 15) % 15;
      const signed = value(await api.sign(base, {label: `s${String(i).padStart(2, '0')}`, algorithm: 'hmac-sha256', signatureInput: `("@method");keyid="${i}";nonce="${nonce}"`}, (a: api.SigningAlgorithm, d: Uint8Array, c = value(api.withDeadline())) => h.sign(a, d, c)));
      fields.push(...signed.fields.slice(base.fields.length));
    }
    const message = value(api.Message.create({...base, fields}));
    const p = policy({keyResolver: ({keyid}: {keyid: string}) => api.ok({algorithm: 'hmac-sha256', key: handles[Number(keyid)]!})});
    const slots = Array.from({length: 16}, (_, i) => ({id: `s${String(i).padStart(2, '0')}`, policy: p, required: true}));
    const q = quorum(slots, {maxSignatures: 64, bindings: [{kind: 'same_parameter', name: 'nonce', slots: slots.map(s => s.id)}]});
    const start = performance.now();
    const r = await api.verifyQuorum(message, q, {});
    const elapsed = performance.now() - start;
    t.diagnostic(`MAX_BOUND_VERIFY signatures=64 slots=16 ms=${elapsed.toFixed(1)} default-deadline=5000 node-limit=131072`);
    assert.equal(r.ok, false);
    if (!r.ok) { assert.equal(r.error.kind, 'core'); assert.equal(r.error.reason, 'limit'); if (r.error.kind === 'core') assert.equal(r.error.layer, 'input'); }
  } finally { for (const h of handles) await h.release(); }
});


test('assignment search yields so an abort can fire between bounded slices', {timeout: 10_000}, async (t) => {
  const {policy, quorum, input} = await import('./support/quorum.ts');
  const p = policy();
  const slots = Array.from({length: 16}, (_, i) => ({id: `s${i}`, policy: p, required: true}));
  const q = quorum(slots, {maxSignatures: 64, bindings: [{kind: 'same_parameter', name: 'nonce', slots: slots.map(s => s.id)}]});
  const ids = Array.from({length: 64}, (_, i) => value(api.KeyIdentity.symmetric(`key${i}`)));
  const records = q.slots.flatMap((slot: any) => ids.map((identity, i) => ({slot, identity, label: `k${i}`, input: input(`();nonce="${i < 15 ? 0 : 1 + (i - 15) % 15}"`)})));
  const controller = new AbortController();
  const context = value(api.withDeadline({signal: controller.signal, timeoutMs: 5000}));
  const timer = setTimeout(() => controller.abort(), 10);
  const start = performance.now();
  try {
    const r = await A.evaluateQuorum(records, q, [], context);
    assert.equal(r.ok, false); assert.equal(r.error.reason, 'deadline_exceeded');
    assert.equal(controller.signal.aborted, true);
    assert.ok(performance.now() - start < 2000);
    t.diagnostic(`SEARCH_ABORT ms=${(performance.now() - start).toFixed(1)}`);
  } finally { clearTimeout(timer); }
});

test('generated assignments and rejection reasons agree with exhaustive enumeration and reference ties', {timeout: 60_000}, async (t) => {
  const {policy, quorum, input} = await import('./support/quorum.ts');
  const {exhaustive, assignmentKey} = await import('./support/quorum-brute.ts');
  const {refEvaluate} = await import('./support/quorum-reference.ts');
  const p = policy();
  let instances = 0;
  const coverage = new Set<string>();
  const extraChoices = new Set<number>();
  let accepted = 0;
  const reasons = new Set<string>();
  await fc.assert(fc.asyncProperty(
    fc.integer({min: 8, max: 16}), fc.constantFrom('keys', 'principals', 'roles'), fc.boolean(), fc.constantFrom('all', 'any', 'threshold'),
    fc.array(fc.record({required: fc.boolean(), principal: fc.integer({min: 0, max: 2}), role: fc.integer({min: 0, max: 2}), labels: fc.subarray([0, 1, 2, 3], {minLength: 2, maxLength: 2}), identity: fc.constantFrom(null, 'a', 'b', 'c'), nonce: fc.constantFrom(null, 'a', 'b')}), {minLength: 16, maxLength: 16}),
    fc.constantFrom('none', 'same_parameter', 'nested'), fc.integer({min: 1, max: 16}),
    async (n, unit, sharedPrincipal, mode, raw, bindingKind, threshold) => {
      const slots = Array.from({length: n}, (_, i) => ({id: `s${String(i).padStart(2, '0')}`, policy: p, required: (i % 3 === 0 && raw[i]!.required) || mode === 'all' && i === 0, principal: `p${raw[i]!.principal}`, role: `r${raw[i]!.role}`}));
      const bindings = bindingKind === 'none' ? [] : bindingKind === 'nested' ? [{kind: 'nested', outer: 's00', inner: 's01'}] : [{kind: 'same_parameter', name: 'nonce', slots: ['s00', 's01']}];
      const q = quorum(slots, {unit, ...(unit === 'roles' ? {sharedPrincipal} : {}), mode: mode === 'threshold' ? {threshold} : mode, bindings});
      const records = q.slots.flatMap((slot: any, i: number) => raw[i]!.labels.map((l: number) => ({slot, label: `l${l}`, identity: value(raw[l]!.identity === null ? api.KeyIdentity.unknown() : api.KeyIdentity.symmetric(raw[l]!.identity!)), input: input(`(${i === 0 ? [0,1,2,3].flatMap(x => [`"signature-input";key="l${x}"`, `"signature";key="l${x}"`]).join(' ') : ''})${raw[i]!.nonce !== null ? `;nonce="${raw[i]!.nonce}"` : ''}`)})));
      if (q.slots.every(s => records.filter((r: any) => r.slot.id === s.id).length > 1)) extraChoices.add(n);
      const expected = exhaustive(records, q);
      const reference = refEvaluate(records.map((r: any) => ({slot: r.slot, label: r.label, idKey: raw[Number(r.label.slice(1))]!.identity, covers: new Set(Number(r.slot.id.slice(1)) === 0 ? [0,1,2,3].map(x => `l${x}`) : []), params: raw[Number(r.slot.id.slice(1))]!.nonce !== null ? {nonce: raw[Number(r.slot.id.slice(1))]!.nonce} : {}})), q, []);
      const actual = await A.evaluateQuorum(records, q, []);
      if (expected.reason) {
        reasons.add(expected.reason);
        assert.equal(actual.ok, false); assert.equal(actual.error.reason, expected.reason);
        assert.equal(reference.ok, false); if (!reference.ok) assert.equal(reference.reason, expected.reason);
      } else {
        accepted++;
        assert.equal(actual.ok, true); assert.equal(reference.ok, true);
        if (!reference.ok) throw new Error(reference.reason);
        assert.equal(actual.value.count, expected.count);
        const chosen = assignmentKey(actual.value.chosen);
        assert.ok(expected.assignments!.has(chosen), chosen);
        assert.equal(chosen, assignmentKey(reference.chosen!));
        assert.deepEqual(q.slots.filter(s => actual.value.chosen.some((r: any) => r.slot.id === s.id)).map(s => s.id), q.slots.filter(s => reference.chosen!.some((r: any) => r.slot.id === s.id)).map(s => s.id));
      }
      coverage.add(`${unit}/${mode}/${bindingKind}/${n}`); instances++;
    }), {numRuns: 2160, seed: 39421});
  for (const unit of ['keys', 'principals', 'roles']) for (const mode of ['all', 'any', 'threshold']) for (const binding of ['none', 'same_parameter', 'nested']) for (let n = 8; n <= 16; n++) assert.ok(coverage.has(`${unit}/${mode}/${binding}/${n}`), `${unit}/${mode}/${binding}/${n}`);
  for (let n = 8; n <= 16; n++) assert.ok(extraChoices.has(n), `all ${n} slots must draw choices from the shared pool`);
  assert.ok(accepted > 0); assert.ok(reasons.size > 0);
  t.diagnostic(`DIFFERENTIAL expanded=${instances} disagreements=0 assignment-optima-and-exact-ties reasons satisfied slots=8..16 coverage=${coverage.size} accepted=${accepted} rejection-reasons=${[...reasons].sort().join(",")}`);
});

test('recorded competing assignments preserve reference signers and reasons', {timeout: 60_000}, async (t) => {
  const {readFile} = await import('node:fs/promises');
  const {policy, quorum, input} = await import('./support/quorum.ts');
  const {refEvaluate} = await import('./support/quorum-reference.ts');
  const {assignmentKey} = await import('./support/quorum-brute.ts');
  const cases = JSON.parse(await readFile(new URL('./support/quorum-divergences.json', import.meta.url), 'utf8'));
  for (const x of cases) {
    const slots = x.slotSpec.slice(0, x.nslots).map((s: any, i: number) => ({id: `s${i}`, policy: policy(), required: s.required, principal: `p${s.principal}`, role: `r${s.role}`}));
    const bindings = x.bindings.map((b: any) => b.kind === 'nested' ? {...b, outer: `s${b.outer}`, inner: `s${b.inner}`} : {...b, slots: b.slots.map((i: number) => `s${i}`)});
    const q = quorum(slots, {unit: x.unit, ...(x.unit === 'roles' ? {sharedPrincipal: x.shared} : {}), mode: x.mode, bindings});
    const labels = x.labelSpec.map((_: any, i: number) => 'l' + String.fromCharCode(97 + i));
    const seen = new Set();
    const edges = x.edges.filter((e: any) => e.s < x.nslots && !seen.has(`${e.s}/${e.l}`) && seen.add(`${e.s}/${e.l}`));
    // Preserve each historical runner's identity observations.
    const records = edges.map((e: any) => ({slot: q.slots[e.s], label: labels[e.l], identity: value(x.identityByLabel ? api.KeyIdentity.symmetric(`k${e.l}`) : e.id === null ? api.KeyIdentity.unknown() : api.KeyIdentity.symmetric(e.id)), input: input(`(${x.labelSpec[e.l].covers.flatMap((l: string) => [`"signature-input";key="${l}"`, `"signature";key="${l}"`]).join(' ')})${x.labelSpec[e.l].nonce ? `;nonce="${x.labelSpec[e.l].nonce}"` : ''}`)}));
    const reference = refEvaluate(edges.map((e: any) => ({slot: q.slots[e.s], label: labels[e.l], idKey: x.identityByLabel ? `k${e.l}` : e.id, covers: new Set(x.labelSpec[e.l].covers), params: x.labelSpec[e.l].nonce ? {nonce: x.labelSpec[e.l].nonce} : {}})), q, x.challenges);
    const actual = await A.evaluateQuorum(records, q, x.challenges.map((label: string) => ({label})));
    assert.equal(actual.ok, reference.ok);
    if (reference.ok) { assert.equal(actual.value.count, reference.count); assert.equal(assignmentKey(actual.value.chosen), assignmentKey(reference.chosen!)); }
    else { assert.equal(actual.error.reason, reference.reason); assert.equal(actual.error.layer, reference.layer); }
  }
  t.diagnostic(`DIFFERENTIAL recorded=${cases.length} disagreements=0`);
});

test('matching group vertices stay separate from opaque caller slot ids', async () => {
  const {policy, quorum, input} = await import('./support/quorum.ts');
  const p = policy();
  const q = quorum([{id: '\0group:p1', policy: p, required: true, principal: 'p0'}, {id: 's1', policy: p, required: false, principal: 'p1'}], {unit: 'principals'});
  const a = value(api.KeyIdentity.symmetric('a')), b = value(api.KeyIdentity.symmetric('b'));
  const records = [{slot: q.slots[0], label: 'a', identity: a, input: input()}, {slot: q.slots[1], label: 'a', identity: a, input: input()}, {slot: q.slots[1], label: 'b', identity: b, input: input()}];
  const r = value(await A.evaluateQuorum(records, q, []));
  assert.equal(r.count, 2);
  assert.deepEqual(r.chosen.map((c: any) => [c.slot.id, c.label]).sort(), [['\0group:p1', 'a'], ['s1', 'b']]);
});
