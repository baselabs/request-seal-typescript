import {KeyIdentity} from '../../src/index.ts';
import {parameters, identities} from '../../src/signature-fields.ts';
import type {Candidate} from '../../src/quorum/evaluation.ts';
import type {Quorum, SignerSlot} from '../../src/quorum.ts';
// Exhaustive graph reachability, assignments, and role subsets. No production
// matching, union-find, search pruning, or counting helpers are shared.
export function exhaustive(records: readonly Candidate[], q: Quorum) {
  const classes = records.map((r, i) => {
    const seen = new Set([i]); const pending = [i];
    while (pending.length) {
      const a = records[pending.pop()!]!;
      records.forEach((b, j) => {
        const same = KeyIdentity.same(a.identity, b.identity);
        if (!seen.has(j) && (a.label === b.label || (a.identity.kind === 'unknown' && b.identity.kind === 'unknown') || (same.ok && same.value))) { seen.add(j); pending.push(j); }
      });
    }
    return Math.min(...seen);
  });
  const known = (r: Candidate) => records.some(x => x.label === r.label && x.identity.kind !== 'unknown');
  if (q.unit === 'keys' && q.slots.some(s => s.required && records.some(r => r.slot.id === s.id) && !records.some(r => r.slot.id === s.id && known(r)))) return {reason: 'ambiguous_key_identity'};
  const pool = records.map((r, i) => ({...r, cls: classes[i]!})).filter(r => q.unit !== 'keys' || known(r));
  type R = typeof pool[number];
  const bound = new Set(q.bindings.flatMap(b => b.kind === 'nested' ? [b.outer, b.inner] : [...b.slots]));
  const enumerate = (slots: readonly SignerSlot[], requiredOnly: boolean, emit: (rs: R[]) => void) => {
    const visit = (i: number, rs: R[]) => {
      if (i === slots.length) { emit(rs); return; }
      const s = slots[i]!;
      if (!requiredOnly && !s.required && !bound.has(s.id)) visit(i + 1, rs);
      for (const r of pool) if (r.slot.id === s.id && !rs.some(x => x.cls === r.cls || x.label === r.label)) visit(i + 1, [...rs, r]);
    };
    visit(0, []);
  };
  const exists = (ss: readonly SignerSlot[]) => { let yes = false; enumerate(ss, true, () => {yes = true;}); return yes; };
  if (!exists(q.slots.filter(s => s.required))) return {reason: 'quorum_not_met'};
  if (!exists(q.slots.filter(s => s.required || bound.has(s.id)))) return {reason: 'binding_unsatisfied'};
  const bindings = (rs: R[]) => q.bindings.every(b => {
    if (b.kind === 'nested') {
      const o = rs.find(r => r.slot.id === b.outer), i = rs.find(r => r.slot.id === b.inner);
      return !!o && !!i && ['signature-input', 'signature'].every(n => identities(o.input).includes(JSON.stringify([n, [['key', {kind: 'string', value: i.label}]]])));
    }
    const selected = rs.filter(r => b.slots.includes(r.slot.id));
    const vs = selected.map(r => parameters(r.input)[b.name]);
    return selected.length === b.slots.length && vs.every(v => v !== undefined) && new Set(vs).size === 1;
  });
  const units = (rs: readonly R[]) => {
    if (q.unit === 'keys') return rs.length;
    if (q.unit === 'principals') return new Set(rs.map(r => r.slot.principal)).size;
    if (q.sharedPrincipal) return new Set(rs.map(r => r.slot.role)).size;
    let max = 0;
    const roles = [...new Set(rs.map(r => r.slot.role))];
    const visit = (i: number, ps: Set<string | null>, n: number) => {
      if (i === roles.length) { max = Math.max(max, n); return; }
      visit(i + 1, ps, n);
      for (const r of rs) if (r.slot.role === roles[i] && !ps.has(r.slot.principal)) visit(i + 1, new Set([...ps, r.slot.principal]), n + 1);
    };
    visit(0, new Set(), 0); return max;
  };
  let bestCount = -1, bestLength = -1;
  const assignments = new Set<string>();
  enumerate(q.slots, false, rs => {
    if (!bindings(rs)) return;
    const n = units(rs);
    if (n > bestCount || (n === bestCount && rs.length > bestLength)) { assignments.clear(); bestCount = n; bestLength = rs.length; }
    if (n === bestCount && rs.length === bestLength) assignments.add(assignmentKey(rs));
  });
  if (bestCount < 0) return {reason: 'binding_unsatisfied'};
  if (bestCount === 0 || (typeof q.mode === 'object' && bestCount < q.mode.threshold)) return {reason: 'quorum_not_met'};
  if (q.mode === 'all' && q.unit === 'roles' && !q.sharedPrincipal) {
    // Every exhaustive winner fills the same required slots; their counting
    // bindings are policy-owned, so evaluate this requirement once.
    const rs = q.slots.filter(s => s.required).map(slot => ({slot})) as R[];
    if (units(rs) !== new Set(rs.map(r => r.slot.role)).size) return {reason: 'quorum_not_met'};
  }
  return {count: bestCount, assignments};
}
export function assignmentKey(rs: readonly Pick<Candidate, 'slot' | 'label'>[]) { return rs.map(r => `${r.slot.id}=${r.label}`).sort().join(','); }
