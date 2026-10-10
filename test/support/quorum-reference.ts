// Deterministic tie oracle transcribed from the published RequestSeal v0.4.0 assignment search.
// Independent exhaustive enumeration separately checks feasibility and every winning assignment.
// Records: {slot, label, idKey: string|null, covers: Set<string>, params: Record<string,string>}
export const BUDGET = 131_072;
class Fail { reason: string; layer: string; constructor(reason: string, layer: string) { this.reason = reason; this.layer = layer; } }
const fail = (r: string, l: string) => { throw new Fail(r, l); };
const cmp = (a: any, b: any) => (a < b ? -1 : a > b ? 1 : 0);
function merge(records: any[]) {
  const parent = new Map<string, string>();
  const root = (n: string): string => { let p = parent.get(n) ?? n; return p === n ? n : root(p); };
  const known = new Set<string>();
  for (const r of records) {
    const label = "L:" + r.label, val = r.idKey === null ? "P:" : "I:" + r.idKey;
    const a = root(label), b = root(val);
    parent.set(label, a); parent.set(val, b);
    if (a !== b) { const [mn, mx] = a < b ? [a, b] : [b, a]; parent.set(mx, mn); }
    if (r.idKey !== null) known.add(r.label);
  }
  return records.map((r) => ({ ...r, cls: root("L:" + r.label), known: known.has(r.label) }));
}
function count(records: any[], q: any): number {
  if (q.unit === "keys") return records.length;
  if (q.unit === "principals") return new Set(records.map((r) => r.slot.principal)).size;
  if (q.sharedPrincipal) return new Set(records.map((r) => r.slot.role)).size;
  const edges = new Map<string, string[]>();
  for (const r of records) edges.set(r.slot.role, [...(edges.get(r.slot.role) ?? []), r.slot.principal]);
  let matched = new Map<string, string>();
  const augment = (role: string, m: Map<string, string>, seen: Set<string>): [boolean, Map<string, string>, Set<string>] => {
    for (const p of [...new Set(edges.get(role))]) {
      if (seen.has(p)) continue;
      seen = new Set([...seen, p]);
      let res: [boolean, Map<string, string>, Set<string>];
      if (!m.has(p)) res = [true, m, seen]; else res = augment(m.get(p)!, m, seen);
      if (res[0]) { const u = new Map(res[1]); u.set(p, role); return [true, u, res[2]]; }
      seen = res[2];
    }
    return [false, m, seen];
  };
  for (const role of [...edges.keys()].sort(cmp)) { const r = augment(role, matched, new Set()); if (r[0]) matched = r[1]; }
  return matched.size;
}
function rolesMet(records: any[], q: any) {
  if (!(q.unit === "roles" && q.sharedPrincipal === false)) return true;
  const required = q.slots.filter((s: any) => s.required);
  const rs = records.filter((r) => required.some((s: any) => s.id === r.slot.id));
  return count(rs, q) === new Set(required.map((s: any) => s.role)).size;
}
function bindingHolds(records: any[], b: any, partial: boolean) {
  if (b.kind === "nested") {
    const o = records.find((r) => r.slot.id === b.outer), i = records.find((r) => r.slot.id === b.inner);
    if (!o || !i) return partial;
    return o.covers.has(i.label);
  }
  const sel = records.filter((r) => b.slots.includes(r.slot.id));
  const vals = sel.map((r) => r.params[b.name]);
  return (partial || sel.length === b.slots.length) && vals.every((v) => v !== undefined) && new Set(vals).size <= 1;
}
const bindingsHold = (rs: any[], bs: any[]) => bs.every((b) => bindingHolds(rs, b, false));
const partialHold = (rs: any[], bs: any[]) => bs.every((b) => bindingHolds(rs, b, true));
type M = Map<string, any>;
function assignSlot(slot: string, edges: Map<string, any[]>, matched: M, seen: Set<string>): [true, M] | [false, Set<string>] {
  let acc: [true, M] | [false, Set<string>] = [false, seen];
  for (const [key, record] of edges.get(slot) ?? []) {
    if (acc[0]) break;
    let s = acc[1] as Set<string>;
    if (s.has(key)) continue;
    s = new Set([...s, key]);
    const occ = matched.get(key);
    const result: [true, M] | [false, Set<string>] = occ === undefined ? [true, matched] : assignSlot(occ.vertex ?? occ.slot.id, edges, matched, s);
    if (result[0]) { const u = new Map(result[1]); u.set(key, record); return [true, u]; }
    acc = [false, result[1]];
  }
  return acc;
}
function cover(slots: any[], edges: Map<string, any[]>, reason: string): M {
  let m: M = new Map();
  for (const s of slots) { const r = assignSlot(s.id, edges, m, new Set()); if (r[0]) m = r[1]; else fail(reason, "quorum"); }
  return m;
}
function fillOptional(slots: any[], edges: Map<string, any[]>, matched: M) {
  let acc = matched;
  for (const s of slots) {
    if ([...acc.values()].some((r) => r.slot.id === s.id)) continue;
    const r = assignSlot(s.id, edges, acc, new Set()); if (r[0]) acc = r[1];
  }
  return [...acc.values()];
}
function maximize(slots: any[], edges: Map<string, any[]>, matched: M, q: any) {
  if (q.unit === "keys") return fillOptional(slots, edges, matched);
  const group = (s: any) => (q.unit === "principals" ? s.principal : s.role);
  const covered = new Set([...matched.values()].map((r) => group(r.slot)));
  const groups = new Map<string, any[]>();
  for (const s of slots.filter((s) => !s.required)) groups.set(group(s), [...(groups.get(group(s)) ?? []), s]);
  const all = new Map<string, any[]>();
  for (const [id, rs] of edges) all.set(id, rs.map(([c, r]) => [c, { ...r, vertex: id }]));
  for (const [g, members] of groups) all.set("\u0000G" + g, members.flatMap((s) => (edges.get(s.id) ?? []).map(([c, r]) => [c, { ...r, vertex: "\u0000G" + g }])));
  let acc: M = new Map([...matched].map(([c, r]) => [c, { ...r, vertex: r.slot.id }]));
  for (const g of [...groups.keys()].sort(cmp)) {
    if (covered.has(g)) continue;
    const r = assignSlot("\u0000G" + g, all, acc, new Set()); if (r[0]) acc = r[1];
  }
  acc = new Map([...acc].map(([c, r]) => { const { vertex, ...rest } = r; return [c, rest]; }));
  return fillOptional(slots, edges, acc);
}
function modeMet(records: any[], q: any) {
  const n = count(records, q);
  return n > 0 && q.slots.every((s: any) => !s.required || records.some((r) => r.slot.id === s.id)) &&
    (q.mode === "all" ? rolesMet(records, q) : q.mode === "any" ? true : n >= q.mode.threshold);
}
export function refEvaluate(input: any[], q: any, challenges: string[]) {
  try {
    let records = merge(input);
    if (q.unit === "keys") {
      const known = records.filter((r) => r.known), unknown = records.filter((r) => !r.known);
      for (const s of q.slots) if (!(!s.required || known.some((r) => r.slot.id === s.id) || !unknown.some((r) => r.slot.id === s.id))) fail("ambiguous_key_identity", "quorum");
      records = known;
    }
    const slots = [...q.slots].sort((a, b) => cmp(a.id, b.id));
    records = [...records].sort((a, b) => cmp(a.slot.id, b.slot.id) || Number(!challenges.includes(a.label)) - Number(!challenges.includes(b.label)) || cmp(a.label, b.label));
    const edges = new Map<string, any[]>();
    for (const r of records) edges.set(r.slot.id, [...(edges.get(r.slot.id) ?? []), [r.cls, r]]);
    const bound = new Set<string>(q.bindings.flatMap((b: any) => (b.kind === "nested" ? [b.outer, b.inner] : b.slots)));
    const required = slots.filter((s) => s.required);
    const mandatory = slots.filter((s) => s.required || bound.has(s.id));
    const requiredMatch = cover(required, edges, "quorum_not_met");
    cover(mandatory, edges, "binding_unsatisfied");
    let chosen: any[]; let nodesUsed = 0;
    if (q.bindings.length === 0 && !(q.unit === "roles" && q.sharedPrincipal === false)) chosen = maximize(slots, edges, requiredMatch, q);
    else {
      const classes = new Set([...edges.values()].flat().map((e) => e[0])).size;
      const fixedEdges = (fixed: Map<string, any>) => { const e = new Map(edges); for (const [id, r] of fixed) e.set(id, [[r.cls, r]]); return e; };
      const better = (rs: any[], best: any[] | null) => best === null || count(rs, q) > count(best, q) || (count(rs, q) === count(best, q) && rs.length > best.length);
      const pruned = (sl: any[], rs: any[], best: any[] | null) => {
        if (best === null) return false;
        const current = count(rs, q);
        const remaining = count([...rs, ...sl.map((s) => ({ slot: s }))], q) - current;
        const upper = current + Math.min(remaining, classes - rs.length);
        const bc = count(best, q), bl = best.length, ul = rs.length + sl.length;
        return upper < bc || (upper === bc && ul <= bl);
      };
      type St = [any[] | null, number, boolean];
      const search = (sl: any[], matched: M, fixed: Map<string, any>, st: St): St => {
        if (st[2]) return st;
        const [best, nodes] = st;
        if (nodes >= BUDGET) return [best, nodes, true];
        const state: St = [best, nodes + 1, false];
        const rs = [...matched.values()];
        if (sl.length === 0) return bindingsHold(rs, q.bindings) && better(rs, best) ? [rs, nodes + 1, false] : state;
        if (pruned(sl, rs, best)) return state;
        const [slot, ...rest] = sl;
        if (bound.has(slot.id)) {
          let acc = state;
          for (const [, record] of edges.get(slot.id) ?? []) {
            const ch = new Map(fixed); ch.set(slot.id, record);
            if (partialHold([...ch.values()], q.bindings)) {
              const r = assignSlot(slot.id, fixedEdges(ch), matched, new Set());
              if (r[0]) acc = search(rest, r[1], ch, acc);
            }
            if (acc[2]) break;
          }
          return acc;
        }
        let s2 = state;
        const r = assignSlot(slot.id, fixedEdges(fixed), matched, new Set());
        if (r[0]) s2 = search(rest, r[1], fixed, s2);
        return slot.required ? s2 : search(rest, matched, fixed, s2);
      };
      const [best, n, exhausted] = search(slots, new Map(), new Map(), [null, 0, false]);
      nodesUsed = n;
      if (exhausted && (best === null || !modeMet(best, q))) fail("limit", "input");
      if (best === null) fail("binding_unsatisfied", "quorum");
      chosen = best!;
    }
    if (new Set(chosen.map((r) => r.label)).size !== chosen.length) fail("quorum_not_met", "quorum");
    if (new Set(chosen.map((r) => r.cls)).size !== chosen.length) fail("quorum_not_met", "quorum");
    if (!required.every((s) => chosen.some((r) => r.slot.id === s.id))) fail("quorum_not_met", "quorum");
    if (!bindingsHold(chosen, q.bindings)) fail("binding_unsatisfied", "quorum");
    // verify/3: met, then bindings
    if (!modeMet(chosen, q)) fail("quorum_not_met", "quorum");
    return { ok: true, count: count(chosen, q), length: chosen.length, chosen, nodes: nodesUsed };
  } catch (e) {
    if (e instanceof Fail) return { ok: false, reason: e.reason, layer: e.layer };
    throw e;
  }
}
