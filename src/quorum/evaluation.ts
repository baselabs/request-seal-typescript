import {
  type KeyIdentity as Identity,
  isKeyIdentity,
  identityClassKey,
} from "../key_identity.ts";
import {
  identities,
  parameters,
  ensure,
  fail,
  bounded,
} from "../signature-fields.ts";
import { QUORUM_MAX_NODES } from "../constants.ts";
import { remainingMs, type Context } from "../context.ts";
import { custodyError, isRequestSealError } from "../errors/types.ts";
import { ok, err, type Result } from "../result.ts";
import type { Quorum, SignerSlot, QuorumBinding } from "../quorum.ts";
import type { InnerList } from "../structured-fields/index.ts";
import type { AcceptSignature } from "../accept-signature.ts";
/** Internal observations; identity material never enters verification results. */
export type Candidate = Readonly<{
  slot: SignerSlot;
  label: string;
  identity: Identity;
  input: InnerList;
}>;
type Vertex = string | symbol;
type RecordCandidate = Candidate &
  Readonly<{ class: number; known: boolean; vertex: Vertex }>;
export type Assignment = Readonly<{
  chosen: readonly Candidate[];
  pool: readonly Candidate[];
  count: number;
  nodes: number;
  exhausted: boolean;
}>;
const now = performance.now.bind(performance);
const compare = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
function merge(records: readonly Candidate[]): RecordCandidate[] {
  const labels = new Map<string, number>(),
    known = new Set<string>(),
    identityNodes = new Map<string, number>(),
    parents: number[] = [];
  const node = () => {
    const n = parents.length;
    parents.push(n);
    return n;
  };
  const root = (n: number): number => {
    while (parents[n] !== n) {
      parents[n] = parents[parents[n]!]!;
      n = parents[n]!;
    }
    return n;
  };
  const unknown = node();
  for (const r of records) {
    ensure(isKeyIdentity(r.identity), "invalid_quorum", "input");
    let l = labels.get(r.label);
    if (l === undefined) {
      l = node();
      labels.set(r.label, l);
    }
    let id = unknown;
    if (r.identity.kind !== "unknown") {
      known.add(r.label);
      const key = identityClassKey(r.identity)!;
      const existing = identityNodes.get(key);
      if (existing !== undefined) id = existing;
      else { id = node(); identityNodes.set(key, id); }
    }
    const a = root(l),
      b = root(id);
    if (a !== b) parents[Math.max(a, b)] = Math.min(a, b);
  }
  return records.map((r) => ({
    ...r,
    class: root(labels.get(r.label)!),
    known: known.has(r.label),
    vertex: r.slot.id,
  }));
}
function count(records: readonly Pick<Candidate, "slot">[], q: Quorum): number {
  if (q.unit === "keys") return records.length;
  if (q.unit === "principals")
    return new Set(records.map((r) => r.slot.principal)).size;
  if (q.sharedPrincipal) return new Set(records.map((r) => r.slot.role)).size;
  const edges = new Map<string, string[]>(),
    matched = new Map<string, string>();
  for (const r of records) {
    const role = r.slot.role!,
      p = r.slot.principal!;
    edges.set(role, [...(edges.get(role) ?? []), p]);
  }
  function augment(role: string, seen: Set<string>): boolean {
    for (const p of edges.get(role) ?? []) {
      if (seen.has(p)) continue;
      seen.add(p);
      const old = matched.get(p);
      if (old === undefined || augment(old, seen)) {
        matched.set(p, role);
        return true;
      }
    }
    return false;
  }
  for (const role of [...edges.keys()].sort(compare)) augment(role, new Set());
  return matched.size;
}
const inputParameters = new WeakMap<InnerList, ReturnType<typeof parameters>>();
const inputCoverage = new WeakMap<InnerList, Set<string>>();
function holds(
  selected: ReadonlyMap<string, Candidate>,
  bindings: readonly QuorumBinding[],
  partial = false,
): boolean {
  for (const b of bindings) {
    if (b.kind === "nested") {
      const o = selected.get(b.outer), i = selected.get(b.inner);
      if (!o || !i) { if (partial) continue; return false; }
      let covered = inputCoverage.get(o.input);
      if (!covered) { covered = new Set(identities(o.input)); inputCoverage.set(o.input, covered); }
      if (!["signature-input", "signature"].every(name => covered.has(JSON.stringify([name, [["key", {kind: "string", value: i.label}]]])))) return false;
    } else {
      let present = false;
      let first: unknown;
      for (const id of b.slots) {
        const r = selected.get(id);
        if (!r) { if (partial) continue; return false; }
        let params = inputParameters.get(r.input);
        if (!params) { params = parameters(r.input); inputParameters.set(r.input, params); }
        const value = params[b.name];
        if (value === undefined || (present && value !== first)) return false;
        first = value; present = true;
      }
    }
  }
  return true;
}

function modeMet(records: readonly Candidate[], q: Quorum): boolean {
  const n = count(records, q);
  if (
    n === 0 ||
    q.slots.some((s) => s.required && !records.some((r) => r.slot.id === s.id))
  )
    return false;
  if (q.mode === "all" && q.unit === "roles" && !q.sharedPrincipal) {
    const required = records.filter((r) => r.slot.required);
    if (
      count(required, q) !==
      new Set(q.slots.filter((s) => s.required).map((s) => s.role)).size
    )
      return false;
  }
  return typeof q.mode === "string" || n >= q.mode.threshold;
}
/** Polynomial augmenting paths over merged classes, with required vertices preserved. */
function augment(
  vertex: Vertex,
  edges: Map<Vertex, RecordCandidate[]>,
  matched: Map<number, RecordCandidate>,
  seen: Set<number>,
  fixed?: ReadonlyMap<string, RecordCandidate>,
): boolean {
  const selected = typeof vertex === "string" ? fixed?.get(vertex) : undefined;
  for (const r of selected ? [selected] : edges.get(vertex) ?? []) {
    if (seen.has(r.class)) continue;
    seen.add(r.class);
    const old = matched.get(r.class);
    if (old === undefined || augment(old.vertex, edges, matched, seen, fixed)) {
      matched.set(r.class, r);
      return true;
    }
  }
  return false;
}
function matching(
  slots: readonly SignerSlot[],
  edges: Map<Vertex, RecordCandidate[]>,
  reason: "quorum_not_met" | "binding_unsatisfied",
): Map<number, RecordCandidate> {
  const matched = new Map<number, RecordCandidate>();
  for (const s of slots)
    ensure(augment(s.id, edges, matched, new Set()), reason, "quorum");
  return matched;
}
function polynomial(
  slots: readonly SignerSlot[],
  edges: Map<Vertex, RecordCandidate[]>,
  matched: Map<number, RecordCandidate>,
  q: Quorum,
): RecordCandidate[] {
  if (q.unit !== "keys") {
    const group = (s: SignerSlot) =>
      q.unit === "principals" ? s.principal! : s.role!;
    const covered = new Set([...matched.values()].map((r) => group(r.slot))),
      groups = new Map<string, SignerSlot[]>();
    for (const s of slots.filter((s) => !s.required)) {
      const g = group(s);
      groups.set(g, [...(groups.get(g) ?? []), s]);
    }
    const all = new Map(edges);
    // Group vertices cannot collide with caller slot IDs.
    const vertices = new Map<string, symbol>();
    for (const [g, ss] of groups) {
      const vertex = Symbol(g);
      vertices.set(g, vertex);
      all.set(vertex, ss.flatMap(s => (edges.get(s.id) ?? []).map(r => ({...r, vertex}))));
    }
    for (const g of [...groups.keys()].sort(compare))
      if (!covered.has(g)) augment(vertices.get(g)!, all, matched, new Set());
    for (const [c, r] of matched) matched.set(c, { ...r, vertex: r.slot.id });
  }
  for (const s of slots)
    if (![...matched.values()].some((r) => r.slot.id === s.id))
      augment(s.id, edges, matched, new Set());
  return [...matched.values()];
}
function* evaluate(
  records: readonly Candidate[],
  q: Quorum,
  requests: AcceptSignature,
  context?: Context,
): Generator<void, Result<Assignment>, void> {
  try {
    const tick = () => {
      if (context && remainingMs(context) <= 0)
        throw custodyError("deadline_exceeded");
    };
    tick();
    let pool = merge(records);
    if (q.unit === "keys") {
      for (const s of q.slots)
        ensure(
          !s.required ||
            pool.some((r) => r.slot.id === s.id && r.known) ||
            !pool.some((r) => r.slot.id === s.id),
          "ambiguous_key_identity",
          "quorum",
        );
      pool = pool.filter((r) => r.known);
    }
    const challenges = new Set(requests.map((r) => r.label)),
      slots = [...q.slots].sort((a, b) => compare(a.id, b.id));
    pool.sort(
      (a, b) =>
        compare(a.slot.id, b.slot.id) ||
        Number(!challenges.has(a.label)) - Number(!challenges.has(b.label)) ||
        compare(a.label, b.label),
    );
    const edges = new Map<Vertex, RecordCandidate[]>();
    for (const r of pool)
      edges.set(r.slot.id, [...(edges.get(r.slot.id) ?? []), r]);
    const bound = new Set(
      q.bindings.flatMap((b) =>
        b.kind === "nested" ? [b.outer, b.inner] : [...b.slots],
      ),
    );
    const required = matching(
      slots.filter((s) => s.required),
      edges,
      "quorum_not_met",
    );
    matching(
      slots.filter((s) => s.required || bound.has(s.id)),
      edges,
      "binding_unsatisfied",
    );
    let chosen: RecordCandidate[] | null = null,
      nodes = 0,
      exhausted = false;
    if (q.bindings.length === 0 && !(q.unit === "roles" && !q.sharedPrincipal))
      chosen = polynomial(slots, edges, required, q);
    else {
      const classes = new Set(pool.map((r) => r.class)).size;
      const slotBindings = new Map<string, QuorumBinding[]>();
      for (const b of q.bindings) {
        for (const id of b.kind === "nested" ? [b.outer, b.inner] : b.slots)
          slotBindings.set(id, [...(slotBindings.get(id) ?? []), b]);
      }
      // Keep candidate order while indexing parameter values. An existing
      // binding value can reject whole groups without visiting search nodes.
      const parameterEdges = new Map<string, Map<QuorumBinding, Map<unknown, RecordCandidate[]>>>();
      for (const [id, bs] of slotBindings) {
        const indexed = new Map<QuorumBinding, Map<unknown, RecordCandidate[]>>();
        for (const b of bs) {
          if (b.kind === "nested") continue;
          const values = new Map<unknown, RecordCandidate[]>();
          for (const r of edges.get(id) ?? []) {
            let params = inputParameters.get(r.input);
            if (!params) { params = parameters(r.input); inputParameters.set(r.input, params); }
            const value = params[b.name];
            if (value !== undefined) values.set(value, [...(values.get(value) ?? []), r]);
          }
          indexed.set(b, values);
        }
        parameterEdges.set(id, indexed);
      }
      const fixedClasses = new Set<number>();
      let sliceStart = now();
      function* search(
        i: number,
        matched: Map<number, RecordCandidate>,
        fixed: Map<string, RecordCandidate>,
        bindingValues: ReadonlyMap<QuorumBinding, unknown>,
      ): Generator<void, void, void> {
        if (exhausted) return;
        if (nodes >= QUORUM_MAX_NODES) { exhausted = true; return; }
        nodes++;
        if (now() - sliceStart >= 10) { yield; tick(); sliceStart = now(); }
        if (i === slots.length) {
          const rs = [...matched.values()];
          if (holds(new Map(rs.map(r => [r.slot.id, r])), q.bindings) &&
              (chosen === null || count(rs, q) > count(chosen, q) ||
               (count(rs, q) === count(chosen, q) && rs.length > chosen.length))) chosen = rs;
          return;
        }
        if (chosen !== null) {
          const rs = [...matched.values()];
          // The reference counts potential units, including role/principal matching,
          // rather than treating every remaining slot as an independent unit.
          const current = count(rs, q);
          const remaining = count([...rs, ...slots.slice(i).map(slot => ({slot}))], q) - current;
          const upper = current + Math.min(remaining, classes - rs.length);
          const best = count(chosen, q);
          if (upper < best || (upper === best && rs.length + slots.length - i <= chosen.length)) return;
        }
        const slot = slots[i]!;
        if (bound.has(slot.id)) {
          // Fixed slots form one active depth-first path; restore it on return.
          const next = fixed;
          let candidates = edges.get(slot.id) ?? [];
          for (const [b, values] of parameterEdges.get(slot.id) ?? []) {
            if (bindingValues.has(b)) {
              const eligible = values.get(bindingValues.get(b)) ?? [];
              if (eligible.length < candidates.length) candidates = eligible;
            }
          }
          for (const r of candidates) {
            // A fixed occupant has exactly one edge; its class cannot be moved.
            // This skips only failed augmenting paths, never a visited search node.
            if (fixedClasses.has(r.class)) continue;
            next.set(slot.id, r);
            // Earlier fixed slots already passed their bindings. Only this
            // slot can introduce a new parameter value or complete a nested pair.
            let valid = true;
            const additions: [QuorumBinding, unknown][] = [];
            for (const b of slotBindings.get(slot.id) ?? []) {
              if (b.kind === "nested") {
                if (!holds(next, [b], true)) { valid = false; break; }
              } else {
                let params = inputParameters.get(r.input);
                if (!params) { params = parameters(r.input); inputParameters.set(r.input, params); }
                const value = params[b.name];
                if (value === undefined || (bindingValues.has(b) && bindingValues.get(b) !== value)) { valid = false; break; }
                if (!bindingValues.has(b)) additions.push([b, value]);
              }
            }
            if (valid) {
              // A free class cannot move an earlier occupant. Borrow the
              // matching on that branch and undo only the new edge afterward.
              // Occupied classes still require a private augmenting-path copy.
              const free = !matched.has(r.class);
              const updated = free ? matched : new Map(matched);
              if (free || augment(slot.id, edges, updated, new Set(), next)) {
                updated.set(r.class, r);
                fixedClasses.add(r.class);
                const values = additions.length ? new Map([...bindingValues, ...additions]) : bindingValues;
                yield* search(i + 1, updated, next, values);
                fixedClasses.delete(r.class);
                if (free) matched.delete(r.class);
              }
            }
            if (exhausted) break;
          }
          next.delete(slot.id);
        } else {
          const updated = new Map(matched);
          if (augment(slot.id, edges, updated, new Set(), fixed)) yield* search(i + 1, updated, fixed, bindingValues);
          if (!slot.required) yield* search(i + 1, matched, fixed, bindingValues);
        }
      }
      yield* search(0, new Map(), new Map(), new Map());
      if (exhausted && (chosen === null || !modeMet(chosen, q)))
        fail("limit", "input");
      ensure(chosen !== null, "binding_unsatisfied", "quorum");
    }
    ensure(holds(new Map(chosen.map(r => [r.slot.id, r])), q.bindings), "binding_unsatisfied", "quorum");
    ensure(modeMet(chosen, q), "quorum_not_met", "quorum");
    tick();
    return ok(
      Object.freeze({
        chosen: Object.freeze(chosen),
        pool: Object.freeze(pool),
        count: count(chosen, q),
        nodes,
        exhausted,
      }),
    );
  } catch (e) {
    if (isRequestSealError(e) && e.kind === "custody") return err(e);
    return err(bounded(e, "invalid_quorum", "input"));
  }
}

/** Evaluation yields after about 10 ms of search work, preserving reference accounting. */
export async function evaluateQuorum(records: readonly Candidate[], q: Quorum, requests: AcceptSignature, context?: Context): Promise<Result<Assignment>> {
  const iterator = evaluate(records, q, requests, context);
  let step = iterator.next();
  while (!step.done) {
    await new Promise<void>(resolve => setTimeout(resolve, 0));
    step = iterator.next();
  }
  return step.value;
}
