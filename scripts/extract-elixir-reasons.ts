import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
// Extraction requires Elixir/OTP for parsing only. Pinned modules are never loaded.
type Node = {call?: string; receiver?: string; args?: Ast[]; var?: string; atom?: string; string?: string; module?: string; tuple?: Ast[]; line?: number; expression?: string};
type Ast = Node | Ast[] | number | null;
type Entry = {kind: string; layer?: string; reason: string; rule_id: string};
type Site = {rule_id: string; path: string; line: number; expression: string; via: {path: string; line: number; expression: string}[]};
type Definition = {id: number; public: boolean; name: string; params: Ast[]; body: Ast; guard?: Ast | undefined; owner: Module};
type Module = {name: string; path: string; aliases: Map<string, string>; imports: string[]; definitions: Definition[]; defaults: Map<string, Ast[]>};
type Env = Map<string, string[]>;
const kinds = ['core', 'message', 'structured_fields', 'signature_base', 'digest', 'crypto', 'custody', 'discovery', 'jose', 'replay', 'adapter'];
const unique = (values: string[]) => [...new Set(values)].sort();
const atoms = (text: string) => [...text.matchAll(/:([a-z][a-z0-9_]*)/g)].map(m => m[1]!);
const obj = (value: Ast | undefined): Node => value && !Array.isArray(value) && typeof value === 'object' ? value : {};
const keyword = (value: Ast | undefined, key: string): Ast | undefined => Array.isArray(value) ? value.map(v => obj(v).tuple).find(t => obj(t?.[0]).atom === key)?.[1] : undefined;
const kindFor = (name: string): string | undefined => kinds.find(kind => name === (kind === 'core' ? 'RequestSeal.Error' : 'RequestSeal.' + (kind === 'jose' ? ['JOSE'] : kind.split('_')).map(x => x === 'JOSE' ? x : x[0]!.toUpperCase() + x.slice(1)).join('') + '.Error'));
function children(value: Ast): Ast[] { return Array.isArray(value) ? value : obj(value).args ?? obj(value).tuple ?? []; }

/** Derive literal error pairs through actual helper calls, defaults and variable bindings. */
export function extractCallSites(sources: Record<string, string>): {entries: Entry[]; sites: Map<string, Site[]>; audited: Site[]} {
  const trees = JSON.parse(execFileSync('elixir', [fileURLToPath(new URL('./elixir-ast.exs', import.meta.url))], {input: JSON.stringify(sources), encoding: 'utf8', maxBuffer: 64 * 1024 * 1024})) as Record<string, Ast>;
  function expressions(value: Ast, lines: string[]): void {
    const n = obj(value);
    if (n.line && !(n.call === '%' && n.expression)) n.expression = lines.slice(n.line - 1, n.line + 3).join('\n').trim();
    for (const child of children(value)) expressions(child, lines);
  }
  for (const [path, tree] of Object.entries(trees)) expressions(tree, sources[path]!.split('\n'));
  const modules: Module[] = [], byName = new Map<string, Module>();
  function resolve(name: string, owner: Module): string {
    if (name === '__MODULE__') return owner.name;
    const parts = name.split('.'); return [owner.aliases.get(parts[0]!) ?? parts[0], ...parts.slice(1)].join('.');
  }
  function gather(value: Ast, path: string, owner?: Module): void {
    const n = obj(value);
    if (n.call === 'defmodule') {
      const name = obj(n.args?.[0]).module!;
      const full = owner && !name.startsWith('RequestSeal') ? owner.name + '.' + name : name;
      const m: Module = {name: full, path, aliases: new Map(owner?.aliases), imports: [], definitions: [], defaults: new Map()}; modules.push(m); byName.set(full, m);
      gather(keyword(n.args?.[1], 'do')!, path, m); return;
    }
    if (owner && n.call === 'alias') {
      const target = obj(n.args?.[0]); const short = obj(keyword(n.args?.[1], 'as')).module;
      if (target.module) { const full = resolve(target.module, owner); owner.aliases.set(short ?? full.split('.').at(-1)!, full); }
      else if (target.call === '{}') {
        const base = resolve(target.receiver!, owner);
        for (const child of target.args ?? []) { const full = base + '.' + obj(child).module; owner.aliases.set(full.split('.').at(-1)!, full); }
      }
      return;
    }
    if (owner && n.call === 'import' && obj(n.args?.[0]).module) { owner.imports.push(resolve(obj(n.args![0]).module!, owner)); return; }
    if (owner && (n.call === 'def' || n.call === 'defp')) {
      let header = obj(n.args?.[0]); let guard: Ast | undefined;
      if (header.call === 'when') { guard = header.args?.[1]; header = obj(header.args?.[0]); }
      const body = keyword(n.args?.[1], 'do');
      if (body === undefined) owner.defaults.set(`${header.call}/${header.args?.length ?? 0}`, header.args ?? []);
      // Rescue/catch keyword bodies also contain error construction sites.
      if (body !== undefined) owner.definitions.push({id: n.line ?? 0, public: n.call === 'def', name: header.call ?? header.var!, params: header.args ?? [], body: n.args![1]!, guard, owner});
      return;
    }
    for (const child of children(value)) gather(child, path, owner);
  }
  for (const [path, tree] of Object.entries(trees)) gather(tree, path);
  for (const m of modules) for (const d of m.definitions) d.params = m.defaults.get(`${d.name}/${d.params.length}`) ?? d.params;
  const entries = new Map<string, Entry>(), sites = new Map<string, Site[]>(), audited: Site[] = [];
  const auditKeys = new Set<string>();
  function audit(value: Ast, path: string): void {
    const n = obj(value);
    if ((n.call === 'new' && /(?:^|\.)Error$/.test(n.receiver ?? '')) || n.call === 'fail' || n.call === 'error' || n.call === '%' && /Error/.test(obj(n.args?.[0]).module ?? '')) {
      const key = `${path}:${n.line}:${n.call}`;
      if (!auditKeys.has(key)) { auditKeys.add(key); audited.push({rule_id: '', path, line: n.line ?? 0, expression: n.expression ?? '', via: []}); }
    }
    for (const child of children(value)) audit(child, path);
  }
  for (const [path, tree] of Object.entries(trees)) audit(tree, path);
  const seen = new Set<string>(), active = new Set<string>();
  function targets(name: string, receiver: string | undefined, owner: Module): Definition[] {
    const candidates = receiver ? [byName.get(resolve(receiver, owner))] : [owner, ...owner.imports.map(x => byName.get(x))];
    return candidates.flatMap(m => m?.definitions.filter(d => d.name === name) ?? []);
  }
  function values(value: Ast | undefined, env: Env, owner: Module, depth = 0): string[] {
    if (value === undefined || depth > 8) return [];
    const n = obj(value);
    if (n.atom) return [n.atom];
    if (n.var) return env.get(n.var) ?? [];
    if (n.call === 'if' || n.call === 'case' || n.call === 'cond') return unique(children(value).flatMap(v => values(v, env, owner, depth + 1)));
    if (n.call === '->') return values(n.args?.[1], env, owner, depth + 1);
    if (n.tuple && obj(n.tuple[0]).atom && ['do', 'else'].includes(obj(n.tuple[0]).atom!)) return values(n.tuple[1], env, owner, depth + 1);
    if (Array.isArray(value)) return unique(value.flatMap(v => values(v, env, owner, depth + 1)));
    if (n.call === '__block__') return values(n.args?.at(-1), env, owner, depth + 1);
    if (n.call) return unique(targets(n.call, n.receiver, owner).flatMap(d => {
      const scope = bind(d, n.args ?? [], env, owner); if (!scope) return [];
      if (d.guard) { const g = obj(d.guard); if (g.call === 'in' && obj(g.args?.[0]).var) scope.set(obj(g.args![0]).var!, values(g.args?.[1], scope, d.owner, depth + 1)); }
      return values(keyword(d.body, 'do'), scope, d.owner, depth + 1);
    }));
    return [];
  }
  function bind(d: Definition, args: Ast[], env: Env, caller: Module): Env | undefined {
    const required = d.params.filter(p => obj(p).call !== '\\\\').length;
    if (args.length < required || args.length > d.params.length) return undefined;
    const scope: Env = new Map();
    for (let i = 0; i < d.params.length; i++) {
      const param = obj(d.params[i]); const base = param.call === '\\\\' ? obj(param.args?.[0]) : param;
      const actual = i < args.length ? values(args[i], env, caller) : values(param.args?.[1], env, d.owner);
      if (base.atom && actual.length && !actual.includes(base.atom)) return undefined;
      if (base.var) scope.set(base.var, actual);
    }
    return scope;
  }
  function emit(kind: string, reasons: string[], layers: string[], owner: Module, n: Node, via: Site['via']): void {
    for (const reason of reasons) for (const layer of kind === 'core' || kind === 'jose' ? layers : ['']) {
      const rule_id = `${kind}/${layer ? layer + '.' : ''}${reason}`;
      entries.set(rule_id, {kind, ...(layer ? {layer} : {}), reason, rule_id});
      const site: Site = {rule_id, path: owner.path, line: n.line ?? 0, expression: n.expression ?? '', via};
      const list = sites.get(kind) ?? [];
      if (!list.some(s => s.rule_id === rule_id && s.path === site.path && s.line === site.line)) list.push(site);
      sites.set(kind, list);
    }
  }
  function visit(value: Ast, env: Env, owner: Module, via: Site['via'] = []): void {
    const n = obj(value);
    if (n.call === '=' && obj(n.args?.[0]).var) { env.set(obj(n.args![0]).var!, values(n.args?.[1], env, owner)); visit(n.args![1]!, env, owner, via); return; }
    if (n.call === '->') {
      const scope = new Map(env);
      const guards = (value: Ast): void => { const g = obj(value); if (g.call === 'when') for (const guard of g.args?.slice(1) ?? []) visit(guard, scope, owner, via); else for (const c of children(value)) guards(c); };
      guards(n.args![0]!); visit(n.args![1]!, scope, owner, via); return;
    }
    if (n.call === 'in' && obj(n.args?.[0]).var && Array.isArray(n.args?.[1])) env.set(obj(n.args![0]).var!, values(n.args![1], env, owner));
    if (n.call === 'new' && n.receiver) {
      const kind = kindFor(resolve(n.receiver, owner));
      if (kind) emit(kind, values(n.args?.[0], env, owner), values(n.args?.[1], env, owner), owner, n, via);
    }
    if (n.call === '%' && obj(n.args?.[0]).module) {
      const kind = kindFor(resolve(obj(n.args![0]).module!, owner));
      const fields = obj(n.args?.[1]).args;
      const reason = fields?.find(v => obj(obj(v).tuple?.[0]).atom === 'reason');
      const layer = fields?.find(v => obj(obj(v).tuple?.[0]).atom === 'layer');
      if (kind) emit(kind, values(obj(reason).tuple?.[1], env, owner), values(obj(layer).tuple?.[1], env, owner), owner, n, via);
    }
    if (n.call === 'throw') {
      const tuple = obj(n.args?.[0]).tuple ?? (obj(n.args?.[0]).call === '{}' ? obj(n.args?.[0]).args : undefined);
      const tag = obj(tuple?.[0]).atom;
      const kind = tag === 'structured_fields' || tag === 'digest' ? tag : tag === 'jose_error' ? 'jose' : tag && ['authentication_error','quorum_error','negotiation_error','web_bot_auth_error'].includes(tag) ? 'core' : undefined;
      if (kind) emit(kind, values(tuple?.[1], env, owner), values(tuple?.[2], env, owner), owner, n, via);
    }
    if (n.call) for (const d of targets(n.call, n.receiver, owner)) {
      const scope = bind(d, n.args ?? [], env, owner); if (!scope) continue;
      const key = `${d.owner.name}/${d.id}/${d.name}/${d.params.length}/${JSON.stringify([...scope])}`;
      if (seen.has(key) || active.has(key)) continue;
      seen.add(key); active.add(key);
      if (d.guard) visit(d.guard, scope, d.owner, via);
      visit(d.body, scope, d.owner, [...via.slice(-7), {path: owner.path, line: n.line ?? 0, expression: n.expression ?? ''}]); active.delete(key);
    }
    for (const child of children(value)) visit(child, env, owner, via);
  }
  for (const owner of modules) for (const d of owner.definitions) { const env: Env = new Map(); if (d.guard) visit(d.guard, env, owner); visit(d.body, env, owner); }
  return {entries: [...entries.values()].sort((a,b) => kinds.indexOf(a.kind) - kinds.indexOf(b.kind) || a.rule_id.localeCompare(b.rule_id, 'en')), sites, audited};
}
export function extract(repo: string, commit: string, output: string, sourceRef = commit): void {
  const sources: Record<string, string> = Object.create(null);
  function read(path: string): string { return execFileSync('git', ['-C', repo, 'show', `${sourceRef}:${path}`], {encoding: 'utf8'}); }
  function walk(path: string): void {
    const source = read(path);
    if (path.endsWith('.ex')) sources[path] = source;
    else for (const name of source.split('\n').slice(2).filter(Boolean)) if (name.endsWith('/') || name.endsWith('.ex')) walk(path + '/' + name.replace(/\/$/, ''));
  }
  walk('lib/request_seal');
  const found = extractCallSites(sources);
  const modules = kinds.map(kind => {
    const path = kind === 'core' ? 'lib/request_seal/error.ex' : `lib/request_seal/${kind}/error.ex`;
    const source = sources[path]!;
    const doc = source.match(/@moduledoc """([\s\S]*?)"""/)?.[1] ?? '';
    const words = source.match(/@reasons ~w\(([\s\S]*?)\)a/)?.[1];
    const union = source.match(/@type reason ::([\s\S]*?)@type t/)?.[1];
    const closed = words ? words.trim().split(/\s+/) : union ? atoms(union) : atoms(source.match(/@type t ::([\s\S]*?)\nend/)?.[1] ?? '');
    const call_sites = found.sites.get(kind) ?? [];
    const entries = ['core','jose','structured_fields','digest'].includes(kind) ? found.entries.filter(e => e.kind === kind) : unique(closed).map(reason => ({kind, reason, rule_id: `${kind}/${reason}`}));
    // Prose cross-checks cannot add reasons to open reason types.
    const documented = ['structured_fields','digest'].includes(kind) ? unique(atoms(doc)).filter(x => x !== 'max_bytes') : [];
    const extracted = unique(entries.map(e => e.reason));
    const docOnly = documented.filter(r => !extracted.includes(r));
    if (docOnly.length) throw new Error(`${kind}: documented reasons without call sites: ${docOnly.join(',')}`);
    if (kind === 'jose' && closed.some(r => !extracted.includes(r))) throw new Error('JOSE reason not resolved from call sites');
    const retryClause = source.match(/retryable:\s*(?:reason in \[([^\]]+)\]|reason == :([a-z_]+))/);
    const constructor = retryClause ? unique(atoms(retryClause[1] ?? `:${retryClause[2]}`)) : [];
    // Constructor defaults are only one owner: direct struct call sites can
    // derive retryability from response status. Retain that rule and provenance.
    const rules = Object.fromEntries(extracted.map(reason => {
      const statusSite = call_sites.find(site => site.rule_id === `${kind}/${reason}` &&
        /retryable:\s*[a-z_]+\s+in\s+500\.\.599/.test(site.expression));
      return [reason, statusSite
        ? {kind: "status-derived (5xx)", minimum: 500, maximum: 599,
            path: statusSite.path, line: statusSite.line}
        : {kind: "constant", value: constructor.includes(reason)}];
    }));
    const fieldsBlock = source.match(/def(?:struct|exception) ([^\n]+)/)?.[1] ?? '';
    const fields = unique([...atoms(fieldsBlock), ...[...fieldsBlock.matchAll(/\b([a-z_]+):/g)].map(m => m[1]!)]);
    return {kind, module: source.match(/defmodule ([\w.]+)/)?.[1], path, fields, reasons: extracted, retryable: {constructor, rules, documented: kind === 'discovery' ? [...constructor, 'unexpected_status (5xx only)'] : constructor}, ...(documented.length ? {documented_reasons: documented} : {}), call_sites, entries};
  });
  const entries = modules.flatMap(m => m.entries);
  if (!entries.some(e => e.rule_id === 'jose/key.algorithm_mismatch') || !entries.some(e => e.rule_id === 'core/crypto.invalid_signature')) throw new Error('known-positive call-site extraction failed');
  writeFileSync(output, JSON.stringify({commit, modules, entries}, null, 2) + '\n');
  console.log(`Extracted ${entries.length} rule IDs from ${Object.keys(sources).length} pinned source files; audited ${found.audited.length} constructor/helper sites`);
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const repo = process.env.REQUEST_SEAL_REPO;
  const [commit, output] = process.argv.slice(2);
  if (!repo || !commit || !output || process.argv.length !== 4) throw new Error('Usage: REQUEST_SEAL_REPO=<repo> extract-elixir-reasons.ts <commit> <output>');
  extract(repo, commit, output);
}
