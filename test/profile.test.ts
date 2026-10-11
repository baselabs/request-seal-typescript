import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { inspect } from "node:util";
import fc from "fast-check";
import * as api from "../src/index.ts";
import type { InnerList, Item } from "../src/structured-fields/index.ts";
import type { FreshnessFacts } from "../src/verification.ts";
import { signatureSchema } from "../src/signature-fields.ts";
import { verificationFacts } from "../src/verification.ts";
import { verifyLabel as authenticateLabel } from "../src/verify.ts";

type Surface = Readonly<{
  validSignatureInput(input: unknown): boolean;
  dictionaries(message: unknown, max: number): api.Result<readonly [readonly (readonly [string, InnerList])[], Readonly<Record<string, Item>>]>;
  preflight(input: unknown, components: unknown, extra: unknown, freshness: unknown): Promise<api.Result<FreshnessFacts | "not_evaluated">>;
  verifyLabel(message: unknown, policy: unknown, label: unknown, input: unknown, signature: unknown, stamp: unknown): Promise<api.Result<api.Verification>>;
}>;
function surface(): Surface {
  const p = (api as unknown as { Profile?: Surface }).Profile;
  assert.ok(p, "package root must export the Profile extension surface");
  assert.equal(Object.isFrozen(p), true);
  return p;
}
function value<T>(r: api.Result<T>): T { assert.ok(r.ok, JSON.stringify(r)); return r.value; }
function rejection(r: api.Result<unknown>, reason: string, layer: string) {
  assert.equal(r.ok, false, `expected ${reason}`);
  if (r.ok) return;
  assert.equal(r.error.kind, "core");
  assert.equal(r.error.reason, reason);
  assert.equal("layer" in r.error && r.error.layer, layer);
  assert.doesNotMatch(JSON.stringify(r.error), /CANARY|stack/);
}
const stamp = { name: ["test_pkg", "synthetic"] as const };
let context: Promise<{ message: api.Message; policy: api.Policy; input: InnerList; signature: Item; publicKey: api.PublicKey }> | undefined;
function fixture() {
  return context ??= (async () => {
    const base = JSON.parse(readFileSync("conformance/sources/rfc9421/rfc9421.json", "utf8")).find((v: {section: string}) => v.section === "B.2.6").message;
    const vector = JSON.parse(readFileSync("conformance/sources/rfc9421/verification/rfc9421.json", "utf8")).find((v: {label: string}) => v.label === "sig-b26");
    const message = value(api.Message.create({
      kind: base.kind, method: base.method, rawTarget: base.raw_target, targetForm: base.target_form,
      scheme: base.scheme, authority: base.authority, status:null, trailers:"unavailable", relatedRequest:null, transport:value(api.TransportFacts.create({})),
      fields: [...base.fields, ["Signature-Input", vector.signature_input], ["Signature", vector.signature]].map(([name, value]: [string, string]) =>
        valueOfField(name, value)),
      body: value(api.Body.create({ state: "unavailable" })),
    }));
    const publicKey = value(await api.PublicKey.import(readFileSync("conformance/sources/rfc9421/keys/ed25519_public.pem", "utf8"), "pem"));
    const policy = value(api.Policy.create({ algorithms: ["ed25519"], components: "()", keyResolver: () => api.ok({algorithm: "ed25519", key: publicKey}), freshness: "not_evaluated", content: "not_required", replay: "not_required" }));
    const [entries, signatures] = value(surface().dictionaries(message, 16));
    return { message, policy, input: entries[0]![1], signature: signatures["sig-b26"]!, publicKey };
  })();
}
function valueOfField(name: string, field: string) { return value(api.FieldOccurrence.create({name, value: field, section: "headers"})); }
async function check(profile: unknown, overrides: Record<string, unknown> = {}) {
  const c = await fixture();
  return surface().verifyLabel(overrides.message ?? c.message, overrides.policy ?? c.policy, overrides.label ?? "sig-b26", overrides.input ?? c.input, overrides.signature ?? c.signature, profile);
}
const accepted: [string, unknown][] = [
  ["minimal", stamp], ["null prototype", Object.assign(Object.create(null), stamp)],
  ["eight keys", {...stamp, a:true, b:false, c:null, d:0, e:"", f:"revision", g:1}],
  ["empty atoms", {name:["", ""]}],
  ...["request_seal", "request-seal", "rfc9421", "web_bot_auth", "web-bot-auth"].map(k => [`core kind ${k}`, {name:["test_pkg", k]}] as [string, unknown]),
  ...[true, false, null, -1, 0, 1, -999_999_999_999_999, 999_999_999_999_999, "", "revision", "x".repeat(256), "é".repeat(128)].map((v, i) => [`scalar ${i}`, {...stamp, metadata:v}] as [string, unknown]),
  ["ordinary special keys", Object.assign(Object.create(null), stamp, {__proto__: null, constructor:"revision"})],
  ["nonenumerable key", Object.defineProperty({...stamp}, "metadata", {value: true})],
];
for (const [name, profile] of accepted) test(`stamp accepts: ${name}`, async () => {
  surface(); const verified = value(await check(profile));
  assert.equal(verified.signature.crypto, "valid");
  assert.equal(verified.principal, "unattributed"); assert.equal(verified.authorization, "not_evaluated");
  assert.deepEqual({...verified.profile}, Object.fromEntries(Object.getOwnPropertyNames(profile as object).map(k=>[k,(profile as Record<string, unknown>)[k]])));
});
const rejected: [string, unknown][] = [
  ["bare name", {name:"synthetic"}], ["bare core name", {name:"rfc9421"}], ["absent name", {}],
  ["null", null], ["array", []], ["function", () => stamp], ["class instance", new (class { name = stamp.name; })()],
  ["custom prototype", Object.create(stamp)], ["symbol key", {...stamp, [Symbol("metadata")]:true}],
  ["nine keys", {...stamp,a:true,b:true,c:true,d:true,e:true,f:true,g:true,h:true}],
  ["short tuple", {name:["p"]}], ["long tuple", {name:["p","k","x"]}], ["sparse tuple", {name:new Array(2)}],
  ["object name", {name:{package:"p",kind:"k"}}], ["nonstring package", {name:[true,"k"]}], ["nonstring kind", {name:["p",1]}],
  ["tuple extra key", {name:Object.assign(["p","k"], {extra:true})}], ["tuple symbol", {name:Object.assign(["p","k"], {[Symbol("x")]:true})}],
  ...["request_seal", "request-seal", "rfc9421", "web_bot_auth", "web-bot-auth"].map(p => [`reserved ${p}`, {name:[p,"synthetic"]}] as [string, unknown]),
  ...["x".repeat(257), "é".repeat(129), -1_000_000_000_000_000, 1_000_000_000_000_000, -1e100, 1e100, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1.5, NaN, Infinity, -Infinity, 1n, [], {}, ["p","k"], new Uint8Array([1]), () => true, Symbol("x"), undefined].map((v, i) => [`invalid scalar ${i}`, {...stamp, metadata:v}] as [string, unknown]),
];
for (const [name, profile] of rejected) test(`stamp rejects: ${name}`, async () => {
  surface(); rejection(await check(profile), "invalid_profile", "input");
});
test("ownership: snapshots getters once, freezes stamp and tuple, retains safe inspection", async () => {
  surface(); let names=0, packages=0, kinds=0, metadata=0;
  const pair = Object.defineProperties([], {0:{get(){packages++; return "test_pkg";}, enumerable:true},1:{get(){kinds++; return "synthetic";}, enumerable:true}});
  const source = {get name(){names++;return pair;}, get revision(){metadata++;return "visible";}};
  const verified = value(await check(source));
  assert.deepEqual([names,packages,kinds,metadata], [1,1,1,1]);
  assert.equal(Object.getPrototypeOf(verified.profile), null);
  assert.equal(Object.isFrozen(verified.profile), true); assert.equal(Object.isFrozen(verified.profile.name), true);
  assert.equal(Object.isFrozen(source), false); assert.equal(Object.isFrozen(pair), false);
  assert.equal(api.isVerification({...verified}), false);
  const printed = inspect(verified); assert.match(printed, /visible/); assert.doesNotMatch(printed, /test-key-ed25519|parameters|signature/);
  assert.deepEqual(Object.keys(JSON.parse(JSON.stringify(verified))), ["label","profile","replay","authorization"]);
  const mutable = {name:["test_pkg","synthetic"], revision:"original"};
  const v = value(await check(mutable)); mutable.name[0]="changed"; mutable.revision="changed";
  assert.deepEqual({...v.profile}, {name:["test_pkg","synthetic"],revision:"original"});
});
test("ownership: thrown accessors protect with invalid_policy without diagnostics", async () => {
  surface(); rejection(await check({get name(){throw new Error("PROFILE-CANARY");}}), "invalid_policy", "input");
});
test("ownership: bounded scalar law over generated metadata and name pairs", async () => {
  surface(); await fc.assert(fc.asyncProperty(fc.string({maxLength:32}), fc.string({maxLength:32}), fc.oneof(fc.boolean(),fc.constant(null),fc.integer({min:-999_999_999_999_999,max:999_999_999_999_999}),fc.string({maxLength:32})), async (packageName, kind, metadata) => {
    fc.pre(!["request_seal","request-seal","rfc9421","web_bot_auth","web-bot-auth"].includes(packageName));
    const p = {name:[packageName,kind],metadata}; const v = value(await check(p)); assert.deepEqual({...v.profile}, p);
  }), {numRuns:32});
});
const precedence: [string, string, string, Record<string, unknown>, unknown][] = [
  ["profile before policy", "invalid_profile", "input", {policy:{}}, {name:"bare"}],
  ["policy before label", "invalid_policy", "input", {policy:{},label:"BAD LABEL"}, stamp],
  ["label before message", "invalid_options", "input", {label:"BAD LABEL",message:{}}, stamp],
  ["message before signature", "invalid_message", "input", {message:{},signature:{}}, stamp],
  ["signature shape before dictionaries", "invalid_signature_field", "fields", {message:"missing-signature",signature:{}}, stamp],
  ["dictionaries before unknown label", "missing_signature", "fields", {message:"missing-signature",label:"absent"}, stamp],
  ["unknown label before input mismatch", "unknown_label", "fields", {label:"absent",input:{}}, stamp],
  ["input mismatch before signature mismatch", "invalid_signature_input", "fields", {input:{},signature:"different-signature"}, stamp],
  ["signature mismatch before input semantics", "invalid_signature_field", "fields", {message:"invalid-semantics",input:"invalid-semantics",signature:"different-signature"}, stamp],
];
for (const [name, reason, layer, raw, profile] of precedence) test(`precedence: ${name}`, async () => {
  surface(); const c = await fixture(), o={...raw};
  if (o.message === "missing-signature") o.message=value(api.Message.create({...c.message,fields:c.message.fields.filter(f=>f.name.toLowerCase()!=="signature")}));
  if (o.signature === "different-signature") o.signature={...c.signature,parameters:[["extra",{kind:"boolean",value:true}]]};
  if (o.message === "invalid-semantics") {
    o.message=value(api.Message.create({...c.message,fields:c.message.fields.map(f=>f.name.toLowerCase()==="signature-input"?valueOfField("Signature-Input",'sig-b26=("UPPER")'):f)}));
    o.input=value(surface().dictionaries(o.message,16))[0][0]![1];
  }
  rejection(await check(profile,o),reason,layer);
});
test("selection: structurally equal separately parsed nodes accept; bytes and parameters differ reject before resolution", async () => {
  surface(); const c=await fixture();
  const [entries, signatures]=value(surface().dictionaries(c.message,16));
  assert.notEqual(entries[0]![1],c.input); assert.notEqual(signatures["sig-b26"],c.signature);
  value(await check(stamp,{input:entries[0]![1],signature:signatures["sig-b26"]}));
  let resolutions=0;
  const p=value(api.Policy.create({...c.policy,keyResolver:()=>{resolutions++;return api.ok({algorithm:"ed25519",key:c.publicKey});}}));
  rejection(await check(stamp,{policy:p,input:{...c.input,parameters:[...c.input.parameters,["tag",{kind:"string",value:"changed"}]]}}),"invalid_signature_input","fields");
  const bytes=new Uint8Array(c.signature.value.value as Uint8Array); bytes[7]=bytes[7]!^1;
  rejection(await check(stamp,{policy:p,signature:{...c.signature,value:{kind:"bytes",value:bytes}}}),"invalid_signature_field","fields");
  rejection(await check(stamp,{policy:p,signature:{...c.signature,parameters:[["extra",{kind:"boolean",value:true}]]}}),"invalid_signature_field","fields");
  assert.equal(resolutions,0);
});
test("selection: signature byte bounds and policy member limit", async () => {
  surface(); const c=await fixture();
  for(const n of [0,1025]) rejection(await check(stamp,{signature:{kind:"item",value:{kind:"bytes",value:new Uint8Array(n)},parameters:[]}}),"invalid_signature_field","fields");
  const missing=value(api.Message.create({...c.message,fields:c.message.fields.filter(f=>f.name.toLowerCase()!=="signature")}));
  for(const n of [1,1024]) rejection(await check(stamp,{message:missing,signature:{kind:"item",value:{kind:"bytes",value:new Uint8Array(n)},parameters:[]}}),"missing_signature","fields");
  const m=value(api.Message.create({...c.message,fields:[...c.message.fields,valueOfField("Signature-Input",'second=()'),valueOfField("Signature",'second=:AQ==:')]}));
  const p=value(api.Policy.create({...c.policy,maxSignatures:1}));
  rejection(await check(stamp,{message:m,policy:p}),"limit","input");
});
test("helpers: validSignatureInput is a nonthrowing semantic predicate", async () => {
  const p=surface(), c=await fixture(); assert.equal(p.validSignatureInput(c.input),true);
  for(const v of [null,undefined,0,"()",{},[],{kind:"inner_list"},{kind:"item"}, {...c.input,value:[c.input.value[0],c.input.value[0]]}, {...c.input,parameters:[["created",{kind:"string",value:"bad"}]]}, {get kind(){throw new Error("CANARY");}}]) assert.equal(p.validSignatureInput(v),false);
  assert.equal(p.validSignatureInput((value(api.StructuredFields.parse("list","()",{schema:signatureSchema})) as api.List).value[0]),true);
});
test("helpers: dictionaries retain order, pairing and safe missing-field results", async () => {
  surface(); const c=await fixture(); const [entries,sigs]=value(surface().dictionaries(c.message,16));
  assert.deepEqual(entries.map(([k])=>k),["sig-b26"]); assert.equal(Object.getPrototypeOf(sigs),null); assert.equal(Object.isFrozen(sigs),true);
  const extra=value(api.Message.create({...c.message,fields:[...c.message.fields,valueOfField("Signature-Input","a=()"),valueOfField("Signature","a=:AQ==:")]}));
  assert.deepEqual(value(surface().dictionaries(extra,16))[0].map(([k])=>k),["sig-b26","a"]);
  const noSig=value(api.Message.create({...c.message,fields:c.message.fields.filter(f=>f.name.toLowerCase()!=="signature")}));
  rejection(surface().dictionaries(noSig,16),"missing_signature","fields");
  const unpaired=value(api.Message.create({...c.message,fields:[...c.message.fields,valueOfField("Signature-Input","a=()")]}));
  rejection(surface().dictionaries(unpaired,16),"label_mismatch","fields");
});
test("helpers: preflight shares coverage and freshness checks before resolution", async () => {
  const p=surface(), c=await fixture();
  assert.equal(value(await p.preflight(c.input,"()","allow","not_evaluated")),"not_evaluated");
  rejection(await p.preflight(c.input,'("@query")',"allow","not_evaluated"),"missing_required_component","policy");
  rejection(await p.preflight(c.input,"()","reject","not_evaluated"),"unexpected_component","policy");
  const fresh={clock:()=>1618884473,maxAge:60,skew:0,requireExpires:false};
  assert.deepEqual(value(await p.preflight(c.input,"()","allow",fresh)),{now:1618884473,created:1618884473,expires:null,maxAge:60,skew:0});
  rejection(await p.preflight(c.input,"()","allow",{...fresh,clock:()=>{throw new Error("CANARY");}}),"invalid_clock","freshness");
  rejection(await p.preflight(c.input,"()","allow",{...fresh,unknown:true}),"invalid_policy","input");
  rejection(await p.preflight(c.input,"()","allow",{clock:()=>0,maxAge:null,requireExpires:false}),"invalid_policy","input");
});
test("canonical extension profile matches reference conversion and retains metadata spelling", async () => {
  surface(); const v=value(await check({...stamp,revision:"one",counter:-1,enabled:true,disabled:false,absent:null,maxAge:2}));
  const expected={name:["test_pkg","synthetic"],revision:"one",counter:-1,enabled:"true",disabled:"false",absent:"",maxAge:2};
  const serialized=JSON.parse(new TextDecoder().decode(value(api.serializeVerification(v))));
  assert.deepEqual(serialized.profile,expected); assert.deepEqual((value(verificationFacts(v)) as {profile:unknown}).profile,expected);
  assert.equal(serialized.signature.crypto,"valid"); assert.equal(serialized.principal,"unattributed");
  assert.doesNotMatch(new TextDecoder().decode(value(api.serializeVerification(v))),/wqcAqbm|BEGIN PUBLIC/);
});
test("replay: commitments bind profile name and separate real atomic memory claims", async () => {
  surface(); const c=await fixture(), store=value(api.createMemoryStore({maxEntries:16}));
  const key=value(await api.Custody.local("ed25519",readFileSync("conformance/sources/rfc9421/keys/ed25519_private.pem","utf8")));
  try {
    const now=Math.floor(Date.now()/1000), seen:unknown[]=[];
    const p=value(api.Policy.create({...c.policy,freshness:{clock:()=>now,maxAge:null,skew:0,requireExpires:true},replay:{identifier:"nonce",namespace:new TextEncoder().encode("profile-test"),store,timeoutMs:1000,commitment:async(facts:api.ReplayFacts)=>{
      seen.push(facts.profile); assert.equal(Object.isFrozen(facts.profile),true);
      return api.ok(new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(JSON.stringify([facts.profile.name,facts.identifier])))));
    }}}));
    const unsigned=value(await api.Message.request("GET","https://example.com/",[],""));
    const signed=value(await api.sign(unsigned,{label:"s",algorithm:"ed25519",signatureInput:`("@method");created=${now};expires=${now+60};nonce="same-nonce"`},key));
    value(await api.verify(signed,p,{label:"s"}));
    const [entries,signatures]=value(surface().dictionaries(signed,16));
    const verify=(profile:unknown)=>surface().verifyLabel(signed,p,"s",entries[0]![1],signatures.s,profile);
    const a=value(await verify(stamp)); assert.deepEqual({...a.profile},stamp);
    rejection(await verify(stamp),"replayed","replay");
    const other={name:["other_pkg","synthetic"]}; value(await verify(other)); rejection(await verify(other),"replayed","replay");
    assert.deepEqual(seen.map(v=>({...v as object})),[{name:"rfc9421"},stamp,stamp,other,other]);
  } finally {await key.release();}
});
test("selection: generic options cannot supply profile or principal", async () => {
  surface(); const c=await fixture();
  for(const k of ["profile","principal"]) rejection(await api.verify(c.message,c.policy,{label:"sig-b26",[k]:{name:"CANARY"}}),"invalid_profile","input");
  assert.equal(surface().verifyLabel.length,6);
});
test("selection: decimal coefficient and scale equality follows reference values", async () => {
  surface(); const c=await fixture();
  const key=value(await api.Custody.local("ed25519",readFileSync("conformance/sources/rfc9421/keys/ed25519_private.pem","utf8")));
  try {
    const unsigned=value(await api.Message.request("GET","https://example.com/",[],""));
    const signed=value(await api.sign(unsigned,{label:"s",algorithm:"ed25519",signatureInput:'("@method");x=1.0;y=0.0'},key));
    const [entries,sigs]=value(surface().dictionaries(signed,16));
    const parse=(wire:string)=>(value(api.StructuredFields.parse("list",wire,{schema:signatureSchema})) as api.List).value[0];
    rejection(await surface().verifyLabel(signed,c.policy,"s",parse('("@method");x=1.00;y=0.0'),sigs.s,stamp),"invalid_signature_input","fields");
    value(await surface().verifyLabel(signed,c.policy,"s",parse('("@method");x=01.0;y=-0.0'),sigs.s,stamp));
    value(await surface().verifyLabel(signed,c.policy,"s",entries[0]![1],sigs.s,stamp));
  } finally {await key.release();}
});
test("helpers: preflight coverage rejects before malformed freshness or its clock", async () => {
  const p=surface(), c=await fixture(); let clocks=0;
  rejection(await p.preflight(c.input,'("@query")',"allow",{clock(){clocks++;return 0;},maxAge:null,requireExpires:false}),"missing_required_component","policy");
  assert.equal(clocks,0);
  const reads:Record<string,number>={clock:0,maxAge:0,skew:0,requireExpires:0};
  const raw={get clock(){reads.clock!++;return ()=>1618884473;},get maxAge(){reads.maxAge!++;return 60;},get skew(){reads.skew!++;return 0;},get requireExpires(){reads.requireExpires!++;return false;}};
  value(await p.preflight(c.input,"()","allow",raw)); assert.deepEqual(reads,{clock:1,maxAge:1,skew:1,requireExpires:1});
});

for (const metadata of ["é", "😀", "\u2028", "\ufffd"]) test(`S1: stamp metadata ${JSON.stringify(metadata)} serializes as strict UTF-8`, async () => {
  const verified = value(await check({...stamp, metadata}));
  const bytes = value(api.serializeVerification(verified));
  const text = new TextDecoder("utf-8", {fatal: true}).decode(bytes);
  assert.equal(JSON.parse(text).profile.metadata, metadata);
  assert.deepEqual(bytes, new TextEncoder().encode(text));
});

test("name parts and keys use the 255-code-point atom bound", async () => {
  for (const character of ["a", "é", "😀"]) {
    for (const position of ["package", "kind", "key"]) {
      const profile = (n: number) => position === "key"
        ? {...stamp, [character.repeat(n)]: true}
        : {name: [position === "package" ? character.repeat(n) : "test_pkg", position === "kind" ? character.repeat(n) : "synthetic"]};
      value(await check(profile(255)));
      rejection(await check(profile(256)), "invalid_profile", "input");
    }
  }
});

test("every stamp string rejects lone surrogates", async () => {
  for (const malformed of ["\ud800", "\udfff", "a\ud800b", "a\udfffb"]) {
    for (const profile of [{name: [malformed, "synthetic"]}, {name: ["test_pkg", malformed]}, {...stamp, [malformed]: true}, {...stamp, metadata: malformed}]) {
      rejection(await check(profile), "invalid_profile", "input");
    }
  }
});

test("preflight components failures use authentication reasons", async () => {
  const c = await fixture();
  for (const components of ["(", 5]) rejection(await surface().preflight(c.input, components, "allow", "not_evaluated"), "invalid_signature_input", "fields");
  rejection(await surface().preflight(c.input, " ".repeat(65_537), "allow", "not_evaluated"), "limit", "input");
});

test("selected decimal clones compare raw fields and parsed nodes compare source scale", async () => {
  const c = await fixture();
  const key = value(await api.Custody.local("ed25519", readFileSync("conformance/sources/rfc9421/keys/ed25519_private.pem", "utf8")));
  try {
    const unsigned = value(await api.Message.request("GET", "https://example.com/", [], ""));
    const signed = value(await api.sign(unsigned, {label: "s", algorithm: "ed25519", signatureInput: '("@method");x=1.50'}, key));
    const [entries, signatures] = value(surface().dictionaries(signed, 16));
    const input = entries[0]![1];
    value(await surface().verifyLabel(signed, c.policy, "s", structuredClone(input), signatures.s, stamp));
    const changed = structuredClone(input);
    const decimal = changed.parameters[0]![1];
    assert.equal(decimal.kind, "decimal");
    if (decimal.kind !== "decimal") throw new Error("expected decimal");
    const different = {...changed, parameters: [["x", {...decimal, value: {...decimal.value, scaled: 1501}}]]};
    rejection(await surface().verifyLabel(signed, c.policy, "s", different, signatures.s, stamp), "invalid_signature_input", "fields");
    const parse = (wire: string) => (value(api.StructuredFields.parse("list", wire, {schema: signatureSchema})) as api.List).value[0];
    const tens = value(await api.sign(unsigned, {label: "s", algorithm: "ed25519", signatureInput: '("@method");x=10.0'}, key));
    const tensSignature = value(surface().dictionaries(tens, 16))[1].s;
    rejection(await surface().verifyLabel(tens, c.policy, "s", parse('("@method");x=1.00'), tensSignature, stamp), "invalid_signature_input", "fields");
    // Equal coefficients with different scales must remain unequal.
    const scaled = structuredClone(input);
    const d = scaled.parameters[0]![1];
    assert.equal(d.kind, "decimal");
    if (d.kind !== "decimal") throw new Error("expected decimal");
    const differentScale = {...scaled, parameters: [["x", {...d, value: {...d.value, scale: 2}}]]};
    rejection(await surface().verifyLabel(signed, c.policy, "s", differentScale, signatures.s, stamp), "invalid_signature_input", "fields");
  } finally { await key.release(); }
});

test("stamp snapshot normalizes negative zero", async () => {
  const verified = value(await check({...stamp, metadata: -0}));
  assert.equal(Object.is((verified.profile as api.ProfileStamp<"metadata">).metadata, 0), true);
});

test("dictionaries invalid arguments use protect's invalid_policy reason", async () => {
  const c = await fixture();
  for (const max of [0, NaN, 100000, "16"]) rejection(surface().dictionaries(c.message, max as number), "invalid_policy", "input");
  rejection(surface().dictionaries({}, 16), "invalid_policy", "input");
  value(surface().dictionaries(c.message, 1024));
  rejection(surface().dictionaries(c.message, 1025), "invalid_policy", "input");
});

test("selected signature 1025-byte rejection precedes dictionaries", async () => {
  const c = await fixture();
  const missing = value(api.Message.create({...c.message, fields: c.message.fields.filter(f => f.name.toLowerCase() !== "signature")}));
  rejection(await check(stamp, {message: missing, signature: {kind: "item", value: {kind: "bytes", value: new Uint8Array(1025)}, parameters: []}}), "invalid_signature_field", "fields");
});

test("extension pipeline unexpected faults retain invalid_policy", async () => {
  const c = await fixture();
  rejection(await authenticateLabel(c.message, c.policy, {label: "sig-b26"}, () => {throw new Error("CANARY");}, undefined, stamp), "invalid_policy", "input");
});

test("reordered stamps agree in serialization and replay commitment input; the name tuple resists callback mutation", async () => {
  const c = await fixture(), store = value(api.createMemoryStore({maxEntries: 16}));
  const key = value(await api.Custody.local("ed25519", readFileSync("conformance/sources/rfc9421/keys/ed25519_private.pem", "utf8")));
  try {
    const now = Math.floor(Date.now() / 1000), seen: string[] = [];
    const p = value(api.Policy.create({...c.policy, freshness: {clock: () => now, maxAge: null, skew: 0, requireExpires: true}, replay: {
      identifier: "nonce", namespace: new TextEncoder().encode("stamp-order"), store, timeoutMs: 1000,
      commitment: async (facts: api.ReplayFacts) => {
        seen.push(JSON.stringify(facts.profile));
        if (Array.isArray(facts.profile.name)) {
          assert.equal(Reflect.set(facts.profile.name, "0", "changed"), false);
          assert.deepEqual(facts.profile.name, stamp.name);
        }
        return api.ok(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify([facts.profile, facts.identifier])))));
      },
    }}));
    const unsigned = value(await api.Message.request("GET", "https://example.com/", [], ""));
    const signed = value(await api.sign(unsigned, {label: "s", algorithm: "ed25519", signatureInput: `("@method");created=${now};expires=${now + 60};nonce="same"`}, key));
    const [entries, signatures] = value(surface().dictionaries(signed, 16));
    const a = {...stamp, m: "one", z: true, "2": false, "10": null, "𐀀": 1, "": 2}, b = {"": 2, "𐀀": 1, "10": null, "2": false, z: true, name: stamp.name, m: "one"};
    const va = value(await check(a)), vb = value(await check(b));
    assert.deepEqual(value(api.serializeVerification(va)), value(api.serializeVerification(vb)));
    assert.deepEqual(Object.keys(va.profile), ["2", "10", "name", "m", "z", "𐀀", ""]);
    assert.deepEqual(structuredClone(va.profile), {...va.profile});
    assert.match(new TextDecoder().decode(value(api.serializeVerification(va))), /"profile":\{"2":"false","10":"","name":\["test_pkg","synthetic"\],"m":"one","z":"true","𐀀":1,"":2\}/);
    const verified = value(await surface().verifyLabel(signed, p, "s", entries[0]![1], signatures.s, a));
    assert.deepEqual(verified.profile.name, stamp.name);
    rejection(await surface().verifyLabel(signed, p, "s", entries[0]![1], signatures.s, b), "replayed", "replay");
    assert.equal(seen.length, 2); assert.equal(seen[0], seen[1]);
  } finally { await key.release(); }
});

test("Deno.inspect exposes only the four redacted verification fields", {skip: !(globalThis as unknown as {Deno?: object}).Deno}, async () => {
  const deno = (globalThis as unknown as {Deno?: {inspect(value: unknown, options?: {colors: boolean; depth: number}): string}}).Deno;
  assert.ok(deno, "Deno.inspect requires Deno");
  let observed: string[] = [];
  assert.equal(deno.inspect({[Symbol.for("Deno.customInspect")](...args: unknown[]) {
    observed = args.map(arg => typeof arg);
    return "redacted";
  }}), "redacted");
  console.log(`Deno.customInspect arguments: ${JSON.stringify(observed)}`);
  assert.deepEqual(observed, ["function", "object"]);
  const verified = value(await check({...stamp, revision: "visible"}));
  const printed = deno.inspect(verified, {colors: false, depth: 10});
  console.log(printed);
  const redacted = {label: verified.label, profile: verified.profile, replay: verified.replay, authorization: verified.authorization};
  assert.equal(printed, deno.inspect(redacted, {colors: false, depth: 10}));
  assert.doesNotMatch(printed, /signature|parameters|principal|freshness|content|test-key-ed25519/);
});

test("extension docs describe whole-stamp replay binding and public type widening", () => {
  const profiles = readFileSync("docs/reference/profiles.md", "utf8");
  const replay = readFileSync("docs/reference/replay.md", "utf8");
  const signing = readFileSync("docs/reference/sign-and-verify.md", "utf8");
  const changelog = readFileSync("CHANGELOG.md", "utf8");
  assert.match(profiles, /whole stamp/);
  assert.match(replay, /facts\.profile,\s*identifiers/);
  assert.match(signing, /extension stamps/);
  assert.match(changelog, /Verification\.profile.*ReplayFacts\.profile/s);
  assert.match(changelog, /exhaustive narrowing/);
  assert.match(changelog, /Render Deno inspection of Verifications/);
});
