import test from 'node:test';
import assert from 'node:assert/strict';
import {Discovery, DiscoverySource, PublicKey, createCache, withDeadline, type Result} from '../src/index.ts';
import {bodyKeys, bodyDocument} from '../src/discovery/body.ts';
import {fromResource} from '../src/discovery/snapshot.ts';
import {fields} from '../src/discovery/headers.ts';
// RFC 8037 Appendix A.3 public key and independently published thumbprint.
const jwk={kty:'OKP',crv:'Ed25519',x:'11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo'};
const kid='kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k';
const jwks=()=>JSON.stringify({keys:[jwk]});
const bytes=(s:string)=>new TextEncoder().encode(s);
const headers=[['content-type','application/json']] as const;
function value<T>(r:Result<T>):T{assert.equal(r.ok,true,JSON.stringify(r));return (r as {ok:true;value:T}).value;}
function reason(r:Result<unknown>,why:string){assert.equal(r.ok,false);if(!r.ok)assert.equal(r.error.reason,why);}
const source=(more={})=>value(DiscoverySource.create({type:'jwks_uri',location:'https://agent.example/keys',...more}));
const snapshot=(s:unknown,now:number)=>Discovery.resolver.fromSnapshot(s,bytes(jwks()),now,headers);
test('directory empty queries reject before normalization',()=>{for(const location of ['https://a.example?','https://a.example/?']) reason(DiscoverySource.create({type:'directory',location}),'invalid_source');});
test('source defects precede invalid negative TTL',()=>{for(const more of [{type:'directory',keyId:'directory'},{requireSignedDirectory:0}]) reason(DiscoverySource.create({type:'jwks_uri',location:'https://a.example',negativeTtl:301,...more}),'invalid_source');});
test('options precede enrollment and tombstone checks',async()=>{
  let now=100; const c=value(createCache({clock:()=>now,maxSources:1})), s=source();
  try {value(await c.refresh(s,value(await snapshot(s,100))));
    reason(await c.resolve(source({location:'https://other.example/keys'}),kid,{algorithms:['nope']}),'invalid_options');
    value(c.remove(s,kid)); now=-1; reason(await c.resolve(s,kid),'invalid_options');
  }finally{c.close();}
});
test('empty CIMD array preserves client_id_mismatch',async()=>{reason(await Discovery.resolver.fromSnapshot({type:'cimd',location:'https://a.example/client'},bytes('[]'),100,headers),'client_id_mismatch');});
test('203 headers under the byte cap are accepted',async()=>{const hs=[...headers,...Array.from({length:202},(_,i)=>[`x-${i}`,'a'] as const)];value(await Discovery.resolver.fromSnapshot(source(),bytes(jwks()),100,hs));});
test('snapshots require the same media type as a fetch',async()=>{for(const hs of [[],[['content-type','text/html']]]) reason(await Discovery.resolver.fromSnapshot(source(),bytes(jwks()),100,hs),'unexpected_media_type');});
test('parsing is internal and unsigned directory resolutions retain proof status',async()=>{
  assert.equal(Object.hasOwn(Discovery,'parseBody'),false);
  const s=source({type:'directory',location:'https://a.example',requireSignedDirectory:false});
  const set=value(await Discovery.resolver.fromSnapshot(s,bytes(jwks()),100,[['content-type','application/http-message-signatures-directory+json']]));
  assert.equal(set.keys[kid]!.proof,'unsigned');assert.equal(set.proof,'unsigned');
});
test('a late body cannot begin key import or parsing after cancellation',async()=>{
  const s=source(); const controller=new AbortController(), c=value(withDeadline({signal:controller.signal}));controller.abort();
  // The actual delayed body contains a bad second key: cancellation must win first.
  const r=await fromResource(s,bytes(jwks()),bytes(jwks()),100,fields(headers),s.location,undefined,false,c);
  reason(r,'deadline_exceeded');
  await assert.rejects(()=>bodyKeys(bodyDocument(bytes('{"keys":[{},{}]}'),s),s,100,s.location,c),e => !!e && typeof e==='object' && 'reason' in e && e.reason==='deadline_exceeded');
});

for (const discarded of ['no-store', 'expiry', 'invalidate'] as const) test(`cache rollback history survives ${discarded}`, async () => {
  let now = 150;
  const s = source(), c = value(createCache({clock:()=>now}));
  // RFC 8032 test 2 public key: a published rotation target, not a generated key.
  const rotated = {kty:'OKP',crv:'Ed25519',x:'PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw'};
  const set = async (keys: unknown[], at: number, freshness: string) => value(await Discovery.resolver.fromSnapshot(s,bytes(JSON.stringify({keys})),at,[...headers,['cache-control',freshness]]));
  try {
    const old = await set([jwk],100,'max-age=5000');
    value(await c.refresh(s,old));
    now = 205;
    const newer = await set([rotated],200,discarded === 'expiry' ? 'max-age=10' : 'max-age=5000');
    value(await c.refresh(s,newer));
    reason(await c.resolve(s,kid),'unknown_key');
    reason(await c.refresh(s,old),'invalid_options');
    now = 300;
    if (discarded === 'no-store') value(await c.refresh(s,await set([rotated],250,'no-store')));
    if (discarded === 'expiry') {
      reason(await c.resolve(s,kid),'source_unavailable');
      value(await c.refresh(s,await set([rotated],250,'max-age=1')));
    }
    if (discarded === 'invalidate') value(c.invalidate(s));
    reason(await c.refresh(s,old),'invalid_options');
    reason(await c.resolve(s,kid),'source_unavailable');
    value(await c.refresh(s,await set([rotated],300,'max-age=5000')));
    reason(await c.resolve(s,kid),'unknown_key');
  } finally {c.close();}
});

test('future fetch results cannot install or poison cache high-water marks', async () => {
  const s = source(), future = value(await snapshot(s, 200)), legitimate = value(await snapshot(s, 100));
  const cache = value(createCache({clock: () => 100, fetch: async () => ({ok: true as const, value: future})}));
  try {
    const fetched = await cache.refresh(s); assert.equal(fetched.ok, false);
    assert.equal(!fetched.ok && fetched.error.reason, 'source_unavailable');
    value(await cache.refresh(s, legitimate)); assert.ok((await cache.resolve(s, kid)).ok);
  } finally {cache.close();}
});
test('quoted and parameterized cache directives pin comma-split and qualified-name contracts', async () => {
  const s = source();
  // Qualified no-store/no-cache zero freshness; a directive name inside a quoted
  // value still lands between commas of the pinned split; look-alike names do not.
  for (const [directive, offset] of [['no-store="x", max-age=20', 0], ['x="a,no-store,b", max-age=20', 0], ['no-cacheable="a", max-age=20', 20]] as const) {
    const set = value(await Discovery.resolver.fromSnapshot(s, bytes(jwks()), 100, [...headers, ['cache-control', directive]]));
    assert.equal(set.expiresAt, 100 + offset);
  }
});
test('source validation accepts pinned numeric and trailing-dot host spellings', () => {
  for (const location of ['https://2130706433/', 'https://0x7f.1/', 'https://example.com./']) assert.ok(DiscoverySource.create({type: 'jwks_uri', location}).ok, location);
});
test('the key-set resolver checks freshness against the caller clock it is given',async()=>{
  // A snapshot fetched at a fixed past time with no cache headers stays fresh for minTtl (300 s).
  const fetchedAt=1_000_000, s=source(), set=value(await snapshot(s,fetchedAt));
  let now=fetchedAt+10;
  const fixed=value(Discovery.resolver(set,{algorithms:['ed25519'],clock:()=>now}));
  assert.equal(value(await fixed({keyid:kid})).algorithm,'ed25519');
  now=fetchedAt+300; reason(await fixed({keyid:kid}),'unknown_key'); // stale against the same clock
  // Without a clock the bridge keeps system time, where this 1970 snapshot is long stale.
  reason(await value(Discovery.resolver(set,{algorithms:['ed25519']}))({keyid:kid}),'unknown_key');
  // The cache bridge passes the same clock to cache.resolve.
  const c=value(createCache({clock:()=>fetchedAt}));
  try {value(await c.refresh(s,set)); now=fetchedAt+10;
    assert.equal(value(await value(Discovery.resolver({cache:c,source:s},{algorithms:['ed25519'],clock:()=>now}))({keyid:kid})).algorithm,'ed25519');
  }finally{c.close();}
  for(const clock of [5,()=>-1,()=>1.5]){
    const r=Discovery.resolver(set,{algorithms:['ed25519'],clock});
    if(r.ok) reason(await r.value({keyid:kid}),'invalid_options'); else reason(r,'invalid_options');
  }
});
test('a throwing resolver clock gives invalid_options on both the key-set and cache paths',async()=>{
  const s=source(), set=value(await snapshot(s,1_000_000)), boom=()=>{throw new Error('clock');};
  reason(await value(Discovery.resolver(set,{algorithms:['ed25519'],clock:boom}))({keyid:kid}),'invalid_options');
  const c=value(createCache({clock:()=>1_000_000}));
  try {value(await c.refresh(s,set));
    reason(await value(Discovery.resolver({cache:c,source:s},{algorithms:['ed25519'],clock:boom}))({keyid:kid}),'invalid_options');
  }finally{c.close();}
});
test('a resolver clock decides freshness but never stamps the shared cache',async()=>{
  const cacheNow=1_000_000, ahead=cacheNow+100_000, s=source();
  const fetches:number[]=[];
  // The fetch callback builds a real snapshot from fixed bytes at the clock the cache hands it.
  const c=value(createCache({clock:()=>cacheNow,fetch:async(src:unknown,{clock}:{clock:()=>number})=>{fetches.push(clock());return Discovery.resolver.fromSnapshot(src,bytes(jwks()),clock(),[...headers,['cache-control','max-age=600']]);}}));
  try {
    // At the resolver's clock the key is long stale, so it is refused...
    reason(await value(Discovery.resolver({cache:c,source:s},{algorithms:['ed25519'],clock:()=>ahead}))({keyid:kid}),'unknown_key');
    // ...but the cache fetched and stored on its own clock, so other callers see a fresh entry.
    assert.deepEqual(fetches,[cacheNow]);
    assert.equal(value(await c.resolve(s,kid)).fetchedAt,cacheNow);
    assert.equal(fetches.length,1,'the stored entry is served without another fetch');
    // A resolver clock inside the entry's lifetime resolves without refetching.
    assert.equal(value(await value(Discovery.resolver({cache:c,source:s},{algorithms:['ed25519'],clock:()=>cacheNow+60}))({keyid:kid})).algorithm,'ed25519');
    assert.equal(fetches.length,1);
  } finally {c.close();}
});

// RFC 7517 Appendix A.1 public members (vendored at
// test/fixtures/upstream/custody/rfc7517.json): the published vector asserts
// the JOSE name RS256, the standard spelling an RFC 7517 source uses.
const rsa={kty:'RSA',n:'0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',e:'AQAB'};
const snapshotKeys=async(s:ReturnType<typeof source>,keys:unknown[])=>Discovery.resolver.fromSnapshot(s,bytes(JSON.stringify({keys})),100,headers);
test('JWKS alg assertions accept both registry spellings normalized once at import',async()=>{
  const s=source();
  // Either spelling of the assertion normalizes to the JOSE name, which exists
  // for every registry entry (PS256 and PS384 have no HTTP identifier).
  for(const asserted of ['ed25519','EdDSA']) {
    const set=value(await snapshotKeys(s,[{...jwk,alg:asserted}]));
    const entry=set.keys[kid]!;
    assert.equal(entry.assertedAlgorithm,'EdDSA');
    assert.deepEqual(entry.algorithm,{jws:'EdDSA'});
    // Either allowlist spelling selects the key; an unrelated one does not.
    value(await set.lookup(kid,['ed25519'],101));
    value(await set.lookup(kid,[{jws:'EdDSA'}],101));
    reason(await set.lookup(kid,['ecdsa-p256-sha256'],101),'unknown_key');
  }
  // The published RSA vector asserts RS256: the HTTP identifier spelling
  // rsa-v1_5-sha256 selects it, the JOSE tuple selects it, and the
  // rsa-pss-sha512 HTTP name (JOSE id PS512) does not.
  const rid=value(await value(await PublicKey.import(rsa)).thumbprint());
  const rs=value(await snapshotKeys(s,[{...rsa,alg:'RS256'}]));
  value(await rs.lookup(rid,['rsa-v1_5-sha256'],101));
  value(await rs.lookup(rid,[{jws:'RS256'}],101));
  reason(await rs.lookup(rid,['rsa-pss-sha512'],101),'unknown_key');
  assert.equal(rs.keys[rid]!.assertedAlgorithm,'RS256');
  // An unasserted RSA key defaults to rsa-pss-sha512 and still selects the
  // JOSE-only spellings PS256 and PS384 by tuple.
  const bare=value(await snapshotKeys(s,[rsa]));
  value(await bare.lookup(rid,['rsa-pss-sha512'],101));
  value(await bare.lookup(rid,[{jws:'PS256'}],101));
  value(await bare.lookup(rid,[{jws:'PS384'}],101));
});
test('out-of-registry alg and unsupported kty or curve skip the key, keeping the set',async()=>{
  const encryption={...rsa,alg:'RSA-OAEP',use:'enc'};
  const unsupported={...jwk,alg:'ES512'};
  // RFC 8037 Appendix A.3 public bytes on the wrong curve: well-formed,
  // unsupported for signature work (RFC 7517 Section 5).
  const x25519={kty:'OKP',crv:'X25519',x:jwk.x};
  const set=value(await snapshotKeys(source(),[encryption,unsupported,x25519,jwk]));
  assert.deepEqual(Object.keys(set.keys),[kid]);
  assert.equal(set.keys[kid]!.assertedAlgorithm,null);
  value(await set.lookup(kid,['ed25519'],101));
  // An explicit null alg is a well-formed key import rejects: skipped like any
  // other unusable entry, not a set rejection.
  const nulled=value(await snapshotKeys(source(),[{...jwk,alg:null},jwk]));
  assert.deepEqual(Object.keys(nulled.keys),[kid]);
  // A set where every key is skipped resolves empty and lookups fail closed.
  const empty=value(await snapshotKeys(source(),[encryption,unsupported]));
  assert.deepEqual(Object.keys(empty.keys),[]);
  reason(await empty.lookup(kid,['ed25519'],100),'unknown_key');
  // An import failure this verifier classifies as an invalid key — here an
  // oversized component — skips like an unsupported kty, not a set rejection.
  const oversized=value(await snapshotKeys(source(),[{...jwk,x:'x'.repeat(22000)},jwk]));
  assert.deepEqual(Object.keys(oversized.keys),[kid]);
  // Skipped keys still count toward the source's maxKeys bound.
  reason(await snapshotKeys(source({maxKeys:2}),[encryption,unsupported,jwk]),'limit');
});
test('leaked private members reject the whole set loudly before any skip decision',async()=>{
  const s=source();
  // The leak must reject even when a skip-eligible neighbor, or the leaked
  // key's own out-of-registry alg, could otherwise hide it.
  for(const keys of [
    [{...jwk,d:'private-canary'}],
    [jwk,{...jwk,d:'private-canary'}],
    [{...jwk,alg:'ES512',d:'private-canary'}],
    [{...rsa,p:'private-canary'},{...jwk,alg:'RSA-OAEP'}],
    [{kty:'oct',k:'c2VjcmV0'}],
  ]) reason(await snapshotKeys(s,keys),'invalid_key_set');
});
