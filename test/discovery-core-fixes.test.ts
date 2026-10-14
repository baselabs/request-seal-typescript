import test from 'node:test';
import assert from 'node:assert/strict';
import {Discovery, DiscoverySource, createCache, withDeadline, type Result} from '../src/index.ts';
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
test('quoted and parameterized cache directives preserve the pinned comma-split contract', async () => {
  const s = source();
  for (const [directive, offset] of [['no-store="x", max-age=20', 20], ['x="a,no-store,b", max-age=20', 0]] as const) {
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
