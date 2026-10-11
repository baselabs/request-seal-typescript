import {resolve, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import type {webcrypto} from 'node:crypto';
import {createInterface} from 'node:readline';
import * as S from '../../src/index.ts';
import {Discovery} from '../../src/discovery/node.ts';
import {resolveAlgorithm, importParameters} from '../../src/crypto/algorithm.ts';
import {peer, type Peer} from '../../test/support/discovery-peer.ts';

export type Request = {
  id: string; op: string; family: string; algorithm: string; enc: string;
  bytes: string; url: string; method: string; now: string; nonce: string;
  fields: [string, string][]; table?: string; namespace?: string; retainUntil?: string; jwk?: webcrypto.JsonWebKey; secret?: string;
  compact?: string; keyId?: string; location?: string; ca?: string;
};
type Wire = Record<string, unknown>;
const v = <T>(r: S.Result<T>): T => {if (!r.ok) throw new Error(S.ruleId(r.error)); return r.value;};
const b = (text: string) => v(S.decodeBase64Url(text));
const e = S.encodeBase64Url;
const selections = (r: Request): S.CustodyAlgorithm => r.algorithm.startsWith('jws:') ? {jws: r.algorithm.slice(4) as S.JwsAlgorithm} : r.family === 'jws' ? {jws: r.algorithm as S.JwsAlgorithm} : r.family === 'jwe' ? {jwe: r.algorithm as 'RSA-OAEP' | 'RSA-OAEP-256'} : r.algorithm as S.HttpAlgorithm;
const recipients = new Map<string, S.KeyHandle>();
let directory: Peer | undefined;
let reply: {body: Uint8Array; fields: [string, string][]} | undefined;
async function key(r: Request) {
  const selected = selections(r), spec = v(resolveAlgorithm(selected, true));
  if (spec.family === 'hmac') {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    return {handle: v(await S.Custody.local(selected, {hmac: secret})), secret: e(secret)};
  }
  const parameters = spec.family === 'rsa'
    ? {...importParameters(spec), modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1])}
    : importParameters(spec);
  const pair = await crypto.subtle.generateKey(parameters, true, spec.unwrap ? ['encrypt', 'decrypt'] : ['sign', 'verify']) as {publicKey: CryptoKey; privateKey: CryptoKey};
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  // Selectors are explicit in the exchange; runtime JOSE metadata must not override them.
  delete privateJwk.alg; delete publicJwk.alg;
  const directoryAlgorithm: S.HttpAlgorithm = spec.family === 'rsa' ? 'rsa-pss-sha512' : spec.family === 'ec' ? spec.curve === 'P-256' ? 'ecdsa-p256-sha256' : 'ecdsa-p384-sha384' : 'ed25519';
  const directoryHandle = r.algorithm.startsWith('jws:') ? v(await S.Custody.local(directoryAlgorithm, privateJwk)) : undefined;
  return {handle: v(await S.Custody.local(selected, privateJwk)), jwk: publicJwk, directoryHandle, directoryAlgorithm};
}
async function message(r: Request) {
  return v(await S.Message.request(r.method, r.url, r.fields.map(([n, x]) => [n, b(x)]), b(r.bytes)));
}
const fields = (m: S.Message): [string, string][] => m.fields.map(f => [f.name, e(f.value)]);
const components = '("@method" "@scheme" "@authority" "@path" "@query" "x-exchange")';
async function verificationKey(r: Request) {
  return r.secret ? v(await S.Custody.local(selections(r), {hmac: b(r.secret)})) : v(await S.PublicKey.import(r.jwk));
}
async function jwsPolicy(r: Request) {
  const k = await verificationKey({...r, family: 'jws'});
  return {policy: {algorithms: [r.algorithm], timeout: 5000, key_resolver: () => S.ok({algorithm: r.algorithm, key: k})}, key: k};
}
async function signedDirectory(r: Request, h: S.KeyHandle, publicKey: S.PublicKey, algorithm: S.CustodyAlgorithm) {
  if (!directory) throw new Error('directory must be started first');
  const location = `https://127.0.0.1:${directory.port}`;
  const req = v(await S.Message.request('GET', location + '/.well-known/http-message-signatures-directory', [], ''));
  const body = new TextEncoder().encode(JSON.stringify({keys: [r.jwk]}));
  const response = v(await S.Message.response(200, [['content-type', 'application/http-message-signatures-directory+json'], ['cache-control', 'max-age=120']], body, {request: req, digest: ['sha-256']}));
  const kid = v(await publicKey.thumbprint());
  const input = `("@authority";req "content-digest");created=${r.now};expires=${BigInt(r.now) + 120n};keyid="${kid}";tag="http-message-signatures-directory"`;
  const signed = v(await S.sign(response, {label: 'directory', algorithm, signatureInput: input}, h));
  reply = {body, fields: signed.fields.map(f => [f.name, new TextDecoder().decode(f.value)])};
}
export async function dispatch(r: Request): Promise<Wire> {
  if (r.op === 'directory.read') {
    if (!reply) throw new Error('Directory is not published');
    return {bytes: e(reply.body), fields: reply.fields.map(([name, text]) => [name, e(new TextEncoder().encode(text))])};
  }
  if (r.op === 'directory.publish') {
    reply = {body: b(r.bytes), fields: r.fields.map(([name, text]) => [name, new TextDecoder().decode(b(text))])};
    return {published: true};
  }
  if (r.op === 'directory.start') {
    directory = await peer((_req, res) => {
      if (!reply) {res.writeHead(503); res.end(); return;}
      res.writeHead(200, Object.fromEntries(reply.fields)); res.end(reply.body);
    });
    return {location: `https://127.0.0.1:${directory.port}`, ca: e(directory.ca)};
  }
  if (r.op === 'sign') {
    const k = await key(r);
    try {
      if (r.family === 'jws') return {...k.secret ? {secret: k.secret} : {jwk: k.jwk}, compact: v(await S.JWS.sign([['alg', r.algorithm]], b(r.bytes), k.handle))};
      const m = await message(r);
      if (r.family === 'web_bot_auth') {
        const pub = v(await S.PublicKey.import(k.jwk));
        await signedDirectory({...r, jwk: k.jwk!}, k.directoryHandle ?? k.handle, pub, k.directoryHandle ? k.directoryAlgorithm! : selections(r));
        const signed = v(await S.WebBotAuth.sign(m, {label: 'agent', key: pub, algorithm: selections(r), agent: {location: r.location, type: 'directory'}, created: Number(r.now), expires: Number(r.now) + 60, nonce: r.nonce, components}, k.handle));
        return {jwk: k.jwk, fields: fields(signed)};
      }
      const signed = v(await S.sign(m, {label: 'sig', algorithm: r.algorithm, signatureInput: `${components};created=${r.now};expires=${BigInt(r.now) + 60n};nonce="${r.nonce}";alg="${r.algorithm}";keyid="exchange"`}, k.handle));
      return {...k.secret ? {secret: k.secret} : {jwk: k.jwk}, fields: fields(signed)};
    } finally {await k.directoryHandle?.release(); await k.handle.release();}
  }
  if (r.op === 'verify') {
    if (r.family === 'web_bot_auth') {
      const source = v(S.DiscoverySource.create({type: 'directory', location: r.location, cacerts: [b(r.ca!)], permittedAddresses: ['127.0.0.1']}));
      const set = v(await Discovery.fetch(source, {clock: () => Number(r.now)}));
      const policy = v(S.WebBotAuth.Policy.create({algorithms: [selections(r)], agents: () => S.ok(set), cache: null, freshness: {clock: () => Number(r.now), maxAge: 60, skew: 0}, content: 'not_required', replay: 'not_required'}));
      const result = await S.WebBotAuth.verify(await message(r), policy);
      return result.ok ? {accepted: true, proof: set.proof} : {accepted: false, rule: S.ruleId(result.error)};
    }
    const k = await verificationKey(r);
    try {
      if (r.family === 'jws') {
        const result = await S.JWS.verify(r.compact, {algorithms: [r.algorithm], timeout: 5000, key_resolver: () => S.ok({algorithm: r.algorithm, key: k})});
        return result.ok ? {accepted: true, bytes: e(result.value.payload)} : {accepted: false, rule: S.ruleId(result.error)};
      }
      const policy = v(S.Policy.create({algorithms: [r.algorithm], components, keyResolver: () => S.ok({algorithm: r.algorithm, key: k}), freshness: {clock: () => Number(r.now), maxAge: 60, skew: 0, requireExpires: true}, content: 'not_required', replay: 'not_required'}));
      const result = await S.verify(await message(r), policy, {label: 'sig'});
      return result.ok ? {accepted: true} : {accepted: false, rule: S.ruleId(result.error)};
    } finally {if (S.isKeyHandle(k)) await k.release();}
  }
  if (r.op === 'prepare') {
    if (!r.algorithm.startsWith('RSA')) return {secret: e(crypto.getRandomValues(new Uint8Array(r.algorithm === 'A128GCMKW' ? 16 : 32)))};
    const k = await key(r); recipients.set(r.id, k.handle); return {jwk: k.jwk, keyId: r.id};
  }
  if (r.op === 'encrypt') {
    let secret = r.secret;
    const owner = r.algorithm.endsWith('GCMKW') ? v(await S.KeyManagement.local(r.algorithm, b(secret!))) : undefined;
    try {
      const recipient = r.algorithm.startsWith('RSA') ? v(await S.PublicKey.import(r.jwk)) : (alg: string, cek: Uint8Array, c: S.Context) => {
        if (alg === 'dir') {secret = e(cek); return S.ok({encrypted_key: new Uint8Array(), header: []});}
        return owner!.wrap(alg, cek, c);
      };
      return {compact: v(await S.JWE.encrypt([['alg', r.algorithm], ['enc', r.enc], ...r.family === 'nested' ? [['cty', 'JWS']] : []], b(r.bytes), recipient)), ...(secret ? {secret} : {})};
    } finally {await owner?.release();}
  }
  if (r.op === 'decrypt') {
    const owner = r.algorithm.startsWith('RSA') ? recipients.get(r.keyId!)! : v(await S.KeyManagement.local(r.algorithm, b(r.secret!)));
    const policy = {algorithms: [r.algorithm], encryption: [r.enc], max_plaintext: 1048576, timeout: 5000, key_resolver: () => S.ok(r.algorithm.startsWith('RSA') ? {algorithm: r.algorithm, key: owner} : {algorithm: r.algorithm, unwrap: (ek: unknown, h: S.JoseProtectedHeader, c: S.Context) => (owner as S.KeyManagementHandle).unwrap(ek, h, c)})};
    try {
      if (r.family === 'nested') {
        const {secret: _secret, ...innerRequest} = r;
        const inner = await jwsPolicy({...innerRequest, algorithm: 'EdDSA'});
        const result = await S.Nested.decrypt(r.compact, {jwe: policy, jws: inner.policy}, {content_types: ['JWS']});
        return result.ok ? {accepted: true, bytes: e(result.value.jws.payload)} : {accepted: false, rule: S.ruleId(result.error)};
      }
      const result = await S.JWE.decrypt(r.compact, policy);
      return result.ok ? {accepted: true, bytes: e(result.value.plaintext)} : {accepted: false, rule: S.ruleId(result.error)};
    } finally {if (!r.algorithm.startsWith('RSA')) await owner.release();}
  }
  if (r.op === 'release') {await recipients.get(r.keyId!)?.release(); recipients.delete(r.keyId!); return {released: true};}
  if (r.op === 'claim') {
    const {pool, query} = await import('../replay/pg.mjs');
    const {createStore} = await import('../../src/replay/postgres.ts');
    const db = pool(process.env.REQUESTSEAL_REPLAY_PG_URL!);
    try {
      const key = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(r.nonce)));
      const claim = v(S.Claim.create({namespace: b(r.namespace!), key, retainUntil: BigInt(r.retainUntil!)}));
      return {claim: v(await S.Replay.claim(v(createStore({table: r.table, query: query(db)})), claim, v(S.withDeadline({timeoutMs: 5000}))))};
    } finally {await db.end();}
  }
  throw new Error('Unknown exchange operation');
}
async function main() {
  process.chdir(resolve(dirname(fileURLToPath(import.meta.url)), '../..'));
  console.log(JSON.stringify({ready: true, language: 'typescript'}));
  const input = createInterface({input: process.stdin, crlfDelay: Infinity});
  try {
    for await (const line of input) {
      const r = JSON.parse(line) as Request;
      try {console.log(JSON.stringify({id: r.id, ...await dispatch(r)}));}
      catch (error) {console.log(JSON.stringify({id: r.id, accepted: false, rule: error instanceof Error ? error.message : String(error)}));}
    }
  } finally {await directory?.close(); for (const h of recipients.values()) await h.release();}
}
main().catch(e => {console.error(e); process.exitCode = 1;});
