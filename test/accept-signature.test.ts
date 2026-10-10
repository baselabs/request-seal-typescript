import test from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import * as api from "../src/index.ts";
const A = api as any;
const value = (r: any): any => {
  assert.equal(r.ok, true);
  return r.value;
};
test("signature requests preserve published bytes and use separate brands", () => {
  assert.equal(
    typeof A.AcceptSignature?.parse,
    "function",
    "AcceptSignature.parse must be exported",
  );
  const wire =
    'sig1=("@method" "@target-uri" "@authority" "content-digest" "cache-control");keyid="test-key-rsa-pss";created;tag="app-123"';
  const requests = value(A.AcceptSignature.parse(wire, { target: "request" }));
  assert.equal(
    new TextDecoder().decode(value(A.AcceptSignature.serialize(requests))),
    wire,
  );
  assert.equal(A.isAcceptSignature(requests), true);
  assert.equal(A.isQuorum(requests), false);
  assert.equal(Object.isFrozen(requests[0].parameters), true);
  assert.equal(
    value(A.AcceptSignature.parse("", { target: "request" })).length,
    0,
  );
});
test("signature requests reject duplicate members, invalid requests and inapplicable components", () => {
  assert.equal(
    typeof A.AcceptSignature?.parse,
    "function",
    "AcceptSignature.parse must be exported",
  );
  for (const [wire, target, reason] of [
    ["s=(), s=()", "request", "duplicate_label"],
    ['s=();nonce="a";nonce="b"', "request", "duplicate_parameter"],
    ['s=("signature";key="a";key="b")', "request", "duplicate_parameter"],
    ['s=("@status")', "request", "inapplicable_component"],
    ['s=("@method";req)', "request", "inapplicable_component"],
    ['s=("@method")', "response", "inapplicable_component"],
    ["s=();created=1", "request", "invalid_accept_signature"],
    ["s=();expires=?0", "request", "invalid_accept_signature"],
    ["s=();nonce", "request", "invalid_accept_signature"],
    ['s=();alg="EdDSA"', "request", "invalid_accept_signature"],
    ["s=();x", "request", "invalid_accept_signature"],
    ['s=("@method" "@method")', "request", "invalid_accept_signature"],
    ['s="@method"', "request", "invalid_accept_signature"],
    ["s=()", "other", "invalid_options"],
    [
      Array.from({ length: 17 }, (_, i) => `s${i}=()`).join(", "),
      "request",
      "limit",
    ],
  ])
    assert.equal(
      A.AcceptSignature.parse(wire, { target }).error.reason,
      reason,
      wire!,
    );
  value(
    A.AcceptSignature.parse('s=("@status" "@method";req)', {
      target: "response",
    }),
  );
  assert.equal(
    A.AcceptSignature.serialize([]).error.reason,
    "invalid_accept_signature",
  );
});
test("signature request canonical serialization is idempotent over generated challenges", () => {
  assert.equal(
    typeof A.AcceptSignature?.parse,
    "function",
    "AcceptSignature.parse must be exported",
  );
  fc.assert(
    fc.property(fc.stringMatching(/^[a-z0-9]{0,24}$/), (nonce) => {
      const first = value(
        A.AcceptSignature.parse(`s=("@method");nonce="${nonce}";created`, {
          target: "request",
        }),
      );
      const bytes = value(A.AcceptSignature.serialize(first));
      assert.deepEqual(
        value(
          A.AcceptSignature.serialize(
            value(A.AcceptSignature.parse(bytes, { target: "request" })),
          ),
        ),
        bytes,
      );
    }),
    { numRuns: 200 },
  );
});


test('request applicability precedes the next request parameter rejection', () => {
  const r = api.AcceptSignature.parse('a=("@status"), b=("@method");foo="x"', {target: 'request'});
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.error.reason, 'inapplicable_component');
});

test('reference string requests normalize token and byte parameter values', () => {
  for (const wire of ['s=();tag=abc', 's=();keyid=:YWJj:']) {
    const r = value(api.AcceptSignature.parse(wire, {target: 'request'}));
    assert.equal(Object.values(r[0].parameters)[0], 'abc');
    assert.match(new TextDecoder().decode(value(api.AcceptSignature.serialize(r))), /="abc"$/);
  }
  for (const wire of ['s=();tag=1', 's=();keyid=?1', 's=();tag=:\/w==:', 's=();tag=:Cg==:']) {
    assert.equal(api.AcceptSignature.parse(wire, {target: 'request'}).ok, false);
  }
});

test('fulfillment appends requests in order and preserves requested strings and times', async () => {
  assert.equal(typeof A.AcceptSignature.fulfill, 'function');
  const {policy, quorum} = await import('./support/quorum.ts');
  const handle = value(await api.Custody.local('hmac-sha256', {hmac: crypto.getRandomValues(new Uint8Array(32)), identity: 'signer'}));
  try {
    const base = value(await api.Message.request('POST', 'https://example.com/a', [['content-type', 'text/plain']], 'hello'));
    const requests = value(api.AcceptSignature.parse(['first=("@method");keyid="key";nonce="challenge\\\"quoted";tag="tag-one"', 'second=("@path");created;expires'], {target: 'request'}));
    const choice = (_request: api.SignatureRequest) => api.ok({algorithm: 'hmac-sha256', created: 1618884473, expires: 1618884540});
    const signer: api.Signer = (algorithm, data, context = value(api.withDeadline())) => handle.sign(algorithm, data, context);
    const signed = value(await A.AcceptSignature.fulfill(base, requests, choice, signer, {}));
    const inputs = signed.fields.filter((f: any) => f.name.toLowerCase() === 'signature-input');
    assert.deepEqual(inputs.map((f: any) => new TextDecoder().decode(f.value).split('=')[0]), ['first', 'second']);
    const p = policy({keyResolver: () => api.ok({algorithm: 'hmac-sha256', key: handle})});
    const r = value(await api.verifyQuorum(signed, quorum([{id: 'only', required: false, policy: p}]), {acceptSignature: requests}));
    assert.equal(r.negotiation, 'fulfilled');
    const first = value(await api.verify(signed, p, {label: 'first'}));
    const second = value(await api.verify(signed, p, {label: 'second'}));
    assert.equal(Object.fromEntries(first.signature.parameters.map(([k, v]: any) => [k, v.value])).nonce, requests[0].parameters.nonce);
    assert.equal(Object.fromEntries(first.signature.parameters.map(([k, v]: any) => [k, v.value])).tag, 'tag-one');
    assert.equal(Object.fromEntries(second.signature.parameters.map(([k, v]: any) => [k, v.value])).created, 1618884473);
    assert.equal(Object.fromEntries(second.signature.parameters.map(([k, v]: any) => [k, v.value])).expires, 1618884540);
    assert.equal(Object.fromEntries(second.signature.parameters.map(([k, v]: any) => [k, v.value])).keyid, undefined);
    for (const wire of ['first=("@method");nonce="other"', 'first=("@method");tag="other"', 'first=("@method");keyid="other"', 'renamed=("@method")', 'first=("@path")', 'first=("@method" "@path")', 'first=("@method");created']) {
      const expected = value(api.AcceptSignature.parse(wire, {target: 'request'}));
      const denied = await api.verifyQuorum(signed, quorum([{id: 'only', required: false, policy: p}]), {acceptSignature: expected});
      assert.equal(denied.ok, false); if (!denied.ok) assert.equal(denied.error.reason, 'negotiation_unfulfilled');
    }
    // Exact covered identity sets ignore order but preserve component parameters.
    const sf = value(api.AcceptSignature.parse('sf=("content-type";bs "@method")', {target: 'request'}));
    const sfSigned = value(await A.AcceptSignature.fulfill(base, sf, choice, signer, {}));
    for (const [wire, succeeds] of [['sf=("@method" "content-type";bs)', true], ['sf=("@method" "content-type")', false]]) {
      const expected = value(api.AcceptSignature.parse(wire, {target: 'request'}));
      const result = await api.verifyQuorum(sfSigned, quorum([{id: 'only', required: false, policy: p}]), {acceptSignature: expected});
      assert.equal(result.ok, succeeds);
      if (!result.ok) assert.equal(result.error.reason, 'negotiation_unfulfilled');
    }
    assert.equal(value(await A.AcceptSignature.fulfill(base, value(api.AcceptSignature.parse('', {target: 'request'})), choice, signer, {})), base);
  } finally { await handle.release(); }
});

test('unfulfillable choices or components reject without partial output or premature signing', async () => {
  assert.equal(typeof A.AcceptSignature.fulfill, 'function');
  const handle = value(await api.Custody.local('hmac-sha256', {hmac: crypto.getRandomValues(new Uint8Array(32)), identity: 'signer'}));
  try {
    const base = value(await api.Message.request('POST', 'https://example.com/a', [], ''));
    const requests = value(api.AcceptSignature.parse('s=("@method");alg="hmac-sha256";created', {target: 'request'}));
    let signs = 0;
    const signer: api.Signer = (algorithm, data, context = value(api.withDeadline())) => { signs++; return handle.sign(algorithm, data, context); };
    const good = (_request: api.SignatureRequest) => api.ok({algorithm: 'hmac-sha256', created: 123, expires: null});
    for (const choice of [
      (_request: api.SignatureRequest) => api.ok(null),
      (_request: api.SignatureRequest) => api.ok({algorithm: {jws: 'HS256'}, created: 123, expires: null}),
      (_request: api.SignatureRequest) => api.ok({algorithm: 'ed25519', created: 123, expires: null}),
      (_request: api.SignatureRequest) => api.ok({algorithm: 'hmac-sha256', created: null, expires: null}),
      (_request: api.SignatureRequest) => api.ok({algorithm: 'hmac-sha256', created: 1e15, expires: null}),
      (_request: api.SignatureRequest) => api.ok({algorithm: 'hmac-sha256', created: 123, expires: null, extra: true}),
      (_request: api.SignatureRequest) => { throw new Error('caller diagnostics'); },
      async (_request: api.SignatureRequest) => { throw new Error('caller diagnostics'); },
    ]) {
      const r = await A.AcceptSignature.fulfill(base, requests, choice, signer, {});
      assert.equal(r.ok, false); assert.equal(r.error.reason, 'negotiation_unfulfillable'); assert.equal(r.error.layer, 'negotiation');
      assert.equal(JSON.stringify(r).includes('caller diagnostics'), false);
    }
    assert.equal(signs, 0);
    const missing = value(api.AcceptSignature.parse('first=("@method"), second=("missing-field")', {target: 'request'}));
    const r = await A.AcceptSignature.fulfill(base, missing, good, signer, {});
    assert.equal(r.ok, false); assert.equal(r.error.reason, 'negotiation_unfulfillable');
    assert.equal(base.fields.length, 0);
    const success = value(await A.AcceptSignature.fulfill(base, requests, good, signer, {}));
    assert.equal(success.fields.length, 2);
    const duplicate = await A.AcceptSignature.fulfill(success, requests, good, signer, {});
    assert.equal(duplicate.error.reason, 'negotiation_unfulfillable');
    for (const args of [[null, requests, good, signer, {}], [base, [], good, signer, {}], [base, requests, null, signer, {}], [base, requests, good, null, {}], [base, requests, good, signer, {extra: true}]]) {
      const rejected = await A.AcceptSignature.fulfill(...args);
      assert.equal(rejected.ok, false);
    }
  } finally { await handle.release(); }
});

test('fulfillment preserves chooser and signing deadlines but bounds other signing rejections', async () => {
  const h = value(await api.Custody.local('hmac-sha256', {hmac: crypto.getRandomValues(new Uint8Array(32)), identity: 'signer'}));
  const base = value(await api.Message.request('POST', 'https://example.com/', [], ''));
  const requests = value(api.AcceptSignature.parse('s=("@method")', {target: 'request'}));
  const choice = (_request: api.SignatureRequest) => api.ok({algorithm: 'hmac-sha256', created: null, expires: null});
  const signer: api.Signer = (a, d, c = value(api.withDeadline())) => h.sign(a, d, c);
  const waitPast = async (c: api.Context) => { await new Promise(resolve => setTimeout(resolve, api.remainingMs(c) + 20)); };
  try {
    for (const stage of ['chooser', 'signer']) {
      const context = value(api.withDeadline({timeoutMs: 100}));
      const slowChoice = async (request: api.SignatureRequest) => { await waitPast(context); return choice(request); };
      const slowSigner: api.Signer = async (a, d, c = context) => { const result = await h.sign(a, d, c); await waitPast(c); return result; };
      const r = await api.AcceptSignature.fulfill(base, requests, stage === 'chooser' ? slowChoice : choice, stage === 'signer' ? slowSigner : signer, {context});
      assert.equal(r.ok, false);
      if (!r.ok) { assert.equal(r.error.kind, 'custody'); assert.equal(r.error.reason, 'deadline_exceeded'); }
    }
    value(await h.release());
    const r = await api.AcceptSignature.fulfill(base, requests, choice, signer);
    assert.equal(r.ok, false);
    if (!r.ok) { assert.equal(r.error.reason, 'negotiation_unfulfillable'); assert.equal(r.error.layer, 'negotiation'); }
    assert.equal(base.fields.length, 0);
  } finally { await h.release(); }
});
