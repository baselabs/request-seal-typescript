**Status:** maintained · **Kind:** reference · **Updated:** October 10, 2026 · **Governed by:** RFC 9421, RFC 9113, Fetch, the OpenSSH agent protocol, and executed transport tests · **Review when:** runtime versions or adapter contracts change

# HTTP and custody adapters

Adapters translate transport values to the existing Message, Policy, signing,
and verification APIs. They return Results and retain bounded errors. They
start no listener or agent, discover no credentials, and grant no authorization.
The core imports no Node modules. Node transports and SSH custody have separate
package subpaths.
Native test lanes run Node HTTP and framework adapter contracts in real Node
subprocesses; Fetch contracts execute on the native runtime. SSH agent/OpenSSL
checks run natively; socket fault and close-event tests use real Node peers.

## Node HTTP

Import from `@request-seal/core/node-http`. `capture(server, options)` installs a
request listener before the application's listener and returns a removable
registration. `captureRequest(req, options)` can instead run as the first
middleware. It retains rawHeaders in occurrence order, the exact target,
method, trailers after EOF, and body bytes. Capture retains at most `maxBytes`
body bytes per request before any policy decision. The default and maximum
ceiling are 1 MiB; `maxBytes` can lower that ceiling. Peak memory also includes
transport buffers and copies of retained bytes. `context` supplies an absolute deadline.
Capture registration options cannot be changed by later middleware. Capture owns
stream consumption: another data listener or a flowing consumer during the read
rejects with `parser_order`. A present Content-Length must equal retained bytes; a mismatch returns
`body_unavailable` for both supplied bodies and live streams.
Do not pair `capture(server)` with a parser reading the original request stream;
use the replay stream, the verified bytes, or the Express verify hook below.

Capture returns `{message, ingress, origin, replay}`. The capture and successful
verification values are frozen and separately branded. Core transport evidence
remains declared. `ingress.evidence` is observed and records socket TLS protocol,
ALPN, HTTP version, and the original origin. HTTP/2 pseudo-headers become
message facts, never field occurrences; cookie crumbs combine with semicolon
space. An occurrence count at or above the server's maxHeadersCount rejects.
HTTP/2 ingress scheme derives from socket TLS. A conflicting :scheme rejects
unless the actual socket peer matches the explicit trusted-proxy policy. A
trusted peer's HTTP(S) pseudo-header remains separate in `ingress.declaredScheme`;
it does not relabel observed socket TLS. The selected external origin still
comes from the validated Forwarded fields. Invalid pseudo-header schemes reject
on every path. The reference ignores the `:scheme` pseudo-header; this adapter
checks it while keeping declared origin separate from observed connection facts.
Host must equal normalized :authority when both occur. A Host without :authority
is refused by this adapter: RFC 9113 Section 8.3.1 permits that rejection.
Use :authority on HTTP/2 requests.
For absolute-form targets the core requires the target's scheme and authority to
match the selected origin byte for byte. An explicit default port such as
`http://127.0.0.1:80/p` is therefore refused after origin normalization. The
reference Plug boundary refuses exact-target coverage when raw transport evidence
is unavailable; origin reconstruction does not restore those bytes.

Call `capture.replay()` once to obtain the retained Readable. Once reads begin,
fully drain it before verification. Verification checks a SHA-256 digest of all
bytes handed out against the captured body. A second replay, partial drain, or
mismatch rejects. Caller transformations after a read remain outside this check;
verification authenticates captured bytes, not parser output.

`verifyRequest(req, policy, {label, context?, representation?, digestState?})`
returns `{capture, verification, bytes}`. Byte access returns copies. Concurrent
or repeated verification is refused. `verification(req)` retrieves successful core, quorum, or Web Bot Auth facts, or the stored
bounded rejection after a verification attempt. Required layers still follow the core Policy.
`verifyQuorum(req, quorum, {context?, acceptSignature?})` returns captured bytes
and the composite verification. All three entry points share the one-verification and
parser-order guards. All three reject malformed option keys and invalid contexts
before reserving the shared attempt. `verifyQuorum` also validates
acceptSignature before reservation. `verifyRequest` reserves its attempt before
core validation of label, representation, and digestState; those core rejections
remain stored and consume the attempt.

`verifyWebBotAuth(req, policy, {context?, timeoutMs?, representation?, digestState?})`
uses the core Web Bot Auth verifier on the captured message and returns
`VerifiedWebBotAuthRequest`: `{capture, verification, bytes}`. The verification is
a `WebBotAuthVerification` envelope; byte access returns copies. It shares the
same reservation and replay-drain checks with generic and quorum verification.
Own option keys are read once. Unknown keys, invalid contexts, and invalid
`timeoutMs` values reject with adapter `invalid_options` before reservation;
`timeoutMs` defaults to 5,000 and accepts integers from 1 through 300,000.
Core policy and content-option validation occurs after reservation, as with
`verifyRequest`. Configure agent trust, signed directories, cache, freshness,
content, and replay explicitly in `WebBotAuth.Policy`.

OBSERVED: `test/adapters-node-web-bot-auth.test.ts` verifies signed captured HTTP
bytes through a caller-configured, signed local TLS directory. It executes the
`authenticateBot` example in [the README](../../README.md#http-adapters-and-ssh-custody).
Unsigned requests return adapter `request_rejected` with the bounded core source
`missing_signature_input`, as the reference does; untrusted agents retain
`agent_unresolved`. Both rejections consume the attempt and remain available
through `verification(req)`. A second attempt returns `already_verified` without
replacing stored facts.

An explicit `trustedProxies: {peers, field}` selects origin reconstruction.
`peers` is a list of CIDR ranges or exact socket IP addresses, including native
or mapped IPv4 (for example `127.0.0.0/8` and `::ffff:127.0.0.1`);
`field` is `forwarded` or `x-forwarded`. The last element supplies external
scheme/authority only after the actual socket peer matches. Every Forwarded
element must parse, with no duplicate keys; X-Forwarded proto and host lists
must have equal counts. A broad IPv6 CIDR compares against the mapped IPv4
address: `::/0` includes IPv4 peers, while `::/96` does not. Raw ingress stays
separate. Configured forwarding requires the selected fields to be present;
absent fields return invalid_request, matching the reference. Forwarded extension
names follow the HTTP token grammar, which permits underscore. Without this
option forwarded fields have no authority.

### Express

OBSERVED: `test/adapters-express.test.ts`, Express 5.2.1, exercises this body-parser
hook before URL rewriting and checks parsed JSON against authenticated bytes:

```ts
import {captureBody, verifyRequest} from '@request-seal/core/node-http';

app.use(express.json({
  inflate: false,
  verify(req, res, buf) {
    const result = captureBody(req, buf);
    if (!result.ok) throw new Error('Request capture failed');
  },
}));
app.use(async (req, res) => {
  const result = await verifyRequest(req, policy, {label: 'sig'});
  res.status(result.ok ? 200 : 401).end();
});
```

Use this hook instead of server-level body consumption. Capture must precede
rewriting; `originalUrl` supplies the original target when middleware already
rewrote `url`. Only identity body-parser input belongs in this recipe: set
`inflate: false` to prevent decoding before capture.

### Fastify

OBSERVED: `test/adapters-fastify.test.ts`, Fastify 5.12.5, exercises capture at the
request event and returns the replay from preParsing. UTF-8 string consumption
retains the original bytes; decoding that replaces malformed bytes rejects before
key resolution.

```ts
const registration = capture(fastify.server);
fastify.addHook('preParsing', async (request, reply, payload) => {
  const result = await captureRequest(request.raw);
  if (!result.ok) throw new Error('Request capture failed');
  const replay = result.value.replay();
  if (!replay.ok) throw new Error('Request replay failed');
  Object.defineProperty(replay.value, 'receivedEncodedLength', {
    value: result.value.message.body.bytes!.length,
  });
  return replay.value;
});
```

Returning another stream changes the parser boundary. The replay digest checks
both byte reads and strings re-encoded with the stream's selected encoding.

### Final responses and clients

`signResponse(res, spec, signer, {body, request?, clock?, nonce?, context?, pendingCookies?})`
requires a Uint8Array body and headers that have not been sent. It samples the
clock once for Date and generated created, sets Content-Length before signing,
then calls writeHead and ends the response with exactly those signed bytes.
Callers do not write or end the response afterward. Informational responses
reject with unsupported_delivery. Status 204 and 304 responses require an empty
body and omit Content-Length. Node response coverage refuses transfer-encoding,
connection, trailer, keep-alive, proxy-connection, te, and upgrade with
unsupported_component. Date and the final Content-Length can be covered.
Both Node and Fetch response checks exempt components carrying `;req` from
response-side field refusals: those components select captured request facts.
Core signing restrictions still apply, including the Host and trailer refusals. A prior write rejects
with unsupported_delivery. Set-Cookie coverage rejects while cookies are pending.
`request` is a branded Capture for request-related components. Later transforms
must not change signed headers or body bytes.

`signedRequest({url, method?, headers?, body?, ca?, context?, clock?, nonce?,
maxBytes?, maxRedirects?, maxRetries?, allowedOrigins?, credentialHeaders?,
verify?}, spec, signer, context?)` sends through http.request or https.request.
Headers are ordered pairs and bodies are bytes. Caller-supplied Host returns
invalid_options; the transport derives it from each final URL. Nonempty GET or HEAD bodies
return invalid_options before delivery. The Node client uppercases the
method before signing to match ClientRequest delivery. Incoming capture preserves
wire method case. Explicit CA material is PEM
bytes. Defaults make no redirect or retry. Every hop/attempt signs afresh;
credential fields are removed on approved cross-origin hops. `allowedOrigins`
contains exact HTTP(S) origins; the default refuses cross-origin redirects.
Both allowedOrigins and credentialHeaders are validated before delivery. Location
parse errors return invalid_request; fragments are removed. A 303 for non-GET/HEAD
and POST 301/302 switch to GET without a body or Content-Type, Content-Length,
Content-Encoding, Content-Language, Content-Location, or Content-Digest;
307/308 retain method and body. Errors report the actual attempt number.
Optional `verify: {policy, label}` withholds every response until verification.
`verifyResponse(response, response.request, policy, options)` binds the exact
sent request. Successful responses expose bounded copied bytes and the Message.

## Fetch

Import from `@request-seal/core/fetch`. `signRequest(request, spec, signer, options)`
returns `{request, message}` with retained final bytes and the URL fragment
removed. `signResponse(response, spec, signer, {request?, ...options})` returns
`{response, message}`. Bodies are consumed once; use the returned rebuilt value.
Options accept context, maxBytes, clock, nonce, and signingTimeout. Request signals
and signedFetch init signals share the Context deadline and cancel body reads,
signing, and delivery. GET or HEAD requests with a body or declared nonempty
Content-Length return invalid_request before signing or verification. Request
signing refuses host, content-length, accept-encoding, connection, transfer-encoding,
trailer, keep-alive, proxy-connection, te, and upgrade coverage because runtime
delivery controls those fields. Node also
refuses sec-fetch-mode, which undici overrides; Deno and Bun preserve it in the
wire lane. The runtime list beside the verification allowlist is authoritative.
Bun string-body Request construction does not add content-type in the measured
lane. Set that header explicitly before signing if coverage requires it.
Node majors below 24 refuse signing URLs with an empty query delimiter.
OBSERVED in `test/fixtures/adapters-fetch-wire.json` by the wire tests:
Node 22.12.0, 22.23.1, and 23.11.0 drop that delimiter; Node 24.21.0 and
26.11.1 preserve it.
Bun signing refuses unusual methods and repeated leading slashes whose wire
representation was not preserved.

`signedFetch(input, init, {spec, signer}, options)` sets redirect to manual and
Accept-Encoding to identity. A caller-supplied Host or an Accept-Encoding value
other than identity returns invalid_options before delivery. Limits, explicit
cross-origin approval, credential
removal, fresh signing per retry/hop, and optional `{policy, label}` verification
match the Node exchange contract. The caller's body is retained within maxBytes.
With `verify` selected, a runtime outside `FETCH_VERIFICATION_RUNTIMES` returns
`invalid_request` before delivery.
The returned value contains the response and the exact signed request. Each
attempt after the first generates fresh nonce entropy when the spec requires
a nonce. Caller signal and Context compose once for the exchange; unused
Request body streams are canceled before rebuilding another attempt. The
caller Context bounds the entire exchange, including every redirect, retry,
body read, signature, and delivery; it does not reset per attempt. The default
Context deadline is five seconds. An explicit init signal replaces the input
Request signal; `signal: null` follows the new native Request's signal state
(Node and Deno reset it; the measured Bun version preserves the aborted state).

Verification is restricted to `FETCH_VERIFICATION_RUNTIMES`, currently
`deno:2.5.6`. OBSERVED by `test/adapters-fetch-wire.test.ts` and recorded in
`test/fixtures/adapters-fetch-wire.json`:

| Runtime | Duplicate response field with OWS | Cookie | Set-Cookie | Unusual method |
| --- | --- | --- | --- | --- |
| Node 22.12.0 / 24.21.0 / 26.11.1 | Per-line OWS remains inside the combined value | Semicolon joined | Two occurrences survive | Preserved outbound |
| Deno 2.5.6 | OWS removed per line, then comma-space joined | Comma joined on responses; semicolon on native ingress | Two occurrences survive | Preserved outbound and native ingress |
| Bun 1.3.14 | Only the last duplicate survives | Semicolon joined | Two occurrences survive | Becomes GET outbound; native ingress closes |

The tested normalized URL removes a dot segment and fragment while keeping an
encoded slash and query escapes. This does not establish exact wire-target
identity. A separate target probe observed Bun 1.3.14 changing `//%2F?`
to `/%2F?`; signing now refuses that shape. Deno preserves mixed-case `gEt` and
`pOsT` on native ingress and preserves an empty query delimiter. `verifyRequest(request, policy, {label, scheme, authority, ...options})`
requires caller-selected origin facts. It refuses @request-target, @target-uri,
@path, @query, every bs/tr parameter, and cookie in required or selected covered
components before resolving keys. @query-param follows the core's form-urlencoded
parse/re-encode semantics; @method uses the proven Deno case preservation.
Fetch verification requires an explicit label; a missing label returns adapter
invalid_options on eligible runtimes before core verification. Response
verification rejects representation with invalid_options because response content
checks cannot apply it on this lane.
`verifyResponse(response, policy, {label, request?, ...options})` preserves
Set-Cookie occurrences through getSetCookie. Successful verification returns
copied bytes plus a rebuilt Request/Response containing those exact bytes.

Exact measured versions stay recorded; an unrecorded patch or runtime is not
eligible for verification. The wire tests assert its refusal while recording
its observations. On all other runtime versions both verification functions return
adapter/invalid_request before option access, body reads, clocks, or key work.
OBSERVED by `test/adapters-fetch.test.ts`: Deno's gzip fetch strips Content-Encoding
and Content-Length after decoding. Therefore required response content checks
return body_unavailable even with an absent encoding header. Incoming request
content checks reject a present Content-Encoding. Fetch verification never
certifies a decoded body as the wire content.

## Reference divergences

The following adapter choices differ from, or are not decided by, the Elixir
v0.4.1 framework boundaries:

The references below are source observations at tag `v0.4.1`; line numbers
refer to files under `lib/request_seal/`.

- GET or HEAD body signing is refused here. The Finch and Req translations pass
  retained bodies through. Fetch ingress that hides a declared nonempty body is
  also refused for signing and verification.
- Node response signing refuses informational (1xx) status codes. The Plug
  response-signing path does not impose this status restriction.
- `verification(req)` returns the stored bounded rejection after a failed Node
  attempt. Plug's `verification(conn)` returns `:error` without successful facts.
- Node response signing refuses hop-by-hop field coverage, and Fetch response
  signing refuses its measured runtime-managed fields. The Plug path signs
  present response headers without either field list. Both TypeScript adapters
  exempt request-related components from response-side lists, subject to core
  signing restrictions.
- Node capture refuses CONNECT with `invalid_request`, matching
  `plug/capture.ex:114–117`; no CONNECT handling difference remains.
- Node `signResponse` can sign without a captured request when no request-related
  components are selected. Plug requires capture even for status-only signing
  and returns `not_captured` (`plug/sign_response.ex:124–128`).
- Node response signing always sets Date from the sampled clock, replacing an
  existing Date even when it is not covered. Plug adds Date only when covered
  and absent (`plug/sign_response.ex:137–147`).
- On response-signing failure before headers are sent, Node restores the
  caller's header snapshot, including Date and Content-Length, and leaves
  delivery to the caller. Plug replaces delivery with its `on_failure` status
  and an empty unsigned body, removing delivery and signature fields
  (`plug/sign_response.ex:181–209`).
- Node and Fetch clients retry only 5xx responses, subject to `maxRetries`;
  transport errors, 408, and 429 do not retry. A 3xx without Location returns
  `invalid_request` while redirects remain. The reference defers whether another
  attempt runs to Req's retry and redirect steps (`req.ex:37–45`), with adapter
  verification ahead of those steps when selected (`req.ex:165–178`).

## SSH-agent custody

Import `createSshAgent` or `SSHAgent.create` from `@request-seal/core/custody-ssh-agent`.
`createSshAgent(algorithm, socketPath, publicKey, {context? | timeoutMs?})` requires
an explicit absolute POSIX socket path (1–103 UTF-8 bytes, no NUL) and a branded
PublicKey. Relative paths return invalid_options; no environment socket is read. The caller owns agent startup, key
loading, and authorization. The adapter proves possession at construction.

Supported HTTP algorithms are ed25519, rsa-v1_5-sha256, ecdsa-p256-sha256, and
ecdsa-p384-sha384; explicit JWS selectors are EdDSA, RS256, ES256, and ES384.
RS256 uses OpenSSH flag 2 (rsa-sha2-256). PSS and HMAC reject. Selection compares
exact public components, never comments or identity-list positions. Every sign
opens a fresh connection, checks current identities, parses bounded frames,
converts ECDSA mpints to fixed-width r || s, and verifies the returned signature
with the trusted public key before release. Receive frames are bounded to 1 MiB,
identity lists to 256, blobs/comments to 16 KiB. Deadline, cancellation, and
release close owned sockets. Errors carry no socket path or agent diagnostics.

Signing and verification accept trailing `{maxBytes}` options on the handle,
with a 1 MiB default and a 16 MiB ceiling. Outgoing requests have no additional
library frame bound. The real agent retains its own limit; a post-send closure
returns `custodian_protocol`. The live test signs a 262,000-byte payload,
measures the agent's accepted/refused boundary, and checks larger requests are
forwarded and refused by the peer. No specific boundary count is required.
See [the v0.4.1 custodian](https://github.com/baselabs/request_seal/blob/v0.4.1/lib/request_seal/custody/ssh_agent.ex).
The shared corpus remains v0.4.0, unchanged between these releases.

Unknown construction keys return custodian_rejected; removed operational keys
return key_not_found; failed connection establishment returns custodian_unavailable;
malformed or incomplete replies return custodian_protocol. Verification uses
local trusted public material and does not assert continued agent possession.
OBSERVED by `test/custody-ssh-agent.test.ts`: generated real OpenSSH keys exercise
all eight selectors, removed/absent keys, a faulty protocol peer, deadlines, and
OpenSSL verification of every algorithm's returned signature.

Connection ENOENT, ECONNREFUSED, and ECONNRESET return custodian_unavailable;
other connection errors return custodian_failure. No socket diagnostics enter errors.
