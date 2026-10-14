**Status:** maintained · **Kind:** reference · **Updated:** October 14, 2026 · **Governed by:** RequestSeal for Elixir 0.4.1 discovery behavior, RFC 7517, RFC 7638, and the shared conformance corpus · **Review when:** discovery policy, body formats, or runtime compatibility changes

# Discovery

Core discovery validates caller-supplied snapshots. It starts no connection or
background refresh. Callers who retrieve bytes themselves own DNS, address and
redirect policy. A key ID never supplies a discovery URL.

API sketches below use caller-supplied values; runnable examples are in the [guides](../../README.md#guides).

```text
import { Discovery, DiscoverySource } from "@request-seal/core";

const source = DiscoverySource.create({
  type: "jwks_uri",
  location: "https://agent.example/keys",
});
// bodyBytes: Uint8Array containing the complete HTTP response body.
// fetchedAt: Unix seconds; headers: ordered [name, value] pairs.
if (source.ok) {
  const snapshot = await Discovery.resolver.fromSnapshot(
    source.value, bodyBytes, fetchedAt, headers,
  );
  if (snapshot.ok) {
    const key = await snapshot.value.lookup(keyId, ["ed25519"], fetchedAt);
  }
}
```

Sources select `directory`, `jwks_uri`, or `cimd`. Directory origins expand to
`/.well-known/http-message-signatures-directory`. CIMD client IDs retain their
exact configured spelling and require a path. URLs require HTTPS and reject
userinfo, fragments, malformed escapes, dot segments, and escaped line breaks.
`DiscoverySource.directoryId()` returns a Result containing whether a directory
ID has 1–256 printable ASCII bytes.

Sources accept `keyId`, `cacerts`, `permittedAddresses`, `revoked`,
`requireSignedDirectory`, `redirectScope`, and the numeric settings below.
Numeric settings may instead appear together in `limits`; supplying a setting
in both places rejects. Unknown keys reject. Options are owned snapshots.
DER CA certificates and body buffers are copied on entry. `cacerts` defaults to
`"os"` or holds 1–256 DER certificates; `revoked` holds at most 256 thumbprints;
`permittedAddresses` holds at most 16 entries; `minTtl` must not exceed `maxTtl`.

| Setting | Default | Ceiling |
| --- | --- | --- |
| `maxBytes`, `maxDecodedBytes` | 65,536 each | 1,048,576 each |
| `maxKeys` | 32 | 256 |
| `timeoutMs` | 5,000 | 300,000 |
| `maxRedirects` | 0 | 3 |
| `minTtl`, `maxTtl` | 300 / 86,400 seconds | 604,800 each |
| `negativeTtl` | 30 seconds | 300 |

JSON has a 32-container depth ceiling and 256 members/items per container.
Individual JWK objects have at most 32 members. CIMD documents also have an
independent 5,120-byte decoded ceiling. Gzip and x-gzip accept one complete
member under the decoded ceiling; unknown or stacked codings reject.
An owned [DEFLATE boundary check](https://www.rfc-editor.org/rfc/rfc1951) counts
output and requires the final block to end at the trailer before runtime inflation.

Default lookup IDs are RFC 7638 thumbprints; a supplied `kid` must match.
Explicit `keyId: "directory"` supports assigned JWKS/CIMD IDs and preserves
thumbprints for revocation. Directory proof sources require thumbprint mode.
`alg`, when supplied, is an HTTP algorithm token, such as `ed25519`, rather than
a JOSE selector. Private, malformed, duplicate eligible, and unsupported keys
reject the set. Expired, future, revoked, and verification-incompatible keys
are excluded before ID uniqueness is checked.

Directory snapshots verify possession before exposing keys: required coverage
includes `@authority;req` and `content-digest`, with created/expires, thumbprint
key ID, and the directory tag. A proof establishes possession; caller trust and
authorization remain explicit. `requireSignedDirectory: false` permits an
unsigned directory with `proof: "unsigned"`.

Key sets and resolutions are frozen and separately branded. They retain source
type, location, normalized origin, fetch/expiry times, proof status and a SHA-256
revision over decoded key-resource bytes. `lookup()` rejects stale keys and
selects only a compatible HTTP or explicit JOSE algorithm from the caller's allowlist.
An asserted HTTP `alg` must match exactly; an unstamped key may bind an explicit
JOSE choice. HMAC public keys remain forbidden.
`Discovery.resolver(snapshot, {algorithms, clock?})` returns a Result containing an async
bridge that accepts `keyid` and returns only the algorithm and public key. `clock`
returns integer Unix seconds; pass the policy's freshness clock so both checks use one
time. Without it, a key set is checked against system time and a cache against its own
clock; with it, the cache bridge passes `clock` to `resolve`. A clock that returns an
invalid time makes the lookup fail with `invalid_options`. RequestSeal for Elixir has no
resolver clock and uses system time.

## Explicit Node transport

```text
import { Discovery, DiscoverySource } from "@request-seal/core/discovery-node";
import { createCache } from "@request-seal/core";

const source = DiscoverySource.create({
  type: "directory",
  location: "https://agent.example",
  cacerts: "os", // Node 22.15+ or 24+: system trust store. DER roots work on 22.12.
});
if (source.ok) {
  const fetched = await Discovery.fetch(source.value, { timeoutMs: 5_000 });
  const cache = createCache({ fetch: Discovery.fetch });
  if (cache.ok) {
    const resolution = await cache.value.resolve(source.value, keyId, {
      algorithms: ["ed25519"],
    });
    cache.value.close();
  }
}
```

The Node subpath vets every literal and every DNS answer using the pinned IANA
special-purpose table, connects to a numeric address, validates the connected
peer after the TLS handshake and before sending HTTP bytes, verifies TLS hostname and CA trust, and uses a
private agent that excludes environment proxies. A DNS host is checked with
`tls.checkServerIdentity`; an IP-literal host must appear as an iPAddress name in the
certificate, checked by OpenSSL through `X509Certificate.checkIP`, because Node
22.23.1's `checkServerIdentity` never matches an IPv6 literal. `permittedAddresses` allows
at most 16 exact IP exceptions. Embedded IPv4 in mapped, NAT64 and 6to4 forms
undergoes the same IPv4 denial policy. IPv6 additionally requires allocated
global-unicast space and denies the pinned special-purpose ranges. See the
[IANA IPv4 registry](https://www.iana.org/assignments/iana-ipv4-special-registry/)
and [IANA IPv6 registry](https://www.iana.org/assignments/iana-ipv6-special-registry/).

Redirects are manual, bounded and re-vetted. The default scope is `same_origin`;
`any_https` must be explicit. CIMD can fetch a same-origin `jwks_uri` under the
same deadline and intersected freshness. A core snapshot with only `jwks_uri`
returns `source_unavailable`; inline `jwks` works without networking.

Fetch options are `timeoutMs`, `clock`, `context` and `dnsServers`. `timeoutMs` can
only shorten the source's `timeoutMs`. The default
resolver uses `dns.lookup(host, {all: true})`. An explicit `dnsServers` list uses
an independent real DNS resolver for A and AAAA, without changing process or OS
settings; it has at most 16 IP server endpoints, with optional ports. Every
answer still passes the same address policy. As in the reference, IPv6 addresses
are tried before IPv4, keeping resolver order within each family; duplicates are
removed before the 64-address bound applies. A host with an unreachable IPv6 route
spends the deadline on that address first. Context cancellation and deadlines
destroy owned sockets. Every refusal returns only bounded discovery facts.
Non-200 statuses map to `unexpected_status` (except the explicit redirect policy).
5xx are retryable; 4xx are not. The rule comes from the pinned status call site.

## Caller-owned cache

`createCache({clock?, maxSources?, maxInFlight?, fetch?})` creates a frozen,
branded capability. Defaults are 64 sources and 8 in-flight operations, with
ceilings of 4,096 and 256. Pending waiters are bounded to 32 per capacity slot.
Equivalent complete source configurations share an entry. No source is silently
evicted, and no timers or refresh jobs run while the cache is idle.

`refresh(source)` invokes the explicitly configured fetch function;
`refresh(source, snapshot)` installs a validated branded snapshot.
`resolve(source, keyId, {algorithms?, clock?, context?, timeoutMs?})` reuses fresh
keys and fetches on expiry only through that configured function. `algorithms`
defaults to every supported HTTP algorithm, and `timeoutMs` can only shorten the
source's `timeoutMs`. A fresh unknown
ID does not trigger a fetch. Without a fetch function, a miss returns
`source_unavailable`. The resolver bridge also accepts `{cache, source}`.

Freshness follows max-age before Expires, adjusted for Date and Age and capped
by source policy, key expiry and proof expiry. Explicit freshness is never
extended by `minTtl`. No-cache/no-store responses serve current waiters only.
Failures never extend the last observed snapshot; stale keys are never served.
CIMD failures are never negatively cached. Concurrent callers share one fetch;
last-waiter cancellation, invalidation, and `close()` cancel owned work.
`remove(source, thumbprint)` persists a denial through refresh and invalidation,
at most 256 per source.
`invalidate(source)` discards freshness while retaining removals.

## Compatibility

Core snapshots and discovery bodies are exercised on Node, Deno 2.5.6 and Bun
1.3.14. The `./discovery-node` transport supports Node only. On Deno and Bun,
the real HTTPS JWKS acceptance probe returned `invalid_response`; Deno's
socket cancellation probe also did not settle. Use core snapshots on these
runtimes. Published conformance expectations remain unchanged.

`cacerts: "os"` uses the operating-system store when Node exposes a non-empty
`tls.getCACertificates("system")` list, never Node's bundled roots. If the API
is absent or the system list is empty, Node source creation and fetch both
refuse with `discovery/transport_unavailable`; supply explicit DER roots instead.
The API was introduced in Node 22.15.0 and 24.0.0, but its presence alone does
not establish system-store availability. Node 22.12.0 lacks the API. Core
snapshot creation is portable and starts no TLS connection.

On the default resolver path, pinning holds by construction: connect goes to
the vetted address and the socket's lookup throws. No test changes a DNS answer on the default path.
The default-lookup tests exercise localhost acceptance and address-policy rejection;
DNS answer changes are tested through the explicit `dnsServers` path.

The peer check follows the TLS handshake, matching the reference. TLS handshake
bytes (including ClientHello) precede the check; HTTP bytes do not. A connected
peer mismatch fails closed without trying another DNS answer. Wire plaintext is
bounded to `maxBytes * 16 + 32768`; chunk-size lines are limited to 1,024 bytes.

Snapshots require the source's fetch media type. Cache snapshot refresh rejects
future `fetchedAt` values against the cache clock and values below the per-source high-water mark.
Fetched sets are checked and stored against the clock passed to that fetch:
`resolve({clock})` uses the caller clock, and `refresh(source)` uses the cache
clock. A shared fetch uses its initiating caller's clock. Future-dated fetch
results are refused against that same clock.
No-store responses, expiry and invalidation retain that mark, preventing an older
snapshot from restoring rotated-out keys. Snapshot construction already caps
expiry at fetch time plus `maxTtl`. Body parsing is internal; use `Discovery.resolver.fromSnapshot`.
