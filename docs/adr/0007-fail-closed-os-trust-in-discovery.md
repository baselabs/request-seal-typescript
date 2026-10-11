**Status:** accepted · **Kind:** record · **Updated:** October 11, 2026 · **Governed by:** src/discovery/node.ts, src/discovery/source.ts, and the discovery transport tests · **Review when:** Node's certificate APIs change, or a trust-store policy is proposed

# ADR 0007: Discovery trusts the operating system store, and fails closed when it is unavailable

- Status: Accepted
- Date: October 11, 2026

## Context

HTTPS key discovery fetches a publisher's keys, so the certificate chain it accepts decides whose keys it believes. Operators manage trust at the operating system level: they add a private CA, remove a compromised one, and expect services to follow. Node ships its own bundled root list, which an operator cannot change without a flag, and Node's `tls.getCACertificates("system")` is available only in recent releases (22.15.0 and 24.0.0 or newer). The API existing does not mean the system store is available or non-empty.

## Decision

1. **A source trusts the operating system store by default.** `cacerts` defaults to `"os"`. The transport reads `tls.getCACertificates("system")` and uses exactly those certificates as the only trust anchors for the connection.
2. **The bundled roots are never a fallback.** If `tls.getCACertificates` is missing, or returns an empty list, creating a source with `cacerts: "os"` through `@request-seal/core/discovery-node` returns custody `unsupported_format`, and so does `Discovery.fetch`. The caller must then supply explicit DER roots.
3. **Explicit roots replace the system store.** `cacerts` may be a list of DER certificates (1 to 256). They are the only anchors for that source. Core source creation, which opens no connection, accepts `"os"` without checking the store, so snapshots stay portable.
4. **Each connection is verified in full.** The transport connects to a vetted numeric address, requires TLS 1.2 or newer, verifies the host name and chain with `rejectUnauthorized: true`, and checks the connected peer before it sends any HTTP bytes.

## Strongest alternatives

1. **Use Node's bundled roots when the system store is unavailable.** Always works. It silently trusts authorities the operator may have removed, and the same configuration would trust different CAs on different Node versions.
2. **Always require explicit roots.** No ambient trust. Every deployment must ship and rotate a CA list that the operating system already manages.
3. **Honor `NODE_EXTRA_CA_CERTS` or `--use-system-ca`.** Familiar to operators. These are process-wide settings outside the source configuration, so a source's trust would depend on the environment that launched the process.
4. **Merge system and bundled roots.** More sites validate. The result is a larger trust set than either operator policy.

## Deciding evidence and deletion test

`src/discovery/node.ts` checks that `tls.getCACertificates("system")` exists and returns a nonempty store; source creation and fetching enforce that result. `test/discovery-fixes.test.ts` exercises a real untrusted TLS peer, expecting `unsupported_format` when the store is unavailable and `tls_failed` when usable system roots reject that peer. `test/discovery-os-trust.test.ts` also checks denied OS-root permission on Deno. These tests observe the available host branches; no bundled-roots fallback or empty-list-check mutation is claimed.

## Consequences

On Node 22.12.0 and any Node with no usable system store, `cacerts: "os"` refuses, so deployments there use DER roots. The behavior depends on the host's trust store, which an operator already owns. Hosts with a private CA need no code change. A change to the trust default is a security change and needs a new decision.

## Acceptance

- `src/discovery/source.ts` defaults `cacerts` to `"os"`; `src/discovery/node.ts` (`systemCertificates`, `tlsSocket`, `fetch`, and the Node `DiscoverySource.create`) enforces the refusal.
- `test/discovery-fixes.test.ts` ("OS trust rejects an untrusted TLS peer or refuses an unavailable system store") and `test/discovery-node.test.ts` run against real TLS peers and report which branch the host exercised.
- `docs/reference/discovery.md` states the Node versions and the refusal.
