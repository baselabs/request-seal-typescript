# 0007 — Discovery trusts the operating system store, and fails closed when it is unavailable

## Context

HTTPS key discovery fetches a publisher's keys, so the certificate chain it accepts decides whose keys it believes. Operators manage trust at the operating system level: they add a private CA, remove a compromised one, and expect services to follow. Node ships its own bundled root list, which an operator cannot change without a flag, and Node's `tls.getCACertificates("system")` is available only in recent releases (22.15.0 and 24.0.0 or newer). The API existing does not mean the system store is available or non-empty.

## Decision

`cacerts: "os"` uses only `tls.getCACertificates("system")`. A missing, empty, or denied system store returns `discovery/transport_unavailable` from Node source creation and fetch, with no bundled-root fallback.
Explicit `cacerts` accepts 1–256 DER roots and replaces the system store. Portable core source creation accepts `"os"` without reading it.
Each connection uses a vetted numeric address, TLS 1.2 or newer, hostname and chain validation with `rejectUnauthorized: true`, and a peer check before any HTTP bytes.

## Consequences

On Node 22.12.0 and any Node with no usable system store, `cacerts: "os"` refuses, so deployments there use DER roots. The behavior depends on the host's trust store, which an operator already owns. Hosts with a private CA need no code change. A change to the trust default is a security change and needs a new decision.
