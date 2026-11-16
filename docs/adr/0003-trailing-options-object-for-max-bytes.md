# 0003 — A trailing options object carries the per-call byte bound

## Context

Per-call byte bounds limit hashing and signing work independently of Context deadlines and the fixed message, body, JWS, adapter, and signature-base limits.

## Decision

Add an optional trailing options object, `{ maxBytes }`, to each of those calls:

```
Crypto.sign(algorithm, handle, data, options?)
Crypto.verify(algorithm, key, signature, data, options?)
handle.sign(algorithm, data, context, options?)
handle.verify(algorithm, signature, data, context, options?)
publicKey.verify(algorithm, signature, data, options?)
```

`maxBytes` is an integer from 1 through `Crypto.maxBytesCeiling()` (16,777,216). The default stays 1,048,576, so existing calls are unchanged. Options are read once into a null-prototype snapshot. An unknown key, an array, or an invalid value returns `invalid_options` before the algorithm, handle, or capability is examined. `Crypto.sign`, `Crypto.verify`, and `publicKey.verify` check the data size before key validity, as the reference does. `unwrap` accepts no `maxBytes`. The custodian sign callback receives {maxBytes: Crypto.maxBytesCeiling()} as its fourth argument; the verify callback receives that object as its fifth. The managed handle has already enforced the per-call bound. A callback enforces the fixed ceiling on its own work and passes it when delegating. `Context` keeps carrying only the deadline and the abort signal. Message, Body, JWS, adapter, and signature-base limits stay fixed.

## Consequences

Existing callers keep the 1 MiB default with no change. Custodian authors must handle sign’s fourth argument and verify’s fifth argument. Any future per-call option joins this object and is read through the same snapshot, so a second options mechanism is a design change. The Elixir keyword option and the TypeScript object stay equivalent.
