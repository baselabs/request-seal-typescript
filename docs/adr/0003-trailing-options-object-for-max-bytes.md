**Status:** accepted · **Kind:** record · **Updated:** October 11, 2026 · **Governed by:** RequestSeal 0.4.1 crypto and custody behavior, and the byte-bound tests · **Review when:** a crypto or custody signature changes, or another per-call option is added

# ADR 0003: A trailing options object carries the per-call byte bound

- Status: Accepted
- Date: October 11, 2026

## Context

RequestSeal for Elixir 0.4.1 added a `max_bytes` option to crypto and custody signing and verification. The bound exists so one call cannot be made to hash or sign an arbitrarily large input, and so that a caller can choose a smaller or larger limit than the default for a specific operation.

In TypeScript the calls already have positional shapes that the documentation, the corpus consumers, and callers depend on: `Crypto.sign(algorithm, handle, data)`, `Crypto.verify(algorithm, key, signature, data)`, `handle.sign(algorithm, data, context)`, `handle.verify(algorithm, signature, data, context)`, and `publicKey.verify(algorithm, signature, data)`. A deadline already travels in the `Context`, which can be shared by a whole verification and its children.

## Decision

Add an optional trailing options object, `{ maxBytes }`, to each of those calls:

```
Crypto.sign(algorithm, handle, data, options?)
Crypto.verify(algorithm, key, signature, data, options?)
handle.sign(algorithm, data, context, options?)
handle.verify(algorithm, signature, data, context, options?)
publicKey.verify(algorithm, signature, data, options?)
```

`maxBytes` is an integer from 1 through `Crypto.maxBytesCeiling()` (16,777,216). The default stays 1,048,576, so existing calls are unchanged. Options are read once into a null-prototype snapshot. An unknown key, an array, or an invalid value returns `invalid_options` before the algorithm, handle, or capability is examined. `Crypto.sign`, `Crypto.verify`, and `publicKey.verify` check the data size before key validity, as the reference does. `unwrap` accepts no `maxBytes`. A custodian callback receives the ceiling as a fourth argument and must enforce its own limit and pass the ceiling when it delegates. `Context` keeps carrying only the deadline and the abort signal. Message, Body, JWS, adapter, and signature-base limits stay fixed.

## Strongest alternatives

1. **Carry the bound on the `Context`.** One object would hold all per-operation limits. A `Context` is shared by a verification and every nested call, so one size would apply to calls that need different bounds, and deadline semantics would mix with size semantics.
2. **Insert `maxBytes` as another positional parameter.** It is explicit, but it changes every existing call and is order-sensitive next to `context`.
3. **Provide separate bounded methods**, such as `signLimited`. No ambiguity, at the price of doubling the surface and the documentation.
4. **A process-wide setting.** Easy to use, and it makes behavior depend on mutable shared state that any module can change.
5. **Bound only in `Policy`.** It covers HTTP verification, and it leaves direct primitive and custody callers unbounded.

## Deciding evidence and deletion test

`src/crypto/options.ts` reads the trailing options through `snapshotOptions`. `test/crypto-max-bytes.test.ts` checks "nested real handles preserve the selected maximum and option precedence over capability", "fixed upper-level and primitive defaults remain separate from the crypto ceiling", and "byte options read own keys once and reject unknown or throwing keys without disclosure". The tests exercise bounds, call shape, precedence, and getter reads; they do not establish a verdict for moving options onto `Context`.

## Consequences

Existing callers keep the 1 MiB default with no change. A custodian author must handle a fourth argument. Any future per-call option joins this object and is read through the same snapshot, so a second options mechanism is a design change. The Elixir keyword option and the TypeScript object stay equivalent.

## Acceptance

- `src/crypto/options.ts` (`byteLimit`) is the one place that reads and validates `maxBytes`, using `snapshotOptions` from `src/brand.ts`.
- `src/constants.ts` defines `CRYPTO_MAX_BYTES_CEILING` and `CRYPTO_DEFAULT_MAX_BYTES`; the package exports them and `Crypto.maxBytesCeiling()`.
- `test/crypto-max-bytes.test.ts` covers inclusive endpoints, option validation order, own-key reads, legacy defaults, direct custodian ceilings, shadowed lengths, nested handles, unwrap, and public-key verification.
- `test/options-probes.test.ts` counts getter reads for every option key.
