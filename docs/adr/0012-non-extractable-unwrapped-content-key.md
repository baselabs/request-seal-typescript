# 0012 — Confine unwrapped content keys to a non-extractable capability

## Context

JWE decryption unwraps a content encryption key in custody and then uses it to authenticate
and decrypt content. Returning the raw key bytes, or an extractable `CryptoKey`, would let any
caller code copy the key out of custody.

## Decision

1. Custody imports the unwrapped key with `extractable: false` and only the `decrypt` usage
   (`src/custody/local.ts:110-117`).
2. It returns an `UnwrappedKey`: a frozen capability with `length`, `decrypt` and `release`, and
   no key bytes or `CryptoKey` (`src/custody/content_key.ts:14-24`,
   `src/custody/content_key.ts:29`).
3. Only the library can construct one (`src/custody/content_key.ts:34`), and
   `isUnwrappedKey` checks a private brand (`src/custody/content_key.ts:26`).
4. `release` drops the key and invalidates the capability.

## Consequences

Content decryption runs through the capability, which accepts caller-selected IV and AAD under fixed AES-GCM width, size, tag and deadline rules. A custody
implementation must return a key that the library can confine, so a third-party custodian
cannot hand back bytes. Indexed unwrap for many tokens is part of the 0.6 parity work
([0013](0013-native-parity-on-the-2-0-corpus.md)).
