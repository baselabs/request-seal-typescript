**Status:** maintained · **Kind:** design · **Updated:** October 9, 2026 · **Governed by:** WebCrypto, public standards, and executed boundary tests · **Review when:** custody mechanics or runtime behavior changes

# Custody and cryptographic boundaries

The boundary confines references within one JavaScript realm. Local handles retain
CryptoKey references only in private fields, behind a frozen, independently branded
handle. Public resolution returns public components, not a runtime key. Signing
returns signature bytes. RSA-OAEP unwrapping returns a separately branded AES
operation capability with a private, non-extractable key; it can authenticate and
decrypt content without exporting the content key. Both 128-bit and 256-bit content
keys are supported; callers select the expected length explicitly.

OBSERVED: `test/custody.test.ts` imports a real HMAC CryptoKey as a positive control. On
Node, `KeyObject.from(key).export()` returns the secret even when `extractable: false`;
that flag constrains WebCrypto export only. Deno 2.5.6 rejects that Node compatibility
conversion. OBSERVED: `test/crypto-fixes.test.ts` confirms that structuredClone and
postMessage of a CryptoKey yield a usable copy on Node 22.12.0 and 24.21.0, Deno 2.7.13,
and Bun 1.3.14. On Deno 2.5.6, both copies lose the CryptoKey brand and signing rejects
with TypeError. This version difference does not establish reference confinement:
handles therefore never let a CryptoKey escape their private fields. A CryptoKey
reference is still a cryptographic capability. OBSERVED: boundary tests traverse
results, JSON, inspection output, and structured clones with a visited set and an actual
CryptoKey positive control. Cloning a handle or an unwrapped capability yields no
reachable CryptoKey. The Node conversion rejects the handle itself. Inspection hooks
expose public facts only. These checks describe the tested representations, not heap
confidentiality.

Local import accepts explicit PEM, PKCS #8 DER, and private JWK material. RSA
moduli, exponents, and CRT components are checked before runtime import. EC/OKP
public components supplied with private material must pass a real agreement check.
When public components are absent, import performs one temporary extractable
import, exports a JWK, retains only public members, and imports the operational key
non-extractably. The temporary key is discarded. The DER decoder creates strings
only for public n, e, x, and y components, curve names, and algorithm OIDs; CRT
checks consume INTEGER content bytes directly. Owned DER copies, parser content
buffers (including rejected trees), and the final PKCS #8 import buffer are
overwritten after import. The wrapper copies private octets directly into one
preallocated final buffer. OBSERVED: the allocation tracker with positive controls
in `test/support/zeroing.ts` checks RSA d, a P-256 scalar, and an Ed25519 seed
on PEM, PKCS #8 DER, and JWK imports and rejections. It also checks that DER
decoder results and imported public JWKs contain no private component members.
Caller PEM text and Base64 body strings, caller JWK private component strings,
and private strings from a temporary runtime JWK export still exist and cannot
be zeroed. Exported private members are deleted after public projection. JavaScript
strings and bigints cannot be overwritten, and garbage collection provides no
memory-erasure guarantee.

PSS-only containers retain their binding to RSA-PSS algorithms. Only absent parameters
are accepted. An empty sequence selects SHA-1, MGF1 SHA-1, and salt 20 default
restrictions under RFC 4055 and rejects, as do all present parameters. They cannot
become PKCS #1 or OAEP keys. PSS-only public keys cannot export to JWK, which has no
equivalent type restriction. Metadata-restricted public keys cannot export to SPKI or
PEM, which would discard their restrictions.

HMAC equivalence is an optional nonsecret caller-supplied identity, never a digest
of the secret. Unknown identities never establish equality. Asymmetric equivalence
uses canonical public members; RSA and PSS-only RSA normalize to the same public
identity. Identity inspection omits the equivalence value.

Every operational handle call shares a branded absolute deadline. Late signature
results are discarded, and late AES capabilities are released. Releasing a handle
drops its operational references and subsequent operations return `key_not_found`.
Cancellation cannot interrupt a native operation already submitted to WebCrypto.
Trusted custom custodians must propagate the context and avoid logging secrets;
the handle wrapper bounds exceptions and validates successful result types.

Subtle methods are captured at module load. The library uses exact HTTP and JWS
registries, fixed PSS salt lengths, raw ECDSA widths and scalar bounds, canonical
Ed25519 S, and `subtle.verify` for HMAC. Verification accepts only literal `true`.
The codec accepts definite, canonical DER lengths under byte, depth, and node
ceilings. It never implements cryptographic primitives.

Handle, PublicKey, KeyIdentity, and content-key prototypes and constructors are
frozen at module load. Crypto verification calls captured module functions, so
replacing the library's own prototype methods cannot forge a verdict. Promise
statics and explicit Promise method calls are captured at module load.

The boundary does not defend against a holder using its handle capability, heap
snapshots, debugger/inspector access, memory disclosure, malicious trusted
custodian code, globals patched before module load, or after-load patches to
Object.prototype (such as a `then` getter) or Promise.prototype. Callers own
authorization,
trust, replay policy, and the decision to expose authenticated plaintext.

# Observed runtime conformance

OBSERVED: published vectors and reciprocal OpenSSL commands execute in
`test/crypto.test.ts`, `test/crypto-corpus.test.ts`, and `test/openssl.test.ts`.
The pinned Wycheproof source is commit `12fd3aa`. Node 24.21.0, Node 22.12.0, and
Deno 2.5.6 assert all 151 Ed25519 and all 262 ECDSA P-256 P1363 items.

Bun 1.3.14 rejects valid ECDSA items 261 (`s = 2^128`) and 262 (`s = n - 2^128`).
Direct WebCrypto calls reproduce both rejections through raw, SPKI, and JWK imports.
Node and OpenSSL verify those same published signatures. The merged batch adapter asserts
all 262 ECDSA items against their published verdicts. The CLI and crypto tests
share the exact-version consumer policy in `tools/conformance/runtime-limits.json`,
which reports these two divergences as `runtime_limited` only on Bun 1.3.14.
Stale entries and other divergences fail. Corpus semantics stay unchanged;
the core adds no cryptographic fallback or acceptance override.

# HMAC timing measurements

OBSERVED: `bench/ceilings.ts` alternates equal-length valid and single-bit-invalid
tags, warms up 100 pairs, and measures 1,000 samples per population. Values are
milliseconds; KS is the two-sample empirical distribution distance. The primitive
measurement uses captured `subtle.verify` directly. The boundary measurement
includes contexts, Result construction, and bounded error handling. These are
observations from one run per runtime, not a pass/fail gate or a constant-time proof.

| Runtime | Path | Valid p50 | Valid p99 | Invalid p50 | Invalid p99 | KS |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Node 24.21.0 | primitive | 0.022125 | 0.277708 | 0.022292 | 0.296375 | 0.022000 |
| Node 24.21.0 | boundary | 0.038542 | 0.608958 | 0.054250 | 0.599709 | 0.218000 |
| Node 22.12.0 | primitive | 0.027625 | 0.301167 | 0.027375 | 0.393625 | 0.024000 |
| Node 22.12.0 | boundary | 0.050208 | 0.462875 | 0.072875 | 0.566625 | 0.474000 |
| Deno 2.5.6 | primitive | 0.025708 | 0.137208 | 0.025959 | 0.122625 | 0.051000 |
| Deno 2.5.6 | boundary | 0.078500 | 2.239167 | 0.103458 | 1.793042 | 0.225000 |
| Bun 1.3.14 | primitive | 0.024458 | 0.548375 | 0.025042 | 0.518750 | 0.044000 |
| Bun 1.3.14 | boundary | 0.049250 | 0.931875 | 0.069042 | 2.019625 | 0.280000 |

The complete boundary has distinguishable distributions because valid and invalid
results take different error-handling paths. Callers receive that validity bit
explicitly. The measurement does not establish resistance to all timing attacks
or attribute every timing difference to a cryptographic comparison.

# JOSE key custody and uniform failure

JWE encryption imports its operational content key non-extractably. RSA public
wrapping encrypts operation-local CEK bytes. GCMKW uses WebCrypto wrapKey, which
requires a temporary extractable content key; that key stays inside the
custodian operation and is discarded. The content operation and recovered AES
capability use independent non-extractable keys. Caller wrappers and unwrap
callbacks are trusted custody code; they can retain explicitly supplied key bytes.
No CryptoKey reference leaves a key-management handle. Primitive decrypt on a
caller-owned key-management handle deliberately returns authenticated bytes;
JWE's RSA and GCMKW handle unwrap uses native `unwrapKey` into a non-extractable
AES capability; recovered CEK bytes never enter library memory. Recovered capability
width must match the selected enc algorithm. Released and mismatched capabilities
follow the same failure path as failed unwrap.

Every decryption generates a fresh non-extractable AES fallback key through
WebCrypto `generateKey`, including successful unwraps. No fallback key bytes
enter library memory. Failed unwrap still attempts authentication
using the fallback. No plaintext is released before authentication and the valid
unwrap check. Malformed input retains the pinned input reasons; the uniform
complete error covers OAEP and authentication failures. Cancellation cannot
interrupt an already submitted native operation. Late operation results are
withheld and owned temporary plaintext buffers are overwritten.

OBSERVED: `test/jose-uniform.test.ts` uses OpenSSL raw RSA operations to change
the OAEP leading zero, masked seed, and masked data block independently. Both
RSA-OAEP hash selections and a changed GCM tag return the complete object
`{kind: "jose", reason: "decryption_failed", layer: "crypto", correlation: null,
retryable: false}`. Independent OpenSSL EVP GCM and CLI OAEP operations execute
in both directions in `test/jose-openssl.test.ts`, including A128GCMKW and
A256GCMKW with empty wrapping AAD and both AES-GCM content widths.

OBSERVED: `bench/ceilings.ts` generates fresh real RSA keys, proves a valid
positive, and rotates four corruption populations. Each population has 100 warmup
operations and 1,000 measured operations. Commands are
`node --experimental-strip-types --no-warnings bench/ceilings.ts`,
`deno run --allow-read --allow-write --allow-env --allow-run=openssl bench/ceilings.ts`,
and `bun run bench/ceilings.ts`. Values below are milliseconds. KS compares each
population with the tag population in the earlier observations below. For two
populations of 1,000 samples, the unadjusted two-sample KS 5% significance
threshold is `1.36 × sqrt(1/1000 + 1/1000) = 0.060821`, approximately 0.0608.
Distances above that threshold indicate a distribution difference in that run.
The four earlier exceedances are Node 24 RSA-OAEP-256 masked data block (0.063)
and Node 22 RSA-OAEP-256 leading zero (0.128), masked seed (0.123), and masked
data block (0.148). These observations are not a timing gate or a constant-time
proof. No constant-time claim is made. Equal errors do not establish
indistinguishable timing.

## Earlier observations (one run per runtime)

| Runtime | Algorithm | Corruption | p50 | p99 | KS vs tag |
| --- | --- | --- | ---: | ---: | ---: |
| Node 24.21.0 | RSA-OAEP | leading zero | 2.533625 | 8.178208 | 0.030000 |
| Node 24.21.0 | RSA-OAEP | masked seed | 2.493792 | 7.846458 | 0.042000 |
| Node 24.21.0 | RSA-OAEP | masked data block | 2.604042 | 8.564958 | 0.038000 |
| Node 24.21.0 | RSA-OAEP | tag | 2.562459 | 9.346000 | 0.000000 |
| Node 24.21.0 | RSA-OAEP-256 | leading zero | 1.529500 | 9.236792 | 0.037000 |
| Node 24.21.0 | RSA-OAEP-256 | masked seed | 1.526000 | 8.871042 | 0.036000 |
| Node 24.21.0 | RSA-OAEP-256 | masked data block | 1.618625 | 9.120750 | 0.063000 |
| Node 24.21.0 | RSA-OAEP-256 | tag | 1.540000 | 10.619000 | 0.000000 |
| Node 22.12.0 | RSA-OAEP | leading zero | 2.163542 | 11.009416 | 0.031000 |
| Node 22.12.0 | RSA-OAEP | masked seed | 2.283958 | 9.966583 | 0.043000 |
| Node 22.12.0 | RSA-OAEP | masked data block | 2.288667 | 8.308000 | 0.054000 |
| Node 22.12.0 | RSA-OAEP | tag | 2.187000 | 9.542750 | 0.000000 |
| Node 22.12.0 | RSA-OAEP-256 | leading zero | 0.445500 | 2.949541 | 0.128000 |
| Node 22.12.0 | RSA-OAEP-256 | masked seed | 0.445416 | 4.256791 | 0.123000 |
| Node 22.12.0 | RSA-OAEP-256 | masked data block | 0.450416 | 6.939041 | 0.148000 |
| Node 22.12.0 | RSA-OAEP-256 | tag | 0.441000 | 5.341625 | 0.000000 |
| Deno 2.5.6 | RSA-OAEP | leading zero | 3.207958 | 10.756667 | 0.037000 |
| Deno 2.5.6 | RSA-OAEP | masked seed | 3.213917 | 13.190500 | 0.039000 |
| Deno 2.5.6 | RSA-OAEP | masked data block | 3.216167 | 13.755667 | 0.039000 |
| Deno 2.5.6 | RSA-OAEP | tag | 3.132417 | 10.211583 | 0.000000 |
| Deno 2.5.6 | RSA-OAEP-256 | leading zero | 2.703042 | 17.727709 | 0.024000 |
| Deno 2.5.6 | RSA-OAEP-256 | masked seed | 2.640292 | 13.743625 | 0.024000 |
| Deno 2.5.6 | RSA-OAEP-256 | masked data block | 2.611083 | 13.495500 | 0.021000 |
| Deno 2.5.6 | RSA-OAEP-256 | tag | 2.645167 | 17.342375 | 0.000000 |
| Bun 1.3.14 | RSA-OAEP | leading zero | 1.963917 | 12.035875 | 0.040000 |
| Bun 1.3.14 | RSA-OAEP | masked seed | 1.956291 | 14.630417 | 0.031000 |
| Bun 1.3.14 | RSA-OAEP | masked data block | 1.960666 | 14.069875 | 0.025000 |
| Bun 1.3.14 | RSA-OAEP | tag | 1.937875 | 13.073833 | 0.000000 |
| Bun 1.3.14 | RSA-OAEP-256 | leading zero | 2.243959 | 15.612333 | 0.040000 |
| Bun 1.3.14 | RSA-OAEP-256 | masked seed | 2.186959 | 16.411208 | 0.032000 |
| Bun 1.3.14 | RSA-OAEP-256 | masked data block | 2.166541 | 13.921791 | 0.027000 |
| Bun 1.3.14 | RSA-OAEP-256 | tag | 2.191834 | 25.071292 | 0.000000 |

## Repeated observations with all corruption pairs

OBSERVED: the same `bench/ceilings.ts` commands above executed three times per
runtime after the native unwrap change. Each run used fresh RSA keys, 100 warmups
and 1,000 samples per corruption population. Deno measurements here used 2.7.13;
the earlier Deno table used 2.5.6. Each row records one run. L = leading zero,
S = masked seed, B = masked data block, T = tag. Quantiles below are p50 / p99
in milliseconds. Pairwise KS uses all six population pairs, including the three
OAEP-only pairs. An asterisk marks a distance exceeding 0.060821. These are
exploratory comparisons, without multiple-comparison adjustment; host scheduling
and native operation timings contribute to measured distributions. They do not
establish an exploitable oracle or justify a constant-time claim.

| Runtime | Run | Algorithm | L p50 / p99 | S p50 / p99 | B p50 / p99 | T p50 / p99 |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| Bun 1.3.14 | Run 1 | RSA-OAEP | 1.737375 / 35.985625 | 1.705333 / 26.246041 | 1.734500 / 22.180542 | 1.753666 / 26.729250 |
| Bun 1.3.14 | Run 1 | RSA-OAEP-256 | 1.927666 / 15.750042 | 2.024500 / 18.457250 | 2.023625 / 19.419667 | 1.949667 / 18.800250 |
| Bun 1.3.14 | Run 2 | RSA-OAEP | 2.219458 / 14.138208 | 2.372709 / 12.813875 | 2.260666 / 12.362166 | 2.306167 / 10.385208 |
| Bun 1.3.14 | Run 2 | RSA-OAEP-256 | 2.097833 / 17.720209 | 2.089500 / 19.819875 | 2.071167 / 12.879542 | 2.056167 / 17.861583 |
| Bun 1.3.14 | Run 3 | RSA-OAEP | 1.333000 / 9.345333 | 1.272667 / 12.012334 | 1.264209 / 10.076959 | 1.253708 / 10.188834 |
| Bun 1.3.14 | Run 3 | RSA-OAEP-256 | 2.238916 / 9.313916 | 2.291208 / 11.439750 | 2.299667 / 14.258458 | 2.302333 / 12.887250 |
| Deno 2.7.13 | Run 1 | RSA-OAEP | 1.497125 / 5.714416 | 1.486875 / 5.064875 | 1.488292 / 6.245958 | 1.506125 / 6.477458 |
| Deno 2.7.13 | Run 1 | RSA-OAEP-256 | 2.179166 / 15.341125 | 2.330584 / 15.239625 | 2.196791 / 14.709750 | 2.195917 / 14.142042 |
| Deno 2.7.13 | Run 2 | RSA-OAEP | 1.315000 / 6.628875 | 1.331875 / 7.280750 | 1.287375 / 5.646375 | 1.293209 / 6.110166 |
| Deno 2.7.13 | Run 2 | RSA-OAEP-256 | 1.586291 / 8.060209 | 1.607583 / 6.765666 | 1.597917 / 7.523625 | 1.583458 / 8.361375 |
| Deno 2.7.13 | Run 3 | RSA-OAEP | 2.960500 / 35.935125 | 2.967583 / 51.242167 | 2.885417 / 32.948000 | 2.924583 / 28.927083 |
| Deno 2.7.13 | Run 3 | RSA-OAEP-256 | 4.215875 / 45.662125 | 4.326041 / 44.007500 | 4.215209 / 33.881667 | 4.220667 / 31.690333 |
| Node 22.12.0 | Run 1 | RSA-OAEP | 1.024500 / 4.537125 | 1.027333 / 4.960708 | 1.053167 / 5.030125 | 1.018875 / 4.396708 |
| Node 22.12.0 | Run 1 | RSA-OAEP-256 | 1.534583 / 13.739958 | 1.557250 / 18.188792 | 1.658583 / 14.997458 | 1.514250 / 13.360708 |
| Node 22.12.0 | Run 2 | RSA-OAEP | 1.504583 / 14.813000 | 1.457916 / 13.000000 | 1.530208 / 12.757208 | 1.467958 / 10.943000 |
| Node 22.12.0 | Run 2 | RSA-OAEP-256 | 0.771500 / 3.938917 | 0.774125 / 4.601833 | 0.795000 / 5.866500 | 0.743209 / 3.798625 |
| Node 22.12.0 | Run 3 | RSA-OAEP | 0.537166 / 3.224292 | 0.536542 / 3.266916 | 0.590625 / 3.597417 | 0.538750 / 3.305083 |
| Node 22.12.0 | Run 3 | RSA-OAEP-256 | 0.878708 / 6.567667 | 0.853333 / 6.833208 | 0.921834 / 5.334750 | 0.895708 / 5.732375 |
| Node 24.21.0 | Run 1 | RSA-OAEP | 0.533625 / 5.057458 | 0.530417 / 4.529375 | 0.590834 / 5.645834 | 0.526833 / 4.220375 |
| Node 24.21.0 | Run 1 | RSA-OAEP-256 | 0.670167 / 3.478416 | 0.665417 / 4.002666 | 0.684917 / 3.984625 | 0.644625 / 4.241750 |
| Node 24.21.0 | Run 2 | RSA-OAEP | 0.675125 / 9.404625 | 0.726584 / 9.439916 | 0.722250 / 8.946000 | 0.706834 / 11.253041 |
| Node 24.21.0 | Run 2 | RSA-OAEP-256 | 1.819083 / 12.104334 | 1.838166 / 12.935000 | 1.842583 / 12.217208 | 1.772167 / 9.991417 |
| Node 24.21.0 | Run 3 | RSA-OAEP | 0.751000 / 3.820667 | 0.747417 / 3.754250 | 0.793209 / 3.633458 | 0.734750 / 3.419625 |
| Node 24.21.0 | Run 3 | RSA-OAEP-256 | 0.588583 / 4.243375 | 0.614125 / 3.888042 | 0.634958 / 3.953958 | 0.596625 / 4.084917 |

| Runtime | Run | Algorithm | L–S | L–B | L–T | S–B | S–T | B–T |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Bun 1.3.14 | Run 1 | RSA-OAEP | 0.031 | 0.026 | 0.034 | 0.025 | 0.029 | 0.024 |
| Bun 1.3.14 | Run 1 | RSA-OAEP-256 | 0.037 | 0.045 | 0.018 | 0.032 | 0.036 | 0.042 |
| Bun 1.3.14 | Run 2 | RSA-OAEP | 0.052 | 0.042 | 0.042 | 0.046 | 0.042 | 0.025 |
| Bun 1.3.14 | Run 2 | RSA-OAEP-256 | 0.037 | 0.044 | 0.037 | 0.026 | 0.026 | 0.032 |
| Bun 1.3.14 | Run 3 | RSA-OAEP | 0.032 | 0.042 | 0.039 | 0.024 | 0.040 | 0.049 |
| Bun 1.3.14 | Run 3 | RSA-OAEP-256 | 0.039 | 0.059 | 0.048 | 0.028 | 0.028 | 0.025 |
| Deno 2.7.13 | Run 1 | RSA-OAEP | 0.023 | 0.028 | 0.027 | 0.027 | 0.022 | 0.034 |
| Deno 2.7.13 | Run 1 | RSA-OAEP-256 | 0.048 | 0.034 | 0.034 | 0.039 | 0.045 | 0.032 |
| Deno 2.7.13 | Run 2 | RSA-OAEP | 0.026 | 0.026 | 0.029 | 0.043 | 0.039 | 0.031 |
| Deno 2.7.13 | Run 2 | RSA-OAEP-256 | 0.023 | 0.027 | 0.021 | 0.027 | 0.030 | 0.040 |
| Deno 2.7.13 | Run 3 | RSA-OAEP | 0.029 | 0.030 | 0.026 | 0.026 | 0.037 | 0.033 |
| Deno 2.7.13 | Run 3 | RSA-OAEP-256 | 0.030 | 0.032 | 0.026 | 0.036 | 0.027 | 0.026 |
| Node 22.12.0 | Run 1 | RSA-OAEP | 0.025 | 0.050 | 0.028 | 0.048 | 0.023 | 0.059 |
| Node 22.12.0 | Run 1 | RSA-OAEP-256 | 0.025 | 0.047 | 0.019 | 0.037 | 0.033 | 0.053 |
| Node 22.12.0 | Run 2 | RSA-OAEP | 0.020 | 0.043 | 0.020 | 0.048 | 0.021 | 0.038 |
| Node 22.12.0 | Run 2 | RSA-OAEP-256 | 0.033 | 0.040 | 0.033 | 0.049 | 0.027 | 0.051 |
| Node 22.12.0 | Run 3 | RSA-OAEP | 0.023 | 0.078* | 0.034 | 0.082* | 0.039 | 0.081* |
| Node 22.12.0 | Run 3 | RSA-OAEP-256 | 0.030 | 0.042 | 0.031 | 0.043 | 0.034 | 0.046 |
| Node 24.21.0 | Run 1 | RSA-OAEP | 0.020 | 0.085* | 0.023 | 0.087* | 0.021 | 0.077* |
| Node 24.21.0 | Run 1 | RSA-OAEP-256 | 0.028 | 0.052 | 0.044 | 0.057 | 0.059 | 0.062* |
| Node 24.21.0 | Run 2 | RSA-OAEP | 0.025 | 0.055 | 0.024 | 0.060 | 0.022 | 0.055 |
| Node 24.21.0 | Run 2 | RSA-OAEP-256 | 0.022 | 0.026 | 0.047 | 0.025 | 0.037 | 0.040 |
| Node 24.21.0 | Run 3 | RSA-OAEP | 0.041 | 0.061* | 0.040 | 0.059 | 0.032 | 0.052 |
| Node 24.21.0 | Run 3 | RSA-OAEP-256 | 0.038 | 0.072* | 0.032 | 0.050 | 0.039 | 0.056 |

OBSERVED exceedances in these repeated runs:

- Node 22.12.0, Run 3, RSA-OAEP: L–B (0.078), S–B (0.082), B–T (0.081).
- Node 24.21.0, Run 1, RSA-OAEP: L–B (0.085), S–B (0.087), B–T (0.077).
- Node 24.21.0, Run 1, RSA-OAEP-256: B–T (0.062).
- Node 24.21.0, Run 3, RSA-OAEP: L–B (0.061).
- Node 24.21.0, Run 3, RSA-OAEP-256: L–B (0.072).

The other recorded pairs did not exceed the stated threshold in their measured
run. OBSERVED in the repeated measurements above: on Node every exceedance involves the masked-data-block population,
which also had the highest p50 in 11 of 12 Node run and algorithm cells, against
none of the six Deno cells and none of the six Bun cells. Across these repeated
runs, this is a reproducible split between OAEP failure classes at the runtime
boundary. Repeated results vary; they are evidence of these runs, not a guarantee
about future timing. No constant-time claim is made.
