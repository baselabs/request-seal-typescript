**Status:** maintained · **Kind:** reference · **Updated:** October 10, 2026 · **Governed by:** RequestSeal v0.4.1 Profile contract, ADR 0013, RFC 9421, and the shared conformance corpus · **Review when:** extension surface, stamps, or verification facts change

# Extension profiles

`Profile` shares HTTP signature parsing, coverage, freshness, cryptography, content,
and replay with independently maintained extension packages. This surface is unstable;
pin `@request-seal/core` exactly. Extensions enforce their source-specific predicates
and select their profile name as a constant in their code.

```ts
import { Profile, type ProfileStamp } from "@request-seal/core";

const stamp: ProfileStamp = Object.freeze({
  name: Object.freeze(["example_pkg", "example"] as const),
  revision: "1",
});
const parsed = Profile.dictionaries(message, 16);
if (parsed.ok) {
  const [entries, signatures] = parsed.value;
  const input = new Map(entries).get(label);
  const prepared = await Profile.preflight(input, '("@method")', "allow", policy.freshness);
  if (prepared.ok) {
    const verified = await Profile.verifyLabel(
      message, policy, label, input, signatures[label], stamp,
    );
    // Apply application decisions to verified.ok and verified.value explicitly.
  }
}
```

`message`, `policy`, and `label` above are caller-selected values; policy must be
created by `Policy.create`. See [signing and verification](sign-and-verify.md).

`Profile.validSignatureInput(input)` returns a boolean for the semantic rules of a
parsed Signature-Input inner list. Malformed values return false. It does not parse
wire text, establish key trust, or validate the entire Structured Fields grammar.
Empty coverage is allowed; policy chooses the required components.

`Profile.dictionaries(message, max)` returns a Result containing ordered
`[label, input]` pairs and a frozen null-prototype signature lookup. It checks paired
labels and preserves encounter order. `Profile.preflight(input, components, extra,
freshness)` asynchronously checks coverage and freshness before discovery or key
resolution. Components use the signature-input inner-list form; extra is `"allow"`
or `"reject"`; freshness is `"not_evaluated"` or the four explicit clock, maxAge,
skew, and requireExpires choices used by Policy. Unknown freshness keys reject.

`Profile.verifyLabel(message, policy, label, input, signature, stamp)` reparses under
`policy.maxSignatures`, requires the supplied nodes to structurally equal that label's
parsed entries, then uses the shared authentication pipeline. Component and parameter
order, bare value types, and decoded signature bytes matter; parser object identity
does not. It has no representation or digest-state options. Required content checks
use retained message body bytes. Generic `verify` retains its explicit content options.

A stamp is a plain object with at most eight own string keys including name. Name is
exactly `[package, kind]`, both strings. Bare string names reject. Packages
`request_seal`, `request-seal`, `rfc9421`, `web_bot_auth`, and `web-bot-auth` are
reserved; those strings can be kinds under an independent package. Metadata accepts
booleans, null, safe integers from -999,999,999,999,999 through 999,999,999,999,999,
and strings through 256 UTF-8 bytes. JavaScript strings cannot distinguish atoms from
binaries; all metadata strings use that byte limit. Class instances, symbol keys,
compound values, and additional tuple keys reject. Own values and tuple elements are
read once into owned snapshots. Returned stamp objects and tuples are frozen.

Rejection precedence is stamp, policy, label, message, signature shape, paired
fields, unknown label, selected input, selected signature, and input semantics.
Failures return bounded Results without caller bytes or callback diagnostics;
unexpected boundary faults become `invalid_policy` at `input`.

Successful verification carries the stamp in `Verification.profile` and in replay
commitment `facts.profile`. Commitments must bind the profile name to distinguish
security scopes. Default JSON and inspection include public profile metadata along
with label, replay, and authorization; signature parameters require explicit access.
`serializeVerification` uses `{name: [package, kind], ...metadata}` for extension
facts, preserves metadata spelling and integers, and encodes boolean/null metadata
as `"true"`, `"false"`, and `"nil"`, matching the reference profile conversion.
Core profile facts retain their existing string names and revision fields.

A stamp records selection; it does not establish that extension predicates ran.
Consumers allowlist trusted profiles and their verification code. Generic verification
refuses profile and principal options. Cryptographic validity grants no authorization;
these results retain principal `"unattributed"` and authorization `"not_evaluated"`.
