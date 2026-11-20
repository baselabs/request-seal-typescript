# Compatibility and deprecation

This is the compatibility contract for `@request-seal/core`, following
[Semantic Versioning](https://semver.org/) and the public
[RequestSeal for Elixir compatibility policy](https://github.com/baselabs/request_seal/blob/main/docs/reference/compatibility.md).
Security support is described in [SECURITY.md](../../SECURITY.md).

## Before 1.0

The current package is on a 0.x line. Each 0.x minor line is a compatibility
boundary: a new minor may introduce documented breaking changes, with migration
instructions in the changelog. Patch releases preserve that minor line's contract,
except for the security fixes below. The promises within a major below apply to
each 0.x minor line until 1.0; they do not imply compatibility across all 0.x minors.
Starting at 1.0, breaking changes require a new major release.

## Stable within a major

- Every documented export at the root and each package subpath, its declared
  signature, option names, accepted values, defaults, and selection rules.
- Documented Result and error shapes and fields, layers and the meaning of each
  error reason. Verification retains `authorization: "not_evaluated"`:
  cryptographic validity never grants authorization.
- Published work, size and time ceilings, and the ability to lower configurable
  ceilings. Raising a ceiling must preserve existing behavior and security;
  lowering an accepted bound requires a compatibility boundary or security fix.
- Wire bytes for a given input, algorithm tokens, canonicalization, and the inputs
  verification accepts or rejects, subject to security fixes below.
- The `Custodian`, `ReplayStore`, context, cancellation and timeout interfaces,
  and the `Profile` extension interface. Core ships standards-derived profiles;
  independently named extensions own their additional predicates.
- Supported explicit standard and draft revisions and their result stamps. A new
  revision is a separate selection; defaults never silently switch revisions.
- Telemetry event names, outcome meanings, fields, units and bounded metadata.

The checked-in public API inventory protects declared exports and signatures.
Treat public result and event fields as extensible: read the fields you need,
handle unknown error reasons with a catch-all, and do not assert whole-object equality.

## Major, minor and patch releases

A **major** release may remove or incompatibly change these contracts. A **minor**
release within a stable major may add exports, optional options with compatible
defaults, explicitly selected algorithms and revisions, result fields, error reasons
and details, and telemetry events or fields. Existing behavior and defaults remain.
Before 1.0 a minor may also make the documented breaking changes described above.

A **patch** release fixes defects while preserving the current compatibility line.
A minor or patch may return a new bounded error reason or detail; callers must
keep a catch-all. It never turns a refusal into implicit authorization.
Raising a supported runtime minimum happens only at a minor release, with a
changelog entry; exact qualified runtimes are in the [runtime matrix](runtime-matrix.md).

## Security fixes

A minor or patch may reject inputs accepted earlier in the same compatibility
line when required by a security fix. Its changelog entry describes the rejected
inputs, why they are unsafe, and the public standard or advisory supporting it.

## Exclusions and deprecation

Private fields, internal modules outside package exports, implementation state,
inspection formatting, exception text, development dependencies and lockfiles
are not public contracts. Use branded values through their documented operations.

Deprecation begins in a minor release and names the replacement in documentation,
with a warning where the runtime or type system supports one. The deprecated API
continues working through that compatibility line and is removed only at the next
major (or, before 1.0, a documented new minor boundary).
