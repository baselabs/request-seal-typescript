**Status:** maintained · **Kind:** policy · **Updated:** October 11, 2026 · **Governed by:** the public error contract · **Review when:** reporting channels or security boundaries change

# Security

Report vulnerabilities privately through [GitHub security advisories](https://github.com/baselabs/request-seal-typescript/security/advisories/new). Include affected versions and a reproduction. Avoid private keys or live credentials.

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.2.x | Yes |
| 0.1.0 | No; upgrade to 0.2.x |

Fixes ship in the latest 0.2.x release. 0.1.0 was published manually without
provenance and predates the 0.4.1 parity and hardening in 0.2.0.

## Verifying a release

Releases from 0.2.0 are staged from a version tag by this repository's release
workflow through npm trusted publishing and carry a signed provenance statement.
Check an installed copy with:

```sh
npm audit signatures
```

## Boundaries

Errors carry bounded reasons. JSON preserves member order and duplicate names; callers must apply their surface's duplicate policy. Bytes are copied on entry. Cancellation discards late callback results; it does not undo external effects.
