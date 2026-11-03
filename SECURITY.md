**Status:** maintained · **Kind:** policy · **Updated:** November 3, 2026 · **Governed by:** the public error contract · **Review when:** reporting channels or security boundaries change

# Security

Report vulnerabilities privately with GitHub private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**, or go straight to the [private report form](https://github.com/baselabs/request-seal-typescript/security/advisories/new). Only you and the repository maintainers can see the report. Do not open a public issue for a vulnerability.

Include the affected versions and a reproduction. Avoid private keys or live credentials.

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.4.x | Yes; use the latest patch |
| 0.3.x and earlier | No; upgrade to 0.4.x |

Security fixes ship in the current 0.4.x line. Check the [changelog](CHANGELOG.md)
for changes before upgrading. Version 0.1.0 was published manually without
provenance; trusted publishing began with 0.2.0.

## Verifying a release

Releases from 0.2.0 are staged from a version tag by this repository's release
workflow through npm trusted publishing and carry a signed provenance statement.
Check an installed copy with:

```sh
npm audit signatures
```

## Boundaries

Errors carry bounded reasons. JSON preserves member order and duplicate names; callers must apply their surface's duplicate policy. Bytes are copied on entry. Cancellation discards late callback results; it does not undo external effects.
