# Security

Report vulnerabilities privately with GitHub private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**, or go straight to the [private report form](https://github.com/baselabs/request-seal-typescript/security/advisories/new). Only you and the repository maintainers can see the report. Do not open a public issue for a vulnerability.

Include the affected versions and a reproduction. Avoid private keys or live credentials.

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.5.x | Yes; use the latest patch |
| 0.4.x and earlier | No; upgrade to 0.5.x. Releases affected by a published advisory are deprecated on npm |

Security fixes ship in the current 0.5.x line. Check the [changelog](CHANGELOG.md)
for changes before upgrading. Version 0.1.0 was published manually without
provenance; trusted publishing began with 0.2.0.

## Published advisories

| Advisory | Affected | Fixed | Summary |
| --- | --- | --- | --- |
| [GHSA-wqp2-3rvg-936p](https://github.com/baselabs/request-seal-typescript/security/advisories/GHSA-wqp2-3rvg-936p) | 0.4.0 and earlier | 0.5.0 | Web Bot Auth required replay could accept a captured request again after relabeling, removing or recombining its signatures. Generic `verify` is not affected. Earlier releases are deprecated on npm. |

## Verifying a release

Releases from 0.2.0 carry npm trusted-publishing provenance. Publication builds and
inspects the archive before staging it with provenance. The owner approves the stage
on npmjs.com; a second dispatch of the same commit verifies public registry digests and
downloaded bytes without uploading again. Different, deprecated, unpublished, or already
tagged versions refuse. A pending stage cannot be inspected with a trusted-publisher
token, so a duplicate request fails closed until approval. See the [release
procedure](docs/releasing.md).

Get the verification files from the [GitHub release for
`v<version>`](https://github.com/baselabs/request-seal-typescript/releases), choosing
the release that matches the package version. Its assets include the inspected
`package.tgz`, `SHA256SUMS`, `pack.json`, `CHANGELOG.md`, `registry.json`, and npm
provenance when available. The following example downloads the two archive-verification
files for 0.5.1; select the version you intend to install:

```sh
version=0.5.1
verification_dir="$(mktemp -d)"
trap 'rm -rf "$verification_dir"' EXIT
cd "$verification_dir"
gh release download "v$version" --repo baselabs/request-seal-typescript --pattern package.tgz --pattern SHA256SUMS
shasum -a 256 --check SHA256SUMS
npm view "@request-seal/core@$version" dist --json
```

Compare the archive with npm's `dist.integrity` (SHA-512 in base64) and `dist.shasum`
(SHA-1 in hex). These commands calculate them without extracting or executing it:

```sh
openssl dgst -sha512 -binary package.tgz | openssl base64 -A
shasum -a 1 package.tgz
```

Check the registry's signatures and provenance from your installed consumer project:

```sh
npm audit signatures
```

## Boundaries

Errors carry bounded reasons. JSON preserves member order and duplicate names; callers must apply their surface's duplicate policy. Bytes are copied on entry. Cancellation discards late callback results; it does not undo external effects.
