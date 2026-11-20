# Releasing

Release commits pass the complete qualification workflow before landing on the default
branch. Qualification runs only for `kci/**` pushes; it installs locked dependencies,
tests local source and packed output, and never installs this package from npm.
`qualified` is the required final check. The default-branch ruleset is the publication
prerequisite; publication does not rerun or query qualification.

## Prepare and approve

1. Update the package version and `VERSION` together, stamp the changelog for that
   version, and update affected documentation. Land the qualified version commit.
2. A release maintainer obtains the owner's approval and dispatches `publish.yml`
   from the default branch, without inputs, in environment `publish`. Both the
   original actor and the triggering actor must be authorized. The package must
   already have a public npm version; first publication belongs to the owner.
3. The workflow installs the exact Node from `.tool-versions` and npm from the root
   `packageManager`, runs `npm ci --ignore-scripts`, builds the library and API docs,
   inspects the package allowlist and exports, and hashes the exact archive. It uses no workflow cache or registry key.
   Configure npm's trusted publisher for `publish.yml` and environment `publish`,
   allowing staged publication. Only the inspected `package.tgz` is staged with
   provenance; lifecycle scripts are disabled during upload.
4. The owner approves the staged version on npmjs.com. Approval is a separate act;
   staging is not public publication. The dependent registry-install job refuses
   to report success until public read-back completes.
5. Dispatch the same qualified commit again after approval, once npm shows the
   approved version: wait until `npm view @request-seal/core@<version> version`
   prints it. Planning reads npm's public state, so a dispatch before then stages
   the version again and npm refuses it with HTTP 409; nothing changes, and the
   next dispatch after npm shows the version continues. If npm serves this
   version with the inspected archive's SHA-512 integrity and/or SHA-1 shasum,
   the upload is skipped. Read-back also downloads the public tarball and compares
   its bytes. A differing digest, differing downloaded bytes, deprecation, recorded
   unpublication, or an existing `v<version>` Git tag refuses the release. Nothing
   rejects a stage, replaces a version, or changes an npm dist-tag.
6. The keyless `published-package` job depends on upload. It installs the exact
   public version in a fresh consumer, verifies its provenance with `npm audit
   signatures`, checks the version and exports, and removes its temporary directory.
7. The release maintainer reads publication back, compares the registry archive to
   the retained archive, and tags the published commit. The maintainer then creates
   the GitHub release for `v<version>` with every file from `release-assets`:
   `package.tgz`, `SHA256SUMS`, `pack.json`, `CHANGELOG.md`, `registry.json`, and
   `provenance.json` when npm supplies attestations. The artifact is also retained
   after an inspected upload fails or is held. Its expiry makes it unsuitable as
   a consumer download location. Consumers use the versioned GitHub release.

## A dispatch while approval is pending

[npm's staged-publishing contract](https://docs.npmjs.com/cli/v11/commands/npm-stage)
reserves the version across staged and public packages. Its trusted-publisher tokens
can publish or stage, but cannot list, view, or download pending stages. The workflow
therefore cannot establish whether an existing pending stage has identical bytes.
A duplicate staging request fails closed under npm's uniqueness constraint, for both
identical and different pending bytes. It never approves, rejects, or replaces that
stage. Approve the intended existing stage on npmjs.com, then rerun the same commit;
public read-back establishes whether its bytes match. A mismatch needs investigation
and a new version, not a replacement.

## API documentation deployment

`pages.yml` is a separate owner-approved dispatch from the default branch. Both jobs
use environment `github-pages` and the same actor restrictions as publication.
It builds the API reference with the exact Node and npm versions and a frozen install,
then deploys that site. A tag or default-branch push starts neither publication nor
site deployment. No workflow creates a GitHub release or pushes a tag.

See [release verification](../SECURITY.md#verifying-a-release) for consumer commands.
