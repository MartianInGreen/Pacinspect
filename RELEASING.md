# Releasing Pacinspect

## GitHub release workflow

Run the **Create release** workflow manually from the GitHub Actions page on the default branch.

Select `patch`, `minor`, or `major` to calculate the next semantic version automatically. Select `custom` and provide an exact `X.Y.Z` version when a nonstandard increment is required. The release can optionally be marked as a prerelease.

The workflow:

1. updates `Cargo.toml`, `Cargo.lock`, `packaging/aur/PKGBUILD`, and `packaging/aur/.SRCINFO`;
2. runs the release helper tests, Rust formatter check, and complete Rust test suite;
3. commits and tags the release as `vX.Y.Z`;
4. downloads GitHub's tagged source archive and calculates its SHA-256;
5. commits the finalized AUR checksum and metadata; and
6. creates the GitHub release with generated notes.

The repository must permit GitHub Actions to write repository contents. Protected-branch rules must also allow the release bot commits.

## Publishing to the AUR

The GitHub workflow updates the AUR files in this repository but deliberately does not push to the external AUR Git server, which requires separate AUR SSH credentials.

After the workflow succeeds, copy `packaging/aur/PKGBUILD` and `packaging/aur/.SRCINFO` into the `pacinspect` AUR Git repository, commit them together, and push the commit to the AUR remote.
