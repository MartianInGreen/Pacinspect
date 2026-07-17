# Releasing Pacinspect

## GitHub release workflow

Run the **Create release** workflow manually from the GitHub Actions page on the default branch. Enter the exact `X.Y.Z` version and choose whether it is a prerelease.

The action installs Rust and runs `release.sh`. The script:

1. updates the Cargo and AUR version fields;
2. runs the formatter check and Rust test suite;
3. commits and tags the release;
4. pushes the commit and tag; and
5. creates the GitHub release with generated notes.

The AUR checksum remains `SKIP` until publication because the tagged source archive does not exist before the tag is pushed.

The repository must permit GitHub Actions to write repository contents. Protected-branch rules must also allow the release bot commit.

## Publishing to the AUR

The GitHub release stages the AUR metadata but deliberately leaves publication to a machine with separate AUR SSH credentials.

After the workflow succeeds, run `./release-to-aur.sh`. The script finds the latest stable GitHub release, calculates the tagged source archive's checksum, regenerates `.SRCINFO`, and commits and pushes both AUR files to `ssh://aur@aur.archlinux.org/pacinspect.git`.

The machine running the script needs `git`, `curl`, `makepkg`, a configured Git commit identity, and SSH access to the `pacinspect` AUR repository.
