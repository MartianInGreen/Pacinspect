#!/usr/bin/env bash
set -euo pipefail

if (( $# < 1 || $# > 2 )); then
  echo "Usage: $0 X.Y.Z [true|false]" >&2
  exit 1
fi

version="${1#v}"
prerelease="${2:-false}"

if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "Version must be X.Y.Z" >&2
  exit 1
fi
if [[ "$prerelease" != true && "$prerelease" != false ]]; then
  echo "Prerelease must be true or false" >&2
  exit 1
fi
if [[ -n "${DEFAULT_BRANCH:-}" && "${GITHUB_REF:-}" != "refs/heads/$DEFAULT_BRANCH" ]]; then
  echo "Run releases from $DEFAULT_BRANCH, not ${GITHUB_REF:-an unknown branch}" >&2
  exit 1
fi

readonly version prerelease
readonly tag="v$version"
readonly branch="${GITHUB_REF_NAME:-$(git branch --show-current)}"

if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then
  echo "Tag $tag already exists" >&2
  exit 1
fi

sed -i "s/^version = \"[^\"]*\"$/version = \"$version\"/" Cargo.toml
sed -i \
  -e "s/^pkgver=.*/pkgver=$version/" \
  -e 's/^pkgrel=.*/pkgrel=1/' \
  -e "s/^_source_ref=.*/_source_ref=$tag/" \
  -e "s/^sha256sums=.*/sha256sums=('SKIP')/" \
  packaging/aur/PKGBUILD
sed -i -E \
  -e "s/(pacinspect-)[0-9]+\.[0-9]+\.[0-9]+(\.tar\.gz)/\1$version\2/" \
  -e "s|(/archive/)[^/]+(\.tar\.gz)|\1$tag\2|" \
  -e "s/^([[:space:]]*pkgver = ).*/\1$version/" \
  -e 's/^([[:space:]]*pkgrel = ).*/\11/' \
  -e 's/^([[:space:]]*sha256sums = ).*/\1SKIP/' \
  packaging/aur/.SRCINFO

cargo check
cargo fmt --all --check
cargo test --locked --all-targets
cargo build --locked --release
readonly asset="pacinspect-$version-$(rustc -vV | sed -n 's/^host: //p')"
cp target/release/pacinspect "$asset"

git add Cargo.toml Cargo.lock packaging/aur/PKGBUILD packaging/aur/.SRCINFO
if ! git diff --cached --quiet; then
  git \
    -c 'user.name=github-actions[bot]' \
    -c 'user.email=41898282+github-actions[bot]@users.noreply.github.com' \
    -c commit.gpgSign=false \
    commit -m "release: $tag"
fi
git -c tag.gpgSign=false tag -a "$tag" -m "Pacinspect $tag"
git push origin "HEAD:$branch" "refs/tags/$tag"

release_args=("$tag" --title "Pacinspect $tag" --generate-notes)
if [[ "$prerelease" == true ]]; then
  release_args+=(--prerelease)
fi
gh release create "${release_args[@]}" "$asset"

echo "Released Pacinspect $tag"
