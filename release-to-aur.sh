#!/usr/bin/env bash
set -euo pipefail

readonly GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-MartianInGreen/Pacinspect}"
readonly AUR_REPOSITORY="${AUR_REPOSITORY:-ssh://aur@aur.archlinux.org/pacinspect.git}"

for command in git curl sha256sum makepkg grep sed mktemp rm; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command not found: $command" >&2
    exit 1
  fi
done

if ! latest_url="$(curl --fail --location --show-error --silent \
  --output /dev/null --write-out '%{url_effective}' \
  "https://github.com/$GITHUB_REPOSITORY/releases/latest")"; then
  echo "Could not find the latest GitHub release for $GITHUB_REPOSITORY" >&2
  exit 1
fi
readonly latest_url
tag="${latest_url##*/}"
readonly tag

if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Latest release tag is not a vX.Y.Z version: $tag" >&2
  exit 1
fi

readonly version="${tag#v}"
workdir="$(mktemp -d)"
readonly workdir
readonly aur_dir="$workdir/aur"
readonly archive="$workdir/pacinspect-$version.tar.gz"
trap 'rm -rf "$workdir"' EXIT

curl --fail --location --show-error --silent \
  --output "$archive" \
  "https://github.com/$GITHUB_REPOSITORY/archive/refs/tags/$tag.tar.gz"
read -r checksum _ < <(sha256sum "$archive")

git clone "$AUR_REPOSITORY" "$aur_dir"
curl --fail --location --show-error --silent \
  --output "$aur_dir/PKGBUILD" \
  "https://raw.githubusercontent.com/$GITHUB_REPOSITORY/$tag/packaging/aur/PKGBUILD"

if ! grep -qxF "pkgver=$version" "$aur_dir/PKGBUILD"; then
  echo "The release PKGBUILD does not contain pkgver=$version" >&2
  exit 1
fi
if ! grep -qxF "_source_ref=$tag" "$aur_dir/PKGBUILD"; then
  echo "The release PKGBUILD does not contain _source_ref=$tag" >&2
  exit 1
fi
if ! grep -q '^sha256sums=' "$aur_dir/PKGBUILD"; then
  echo "The release PKGBUILD has no sha256sums entry" >&2
  exit 1
fi

sed -i "s/^sha256sums=.*/sha256sums=('$checksum')/" "$aur_dir/PKGBUILD"
(
  cd "$aur_dir"
  makepkg --printsrcinfo > .SRCINFO
)

git -C "$aur_dir" add PKGBUILD .SRCINFO
if git -C "$aur_dir" diff --cached --quiet; then
  echo "AUR package is already up to date at $tag"
  exit 0
fi

git -C "$aur_dir" commit -m "Update to $tag"
git -C "$aur_dir" push

echo "Released $tag to the AUR"
