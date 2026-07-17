#!/usr/bin/env python3
"""Prepare and finalize a Pacinspect release without external Python packages."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

SEMVER = re.compile(r"^(?:v)?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def parse_version(value: str) -> tuple[int, int, int]:
    match = SEMVER.fullmatch(value.strip())
    if not match:
        raise ValueError(f"invalid semantic version {value!r}; expected X.Y.Z")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def format_version(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def cargo_version(cargo_toml: Path) -> tuple[int, int, int]:
    in_package = False
    for line in cargo_toml.read_text().splitlines():
        if line.startswith("["):
            in_package = line.strip() == "[package]"
        elif in_package and (match := re.fullmatch(r'version\s*=\s*"([^"]+)"', line.strip())):
            return parse_version(match.group(1))
    raise ValueError(f"could not find [package].version in {cargo_toml}")


def replace_line(path: Path, pattern: str, replacement: str) -> None:
    text = path.read_text()
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise ValueError(f"expected exactly one {pattern!r} line in {path}")
    path.write_text(updated)


def next_version(
    current: tuple[int, int, int], bump: str, custom: str | None
) -> tuple[int, int, int]:
    major, minor, patch = current
    if bump == "major":
        candidate = (major + 1, 0, 0)
    elif bump == "minor":
        candidate = (major, minor + 1, 0)
    elif bump == "patch":
        candidate = (major, minor, patch + 1)
    elif bump == "custom":
        if not custom:
            raise ValueError("custom_version is required when bump is custom")
        candidate = parse_version(custom)
    else:
        raise ValueError(f"unsupported bump type {bump!r}")
    if candidate <= current:
        raise ValueError(
            f"new version {format_version(candidate)} must be newer than {format_version(current)}"
        )
    return candidate


def prepare(root: Path, bump: str, custom: str | None) -> str:
    cargo_toml = root / "Cargo.toml"
    pkgbuild = root / "packaging/aur/PKGBUILD"
    current = cargo_version(cargo_toml)
    version = format_version(next_version(current, bump, custom))

    replace_line(cargo_toml, r'^version\s*=\s*"[^"]+"$', f'version = "{version}"')
    replace_line(pkgbuild, r"^pkgver=.*$", f"pkgver={version}")
    replace_line(pkgbuild, r"^pkgrel=.*$", "pkgrel=1")
    replace_line(pkgbuild, r"^_source_ref=.*$", f"_source_ref=v{version}")
    replace_line(pkgbuild, r"^sha256sums=.*$", "sha256sums=('SKIP')")
    return version


def finalize(root: Path, checksum: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise ValueError("checksum must be a lowercase SHA-256 digest")
    replace_line(
        root / "packaging/aur/PKGBUILD",
        r"^sha256sums=.*$",
        f"sha256sums=('{checksum}')",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    commands = parser.add_subparsers(dest="command", required=True)

    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--bump", choices=("major", "minor", "patch", "custom"), required=True)
    prepare_parser.add_argument("--custom-version")

    finalize_parser = commands.add_parser("finalize")
    finalize_parser.add_argument("--checksum", required=True)

    args = parser.parse_args()
    try:
        if args.command == "prepare":
            print(prepare(args.root.resolve(), args.bump, args.custom_version))
        else:
            finalize(args.root.resolve(), args.checksum)
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
