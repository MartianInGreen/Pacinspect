import tempfile
import unittest
from pathlib import Path

import release_version


class ReleaseVersionTests(unittest.TestCase):
    def fixture(self) -> Path:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (root / "packaging/aur").mkdir(parents=True)
        (root / "Cargo.toml").write_text(
            '[package]\nname = "pacinspect"\nversion = "1.2.3"\n'
        )
        (root / "packaging/aur/PKGBUILD").write_text(
            "pkgver=1.2.3\n"
            "pkgrel=4\n"
            "_source_ref=v1.2.3\n"
            "sha256sums=('old')\n"
        )
        return root

    def test_prepare_updates_cargo_and_aur_versions(self) -> None:
        root = self.fixture()
        self.assertEqual(release_version.prepare(root, "minor", None), "1.3.0")
        self.assertIn('version = "1.3.0"', (root / "Cargo.toml").read_text())
        pkgbuild = (root / "packaging/aur/PKGBUILD").read_text()
        self.assertIn("pkgver=1.3.0", pkgbuild)
        self.assertIn("pkgrel=1", pkgbuild)
        self.assertIn("_source_ref=v1.3.0", pkgbuild)
        self.assertIn("sha256sums=('SKIP')", pkgbuild)

    def test_finalize_requires_and_writes_sha256(self) -> None:
        root = self.fixture()
        checksum = "a" * 64
        release_version.finalize(root, checksum)
        self.assertIn(
            f"sha256sums=('{checksum}')",
            (root / "packaging/aur/PKGBUILD").read_text(),
        )
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            release_version.finalize(root, "invalid")

    def test_custom_version_must_advance(self) -> None:
        root = self.fixture()
        with self.assertRaisesRegex(ValueError, "must be newer"):
            release_version.prepare(root, "custom", "1.2.3")


if __name__ == "__main__":
    unittest.main()
