"""Release metadata and asset staging must fail closed."""

import contextlib
import hashlib
import io
from pathlib import Path
import runpy
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
RELEASE = runpy.run_path(str(ROOT / 'packaging/release.py'))


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        fixtures = {
            'pyproject.toml': '[project]\nversion = "0.4.0"\n',
            'packaging/rpm/tpm-luks-tool.spec': 'Version: 0.4.0\nRelease: 2%{?dist}\n',
            'packaging/debian/changelog': 'tpm-luks-tool (0.4.0-2) unstable; urgency=medium\n',
        }
        for path, content in fixtures.items():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)

    def validate(self, tag='v0.4.0'):
        with contextlib.redirect_stdout(io.StringIO()):
            RELEASE['validate'](tag, self.root)

    def test_validation_preserves_native_revisions(self):
        before = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.validate()
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_wrong_or_native_revision_tags_rejected(self):
        for tag in ('0.4.0', 'v0.4.1', 'v0.4.0-2', 'v0.4.0-rc1', 'v0.4.0\n'):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                self.validate(tag)

    def test_native_upstream_mismatch_rejected(self):
        for name in ('packaging/rpm/tpm-luks-tool.spec', 'packaging/debian/changelog'):
            path = self.root / name
            original = path.read_text()
            path.write_text(original.replace('0.4.0', '0.5.0'))
            with self.subTest(path=name), self.assertRaises(ValueError):
                self.validate()
            path.write_text(original)

    def make_artifacts(self):
        artifacts = self.root / 'artifacts'
        for target in ('rpm-fedora', 'rpm-rocky9', 'deb-debian12', 'deb-ubuntu2404'):
            directory = artifacts / target
            directory.mkdir(parents=True)
            filename = 'tpm-luks-tool-0.4.0-2.noarch.rpm' if target.startswith('rpm') else 'tpm-luks-tool_0.4.0-2_all.deb'
            (directory / filename).write_bytes(target.encode())
        return artifacts

    def test_distinct_assets_and_checksums(self):
        destination = self.root / 'assets'
        RELEASE['stage'](self.make_artifacts(), destination)
        lines = (destination / 'SHA256SUMS').read_text().splitlines()
        self.assertEqual(len(lines), 4)
        for line in lines:
            digest, filename = line.split('  ')
            self.assertEqual(digest, hashlib.sha256((destination / filename).read_bytes()).hexdigest())
        self.assertEqual(len(list(destination.iterdir())), 5)

    def test_missing_duplicate_and_empty_packages_rejected(self):
        artifacts = self.make_artifacts()
        package = next((artifacts / 'deb-debian12').iterdir())
        for problem in ('duplicate', 'empty', 'missing'):
            with self.subTest(problem=problem):
                extra = package.with_name('tpm-luks-tool_9.9.9-1_all.deb')
                if problem == 'duplicate':
                    extra.write_bytes(b'duplicate')
                elif problem == 'empty':
                    extra.unlink()
                    package.write_bytes(b'')
                else:
                    package.unlink()
                destination = self.root / 'assets'
                with self.assertRaises(ValueError):
                    RELEASE['stage'](artifacts, destination)
                self.assertFalse(destination.exists())
