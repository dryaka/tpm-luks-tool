import tempfile
import unittest
from pathlib import Path

from tpm_luks.config import PolicyError, load_policy


BASE = """
policy_name = "test"
[tpm]
device = "auto"
bank = "sha256"
pcrs = [7]
[[volume]]
name = "A"
uuid = "9f36aa12-4b29-4e3d-9b1a-2d4ce85f71a0"
[audit]
header_backup = true
{extra}
"""


class Phase2ConfigTests(unittest.TestCase):
    def _load(self, extra=""):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.toml"
            path.write_text(BASE.format(extra=extra), encoding="utf-8")
            return load_policy(path)

    def test_header_backup_dir_is_loaded(self):
        policy = self._load('header_backup_dir = "/mnt/secure/tpm-luks"')
        self.assertEqual(policy.audit.header_backup_dir, "/mnt/secure/tpm-luks")

    def test_header_backup_dir_must_be_absolute(self):
        with self.assertRaisesRegex(PolicyError, "absolute path"):
            self._load('header_backup_dir = "relative/path"')


if __name__ == "__main__":
    unittest.main()
