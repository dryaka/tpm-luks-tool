import tempfile
import unittest
from pathlib import Path

from tpm_luks.config import PolicyError, load_policy


VALID = """
policy_name = "test"
[tpm]
device = "auto"
bank = "sha256"
pcrs = [7, 11]
[[volume]]
name = "A"
uuid = "9f36aa12-4b29-4e3d-9b1a-2d4ce85f71a0"
[luks]
minimum_recovery_slots = 1
"""


class ConfigTests(unittest.TestCase):
    def _load(self, text: str):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.toml"
            path.write_text(text, encoding="utf-8")
            return load_policy(path)

    def test_load_valid_policy(self):
        policy = self._load(VALID)
        self.assertEqual(policy.policy_name, "test")
        self.assertEqual(policy.tpm.pcrs, (7, 11))
        self.assertEqual(policy.tpm.bank, "sha256")
        self.assertEqual(policy.volumes[0].name, "A")

    def test_reject_duplicate_pcr(self):
        with self.assertRaisesRegex(PolicyError, "duplicates"):
            self._load(VALID.replace("[7, 11]", "[7, 7]"))

    def test_reject_unsupported_bank(self):
        with self.assertRaisesRegex(PolicyError, "only tpm.bank"):
            self._load(VALID.replace('bank = "sha256"', 'bank = "sha1"'))

    def test_reject_explicit_tpm_device_in_phase1(self):
        with self.assertRaisesRegex(PolicyError, "only tpm.device"):
            self._load(VALID.replace('device = "auto"', 'device = "/dev/tpmrm0"'))

    def test_normalizes_pcr_order(self):
        policy = self._load(VALID.replace("[7, 11]", "[11, 7]"))
        self.assertEqual(policy.tpm.pcrs, (7, 11))

    def test_reject_unknown_option(self):
        with self.assertRaisesRegex(PolicyError, "unknown tpm option"):
            self._load(VALID.replace('pcrs = [7, 11]', 'pcrs = [7, 11]\nmagic = true'))
