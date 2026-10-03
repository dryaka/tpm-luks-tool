import tempfile
import unittest
from pathlib import Path

from tpm_luks.pcr import parse_systemd_analyze_pcrs, read_secure_boot


class PCRTests(unittest.TestCase):
    def test_parse_pcr_table(self):
        text = """
NR NAME                SHA256
 7 secure-boot-policy  dc09b8051cf2dfacf2e6c79607d8984286ff60c5949948933c01dc3f94e53c6d
11 kernel-boot         0000000000000000000000000000000000000000000000000000000000000000
"""
        values = parse_systemd_analyze_pcrs(text)
        self.assertEqual(values[7], "dc09b8051cf2dfacf2e6c79607d8984286ff60c5949948933c01dc3f94e53c6d")
        self.assertEqual(values[11], "0" * 64)

    def test_secure_boot_efivar(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "SecureBoot-1234"
            path.write_bytes(bytes([7, 0, 0, 0, 1]))
            self.assertTrue(read_secure_boot(directory))
            path.write_bytes(bytes([7, 0, 0, 0, 0]))
            self.assertFalse(read_secure_boot(directory))
