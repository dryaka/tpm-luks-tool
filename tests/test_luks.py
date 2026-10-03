import unittest

from tpm_luks.luks import parse_luks_metadata
from tpm_luks.models import VolumePolicy


class LUKSTests(unittest.TestCase):
    def test_parse_tpm_token_and_recovery_slots(self):
        volume = VolumePolicy("A", "9f36aa12-4b29-4e3d-9b1a-2d4ce85f71a0")
        metadata = {
            "keyslots": {
                "0": {"type": "luks2"},
                "2": {"type": "luks2"},
                "4": {"type": "luks2"},
            },
            "tokens": {
                "1": {
                    "type": "systemd-tpm2",
                    "keyslots": ["2"],
                    "tpm2-pcrs": [7],
                    "tpm2-pcr-bank": "sha256",
                },
                "3": {"type": "systemd-fido2", "keyslots": ["4"]},
            },
        }
        parsed = parse_luks_metadata(volume, "/dev/example", metadata)
        self.assertEqual(parsed.keyslots, (0, 2, 4))
        self.assertEqual(parsed.non_tpm_keyslots, (0, 4))
        self.assertEqual(parsed.token_bound_keyslots, (2, 4))
        self.assertEqual(parsed.recovery_keyslots, (0,))
        self.assertEqual(parsed.tpm_tokens[0].token_id, 1)


if __name__ == "__main__":
    unittest.main()
