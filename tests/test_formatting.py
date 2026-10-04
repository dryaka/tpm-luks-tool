import unittest

from tpm_luks.formatting import format_status
from tpm_luks.models import (
    AuditPolicy,
    DriftState,
    LUKSPolicy,
    PCRComparison,
    PCRState,
    Policy,
    SystemSnapshot,
    TPMPolicy,
    TPMToken,
    VolumeMetadata,
)


class FormattingTests(unittest.TestCase):
    def test_status_shows_full_pcr_and_policy_digests_multiline(self):
        current = "a" * 64
        operational = "b" * 64
        desired = current
        policy_hash = "c" * 64
        policy = Policy(
            "test",
            TPMPolicy("auto", "sha256", (7,)),
            (),
            LUKSPolicy(),
            AuditPolicy(),
        )
        volume = VolumeMetadata(
            name="A",
            uuid="9f36aa12-4b29-4e3d-9b1a-2d4ce85f71a0",
            device="/dev/disk/by-uuid/9f36aa12-4b29-4e3d-9b1a-2d4ce85f71a0",
            keyslots=(0, 1),
            tpm_tokens=(
                TPMToken(
                    token_id=0,
                    keyslots=(1,),
                    pcrs=(7,),
                    bank="sha256",
                    policy_hashes=(policy_hash,),
                ),
            ),
            non_tpm_keyslots=(0,),
            token_bound_keyslots=(1,),
            recovery_keyslots=(0,),
        )
        snapshot = SystemSnapshot(
            policy=policy,
            current_pcrs={7: current},
            operational_state=PCRState("test", "sha256", (7,), {7: operational}),
            desired_state=PCRState("test", "sha256", (7,), {7: desired}),
            drift_state=DriftState.DRIFT,
            pcr_comparisons=(
                PCRComparison(
                    pcr=7,
                    operational=operational,
                    desired=desired,
                    current=current,
                    matches_operational=False,
                    matches_desired=True,
                ),
            ),
            volumes=(volume,),
            secure_boot=True,
            pending_transaction_id="tx",
            pending_transaction_state="APPROVED_PENDING_ENROLLMENT",
        )

        output = format_status(snapshot)

        self.assertIn("PCR state:\n  PCR 7:", output)
        self.assertIn(f"    Operational:       {operational}", output)
        self.assertIn(f"    Desired:           {desired}", output)
        self.assertIn(f"    Current:           {current}", output)
        self.assertIn("    Operational match: CHANGED", output)
        self.assertIn("    Desired match:     MATCH", output)
        self.assertIn("    token 0: keyslot=1 bank=sha256 pcrs=7", output)
        self.assertIn(f"      policy hash: {policy_hash}", output)
        self.assertNotIn("...", output)
        self.assertIn("APPROVED_PENDING_ENROLLMENT", output)


if __name__ == "__main__":
    unittest.main()
