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
)


class FormattingTests(unittest.TestCase):
    def test_status_distinguishes_operational_desired_and_current(self):
        current = "a" * 64
        operational = "b" * 64
        desired = current
        policy = Policy(
            "test",
            TPMPolicy("auto", "sha256", (7,)),
            (),
            LUKSPolicy(),
            AuditPolicy(),
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
            volumes=(),
            secure_boot=True,
            pending_transaction_id="tx",
            pending_transaction_state="APPROVED_PENDING_ENROLLMENT",
        )

        output = format_status(snapshot)
        line = next(line for line in output.splitlines() if line.startswith("7"))
        self.assertTrue(line.endswith(current))
        self.assertIn("CHANGED", line)
        self.assertIn("MATCH", line)
        header = next(line for line in output.splitlines() if line.startswith("PCR  "))
        self.assertIn("OPERATIONAL", header)
        self.assertIn("DESIRED", header)
        self.assertTrue(header.endswith("CURRENT"))
        self.assertIn("APPROVED_PENDING_ENROLLMENT", output)


if __name__ == "__main__":
    unittest.main()
