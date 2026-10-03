import unittest

from tpm_luks.formatting import format_status
from tpm_luks.models import (
    ApprovedState,
    AuditPolicy,
    DriftState,
    LUKSPolicy,
    PCRComparison,
    Policy,
    SystemSnapshot,
    TPMPolicy,
)


class FormattingTests(unittest.TestCase):
    def test_status_shows_full_current_pcr_as_last_field(self):
        current = "a" * 64
        approved = "b" * 64
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
            approved_state=ApprovedState("test", "sha256", (7,), {7: approved}),
            drift_state=DriftState.DRIFT,
            pcr_comparisons=(PCRComparison(7, approved, current, False),),
            volumes=(),
            secure_boot=True,
        )

        output = format_status(snapshot)
        line = next(line for line in output.splitlines() if line.startswith("7"))
        self.assertTrue(line.endswith(current))
        self.assertIn("CHANGED", line)
        self.assertIn("CURRENT", output.splitlines()[8])


if __name__ == "__main__":
    unittest.main()
