import contextlib
import io
import unittest
from unittest.mock import patch

from tpm_luks.approval import ApprovalInterrupted
from tpm_luks.cleanup import CleanupInterrupted
from tpm_luks.cli import _normalize_command_flags, main
from tpm_luks.transaction import EnrollmentInterrupted


class WorkflowCLITests(unittest.TestCase):
    def _help(self, argv):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            with self.assertRaises(SystemExit) as exit_context:
                main(argv)
        self.assertEqual(exit_context.exception.code, 0)
        return stream.getvalue()

    def test_approve_help_before_command(self):
        text = self._help(["--help", "approve"])
        self.assertIn("usage: tpm-luks approve", text)
        self.assertIn("--yes", text)

    def test_approve_yes_flag_can_precede_command(self):
        normalized = _normalize_command_flags(["--yes", "approve"])
        self.assertEqual(normalized, ["approve", "--yes"])

    def test_reenroll_help_has_no_force_override(self):
        text = self._help(["--help", "reenroll"])
        self.assertIn("usage: tpm-luks reenroll", text)
        self.assertIn("--yes", text)
        self.assertNotIn("--force", text)

    def test_reenroll_yes_flag_can_precede_command(self):
        normalized = _normalize_command_flags(["--yes", "reenroll"])
        self.assertEqual(normalized, ["reenroll", "--yes"])

    def test_cleanup_help_before_command(self):
        text = self._help(["--help", "cleanup"])
        self.assertIn("usage: tpm-luks cleanup", text)
        self.assertIn("--yes", text)

    def test_cleanup_yes_flag_can_precede_command(self):
        normalized = _normalize_command_flags(["--yes", "cleanup"])
        self.assertEqual(normalized, ["cleanup", "--yes"])

    def test_interrupted_approval_returns_130_without_traceback(self):
        stderr = io.StringIO()
        with patch(
            "tpm_luks.cli._run_approve",
            side_effect=ApprovalInterrupted("approval interrupted"),
        ):
            with contextlib.redirect_stderr(stderr):
                rc = main(["approve"])
        self.assertEqual(rc, 130)
        self.assertIn("approval interrupted", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_interrupted_cleanup_returns_130_without_traceback(self):
        stderr = io.StringIO()
        with patch(
            "tpm_luks.cli._run_cleanup",
            side_effect=CleanupInterrupted("cleanup interrupted for A"),
        ):
            with contextlib.redirect_stderr(stderr):
                rc = main(["cleanup"])
        self.assertEqual(rc, 130)
        self.assertIn("cleanup interrupted for A", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_interrupted_reenroll_returns_130_without_traceback(self):
        stderr = io.StringIO()
        with patch(
            "tpm_luks.cli._run_reenroll",
            side_effect=EnrollmentInterrupted("TPM enrollment interrupted for A"),
        ):
            with contextlib.redirect_stderr(stderr):
                rc = main(["reenroll"])
        self.assertEqual(rc, 130)
        self.assertIn("TPM enrollment interrupted for A", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
