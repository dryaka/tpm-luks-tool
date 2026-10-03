import contextlib
import io
import unittest
from unittest.mock import patch

from tpm_luks.cli import _normalize_command_flags, main
from tpm_luks.transaction import EnrollmentInterrupted


class Phase2CLITests(unittest.TestCase):
    def _help(self, argv):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            with self.assertRaises(SystemExit) as exit_context:
                main(argv)
        self.assertEqual(exit_context.exception.code, 0)
        return stream.getvalue()

    def test_reenroll_help_before_command(self):
        text = self._help(["--help", "reenroll"])
        self.assertIn("usage: tpm-luks reenroll", text)
        self.assertIn("--yes", text)
        self.assertIn("--force", text)

    def test_reenroll_flags_can_precede_command(self):
        normalized = _normalize_command_flags(["--yes", "--force", "reenroll"])
        self.assertEqual(normalized, ["reenroll", "--yes", "--force"])

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
