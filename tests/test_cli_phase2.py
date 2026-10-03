import contextlib
import io
import unittest

from tpm_luks.cli import _normalize_command_flags, main


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


if __name__ == "__main__":
    unittest.main()
