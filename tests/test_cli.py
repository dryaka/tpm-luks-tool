import contextlib
import io
import unittest

from tpm_luks.cli import build_parser


class CLIHelpTests(unittest.TestCase):
    def _help(self, command: str) -> str:
        parser = build_parser()
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            with self.assertRaises(SystemExit) as exit_context:
                parser.parse_args([command, "--help"])
        self.assertEqual(exit_context.exception.code, 0)
        return stream.getvalue()

    def test_status_help_has_description_and_options(self):
        help_text = self._help("status")
        self.assertIn("Inspect the configured PCR policy", help_text)
        self.assertIn("--config PATH", help_text)
        self.assertIn("--state-dir PATH", help_text)
        self.assertIn("Example:", help_text)

    def test_check_help_documents_exit_codes(self):
        help_text = self._help("check")
        self.assertIn("--config PATH", help_text)
        self.assertIn("--state-dir PATH", help_text)
        self.assertIn("Exit codes:", help_text)
        self.assertIn("PCR drift detected", help_text)

    def test_history_help_only_has_relevant_state_option(self):
        help_text = self._help("history")
        self.assertIn("--state-dir PATH", help_text)
        self.assertNotIn("--config PATH", help_text)

    def test_show_help_describes_transaction_id(self):
        help_text = self._help("show")
        self.assertIn("TRANSACTION_ID", help_text)
        self.assertIn("transaction identifier", help_text)
        self.assertIn("--state-dir PATH", help_text)

    def test_options_are_accepted_after_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "status",
                "--config",
                "./policy.toml",
                "--state-dir",
                "./state",
            ]
        )
        self.assertEqual(args.config, "./policy.toml")
        self.assertEqual(args.state_dir, "./state")

    def test_global_options_still_work_before_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "--config",
                "./policy.toml",
                "--state-dir",
                "./state",
                "status",
            ]
        )
        self.assertEqual(args.config, "./policy.toml")
        self.assertEqual(args.state_dir, "./state")


if __name__ == "__main__":
    unittest.main()
