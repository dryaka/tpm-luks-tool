import contextlib
import io
import unittest
from unittest.mock import patch

from tpm_luks.cli import build_parser, main
from tpm_luks.state import StateError


class CLIHelpTests(unittest.TestCase):
    def _help(self, command: str) -> str:
        parser = build_parser()
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            with self.assertRaises(SystemExit) as exit_context:
                parser.parse_args([command, "--help"])
        self.assertEqual(exit_context.exception.code, 0)
        return stream.getvalue()

    def _main_help(self, argv: list[str]) -> str:
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            with self.assertRaises(SystemExit) as exit_context:
                main(argv)
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
        self.assertIn("PCR drift from operational baseline", help_text)

    def test_history_help_only_has_relevant_state_option(self):
        help_text = self._help("history")
        self.assertIn("--state-dir PATH", help_text)
        self.assertNotIn("--config PATH", help_text)


    def test_history_reports_state_access_error(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        error = StateError(
            "cannot read history directory /protected/history: [Errno 13] Permission denied"
        )
        with patch("tpm_luks.cli.StateStore.list_history", side_effect=error):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = main(["history", "--state-dir", "/protected"])

        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("Permission denied", stderr.getvalue())
        self.assertNotIn("No transaction history.", stderr.getvalue())

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

    def test_short_help_before_command_targets_command(self):
        help_text = self._main_help(["-h", "show"])
        self.assertIn("usage: tpm-luks show", help_text)
        self.assertIn("Display one transaction manifest", help_text)

    def test_long_help_before_command_targets_command(self):
        help_text = self._main_help(["--help", "history"])
        self.assertIn("usage: tpm-luks history", help_text)
        self.assertIn("List transaction manifests", help_text)

    def test_help_before_command_with_other_global_options(self):
        help_text = self._main_help(
            ["--state-dir", "./state", "--help", "history"]
        )
        self.assertIn("usage: tpm-luks history", help_text)
        self.assertIn("--state-dir PATH", help_text)

    def test_help_after_command_still_targets_command(self):
        help_text = self._main_help(
            ["--state-dir", "./state", "history", "--help"]
        )
        self.assertIn("usage: tpm-luks history", help_text)

    def test_option_value_named_like_command_is_not_misdetected(self):
        help_text = self._main_help(
            ["--config", "show", "--help", "status"]
        )
        self.assertIn("usage: tpm-luks status", help_text)
        self.assertIn("Inspect the configured PCR policy", help_text)

    def test_help_without_command_remains_top_level(self):
        help_text = self._main_help(["--help"])
        self.assertIn("usage: tpm-luks ", help_text)
        self.assertIn("commands:", help_text)
        self.assertNotIn("usage: tpm-luks status", help_text)


if __name__ == "__main__":
    unittest.main()
