import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tpm_luks.state import StateError, StateStore


class HistoryTests(unittest.TestCase):
    def test_list_and_show_history(self):
        with tempfile.TemporaryDirectory() as directory:
            tx = Path(directory, "history", "20261003T180000+0200")
            tx.mkdir(parents=True)
            manifest = {"id": "20261003T180000+0200", "type": "PCR_DRIFT", "state": "COMPLETE"}
            (tx / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            store = StateStore(directory)
            self.assertEqual(store.list_history()[0]["type"], "PCR_DRIFT")
            self.assertEqual(store.load_manifest("20261003T180000+0200")["state"], "COMPLETE")

    def test_missing_history_is_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(StateStore(directory).list_history(), [])

    def test_unreadable_history_is_error(self):
        store = StateStore("/protected-state")
        error = PermissionError(13, "Permission denied")
        with patch("tpm_luks.state.os.scandir", side_effect=error):
            with self.assertRaisesRegex(
                StateError,
                "cannot read history directory /protected-state/history",
            ):
                store.list_history()

    def test_reject_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(StateError):
                StateStore(directory).load_manifest("../state")
