import os
import tempfile
import unittest
from pathlib import Path

from tpm_luks.state import StateStore


class StatePhase2Tests(unittest.TestCase):
    def test_transaction_and_evidence_are_private(self):
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state")
            txid = store.create_transaction({"state": "PREPARING", "type": "TEST"})
            store.write_evidence_bytes(txid, "event.bin", b"abc")
            manifest = store.history_path / txid / "manifest.json"
            evidence = store.history_path / txid / "event.bin"
            self.assertEqual(os.stat(manifest).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(evidence).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(store.history_path / txid).st_mode & 0o777, 0o700)

    def test_active_transaction_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(directory)
            txid = store.create_transaction({"state": "PREPARING", "type": "TEST"})
            self.assertEqual(store.find_active_transaction()["id"], txid)
            store.update_manifest(txid, state="CANCELLED")
            self.assertIsNone(store.find_active_transaction())


if __name__ == "__main__":
    unittest.main()
