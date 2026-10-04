import json
import os
import tempfile
import unittest
from pathlib import Path

from tpm_luks.models import PCRState
from tpm_luks.state import StateStore


PCR = "a" * 64
OLD = "b" * 64


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

    def test_v2_desired_promotes_to_operational(self):
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(directory)
            store.write_operational_state(
                PCRState("test", "sha256", (7,), {7: OLD}),
                transaction_id="old",
                established_at="2026-10-03T19:00:00+00:00",
            )
            store.write_desired_state(
                PCRState("test", "sha256", (7,), {7: PCR}),
                transaction_id="new",
                approved_at="2026-10-03T20:00:00+00:00",
            )

            operational, desired = store.load_policy_states()
            self.assertEqual(operational.values[7], OLD)
            self.assertEqual(desired.values[7], PCR)

            promoted = store.promote_desired_to_operational(
                transaction_id="new",
                established_at="2026-10-03T21:00:00+00:00",
            )
            self.assertEqual(promoted.values[7], PCR)
            operational, desired = store.load_policy_states()
            self.assertEqual(operational.values[7], PCR)
            self.assertIsNone(desired)

    def test_legacy_pending_transaction_is_interpreted_as_desired(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.mkdir(parents=True, exist_ok=True)
            (root / "state.json").write_text(
                json.dumps(
                    {
                        "policy_name": "test",
                        "bank": "sha256",
                        "pcrs": [7],
                        "values": {"7": PCR},
                    }
                ),
                encoding="utf-8",
            )
            store = StateStore(root)
            store.create_transaction(
                {
                    "type": "INITIAL_ENROLLMENT",
                    "state": "PENDING_BOOT_TEST",
                    "policy": {"name": "test", "bank": "sha256", "pcrs": [7]},
                    "old_values": {},
                    "new_values": {"7": PCR},
                }
            )

            operational, desired = store.load_policy_states()
            self.assertIsNone(operational)
            self.assertEqual(desired.values[7], PCR)

    def test_legacy_failed_transactions_do_not_become_active_v2_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(directory)
            store.create_transaction(
                {
                    "state": "FAILED_ENROLLMENT",
                    "type": "INITIAL_ENROLLMENT",
                }
            )
            self.assertIsNone(store.find_active_transaction())


if __name__ == "__main__":
    unittest.main()
