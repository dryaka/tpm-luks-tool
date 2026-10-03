import json
import tempfile
import unittest
from pathlib import Path

from tpm_luks.models import (
    AuditPolicy,
    DriftState,
    LUKSPolicy,
    Policy,
    TPMPolicy,
    VolumeMetadata,
    VolumePolicy,
)
from tpm_luks.service import collect_snapshot
from tpm_luks.state import StateStore


PCR_VALUE = "a" * 64


class FakePCRReader:
    def read(self, pcrs, bank):
        return {7: PCR_VALUE}


class FakeLUKSReader:
    def read(self, volume):
        return VolumeMetadata(volume.name, volume.uuid, str(volume.device_path), (0, 2), (), (0, 2))


class StateTests(unittest.TestCase):
    def _policy(self):
        return Policy(
            "test",
            TPMPolicy("auto", "sha256", (7,)),
            (VolumePolicy("A", "9f36aa12-4b29-4e3d-9b1a-2d4ce85f71a0"),),
            LUKSPolicy(),
            AuditPolicy(),
        )

    def test_uninitialized_state(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot = collect_snapshot(
                self._policy(), FakePCRReader(), FakeLUKSReader(), StateStore(directory)
            )
            self.assertEqual(snapshot.drift_state, DriftState.UNINITIALIZED)

    def test_matching_state(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "state.json").write_text(
                json.dumps(
                    {
                        "policy_name": "test",
                        "bank": "sha256",
                        "pcrs": [7],
                        "values": {"7": PCR_VALUE},
                    }
                ),
                encoding="utf-8",
            )
            snapshot = collect_snapshot(
                self._policy(), FakePCRReader(), FakeLUKSReader(), StateStore(directory)
            )
            self.assertEqual(snapshot.drift_state, DriftState.MATCH)

    def test_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "state.json").write_text(
                json.dumps(
                    {
                        "policy_name": "test",
                        "bank": "sha256",
                        "pcrs": [7],
                        "values": {"7": "b" * 64},
                    }
                ),
                encoding="utf-8",
            )
            snapshot = collect_snapshot(
                self._policy(), FakePCRReader(), FakeLUKSReader(), StateStore(directory)
            )
            self.assertEqual(snapshot.drift_state, DriftState.DRIFT)

    def test_policy_change(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "state.json").write_text(
                json.dumps(
                    {
                        "policy_name": "old-policy",
                        "bank": "sha256",
                        "pcrs": [7],
                        "values": {"7": PCR_VALUE},
                    }
                ),
                encoding="utf-8",
            )
            snapshot = collect_snapshot(
                self._policy(), FakePCRReader(), FakeLUKSReader(), StateStore(directory)
            )
            self.assertEqual(snapshot.drift_state, DriftState.POLICY_CHANGE)
