import tempfile
import unittest

from tpm_luks.approval import ApprovalError, ApprovalService
from tpm_luks.models import (
    AuditPolicy,
    LUKSPolicy,
    PCRState,
    Policy,
    TPMPolicy,
    VolumeMetadata,
    VolumePolicy,
)
from tpm_luks.state import StateStore


PCR = "a" * 64
OLD_PCR = "b" * 64
UUID = "9f36aa12-4b29-4e3d-9b1a-2d4ce85f71a0"


class FakePCRReader:
    def __init__(self, value=PCR):
        self.value = value

    def read(self, pcrs, bank):
        return {pcr: self.value for pcr in pcrs}


class FakeLUKSReader:
    def read(self, volume):
        return VolumeMetadata(
            volume.name,
            volume.uuid,
            str(volume.device_path),
            (0,),
            (),
            (0,),
            (),
            (0,),
        )

    def read_document(self, volume):
        metadata = self.read(volume)
        return {"keyslots": {"0": {}}, "tokens": {}}, metadata


class ApprovalTests(unittest.TestCase):
    def _policy(self):
        return Policy(
            "test",
            TPMPolicy("auto", "sha256", (7,)),
            (VolumePolicy("A", UUID),),
            LUKSPolicy(),
            AuditPolicy(
                event_log=False,
                luks_dump=True,
                header_backup=False,
            ),
        )

    def test_approve_records_desired_without_changing_operational(self):
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(directory)
            store.write_operational_state(
                PCRState("test", "sha256", (7,), {7: OLD_PCR}),
                transaction_id="seed",
                established_at="2026-10-03T19:00:00+00:00",
            )
            service = ApprovalService(
                self._policy(),
                FakePCRReader(),
                FakeLUKSReader(),
                store,
            )

            plan = service.prepare()
            self.assertEqual(plan.transaction_type, "PCR_DRIFT")
            manifest = service.execute(plan)

            self.assertEqual(manifest["state"], "APPROVED_PENDING_ENROLLMENT")
            self.assertEqual(manifest["target_source"], "desired")
            self.assertEqual(manifest["workflow_version"], 2)
            operational, desired = store.load_policy_states()
            self.assertEqual(operational.values[7], OLD_PCR)
            self.assertEqual(desired.values[7], PCR)
            self.assertEqual(store.find_active_transaction()["id"], manifest["id"])

    def test_initial_approval_has_no_operational_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(directory)
            service = ApprovalService(
                self._policy(),
                FakePCRReader(),
                FakeLUKSReader(),
                store,
            )

            plan = service.prepare()
            self.assertEqual(plan.transaction_type, "INITIAL_ENROLLMENT")
            service.execute(plan)

            operational, desired = store.load_policy_states()
            self.assertIsNone(operational)
            self.assertEqual(desired.values[7], PCR)

    def test_matching_operational_state_has_nothing_to_approve(self):
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(directory)
            store.write_operational_state(
                PCRState("test", "sha256", (7,), {7: PCR}),
                transaction_id="seed",
                established_at="2026-10-03T19:00:00+00:00",
            )
            service = ApprovalService(
                self._policy(),
                FakePCRReader(),
                FakeLUKSReader(),
                store,
            )

            with self.assertRaisesRegex(ApprovalError, "nothing to approve"):
                service.prepare()
            self.assertEqual(len(store.list_history()), 0)

    def test_active_transaction_blocks_new_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(directory)
            store.create_transaction(
                {
                    "workflow_version": 2,
                    "state": "APPROVED_PENDING_ENROLLMENT",
                    "type": "PCR_DRIFT",
                }
            )
            service = ApprovalService(
                self._policy(),
                FakePCRReader(),
                FakeLUKSReader(),
                store,
            )

            with self.assertRaisesRegex(ApprovalError, "already APPROVED_PENDING_ENROLLMENT"):
                service.prepare()


if __name__ == "__main__":
    unittest.main()
