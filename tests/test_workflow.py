import tempfile
import unittest
from pathlib import Path

from tpm_luks.approval import ApprovalService
from tpm_luks.cleanup import CleanupService
from tpm_luks.luks import parse_luks_metadata
from tpm_luks.models import (
    AuditPolicy,
    LUKSPolicy,
    PCRState,
    Policy,
    TPMPolicy,
    VolumePolicy,
)
from tpm_luks.runner import CommandResult
from tpm_luks.state import StateStore
from tpm_luks.transaction import EnrollmentService


OLD_PCR = "a" * 64
NEW_PCR = "b" * 64
OLD_HASH = "1" * 64
TARGET_HASH = "2" * 64
UUID_A = "9f36aa12-4b29-4e3d-9b1a-2d4ce85f71a0"
UUID_B = "3a80df27-6c14-49b7-a526-1f9de3b4c802"


def tpm_token(keyslot, policy_hash):
    return {
        "type": "systemd-tpm2",
        "keyslots": [str(keyslot)],
        "tpm2-pcrs": [7],
        "tpm2-pcr-bank": "sha256",
        "tpm2-policy-hash": policy_hash,
    }


def initial_document():
    return {
        "keyslots": {
            "0": {"type": "luks2"},
            "2": {"type": "luks2"},
        },
        "tokens": {
            "1": tpm_token(2, OLD_HASH),
        },
    }


class FakePCRReader:
    def read(self, pcrs, bank):
        return {pcr: NEW_PCR for pcr in pcrs}


class MutableLUKSReader:
    def __init__(self):
        self.documents = {
            "A": initial_document(),
            "B": initial_document(),
        }

    def read_document(self, volume):
        raw = self.documents[volume.name]
        return raw, parse_luks_metadata(volume, str(volume.device_path), raw)

    def read(self, volume):
        return self.read_document(volume)[1]


class WorkflowRunner:
    def __init__(self, reader):
        self.reader = reader
        self.calls = []

    def run(self, argv, **kwargs):
        args = tuple(str(item) for item in argv)
        self.calls.append((args, kwargs))

        volume_name = None
        if any(UUID_A in item for item in args):
            volume_name = "A"
        elif any(UUID_B in item for item in args):
            volume_name = "B"

        if args[0] == "systemd-cryptenroll":
            assert volume_name is not None
            doc = self.reader.documents[volume_name]
            if not any(
                token.get("tpm2-policy-hash") == TARGET_HASH
                for token in doc["tokens"].values()
            ):
                doc["keyslots"]["1"] = {"type": "luks2"}
                doc["tokens"]["0"] = tpm_token(1, TARGET_HASH)
            return CommandResult(args, 0, "", "")

        if args[0:2] == ("cryptsetup", "luksKillSlot"):
            assert volume_name is not None
            keyslot = args[-1]
            self.reader.documents[volume_name]["keyslots"].pop(keyslot, None)
            return CommandResult(args, 0, "", "")

        if args[0:3] == ("cryptsetup", "token", "remove"):
            assert volume_name is not None
            token_id = args[args.index("--token-id") + 1]
            self.reader.documents[volume_name]["tokens"].pop(token_id, None)
            return CommandResult(args, 0, "", "")

        return CommandResult(args, 0, "", "")


class WorkflowTests(unittest.TestCase):
    def test_approve_reenroll_cleanup_promotes_desired_to_operational(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Policy(
                "test",
                TPMPolicy("auto", "sha256", (7,)),
                (VolumePolicy("A", UUID_A), VolumePolicy("B", UUID_B)),
                LUKSPolicy(True, True, 1),
                AuditPolicy(
                    event_log=False,
                    luks_dump=True,
                    header_backup=False,
                ),
            )
            store = StateStore(Path(directory) / "state")
            store.write_operational_state(
                PCRState("test", "sha256", (7,), {7: OLD_PCR}),
                transaction_id="seed",
                established_at="2026-10-03T19:00:00+00:00",
            )
            reader = MutableLUKSReader()
            pcr_reader = FakePCRReader()
            runner = WorkflowRunner(reader)

            approval = ApprovalService(policy, pcr_reader, reader, store)
            approval_plan = approval.prepare()
            approved = approval.execute(approval_plan)
            self.assertEqual(approved["state"], "APPROVED_PENDING_ENROLLMENT")
            operational, desired = store.load_policy_states()
            self.assertEqual(operational.values[7], OLD_PCR)
            self.assertEqual(desired.values[7], NEW_PCR)

            enrollment = EnrollmentService(
                policy,
                runner,
                pcr_reader,
                reader,
                store,
                auto_public_key_paths=(),
            )
            enrollment_plan = enrollment.prepare()
            enrolled = enrollment.execute(enrollment_plan)
            self.assertEqual(enrolled["state"], "PENDING_BOOT_TEST")
            operational, desired = store.load_policy_states()
            self.assertEqual(operational.values[7], OLD_PCR)
            self.assertEqual(desired.values[7], NEW_PCR)

            cleanup = CleanupService(
                policy,
                runner,
                pcr_reader,
                reader,
                store,
                boot_id_path=Path(directory) / "unavailable-boot-id",
            )
            cleanup_plan = cleanup.prepare()
            self.assertEqual(cleanup_plan.target_source, "desired")
            self.assertEqual(
                {(target.volume_name, target.token_id, target.keyslot)
                 for target in cleanup_plan.targets},
                {("A", 1, 2), ("B", 1, 2)},
            )
            completed = cleanup.execute(cleanup_plan)
            self.assertEqual(completed["state"], "COMPLETE")

            operational, desired = store.load_policy_states()
            self.assertEqual(operational.values[7], NEW_PCR)
            self.assertIsNone(desired)
            self.assertIsNone(store.find_active_transaction())

            for volume in policy.volumes:
                metadata = reader.read(volume)
                self.assertEqual(metadata.recovery_keyslots, (0,))
                self.assertEqual(metadata.keyslots, (0, 1))
                self.assertEqual(len(metadata.tpm_tokens), 1)
                self.assertEqual(metadata.tpm_tokens[0].policy_hashes, (TARGET_HASH,))


if __name__ == "__main__":
    unittest.main()
