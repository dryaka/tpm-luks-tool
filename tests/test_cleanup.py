import tempfile
import unittest
from pathlib import Path

from tpm_luks.cleanup import CleanupError, CleanupInterrupted, CleanupService
from tpm_luks.luks import parse_luks_metadata
from tpm_luks.models import (
    ApprovedState,
    AuditPolicy,
    LUKSPolicy,
    Policy,
    TPMPolicy,
    VolumePolicy,
)
from tpm_luks.runner import CommandResult
from tpm_luks.state import StateStore


PCR = "a" * 64
TARGET_HASH = "1" * 64
OLD_HASH = "2" * 64
UUID_A = "9f36aa12-4b29-4e3d-9b1a-2d4ce85f71a0"
UUID_B = "3a80df27-6c14-49b7-a526-1f9de3b4c802"


def token(token_id, keyslot, policy_hash):
    return {
        "type": "systemd-tpm2",
        "keyslots": [str(keyslot)],
        "tpm2-pcrs": [7],
        "tpm2-pcr-bank": "sha256",
        "tpm2-policy-hash": policy_hash,
    }


def document(tokens):
    keyslots = {"0": {"type": "luks2"}}
    raw_tokens = {}
    for token_id, keyslot, policy_hash in tokens:
        keyslots[str(keyslot)] = {"type": "luks2"}
        raw_tokens[str(token_id)] = token(token_id, keyslot, policy_hash)
    return {"keyslots": keyslots, "tokens": raw_tokens}


def summary(volume):
    return {
        "keyslots": list(volume.keyslots),
        "recovery_keyslots": list(volume.recovery_keyslots),
        "tpm_tokens": [
            {
                "token_id": item.token_id,
                "keyslots": list(item.keyslots),
                "bank": item.bank,
                "pcrs": list(item.pcrs),
            }
            for item in volume.tpm_tokens
        ],
    }


class MutableLUKSReader:
    def __init__(self, documents):
        self.documents = documents

    def read_document(self, volume):
        raw = self.documents[volume.name]
        metadata = parse_luks_metadata(volume, str(volume.device_path), raw)
        return raw, metadata

    def read(self, volume):
        return self.read_document(volume)[1]


class FakePCRReader:
    def read(self, pcrs, bank):
        return {pcr: PCR for pcr in pcrs}


class FakeRunner:
    def __init__(self, reader):
        self.reader = reader
        self.calls = []
        self.interrupt_token_remove_once = False

    def run(self, argv, **kwargs):
        args = tuple(str(item) for item in argv)
        self.calls.append((args, kwargs))

        if args[0:2] == ("cryptsetup", "luksHeaderBackup"):
            Path(args[3]).write_bytes(b"header-backup")
            return CommandResult(args, 0, "", "")

        volume_name = None
        for name, raw in self.reader.documents.items():
            uuid = UUID_A if name == "A" else UUID_B
            if uuid in args[-1] or any(uuid in item for item in args):
                volume_name = name
                break

        if args[0:2] == ("cryptsetup", "luksKillSlot"):
            assert volume_name is not None
            keyslot = int(args[-1])
            self.reader.documents[volume_name]["keyslots"].pop(str(keyslot), None)
            return CommandResult(args, 0, "", "")

        if args[0:3] == ("cryptsetup", "token", "remove"):
            if self.interrupt_token_remove_once:
                self.interrupt_token_remove_once = False
                raise KeyboardInterrupt
            assert volume_name is not None
            token_index = args.index("--token-id") + 1
            token_id = int(args[token_index])
            self.reader.documents[volume_name]["tokens"].pop(str(token_id), None)
            return CommandResult(args, 0, "", "")

        return CommandResult(args, 0, "", "")


class CleanupTests(unittest.TestCase):
    def _policy(self, *, header_backup=False, header_backup_dir=None):
        return Policy(
            "test",
            TPMPolicy("auto", "sha256", (7,)),
            (VolumePolicy("A", UUID_A), VolumePolicy("B", UUID_B)),
            LUKSPolicy(True, True, 1),
            AuditPolicy(
                event_log=False,
                luks_dump=True,
                header_backup=header_backup,
                header_backup_dir=header_backup_dir,
            ),
        )

    def _setup_pending(self, root, *, boot_id_at_enroll=None, header_backup=False):
        documents = {
            "A": document(
                [
                    (0, 1, TARGET_HASH),
                    (1, 2, OLD_HASH),
                ]
            ),
            "B": document(
                [
                    (0, 1, TARGET_HASH),
                    (1, 2, OLD_HASH),
                ]
            ),
        }
        reader = MutableLUKSReader(documents)
        runner = FakeRunner(reader)
        backup_dir = Path(root) / "backups"
        if header_backup:
            backup_dir.mkdir()

        policy = self._policy(
            header_backup=header_backup,
            header_backup_dir=str(backup_dir) if header_backup else None,
        )
        store = StateStore(Path(root) / "state")
        store.write_approved_state(
            ApprovedState("test", "sha256", (7,), {7: PCR}),
            transaction_id="seed",
            approved_at="2026-10-03T20:00:00+00:00",
        )

        a_after = reader.read(policy.volumes[0])
        b_after = reader.read(policy.volumes[1])
        b_before_raw = document([(1, 2, OLD_HASH)])
        b_before = parse_luks_metadata(
            policy.volumes[1],
            str(policy.volumes[1].device_path),
            b_before_raw,
        )
        manifest = {
            "type": "INITIAL_ENROLLMENT",
            "state": "PENDING_BOOT_TEST",
            "created_at": "2026-10-03T20:00:00+00:00",
            "enrolled_at": "2026-10-03T20:01:00+00:00",
            "policy": {
                "name": "test",
                "device": "auto",
                "bank": "sha256",
                "pcrs": [7],
            },
            "old_values": {},
            "new_values": {"7": PCR},
            "volumes": {
                "A": {
                    "uuid": UUID_A,
                    "before": summary(a_after),
                    "enrollment_result": "ALREADY_PRESENT",
                    "new_token": None,
                    "new_keyslot": None,
                    "after_enroll": summary(a_after),
                },
                "B": {
                    "uuid": UUID_B,
                    "before": summary(b_before),
                    "enrollment_result": "ADDED",
                    "new_token": 0,
                    "new_keyslot": 1,
                    "after_enroll": summary(b_after),
                },
            },
        }
        if boot_id_at_enroll is not None:
            manifest["boot_id_at_enroll"] = boot_id_at_enroll
        txid = store.create_transaction(manifest)
        return policy, store, reader, runner, txid, backup_dir

    def test_mixed_partial_reenrollment_cleanup_completes(self):
        with tempfile.TemporaryDirectory() as directory:
            policy, store, reader, runner, txid, _ = self._setup_pending(directory)
            service = CleanupService(
                policy,
                runner,
                FakePCRReader(),
                reader,
                store,
                boot_id_path=Path(directory) / "missing-boot-id",
            )

            plan = service.prepare()
            self.assertEqual(plan.transaction_id, txid)
            self.assertEqual(plan.boot_verification, "LEGACY_OPERATOR_ATTESTATION")
            self.assertEqual(
                {(item.volume_name, item.token_id, item.keyslot) for item in plan.targets},
                {("A", 1, 2), ("B", 1, 2)},
            )
            self.assertEqual(plan.target_policy_hashes, (TARGET_HASH,))

            manifest = service.execute(plan)
            self.assertEqual(manifest["state"], "COMPLETE")

            for volume in policy.volumes:
                metadata = reader.read(volume)
                self.assertEqual(metadata.keyslots, (0, 1))
                self.assertEqual(metadata.recovery_keyslots, (0,))
                self.assertEqual(len(metadata.tpm_tokens), 1)
                self.assertEqual(metadata.tpm_tokens[0].token_id, 0)
                self.assertEqual(metadata.tpm_tokens[0].policy_hashes, (TARGET_HASH,))

            kill_calls = [
                call[0] for call in runner.calls if call[0][0:2] == ("cryptsetup", "luksKillSlot")
            ]
            remove_calls = [
                call[0]
                for call in runner.calls
                if call[0][0:3] == ("cryptsetup", "token", "remove")
            ]
            self.assertEqual(len(kill_calls), 2)
            self.assertEqual(len(remove_calls), 2)
            self.assertTrue(all("--batch-mode" in call for call in kill_calls + remove_calls))

    def test_same_boot_is_rejected_before_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            boot_file = Path(directory) / "boot-id"
            boot_file.write_text("same-boot\n", encoding="ascii")
            policy, store, reader, runner, _, _ = self._setup_pending(
                directory,
                boot_id_at_enroll="same-boot",
            )
            service = CleanupService(
                policy,
                runner,
                FakePCRReader(),
                reader,
                store,
                boot_id_path=boot_file,
            )
            with self.assertRaisesRegex(CleanupError, "no reboot detected"):
                service.prepare()
            self.assertEqual(runner.calls, [])

    def test_metadata_drift_is_rejected_before_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            policy, store, reader, runner, _, _ = self._setup_pending(directory)
            reader.documents["A"]["tokens"]["5"] = token(5, 1, TARGET_HASH)
            service = CleanupService(
                policy,
                runner,
                FakePCRReader(),
                reader,
                store,
                boot_id_path=Path(directory) / "missing",
            )
            with self.assertRaisesRegex(CleanupError, "changed since enrollment"):
                service.prepare()
            self.assertEqual(runner.calls, [])

    def test_cleanup_interrupt_is_resumable(self):
        with tempfile.TemporaryDirectory() as directory:
            policy, store, reader, runner, txid, _ = self._setup_pending(directory)
            service = CleanupService(
                policy,
                runner,
                FakePCRReader(),
                reader,
                store,
                boot_id_path=Path(directory) / "missing",
            )
            plan = service.prepare()
            runner.interrupt_token_remove_once = True

            with self.assertRaises(CleanupInterrupted):
                service.execute(plan)

            failed = store.load_manifest(txid)
            self.assertEqual(failed["state"], "FAILED_CLEANUP")
            self.assertEqual(failed["failed_volume"], "A")
            self.assertNotIn("2", reader.documents["A"]["keyslots"])
            self.assertIn("1", reader.documents["A"]["tokens"])

            retry = service.prepare()
            final = service.execute(retry)
            self.assertEqual(final["state"], "COMPLETE")
            self.assertNotIn("1", reader.documents["A"]["tokens"])
            self.assertNotIn("1", reader.documents["B"]["tokens"])

    def test_pre_cleanup_backups_finish_before_first_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            policy, store, reader, runner, _, backup_dir = self._setup_pending(
                directory,
                header_backup=True,
            )
            service = CleanupService(
                policy,
                runner,
                FakePCRReader(),
                reader,
                store,
                boot_id_path=Path(directory) / "missing",
            )
            plan = service.prepare()
            service.execute(plan)

            first_delete = next(
                index
                for index, call in enumerate(runner.calls)
                if call[0][0:2] == ("cryptsetup", "luksKillSlot")
            )
            backup_calls = [
                index
                for index, call in enumerate(runner.calls)
                if call[0][0:2] == ("cryptsetup", "luksHeaderBackup")
            ]
            self.assertEqual(len(backup_calls), 2)
            self.assertTrue(all(index < first_delete for index in backup_calls))
            self.assertEqual(len(list(backup_dir.glob("*-pre-cleanup.luks-header"))), 2)


if __name__ == "__main__":
    unittest.main()
