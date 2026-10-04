import os
import tempfile
import unittest
from pathlib import Path

from tpm_luks.models import (
    AuditPolicy,
    LUKSPolicy,
    PCRState,
    Policy,
    TPMPolicy,
    TPMToken,
    VolumeMetadata,
    VolumePolicy,
)
from tpm_luks.runner import CommandError, CommandResult
from tpm_luks.state import StateStore
from tpm_luks.transaction import EnrollmentError, EnrollmentInterrupted, EnrollmentService


PCR = "a" * 64
OLD_PCR = "b" * 64
UUID_A = "9f36aa12-4b29-4e3d-9b1a-2d4ce85f71a0"
UUID_B = "3a80df27-6c14-49b7-a526-1f9de3b4c802"


class FakePCRReader:
    def __init__(self, value=PCR):
        self.value = value

    def read(self, pcrs, bank):
        return {pcr: self.value for pcr in pcrs}


class FakeLUKSReader:
    def __init__(self, before, after):
        self.before = before
        self.after = after
        self.enrolled = set()

    def read(self, volume):
        return self.after[volume.name] if volume.name in self.enrolled else self.before[volume.name]

    def read_document(self, volume):
        metadata = self.read(volume)
        return {"keyslots": {str(k): {} for k in metadata.keyslots}, "tokens": {}}, metadata


class FakeRunner:
    def __init__(self, luks_reader, fail_volume=None):
        self.luks_reader = luks_reader
        self.fail_volume = fail_volume
        self.calls = []

    def run(self, argv, **kwargs):
        args = tuple(str(x) for x in argv)
        self.calls.append((args, kwargs))
        if args[0] == "cryptsetup" and args[1] == "luksHeaderBackup":
            Path(args[3]).write_bytes(b"header-backup")
        if args[0] == "systemd-cryptenroll":
            volume_name = "A" if UUID_A in args[-1] else "B"
            if self.fail_volume == volume_name:
                raise CommandError(CommandResult(args, 1, "", "simulated failure"))
            self.luks_reader.enrolled.add(volume_name)
        return CommandResult(args, 0, "", "")


def volume(name, uuid, token_id=1, keyslot=2):
    return VolumeMetadata(
        name,
        uuid,
        f"/dev/disk/by-uuid/{uuid}",
        (0, keyslot),
        (TPMToken(token_id, (keyslot,), (7,), "sha256"),),
        (0,),
        (keyslot,),
        (0,),
    )


def after_volume(name, uuid):
    return VolumeMetadata(
        name,
        uuid,
        f"/dev/disk/by-uuid/{uuid}",
        (0, 2, 3),
        (
            TPMToken(1, (2,), (7,), "sha256"),
            TPMToken(2, (3,), (7,), "sha256"),
        ),
        (0,),
        (2, 3),
        (0,),
    )


def summary(metadata):
    return {
        "keyslots": list(metadata.keyslots),
        "recovery_keyslots": list(metadata.recovery_keyslots),
        "tpm_tokens": [
            {
                "token_id": token.token_id,
                "keyslots": list(token.keyslots),
                "bank": token.bank,
                "pcrs": list(token.pcrs),
                "policy_hashes": list(token.policy_hashes),
            }
            for token in metadata.tpm_tokens
        ],
    }


class TransactionTests(unittest.TestCase):
    def _policy(self, *, backup=False, backup_dir=None):
        return Policy(
            "test",
            TPMPolicy("auto", "sha256", (7,)),
            (VolumePolicy("A", UUID_A), VolumePolicy("B", UUID_B)),
            LUKSPolicy(True, True, 1),
            AuditPolicy(
                event_log=False,
                luks_dump=True,
                header_backup=backup,
                header_backup_dir=backup_dir,
            ),
        )

    def _components(self, directory, *, fail_volume=None, policy=None):
        before = {"A": volume("A", UUID_A), "B": volume("B", UUID_B)}
        after = {"A": after_volume("A", UUID_A), "B": after_volume("B", UUID_B)}
        reader = FakeLUKSReader(before, after)
        runner = FakeRunner(reader, fail_volume=fail_volume)
        store = StateStore(directory)
        service = EnrollmentService(
            policy or self._policy(),
            runner,
            FakePCRReader(),
            reader,
            store,
            auto_public_key_paths=(),
        )
        return service, runner, reader, store

    def _approved_target(self, store, reader):
        store.write_operational_state(
            PCRState("test", "sha256", (7,), {7: OLD_PCR}),
            transaction_id="seed",
            established_at="2026-10-03T19:00:00+00:00",
        )
        manifest = {
            "workflow_version": 2,
            "target_source": "desired",
            "type": "PCR_DRIFT",
            "state": "APPROVED_PENDING_ENROLLMENT",
            "policy": {"name": "test", "device": "auto", "bank": "sha256", "pcrs": [7]},
            "old_values": {"7": OLD_PCR},
            "new_values": {"7": PCR},
            "volumes": {
                name: {
                    "uuid": UUID_A if name == "A" else UUID_B,
                    "before": summary(metadata),
                    "header_backup": None,
                    "enrollment_result": None,
                    "new_token": None,
                    "new_keyslot": None,
                }
                for name, metadata in reader.before.items()
            },
        }
        txid = store.create_transaction(manifest)
        store.write_desired_state(
            PCRState("test", "sha256", (7,), {7: PCR}),
            transaction_id=txid,
            approved_at="2026-10-03T20:00:00+00:00",
        )
        return txid

    def test_successful_reenroll_keeps_desired_separate_from_operational(self):
        with tempfile.TemporaryDirectory() as directory:
            service, runner, reader, store = self._components(directory)
            self._approved_target(store, reader)

            plan = service.prepare()
            self.assertEqual(plan.target_source, "desired")
            manifest = service.execute(plan)

            self.assertEqual(manifest["state"], "PENDING_BOOT_TEST")
            stored = store.load_manifest(plan.transaction_id)
            self.assertEqual(stored["volumes"]["A"]["enrollment_result"], "ADDED")
            self.assertEqual(stored["volumes"]["A"]["new_token"], 2)
            self.assertEqual(stored["volumes"]["A"]["new_keyslot"], 3)

            operational, desired = store.load_policy_states()
            self.assertEqual(operational.values[7], OLD_PCR)
            self.assertEqual(desired.values[7], PCR)

            enroll_call = next(call for call in runner.calls if call[0][0] == "systemd-cryptenroll")
            self.assertIn(f"--tpm2-pcrs=7:sha256={PCR}", enroll_call[0])
            self.assertIn("--tpm2-pcrlock=", enroll_call[0])
            self.assertIn("--tpm2-with-pin=no", enroll_call[0])
            self.assertIsNone(enroll_call[1]["timeout"])
            self.assertFalse(enroll_call[1]["capture_output"])

    def test_existing_exact_enrollment_is_idempotent_and_other_volume_progresses(self):
        with tempfile.TemporaryDirectory() as directory:
            service, runner, reader, store = self._components(directory)
            reader.before["A"] = after_volume("A", UUID_A)
            self._approved_target(store, reader)
            original_run = runner.run

            def no_op_a(argv, **kwargs):
                args = tuple(str(x) for x in argv)
                if args[0] == "systemd-cryptenroll" and UUID_A in args[-1]:
                    runner.calls.append((args, kwargs))
                    return CommandResult(args, 0, "", "")
                return original_run(argv, **kwargs)

            runner.run = no_op_a
            plan = service.prepare()
            manifest = service.execute(plan)

            self.assertEqual(manifest["state"], "PENDING_BOOT_TEST")
            stored = store.load_manifest(plan.transaction_id)
            self.assertEqual(stored["volumes"]["A"]["enrollment_result"], "ALREADY_PRESENT")
            self.assertIsNone(stored["volumes"]["A"]["new_token"])
            self.assertEqual(stored["volumes"]["B"]["enrollment_result"], "ADDED")

    def test_enrollment_interrupt_is_durable_and_desired_target_survives(self):
        with tempfile.TemporaryDirectory() as directory:
            service, runner, reader, store = self._components(directory)
            txid = self._approved_target(store, reader)
            plan = service.prepare()
            original_run = runner.run

            def interrupt_enrollment(argv, **kwargs):
                if argv[0] == "systemd-cryptenroll":
                    raise KeyboardInterrupt
                return original_run(argv, **kwargs)

            runner.run = interrupt_enrollment
            with self.assertRaises(EnrollmentInterrupted):
                service.execute(plan)

            manifest = store.load_manifest(txid)
            self.assertEqual(manifest["state"], "FAILED_ENROLLMENT")
            self.assertEqual(manifest["failed_volume"], "A")
            self.assertEqual(store.load_desired_state().values[7], PCR)
            self.assertEqual(store.load_operational_state().values[7], OLD_PCR)
            self.assertEqual(store.find_active_transaction()["id"], txid)

    def test_enrollment_failure_is_resumable_active_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            service, _, reader, store = self._components(directory, fail_volume="B")
            txid = self._approved_target(store, reader)
            plan = service.prepare()

            with self.assertRaises(EnrollmentError):
                service.execute(plan)

            manifest = store.load_manifest(txid)
            self.assertEqual(manifest["state"], "FAILED_ENROLLMENT")
            self.assertEqual(manifest["failed_volume"], "B")
            retry = service.prepare()
            self.assertEqual(retry.transaction_id, txid)
            self.assertEqual(retry.target_source, "desired")

    def test_unapproved_pcr_drift_blocks_reenroll(self):
        with tempfile.TemporaryDirectory() as directory:
            service, _, _, store = self._components(directory)
            store.write_operational_state(
                PCRState("test", "sha256", (7,), {7: OLD_PCR}),
                transaction_id="seed",
                established_at="2026-10-03T19:00:00+00:00",
            )
            with self.assertRaisesRegex(EnrollmentError, "run 'tpm-luks approve'"):
                service.prepare()
            self.assertEqual(store.list_history(), [])

    def test_reenroll_reconciles_operational_target_without_new_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            service, _, _, store = self._components(directory)
            store.write_operational_state(
                PCRState("test", "sha256", (7,), {7: PCR}),
                transaction_id="seed",
                established_at="2026-10-03T19:00:00+00:00",
            )

            plan = service.prepare()
            self.assertEqual(plan.target_source, "operational")
            self.assertEqual(plan.transaction_type, "RECONCILIATION")
            self.assertTrue(plan.transaction_created)
            manifest = service.execute(plan)
            self.assertEqual(manifest["state"], "PENDING_BOOT_TEST")
            self.assertIsNone(store.load_desired_state())
            self.assertEqual(store.load_operational_state().values[7], PCR)

    def test_cancel_existing_approval_leaves_target_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            service, runner, reader, store = self._components(directory)
            txid = self._approved_target(store, reader)

            plan = service.prepare()
            service.cancel(plan)

            self.assertEqual(
                store.load_manifest(txid)["state"],
                "APPROVED_PENDING_ENROLLMENT",
            )
            self.assertEqual(store.load_desired_state().values[7], PCR)
            self.assertFalse(any(call[0][0] == "systemd-cryptenroll" for call in runner.calls))

    def test_cancel_new_reconciliation_marks_transaction_cancelled(self):
        with tempfile.TemporaryDirectory() as directory:
            service, runner, _, store = self._components(directory)
            store.write_operational_state(
                PCRState("test", "sha256", (7,), {7: PCR}),
                transaction_id="seed",
                established_at="2026-10-03T19:00:00+00:00",
            )
            plan = service.prepare()
            service.cancel(plan)
            self.assertEqual(store.load_manifest(plan.transaction_id)["state"], "CANCELLED")
            self.assertFalse(any(call[0][0] == "systemd-cryptenroll" for call in runner.calls))

    def test_recovery_slot_policy_blocks_prepare(self):
        with tempfile.TemporaryDirectory() as directory:
            service, _, reader, store = self._components(directory)
            self._approved_target(store, reader)
            reader.before["A"] = VolumeMetadata(
                "A",
                UUID_A,
                "/dev/a",
                (2,),
                (TPMToken(1, (2,), (7,), "sha256"),),
                (),
                (2,),
                (),
            )
            with self.assertRaisesRegex(EnrollmentError, "requires at least"):
                service.prepare()

    def test_enabled_header_backup_requires_explicit_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = self._policy(backup=True, backup_dir=None)
            service, _, reader, store = self._components(directory, policy=policy)
            self._approved_target(store, reader)
            with self.assertRaisesRegex(EnrollmentError, "header_backup_dir"):
                service.prepare()

    def test_header_backup_failure_keeps_approved_target_resumable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup_dir = root / "backups"
            backup_dir.mkdir()
            policy = self._policy(backup=True, backup_dir=str(backup_dir))
            service, runner, reader, store = self._components(root / "state", policy=policy)
            txid = self._approved_target(store, reader)
            original_run = runner.run

            def fail_backup(argv, **kwargs):
                args = tuple(str(x) for x in argv)
                if args[0:2] == ("cryptsetup", "luksHeaderBackup"):
                    raise CommandError(CommandResult(args, 1, "", "simulated backup failure"))
                return original_run(argv, **kwargs)

            runner.run = fail_backup
            plan = service.prepare()
            with self.assertRaisesRegex(EnrollmentError, "header backup failed"):
                service.execute(plan)

            self.assertEqual(store.load_manifest(txid)["state"], "FAILED_ENROLLMENT")
            self.assertEqual(store.find_active_transaction()["id"], txid)
            self.assertEqual(store.load_desired_state().values[7], PCR)

    def test_header_backups_complete_before_first_enrollment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup_dir = root / "backups"
            backup_dir.mkdir()
            policy = self._policy(backup=True, backup_dir=str(backup_dir))
            service, runner, reader, store = self._components(root / "state", policy=policy)
            self._approved_target(store, reader)

            plan = service.prepare()
            service.execute(plan)

            first_enroll = next(
                i for i, call in enumerate(runner.calls) if call[0][0] == "systemd-cryptenroll"
            )
            backup_calls = [
                i
                for i, call in enumerate(runner.calls)
                if call[0][0:2] == ("cryptsetup", "luksHeaderBackup")
            ]
            self.assertEqual(len(backup_calls), 2)
            self.assertTrue(all(i < first_enroll for i in backup_calls))
            backups = list(backup_dir.glob("*.luks-header"))
            self.assertEqual(len(backups), 2)
            self.assertTrue(all((os.stat(path).st_mode & 0o777) == 0o600 for path in backups))

    def test_automatic_signed_policy_public_key_blocks_prepare(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            auto_key = root / "tpm2-pcr-public-key.pem"
            auto_key.write_text("dummy", encoding="utf-8")
            service, _, reader, store = self._components(root / "state")
            self._approved_target(store, reader)
            service.auto_public_key_paths = (auto_key,)
            with self.assertRaisesRegex(EnrollmentError, "signed-policy public key"):
                service.prepare()


if __name__ == "__main__":
    unittest.main()
