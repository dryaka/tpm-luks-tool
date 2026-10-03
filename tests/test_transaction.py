import os
import tempfile
import unittest
from pathlib import Path

from tpm_luks.models import (
    AuditPolicy,
    LUKSPolicy,
    Policy,
    TPMPolicy,
    TPMToken,
    VolumeMetadata,
    VolumePolicy,
)
from tpm_luks.runner import CommandError, CommandResult
from tpm_luks.state import StateStore
from tpm_luks.transaction import EnrollmentError, EnrollmentService


PCR = "a" * 64
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


class TransactionTests(unittest.TestCase):
    def _policy(self, backup=False):
        return Policy(
            "test",
            TPMPolicy("auto", "sha256", (7,)),
            (VolumePolicy("A", UUID_A), VolumePolicy("B", UUID_B)),
            LUKSPolicy(True, True, 1),
            AuditPolicy(event_log=False, luks_dump=True, header_backup=backup, header_backup_dir=None),
        )

    def _service(self, directory, fail_volume=None):
        before = {"A": volume("A", UUID_A), "B": volume("B", UUID_B)}
        after = {"A": after_volume("A", UUID_A), "B": after_volume("B", UUID_B)}
        reader = FakeLUKSReader(before, after)
        runner = FakeRunner(reader, fail_volume=fail_volume)
        service = EnrollmentService(
            self._policy(),
            runner,
            FakePCRReader(),
            reader,
            StateStore(directory),
            auto_public_key_paths=(),
        )
        return service, runner

    def test_successful_reenroll_writes_pending_transaction_and_approved_state(self):
        with tempfile.TemporaryDirectory() as directory:
            service, runner = self._service(directory)
            plan = service.prepare()
            manifest = service.execute(plan)
            self.assertEqual(manifest["state"], "PENDING_BOOT_TEST")
            stored = StateStore(directory).load_manifest(plan.transaction_id)
            self.assertEqual(stored["volumes"]["A"]["new_token"], 2)
            self.assertEqual(stored["volumes"]["A"]["new_keyslot"], 3)
            approved = StateStore(directory).load_approved_state()
            self.assertEqual(approved.values[7], PCR)
            enroll_call = next(call for call in runner.calls if call[0][0] == "systemd-cryptenroll")
            self.assertIn(f"--tpm2-pcrs=7:sha256={PCR}", enroll_call[0])
            self.assertIn("--tpm2-pcrlock=", enroll_call[0])
            self.assertIn("--tpm2-with-pin=no", enroll_call[0])
            self.assertIsNone(enroll_call[1]["timeout"])
            self.assertFalse(enroll_call[1]["capture_output"])

    def test_enrollment_failure_is_durable_and_does_not_update_approved_state(self):
        with tempfile.TemporaryDirectory() as directory:
            service, _ = self._service(directory, fail_volume="B")
            plan = service.prepare()
            with self.assertRaises(EnrollmentError):
                service.execute(plan)
            manifest = StateStore(directory).load_manifest(plan.transaction_id)
            self.assertEqual(manifest["state"], "FAILED_ENROLLMENT")
            self.assertEqual(manifest["failed_volume"], "B")
            self.assertIsNone(StateStore(directory).load_approved_state())

    def test_recovery_slot_policy_blocks_prepare(self):
        with tempfile.TemporaryDirectory() as directory:
            service, _ = self._service(directory)
            bad = VolumeMetadata(
                "A",
                UUID_A,
                "/dev/a",
                (2,),
                (TPMToken(1, (2,), (7,), "sha256"),),
                (),
                (2,),
                (),
            )
            service.luks_reader.before["A"] = bad
            with self.assertRaisesRegex(EnrollmentError, "requires at least"):
                service.prepare()
            self.assertEqual(StateStore(directory).list_history(), [])

    def test_enabled_header_backup_requires_explicit_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            before = {"A": volume("A", UUID_A), "B": volume("B", UUID_B)}
            after = {"A": after_volume("A", UUID_A), "B": after_volume("B", UUID_B)}
            reader = FakeLUKSReader(before, after)
            runner = FakeRunner(reader)
            service = EnrollmentService(
                self._policy(backup=True),
                runner,
                FakePCRReader(),
                reader,
                StateStore(directory),
                auto_public_key_paths=(),
            )
            with self.assertRaisesRegex(EnrollmentError, "header_backup_dir"):
                service.prepare()

    def test_cancel_marks_transaction_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            service, runner = self._service(directory)
            plan = service.prepare()
            service.cancel(plan)
            manifest = StateStore(directory).load_manifest(plan.transaction_id)
            self.assertEqual(manifest["state"], "CANCELLED")
            self.assertFalse(any(call[0][0] == "systemd-cryptenroll" for call in runner.calls))

    def test_active_transaction_blocks_new_prepare(self):
        with tempfile.TemporaryDirectory() as directory:
            service, _ = self._service(directory)
            service.prepare()
            with self.assertRaisesRegex(EnrollmentError, "already PREPARING"):
                service.prepare()

    def test_header_backups_complete_before_first_enrollment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup_dir = root / "backups"
            backup_dir.mkdir()
            state_dir = root / "state"
            before = {"A": volume("A", UUID_A), "B": volume("B", UUID_B)}
            after = {"A": after_volume("A", UUID_A), "B": after_volume("B", UUID_B)}
            reader = FakeLUKSReader(before, after)
            runner = FakeRunner(reader)
            policy = Policy(
                "test",
                TPMPolicy("auto", "sha256", (7,)),
                (VolumePolicy("A", UUID_A), VolumePolicy("B", UUID_B)),
                LUKSPolicy(True, True, 1),
                AuditPolicy(
                    event_log=False,
                    luks_dump=True,
                    header_backup=True,
                    header_backup_dir=str(backup_dir),
                ),
            )
            service = EnrollmentService(
                policy,
                runner,
                FakePCRReader(),
                reader,
                StateStore(state_dir),
                auto_public_key_paths=(),
            )
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
            service, _ = self._service(root / "state")
            service.auto_public_key_paths = (auto_key,)
            with self.assertRaisesRegex(EnrollmentError, "signed-policy public key"):
                service.prepare()


if __name__ == "__main__":
    unittest.main()
