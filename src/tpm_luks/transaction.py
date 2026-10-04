from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .luks import LUKSMetadataReader
from .models import PCRState, Policy, SystemSnapshot, TPMToken, VolumeMetadata, VolumePolicy
from .pcr import PCRReader
from .runner import CommandError, Runner
from .service import collect_snapshot, state_matches_policy
from .state import StateError, StateStore


class EnrollmentError(RuntimeError):
    pass


class EnrollmentInterrupted(EnrollmentError):
    pass


@dataclass(frozen=True)
class EnrollmentPlan:
    transaction_id: str
    transaction_type: str
    snapshot: SystemSnapshot
    header_backup_dir: str | None
    target_pcrs: dict[int, str]
    target_source: str
    previous_state: str
    transaction_created: bool


_AUTO_PUBLIC_KEY_PATHS = (
    Path("/etc/systemd/tpm2-pcr-public-key.pem"),
    Path("/run/systemd/tpm2-pcr-public-key.pem"),
    Path("/usr/lib/systemd/tpm2-pcr-public-key.pem"),
)
_DEFAULT_EVENT_LOG = Path("/sys/kernel/security/tpm0/binary_bios_measurements")
_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_boot_id(path: Path = _BOOT_ID_PATH) -> str | None:
    try:
        value = path.read_text(encoding="ascii").strip()
    except OSError:
        return None
    return value or None


def _token_summary(token: TPMToken) -> dict[str, Any]:
    return {
        "token_id": token.token_id,
        "keyslots": list(token.keyslots),
        "bank": token.bank,
        "pcrs": list(token.pcrs),
        "policy_hashes": list(token.policy_hashes),
    }


def _volume_summary(volume: VolumeMetadata) -> dict[str, Any]:
    return {
        "keyslots": list(volume.keyslots),
        "recovery_keyslots": list(volume.recovery_keyslots),
        "tpm_tokens": [_token_summary(token) for token in volume.tpm_tokens],
    }


class EnrollmentService:
    def __init__(
        self,
        policy: Policy,
        runner: Runner,
        pcr_reader: PCRReader,
        luks_reader: LUKSMetadataReader,
        state_store: StateStore,
        *,
        event_log_path: Path = _DEFAULT_EVENT_LOG,
        auto_public_key_paths: tuple[Path, ...] = _AUTO_PUBLIC_KEY_PATHS,
    ):
        self.policy = policy
        self.runner = runner
        self.pcr_reader = pcr_reader
        self.luks_reader = luks_reader
        self.state_store = state_store
        self.event_log_path = event_log_path
        self.auto_public_key_paths = auto_public_key_paths

    def prepare(self) -> EnrollmentPlan:
        snapshot = collect_snapshot(
            self.policy,
            self.pcr_reader,
            self.luks_reader,
            self.state_store,
        )
        active = self.state_store.find_active_transaction()
        transaction_created = False

        if active is not None:
            state = str(active.get("state"))
            if active.get("workflow_version") != 2 or state not in {
                "APPROVED_PENDING_ENROLLMENT",
                "ENROLLING",
                "FAILED_ENROLLMENT",
                "FAILED_VERIFICATION",
            }:
                raise EnrollmentError(
                    f"transaction {active.get('id')} is already {state}; "
                    "finish or repair it before starting enrollment"
                )
            target_source = str(active.get("target_source", "desired"))
            target = (
                snapshot.desired_state
                if target_source == "desired"
                else snapshot.operational_state
            )
            if target is None:
                raise EnrollmentError(
                    f"transaction {active.get('id')} has no {target_source} PCR target"
                )
            transaction_id = str(active.get("id"))
            transaction_type = str(active.get("type", "RECONCILIATION"))
            previous_state = state
            self._validate_transaction_context(active)
        else:
            if snapshot.desired_state is not None:
                raise EnrollmentError(
                    "a desired PCR target exists without an active transaction; manual repair is required"
                )
            target = snapshot.operational_state
            if target is None:
                raise EnrollmentError(
                    "no operational PCR target exists; approve the current PCR state first"
                )
            if not state_matches_policy(target, self.policy):
                raise EnrollmentError(
                    "configured PCR policy differs from the operational baseline; "
                    "approve the current policy before enrollment"
                )
            if snapshot.current_pcrs != target.values:
                raise EnrollmentError(
                    "current PCR values differ from the operational baseline and are not approved; "
                    "run 'tpm-luks approve' first"
                )
            transaction_id = self._create_reconciliation_transaction(snapshot, target)
            transaction_type = "RECONCILIATION"
            target_source = "operational"
            previous_state = "APPROVED_PENDING_ENROLLMENT"
            transaction_created = True

        if not state_matches_policy(target, self.policy):
            raise EnrollmentError(
                f"{target_source} PCR target does not match the configured policy"
            )
        if snapshot.current_pcrs != target.values:
            raise EnrollmentError(
                f"current PCR values no longer match the {target_source} target; "
                "do not enroll an unapproved state"
            )

        self._validate_recovery_access(snapshot)
        backup_dir = self._validate_header_backup_configuration()
        self._validate_automatic_policy_inputs()

        return EnrollmentPlan(
            transaction_id=transaction_id,
            transaction_type=transaction_type,
            snapshot=snapshot,
            header_backup_dir=str(backup_dir) if backup_dir else None,
            target_pcrs=dict(target.values),
            target_source=target_source,
            previous_state=previous_state,
            transaction_created=transaction_created,
        )

    def _create_reconciliation_transaction(
        self,
        snapshot: SystemSnapshot,
        target: PCRState,
    ) -> str:
        manifest = {
            "workflow_version": 2,
            "target_source": "operational",
            "type": "RECONCILIATION",
            "state": "APPROVED_PENDING_ENROLLMENT",
            "created_at": _now(),
            "approved_at": None,
            "policy": {
                "name": self.policy.policy_name,
                "device": self.policy.tpm.device,
                "bank": self.policy.tpm.bank,
                "pcrs": list(self.policy.tpm.pcrs),
            },
            "old_values": {str(pcr): value for pcr, value in target.values.items()},
            "new_values": {str(pcr): value for pcr, value in target.values.items()},
            "secure_boot": snapshot.secure_boot,
            "volumes": {
                volume.name: {
                    "uuid": volume.uuid,
                    "before": _volume_summary(volume),
                    "header_backup": None,
                    "enrollment_result": None,
                    "new_token": None,
                    "new_keyslot": None,
                }
                for volume in snapshot.volumes
            },
        }
        transaction_id = self.state_store.create_transaction(manifest)
        try:
            self.state_store.write_evidence_json(
                transaction_id,
                "pcrs-before.json",
                {str(pcr): value for pcr, value in snapshot.current_pcrs.items()},
            )
            if self.policy.audit.luks_dump:
                for volume in self.policy.volumes:
                    document, _ = self.luks_reader.read_document(volume)
                    self.state_store.write_evidence_json(
                        transaction_id,
                        f"volume-{volume.uuid}-before.json",
                        document,
                    )
            if self.policy.audit.event_log:
                self._capture_event_log(transaction_id)
        except KeyboardInterrupt as exc:
            interruption = EnrollmentInterrupted(
                "interrupted during reconciliation evidence capture"
            )
            self._mark_failure(transaction_id, "FAILED_PRECHECK", interruption)
            raise interruption from exc
        except Exception as exc:
            self._mark_failure(transaction_id, "FAILED_PRECHECK", exc)
            raise EnrollmentError(
                f"reconciliation evidence capture failed: {exc}"
            ) from exc
        return transaction_id

    def _validate_transaction_context(self, manifest: dict[str, Any]) -> None:
        raw_policy = manifest.get("policy")
        if not isinstance(raw_policy, dict):
            raise EnrollmentError("active transaction lacks policy metadata")
        if (
            raw_policy.get("name") != self.policy.policy_name
            or raw_policy.get("bank") != self.policy.tpm.bank
            or tuple(sorted(raw_policy.get("pcrs", []))) != self.policy.tpm.pcrs
        ):
            raise EnrollmentError("active transaction policy differs from current configuration")
        raw_volumes = manifest.get("volumes")
        if not isinstance(raw_volumes, dict):
            raise EnrollmentError("active transaction lacks volume metadata")
        for volume in self.policy.volumes:
            entry = raw_volumes.get(volume.name)
            if not isinstance(entry, dict) or entry.get("uuid") != volume.uuid:
                raise EnrollmentError(
                    f"active transaction volume {volume.name} differs from current configuration"
                )
        if set(raw_volumes) != {volume.name for volume in self.policy.volumes}:
            raise EnrollmentError("active transaction volume set differs from current configuration")

    def cancel(self, plan: EnrollmentPlan) -> None:
        if plan.transaction_created:
            self.state_store.update_manifest(
                plan.transaction_id,
                state="CANCELLED",
                cancelled_at=_now(),
            )

    def execute(self, plan: EnrollmentPlan) -> dict[str, Any]:
        manifest = self.state_store.load_manifest(plan.transaction_id)
        if manifest.get("state") not in {
            "APPROVED_PENDING_ENROLLMENT",
            "ENROLLING",
            "FAILED_ENROLLMENT",
            "FAILED_VERIFICATION",
        }:
            raise EnrollmentError(
                f"transaction {plan.transaction_id} is {manifest.get('state')}, "
                "expected an enrollment-pending state"
            )
        manifest = self.state_store.update_manifest(
            plan.transaction_id,
            state="ENROLLING",
            enrollment_started_at=_now(),
        )

        if self.policy.audit.header_backup:
            try:
                manifest = self._backup_headers(plan, manifest)
            except KeyboardInterrupt as exc:
                interruption = EnrollmentInterrupted("interrupted during LUKS header backup")
                self._mark_failure(
                    plan.transaction_id,
                    "FAILED_ENROLLMENT",
                    interruption,
                )
                raise interruption from exc
            except Exception as exc:
                self._mark_failure(
                    plan.transaction_id,
                    "FAILED_ENROLLMENT",
                    exc,
                )
                raise EnrollmentError(
                    f"LUKS header backup failed before enrollment: {exc}"
                ) from exc

        before_by_name = {volume.name: volume for volume in plan.snapshot.volumes}
        for volume_policy in self.policy.volumes:
            before = before_by_name[volume_policy.name]
            try:
                self.runner.run(
                    self._enrollment_command(volume_policy, plan.target_pcrs),
                    timeout=None,
                    capture_output=False,
                )
            except KeyboardInterrupt as exc:
                interruption = EnrollmentInterrupted(
                    f"TPM enrollment interrupted for {volume_policy.name}"
                )
                self._mark_failure(
                    plan.transaction_id,
                    "FAILED_ENROLLMENT",
                    interruption,
                    failed_volume=volume_policy.name,
                )
                raise interruption from exc
            except (CommandError, OSError) as exc:
                self._mark_failure(
                    plan.transaction_id,
                    "FAILED_ENROLLMENT",
                    exc,
                    failed_volume=volume_policy.name,
                )
                raise EnrollmentError(f"TPM enrollment failed for {volume_policy.name}: {exc}") from exc

            try:
                document, after = self.luks_reader.read_document(volume_policy)
                enrollment_result, new_token, new_keyslot = self._verify_enrollment(before, after)
                if self.policy.audit.luks_dump:
                    self.state_store.write_evidence_json(
                        plan.transaction_id,
                        f"volume-{volume_policy.uuid}-after-enroll.json",
                        document,
                    )
                manifest = self.state_store.load_manifest(plan.transaction_id)
                volume_entry = manifest["volumes"][volume_policy.name]
                volume_entry["enrollment_result"] = enrollment_result
                volume_entry["new_token"] = new_token.token_id if new_token else None
                volume_entry["new_keyslot"] = new_keyslot
                volume_entry["after_enroll"] = _volume_summary(after)
                self.state_store.write_manifest(plan.transaction_id, manifest)
            except KeyboardInterrupt as exc:
                interruption = EnrollmentInterrupted(
                    f"post-enrollment verification interrupted for {volume_policy.name}"
                )
                self._mark_failure(
                    plan.transaction_id,
                    "FAILED_VERIFICATION",
                    interruption,
                    failed_volume=volume_policy.name,
                )
                raise interruption from exc
            except Exception as exc:
                self._mark_failure(
                    plan.transaction_id,
                    "FAILED_VERIFICATION",
                    exc,
                    failed_volume=volume_policy.name,
                )
                raise EnrollmentError(f"post-enrollment verification failed for {volume_policy.name}: {exc}") from exc

        try:
            after_pcrs = self.pcr_reader.read(self.policy.tpm.pcrs, self.policy.tpm.bank)
            if after_pcrs != plan.target_pcrs:
                raise EnrollmentError("PCR values changed away from the approved enrollment target")
            self.state_store.write_evidence_json(
                plan.transaction_id,
                "pcrs-after.json",
                {str(pcr): value for pcr, value in after_pcrs.items()},
            )
            enrolled_at = _now()
            return self.state_store.update_manifest(
                plan.transaction_id,
                state="PENDING_BOOT_TEST",
                enrolled_at=enrolled_at,
                boot_id_at_enroll=_read_boot_id(),
            )
        except KeyboardInterrupt as exc:
            interruption = EnrollmentInterrupted("interrupted during final enrollment verification")
            self._mark_failure(plan.transaction_id, "FAILED_VERIFICATION", interruption)
            raise interruption from exc
        except Exception as exc:
            self._mark_failure(plan.transaction_id, "FAILED_VERIFICATION", exc)
            raise EnrollmentError(f"final enrollment verification failed: {exc}") from exc

    def _validate_recovery_access(self, snapshot: SystemSnapshot) -> None:
        minimum = self.policy.luks.minimum_recovery_slots if self.policy.luks.require_recovery_slot else 0
        for volume in snapshot.volumes:
            if len(volume.recovery_keyslots) < minimum:
                raise EnrollmentError(
                    f"{volume.name} has {len(volume.recovery_keyslots)} passphrase/recovery keyslot(s), "
                    f"but policy requires at least {minimum}"
                )

    def _validate_header_backup_configuration(self) -> Path | None:
        if not self.policy.audit.header_backup:
            return None
        configured = self.policy.audit.header_backup_dir
        if not configured:
            raise EnrollmentError(
                "audit.header_backup is enabled but audit.header_backup_dir is not configured"
            )
        backup_dir = Path(configured)
        if not backup_dir.exists() or not backup_dir.is_dir():
            raise EnrollmentError(f"header backup directory does not exist: {backup_dir}")
        if backup_dir.is_symlink():
            raise EnrollmentError(f"refusing symlinked header backup directory: {backup_dir}")
        state_root = self.state_store.root.resolve()
        backup_resolved = backup_dir.resolve()
        if backup_resolved == state_root or backup_resolved.is_relative_to(state_root):
            raise EnrollmentError("header backup directory must be outside the runtime state directory")
        if not os.access(backup_dir, os.W_OK | os.X_OK):
            raise EnrollmentError(f"header backup directory is not writable: {backup_dir}")
        return backup_dir

    def _validate_automatic_policy_inputs(self) -> None:
        present = [str(path) for path in self.auto_public_key_paths if path.exists()]
        if present:
            joined = ", ".join(present)
            raise EnrollmentError(
                "systemd automatic TPM signed-policy public key detected; this tool does not yet "
                f"manage signed PCR policies: {joined}"
            )

    def _capture_event_log(self, transaction_id: str) -> None:
        try:
            data = self.event_log_path.read_bytes()
        except OSError as exc:
            raise EnrollmentError(f"cannot read TPM event log {self.event_log_path}: {exc}") from exc
        if not data:
            raise EnrollmentError(f"TPM event log is empty: {self.event_log_path}")
        self.state_store.write_evidence_bytes(transaction_id, "tpm-eventlog-before.bin", data)

    def _backup_headers(self, plan: EnrollmentPlan, manifest: dict[str, Any]) -> dict[str, Any]:
        assert plan.header_backup_dir is not None
        backup_dir = Path(plan.header_backup_dir)
        for volume in self.policy.volumes:
            manifest = self.state_store.load_manifest(plan.transaction_id)
            recorded = manifest["volumes"][volume.name].get("header_backup")
            if recorded:
                backup_path = Path(recorded)
                if not backup_path.exists():
                    raise EnrollmentError(
                        f"recorded LUKS header backup is missing: {backup_path}"
                    )
                continue
            backup_path = backup_dir / f"{plan.transaction_id}-{volume.uuid}.luks-header"
            if backup_path.exists():
                raise EnrollmentError(f"refusing to overwrite existing header backup: {backup_path}")
            self.runner.run(
                [
                    "cryptsetup",
                    "luksHeaderBackup",
                    "--header-backup-file",
                    str(backup_path),
                    str(volume.device_path),
                ],
                timeout=60,
            )
            if not backup_path.exists():
                raise EnrollmentError(f"cryptsetup did not create expected header backup: {backup_path}")
            os.chmod(backup_path, 0o600)
            manifest["volumes"][volume.name]["header_backup"] = str(backup_path)
            self.state_store.write_manifest(plan.transaction_id, manifest)
        return manifest

    def _enrollment_command(self, volume: VolumePolicy, pcr_values: dict[int, str]) -> list[str]:
        pcr_expression = "+".join(
            f"{pcr}:{self.policy.tpm.bank}={pcr_values[pcr]}" for pcr in self.policy.tpm.pcrs
        )
        return [
            "systemd-cryptenroll",
            f"--tpm2-device={self.policy.tpm.device}",
            f"--tpm2-pcrs={pcr_expression}",
            "--tpm2-pcrlock=",
            "--tpm2-with-pin=no",
            str(volume.device_path),
        ]

    def _verify_enrollment(
        self,
        before: VolumeMetadata,
        after: VolumeMetadata,
    ) -> tuple[str, TPMToken | None, int | None]:
        before_slots = set(before.keyslots)
        after_slots = set(after.keyslots)
        if not before_slots.issubset(after_slots):
            raise EnrollmentError("an existing keyslot disappeared during enrollment")

        before_tokens = {token.token_id for token in before.tpm_tokens}
        after_tokens = {token.token_id: token for token in after.tpm_tokens}
        if not before_tokens.issubset(after_tokens):
            raise EnrollmentError("an existing TPM token disappeared during enrollment")

        added_token_ids = sorted(set(after_tokens) - before_tokens)
        added_slots = sorted(after_slots - before_slots)

        if not added_token_ids and not added_slots:
            if after.keyslots != before.keyslots or after.tpm_tokens != before.tpm_tokens:
                raise EnrollmentError("enrollment returned success but TPM metadata changed unexpectedly")
            if not any(
                token.bank == self.policy.tpm.bank
                and tuple(sorted(token.pcrs)) == self.policy.tpm.pcrs
                for token in after.tpm_tokens
            ):
                raise EnrollmentError(
                    "enrollment returned success without metadata changes, but no matching TPM token exists"
                )
            self._validate_recovery_after(before, after)
            return "ALREADY_PRESENT", None, None

        if len(added_token_ids) != 1:
            raise EnrollmentError(f"expected exactly one new TPM token, found {len(added_token_ids)}")
        new_token = after_tokens[added_token_ids[0]]
        if new_token.bank != self.policy.tpm.bank:
            raise EnrollmentError(
                f"new TPM token uses PCR bank {new_token.bank!r}, expected {self.policy.tpm.bank!r}"
            )
        if tuple(sorted(new_token.pcrs)) != self.policy.tpm.pcrs:
            raise EnrollmentError(
                f"new TPM token PCRs {new_token.pcrs!r} do not match policy {self.policy.tpm.pcrs!r}"
            )

        if len(added_slots) != 1:
            raise EnrollmentError(f"expected exactly one new keyslot, found {len(added_slots)}")
        new_keyslot = added_slots[0]
        if new_token.keyslots != (new_keyslot,):
            raise EnrollmentError(
                f"new TPM token references keyslots {new_token.keyslots!r}, expected ({new_keyslot},)"
            )

        self._validate_recovery_after(before, after)
        return "ADDED", new_token, new_keyslot

    def _validate_recovery_after(
        self,
        before: VolumeMetadata,
        after: VolumeMetadata,
    ) -> None:
        if self.policy.luks.preserve_non_tpm_slots:
            if not set(before.recovery_keyslots).issubset(after.recovery_keyslots):
                raise EnrollmentError("a passphrase/recovery keyslot disappeared during enrollment")
        minimum = self.policy.luks.minimum_recovery_slots if self.policy.luks.require_recovery_slot else 0
        if len(after.recovery_keyslots) < minimum:
            raise EnrollmentError("recovery keyslot policy is no longer satisfied after enrollment")

    def _mark_failure(
        self,
        transaction_id: str,
        state: str,
        exc: BaseException,
        *,
        failed_volume: str | None = None,
    ) -> None:
        updates: dict[str, Any] = {
            "state": state,
            "failed_at": _now(),
            "error": str(exc),
        }
        if failed_volume is not None:
            updates["failed_volume"] = failed_volume
        try:
            self.state_store.update_manifest(transaction_id, **updates)
        except StateError:
            pass
