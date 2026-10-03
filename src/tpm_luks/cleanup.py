from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .luks import LUKSMetadataReader
from .models import ApprovedState, Policy, TPMToken, VolumeMetadata, VolumePolicy
from .pcr import PCRReader
from .runner import CommandError, Runner
from .state import StateError, StateStore


class CleanupError(RuntimeError):
    pass


class CleanupInterrupted(CleanupError):
    pass


@dataclass(frozen=True)
class CleanupTarget:
    volume_name: str
    volume_uuid: str
    token_id: int
    keyslot: int
    policy_hashes: tuple[str, ...]


@dataclass(frozen=True)
class CleanupPlan:
    transaction_id: str
    previous_state: str
    target_policy_hashes: tuple[str, ...]
    targets: tuple[CleanupTarget, ...]
    boot_verification: str
    boot_id_at_enroll: str | None
    current_boot_id: str | None
    header_backup_dir: str | None


_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_boot_id(path: Path = _BOOT_ID_PATH) -> str | None:
    try:
        value = path.read_text(encoding="ascii").strip()
    except OSError:
        return None
    return value or None


def _token_by_id(volume: VolumeMetadata, token_id: int) -> TPMToken | None:
    for token in volume.tpm_tokens:
        if token.token_id == token_id:
            return token
    return None


def _token_basic(token: TPMToken) -> tuple[int, tuple[int, ...], tuple[int, ...], str | None]:
    return token.token_id, token.keyslots, token.pcrs, token.bank


def _recorded_token_basic(raw: dict[str, Any]) -> tuple[int, tuple[int, ...], tuple[int, ...], str | None]:
    try:
        token_id = int(raw["token_id"])
        keyslots = tuple(sorted(int(item) for item in raw.get("keyslots", [])))
        pcrs = tuple(sorted(int(item) for item in raw.get("pcrs", [])))
    except (KeyError, TypeError, ValueError) as exc:
        raise CleanupError("transaction contains invalid recorded TPM token metadata") from exc
    bank = raw.get("bank")
    if bank is not None and not isinstance(bank, str):
        raise CleanupError("transaction contains invalid recorded TPM token bank")
    return token_id, keyslots, pcrs, bank


class CleanupService:
    def __init__(
        self,
        policy: Policy,
        runner: Runner,
        pcr_reader: PCRReader,
        luks_reader: LUKSMetadataReader,
        state_store: StateStore,
        *,
        boot_id_path: Path = _BOOT_ID_PATH,
    ):
        self.policy = policy
        self.runner = runner
        self.pcr_reader = pcr_reader
        self.luks_reader = luks_reader
        self.state_store = state_store
        self.boot_id_path = boot_id_path

    def prepare(self) -> CleanupPlan:
        manifest = self.state_store.find_active_transaction()
        if manifest is None:
            raise CleanupError("no transaction is awaiting cleanup")
        state = str(manifest.get("state"))
        if state not in {"PENDING_BOOT_TEST", "FAILED_CLEANUP"}:
            raise CleanupError(
                f"transaction {manifest.get('id')} is {state}; cleanup requires PENDING_BOOT_TEST "
                "or FAILED_CLEANUP"
            )

        transaction_id = str(manifest.get("id"))
        self._validate_manifest_policy(manifest)
        expected_pcrs = self._expected_pcrs(manifest)
        current_pcrs = self.pcr_reader.read(self.policy.tpm.pcrs, self.policy.tpm.bank)
        if current_pcrs != expected_pcrs:
            raise CleanupError("current PCR values do not match the enrolled transaction state")
        self._validate_approved_state(expected_pcrs)

        boot_id_at_enroll = manifest.get("boot_id_at_enroll")
        if boot_id_at_enroll is not None and not isinstance(boot_id_at_enroll, str):
            raise CleanupError("transaction contains invalid boot_id_at_enroll")
        current_boot_id = _read_boot_id(self.boot_id_path)
        if boot_id_at_enroll and current_boot_id:
            if boot_id_at_enroll == current_boot_id:
                raise CleanupError(
                    "no reboot detected since enrollment; verify the new TPM unlock by rebooting before cleanup"
                )
            boot_verification = "REBOOT_DETECTED"
        else:
            boot_verification = "LEGACY_OPERATOR_ATTESTATION"

        current: dict[str, tuple[dict[str, Any], VolumeMetadata]] = {}
        for volume_policy in self.policy.volumes:
            current[volume_policy.name] = self.luks_reader.read_document(volume_policy)
        self._validate_recovery_access({name: item[1] for name, item in current.items()})

        raw_targets = manifest.get("cleanup_targets")
        raw_target_hashes = manifest.get("target_policy_hashes")
        if raw_targets is not None or raw_target_hashes is not None:
            target_policy_hashes = self._parse_target_policy_hashes(raw_target_hashes)
            targets = self._parse_cleanup_targets(raw_targets)
            self._validate_retry_metadata(manifest, current, targets, target_policy_hashes)
        else:
            self._validate_initial_metadata(manifest, current)
            target_policy_hashes = self._derive_target_policy_hashes(manifest, current)
            targets = self._identify_cleanup_targets(manifest, current, target_policy_hashes)
            self.state_store.update_manifest(
                transaction_id,
                target_policy_hashes=list(target_policy_hashes),
                cleanup_targets=self._serialize_targets(targets),
                cleanup_prepared_at=_now(),
                cleanup_boot_verification=boot_verification,
                cleanup_boot_id=current_boot_id,
            )

        return CleanupPlan(
            transaction_id=transaction_id,
            previous_state=state,
            target_policy_hashes=target_policy_hashes,
            targets=targets,
            boot_verification=boot_verification,
            boot_id_at_enroll=boot_id_at_enroll,
            current_boot_id=current_boot_id,
            header_backup_dir=self.policy.audit.header_backup_dir
            if self.policy.audit.header_backup
            else None,
        )

    def execute(self, plan: CleanupPlan) -> dict[str, Any]:
        manifest = self.state_store.load_manifest(plan.transaction_id)
        if manifest.get("state") not in {"PENDING_BOOT_TEST", "FAILED_CLEANUP"}:
            raise CleanupError(
                f"transaction {plan.transaction_id} is {manifest.get('state')}, "
                "expected PENDING_BOOT_TEST or FAILED_CLEANUP"
            )

        self.state_store.update_manifest(
            plan.transaction_id,
            state="CLEANING",
            cleanup_started_at=_now(),
            cleanup_boot_verification=plan.boot_verification,
            cleanup_boot_id=plan.current_boot_id,
        )

        try:
            if self.policy.audit.header_backup:
                self._backup_headers(plan)

            for target in plan.targets:
                try:
                    self._remove_target(plan.transaction_id, target)
                except KeyboardInterrupt as exc:
                    interruption = CleanupInterrupted(
                        f"cleanup interrupted for {target.volume_name} "
                        f"token {target.token_id}/keyslot {target.keyslot}"
                    )
                    self._mark_failure(plan.transaction_id, interruption, target)
                    raise interruption from exc
                except (CleanupError, CommandError, OSError) as exc:
                    self._mark_failure(plan.transaction_id, exc, target)
                    raise CleanupError(
                        f"cleanup failed for {target.volume_name} "
                        f"token {target.token_id}/keyslot {target.keyslot}: {exc}"
                    ) from exc

            self._verify_complete(plan)
            return self.state_store.update_manifest(
                plan.transaction_id,
                state="COMPLETE",
                completed_at=_now(),
                cleanup_boot_id=plan.current_boot_id,
            )
        except KeyboardInterrupt as exc:
            interruption = CleanupInterrupted("cleanup interrupted")
            self._mark_failure(plan.transaction_id, interruption, None)
            raise interruption from exc
        except CleanupInterrupted:
            raise
        except Exception as exc:
            current = self.state_store.load_manifest(plan.transaction_id)
            if current.get("state") != "FAILED_CLEANUP":
                self._mark_failure(plan.transaction_id, exc, None)
            if isinstance(exc, CleanupError):
                raise
            raise CleanupError(f"cleanup failed: {exc}") from exc

    def _validate_manifest_policy(self, manifest: dict[str, Any]) -> None:
        raw_policy = manifest.get("policy")
        if not isinstance(raw_policy, dict):
            raise CleanupError("transaction lacks policy metadata")
        if raw_policy.get("name") != self.policy.policy_name:
            raise CleanupError("configured policy name differs from the transaction")
        if raw_policy.get("bank") != self.policy.tpm.bank:
            raise CleanupError("configured PCR bank differs from the transaction")
        try:
            recorded_pcrs = tuple(sorted(int(item) for item in raw_policy.get("pcrs", [])))
        except (TypeError, ValueError) as exc:
            raise CleanupError("transaction contains invalid PCR policy") from exc
        if recorded_pcrs != self.policy.tpm.pcrs:
            raise CleanupError("configured PCR selection differs from the transaction")

        raw_volumes = manifest.get("volumes")
        if not isinstance(raw_volumes, dict):
            raise CleanupError("transaction lacks volume metadata")
        expected_names = {volume.name for volume in self.policy.volumes}
        if set(raw_volumes) != expected_names:
            raise CleanupError("configured volume set differs from the transaction")
        for volume in self.policy.volumes:
            entry = raw_volumes.get(volume.name)
            if not isinstance(entry, dict) or entry.get("uuid") != volume.uuid:
                raise CleanupError(f"configured volume {volume.name} differs from the transaction")

    def _expected_pcrs(self, manifest: dict[str, Any]) -> dict[int, str]:
        raw_values = manifest.get("new_values")
        if not isinstance(raw_values, dict):
            raise CleanupError("transaction lacks enrolled PCR values")
        values: dict[int, str] = {}
        for pcr in self.policy.tpm.pcrs:
            value = raw_values.get(str(pcr))
            if not isinstance(value, str):
                raise CleanupError(f"transaction lacks enrolled value for PCR {pcr}")
            values[pcr] = value.lower()
        return values

    def _validate_approved_state(self, expected_pcrs: dict[int, str]) -> None:
        approved = self.state_store.load_approved_state()
        if approved is None:
            raise CleanupError("approved state is missing")
        expected = ApprovedState(
            policy_name=self.policy.policy_name,
            bank=self.policy.tpm.bank,
            pcrs=self.policy.tpm.pcrs,
            values=expected_pcrs,
        )
        if approved != expected:
            raise CleanupError("approved state no longer matches the transaction")

    def _validate_recovery_access(self, volumes: dict[str, VolumeMetadata]) -> None:
        minimum = self.policy.luks.minimum_recovery_slots if self.policy.luks.require_recovery_slot else 0
        for name, volume in volumes.items():
            if len(volume.recovery_keyslots) < minimum:
                raise CleanupError(
                    f"{name} has {len(volume.recovery_keyslots)} passphrase/recovery keyslot(s), "
                    f"but policy requires at least {minimum}"
                )

    def _validate_initial_metadata(
        self,
        manifest: dict[str, Any],
        current: dict[str, tuple[dict[str, Any], VolumeMetadata]],
    ) -> None:
        for volume_policy in self.policy.volumes:
            entry = manifest["volumes"][volume_policy.name]
            recorded = entry.get("after_enroll")
            if not isinstance(recorded, dict):
                raise CleanupError(
                    f"transaction lacks post-enrollment metadata for {volume_policy.name}"
                )
            metadata = current[volume_policy.name][1]
            self._require_matches_recorded(metadata, recorded, volume_policy.name)

    def _require_matches_recorded(
        self,
        current: VolumeMetadata,
        recorded: dict[str, Any],
        volume_name: str,
    ) -> None:
        try:
            recorded_keyslots = tuple(sorted(int(item) for item in recorded.get("keyslots", [])))
            recorded_tokens_raw = recorded.get("tpm_tokens", [])
            if not isinstance(recorded_tokens_raw, list):
                raise TypeError
            recorded_tokens = sorted(_recorded_token_basic(item) for item in recorded_tokens_raw)
        except (TypeError, ValueError) as exc:
            raise CleanupError(
                f"transaction contains invalid post-enrollment metadata for {volume_name}"
            ) from exc
        current_tokens = sorted(_token_basic(token) for token in current.tpm_tokens)
        if current.keyslots != recorded_keyslots or current_tokens != recorded_tokens:
            raise CleanupError(
                f"LUKS metadata for {volume_name} changed since enrollment; refusing cleanup"
            )

    def _derive_target_policy_hashes(
        self,
        manifest: dict[str, Any],
        current: dict[str, tuple[dict[str, Any], VolumeMetadata]],
    ) -> tuple[str, ...]:
        identities: set[tuple[str, ...]] = set()
        for volume_policy in self.policy.volumes:
            entry = manifest["volumes"][volume_policy.name]
            if entry.get("enrollment_result") != "ADDED":
                continue
            raw_token = entry.get("new_token")
            raw_keyslot = entry.get("new_keyslot")
            if type(raw_token) is not int or type(raw_keyslot) is not int:
                raise CleanupError(
                    f"transaction lacks replacement token/keyslot for {volume_policy.name}"
                )
            token = _token_by_id(current[volume_policy.name][1], raw_token)
            if token is None or token.keyslots != (raw_keyslot,):
                raise CleanupError(
                    f"replacement TPM token/keyslot for {volume_policy.name} is missing"
                )
            if not token.policy_hashes:
                raise CleanupError(
                    f"replacement TPM token {raw_token} on {volume_policy.name} lacks policy hash"
                )
            identities.add(token.policy_hashes)

        if identities:
            if len(identities) != 1:
                raise CleanupError("replacement TPM policy hashes differ across volumes")
            target = next(iter(identities))
        else:
            common: set[tuple[str, ...]] | None = None
            for volume_policy in self.policy.volumes:
                candidates = {
                    token.policy_hashes
                    for token in current[volume_policy.name][1].tpm_tokens
                    if token.bank == self.policy.tpm.bank
                    and tuple(sorted(token.pcrs)) == self.policy.tpm.pcrs
                    and token.policy_hashes
                }
                common = candidates if common is None else common & candidates
            if not common or len(common) != 1:
                raise CleanupError(
                    "cannot uniquely identify the target TPM policy from already-present enrollments"
                )
            target = next(iter(common))

        for volume_policy in self.policy.volumes:
            if not any(
                token.policy_hashes == target
                and token.bank == self.policy.tpm.bank
                and tuple(sorted(token.pcrs)) == self.policy.tpm.pcrs
                for token in current[volume_policy.name][1].tpm_tokens
            ):
                raise CleanupError(
                    f"{volume_policy.name} does not contain the verified target TPM policy"
                )
        return target

    def _identify_cleanup_targets(
        self,
        manifest: dict[str, Any],
        current: dict[str, tuple[dict[str, Any], VolumeMetadata]],
        target_policy_hashes: tuple[str, ...],
    ) -> tuple[CleanupTarget, ...]:
        targets: list[CleanupTarget] = []
        for volume_policy in self.policy.volumes:
            entry = manifest["volumes"][volume_policy.name]
            before = entry.get("before")
            if not isinstance(before, dict):
                raise CleanupError(f"transaction lacks before-state metadata for {volume_policy.name}")
            raw_tokens = before.get("tpm_tokens", [])
            if not isinstance(raw_tokens, list):
                raise CleanupError(
                    f"transaction contains invalid before-state metadata for {volume_policy.name}"
                )
            document, metadata = current[volume_policy.name]
            for raw_token in raw_tokens:
                token_id = _recorded_token_basic(raw_token)[0]
                token = _token_by_id(metadata, token_id)
                if token is None:
                    raise CleanupError(
                        f"pre-existing TPM token {token_id} disappeared from {volume_policy.name}"
                    )
                if not token.policy_hashes:
                    raise CleanupError(
                        f"TPM token {token_id} on {volume_policy.name} lacks policy hash; "
                        "cannot prove it is obsolete"
                    )
                if token.policy_hashes == target_policy_hashes:
                    continue
                if len(token.keyslots) != 1:
                    raise CleanupError(
                        f"TPM token {token_id} on {volume_policy.name} references "
                        f"{len(token.keyslots)} keyslots; refusing cleanup"
                    )
                keyslot = token.keyslots[0]
                if keyslot not in metadata.keyslots:
                    raise CleanupError(
                        f"TPM token {token_id} on {volume_policy.name} references missing keyslot {keyslot}"
                    )
                users = self._token_users(document, keyslot)
                if users != {token_id}:
                    raise CleanupError(
                        f"keyslot {keyslot} on {volume_policy.name} is shared by tokens "
                        f"{sorted(users)}; refusing cleanup"
                    )
                targets.append(
                    CleanupTarget(
                        volume_name=volume_policy.name,
                        volume_uuid=volume_policy.uuid,
                        token_id=token_id,
                        keyslot=keyslot,
                        policy_hashes=token.policy_hashes,
                    )
                )
        return tuple(targets)

    def _validate_retry_metadata(
        self,
        manifest: dict[str, Any],
        current: dict[str, tuple[dict[str, Any], VolumeMetadata]],
        targets: tuple[CleanupTarget, ...],
        target_policy_hashes: tuple[str, ...],
    ) -> None:
        targets_by_volume: dict[str, list[CleanupTarget]] = {}
        for target in targets:
            targets_by_volume.setdefault(target.volume_name, []).append(target)

        for volume_policy in self.policy.volumes:
            entry = manifest["volumes"][volume_policy.name]
            recorded = entry.get("after_enroll")
            if not isinstance(recorded, dict):
                raise CleanupError(
                    f"transaction lacks post-enrollment metadata for {volume_policy.name}"
                )
            document, metadata = current[volume_policy.name]
            volume_targets = targets_by_volume.get(volume_policy.name, [])
            target_ids = {target.token_id for target in volume_targets}
            target_slots = {target.keyslot for target in volume_targets}

            try:
                recorded_keyslots = {int(item) for item in recorded.get("keyslots", [])}
                recorded_tokens_raw = recorded.get("tpm_tokens", [])
                if not isinstance(recorded_tokens_raw, list):
                    raise TypeError
                recorded_tokens = {
                    _recorded_token_basic(item)[0]: _recorded_token_basic(item)
                    for item in recorded_tokens_raw
                }
            except (TypeError, ValueError) as exc:
                raise CleanupError(
                    f"transaction contains invalid post-enrollment metadata for {volume_policy.name}"
                ) from exc

            current_keyslots = set(metadata.keyslots)
            if not current_keyslots.issubset(recorded_keyslots):
                raise CleanupError(
                    f"unexpected keyslot appeared on {volume_policy.name}; refusing cleanup resume"
                )
            missing_keyslots = recorded_keyslots - current_keyslots
            if not missing_keyslots.issubset(target_slots):
                raise CleanupError(
                    f"non-target keyslot disappeared from {volume_policy.name}; refusing cleanup resume"
                )

            current_tokens = {token.token_id: token for token in metadata.tpm_tokens}
            if not set(current_tokens).issubset(recorded_tokens):
                raise CleanupError(
                    f"unexpected TPM token appeared on {volume_policy.name}; refusing cleanup resume"
                )
            missing_tokens = set(recorded_tokens) - set(current_tokens)
            if not missing_tokens.issubset(target_ids):
                raise CleanupError(
                    f"non-target TPM token disappeared from {volume_policy.name}; refusing cleanup resume"
                )
            for token_id, token in current_tokens.items():
                if _token_basic(token) != recorded_tokens[token_id]:
                    raise CleanupError(
                        f"TPM token {token_id} changed on {volume_policy.name}; refusing cleanup resume"
                    )

            if not any(
                token.policy_hashes == target_policy_hashes
                and token.bank == self.policy.tpm.bank
                and tuple(sorted(token.pcrs)) == self.policy.tpm.pcrs
                for token in metadata.tpm_tokens
            ):
                raise CleanupError(
                    f"{volume_policy.name} no longer contains the verified target TPM policy"
                )

            for target in volume_targets:
                token = current_tokens.get(target.token_id)
                if token is not None:
                    if token.policy_hashes != target.policy_hashes:
                        raise CleanupError(
                            f"cleanup target token {target.token_id} changed on {volume_policy.name}"
                        )
                    users = self._token_users(document, target.keyslot)
                    if users - {target.token_id}:
                        raise CleanupError(
                            f"cleanup target keyslot {target.keyslot} on {volume_policy.name} "
                            "became shared; refusing cleanup resume"
                        )

        self._validate_recovery_access({name: item[1] for name, item in current.items()})

    def _backup_headers(self, plan: CleanupPlan) -> None:
        configured = self.policy.audit.header_backup_dir
        if not configured:
            raise CleanupError(
                "audit.header_backup is enabled but audit.header_backup_dir is not configured"
            )
        backup_dir = Path(configured)
        if not backup_dir.exists() or not backup_dir.is_dir() or backup_dir.is_symlink():
            raise CleanupError(f"invalid header backup directory: {backup_dir}")
        state_root = self.state_store.root.resolve()
        backup_resolved = backup_dir.resolve()
        if backup_resolved == state_root or backup_resolved.is_relative_to(state_root):
            raise CleanupError("header backup directory must be outside the runtime state directory")
        if not os.access(backup_dir, os.W_OK | os.X_OK):
            raise CleanupError(f"header backup directory is not writable: {backup_dir}")

        manifest = self.state_store.load_manifest(plan.transaction_id)
        for volume in self.policy.volumes:
            entry = manifest["volumes"][volume.name]
            recorded = entry.get("cleanup_header_backup")
            if recorded:
                path = Path(recorded)
                if not path.exists():
                    raise CleanupError(f"recorded pre-cleanup header backup is missing: {path}")
                continue
            backup_path = backup_dir / f"{plan.transaction_id}-{volume.uuid}-pre-cleanup.luks-header"
            if backup_path.exists():
                raise CleanupError(f"refusing to overwrite existing header backup: {backup_path}")
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
                raise CleanupError(f"cryptsetup did not create expected header backup: {backup_path}")
            os.chmod(backup_path, 0o600)
            manifest = self.state_store.load_manifest(plan.transaction_id)
            manifest["volumes"][volume.name]["cleanup_header_backup"] = str(backup_path)
            self.state_store.write_manifest(plan.transaction_id, manifest)

    def _remove_target(self, transaction_id: str, target: CleanupTarget) -> None:
        volume_policy = next(
            (volume for volume in self.policy.volumes if volume.name == target.volume_name),
            None,
        )
        if volume_policy is None:
            raise CleanupError(f"cleanup target references unknown volume {target.volume_name}")

        document, metadata = self.luks_reader.read_document(volume_policy)
        token = _token_by_id(metadata, target.token_id)
        if token is not None and (
            token.keyslots != (target.keyslot,) or token.policy_hashes != target.policy_hashes
        ):
            raise CleanupError(
                f"cleanup target token {target.token_id} changed on {target.volume_name}"
            )

        if target.keyslot in metadata.keyslots:
            self._validate_recovery_access({target.volume_name: metadata})
            users = self._token_users(document, target.keyslot)
            if users - {target.token_id}:
                raise CleanupError(
                    f"cleanup target keyslot {target.keyslot} on {target.volume_name} is shared"
                )
            self.runner.run(
                [
                    "cryptsetup",
                    "luksKillSlot",
                    "--batch-mode",
                    str(volume_policy.device_path),
                    str(target.keyslot),
                ],
                timeout=60,
            )
            _, after_slot = self.luks_reader.read_document(volume_policy)
            if target.keyslot in after_slot.keyslots:
                raise CleanupError(
                    f"keyslot {target.keyslot} still exists on {target.volume_name} after deletion"
                )
            self._set_target_state(transaction_id, target, "KEYSLOT_REMOVED")

        document, metadata = self.luks_reader.read_document(volume_policy)
        token = _token_by_id(metadata, target.token_id)
        if token is not None:
            if token.policy_hashes != target.policy_hashes:
                raise CleanupError(
                    f"cleanup target token {target.token_id} changed on {target.volume_name}"
                )
            self.runner.run(
                [
                    "cryptsetup",
                    "token",
                    "remove",
                    "--batch-mode",
                    "--token-id",
                    str(target.token_id),
                    str(volume_policy.device_path),
                ],
                timeout=60,
            )
            _, after_token = self.luks_reader.read_document(volume_policy)
            if _token_by_id(after_token, target.token_id) is not None:
                raise CleanupError(
                    f"token {target.token_id} still exists on {target.volume_name} after deletion"
                )

        self._set_target_state(transaction_id, target, "REMOVED")

    def _verify_complete(self, plan: CleanupPlan) -> None:
        expected_pcrs = self._expected_pcrs(self.state_store.load_manifest(plan.transaction_id))
        current_pcrs = self.pcr_reader.read(self.policy.tpm.pcrs, self.policy.tpm.bank)
        if current_pcrs != expected_pcrs:
            raise CleanupError("PCR values changed during cleanup")

        manifest = self.state_store.load_manifest(plan.transaction_id)
        targets_by_volume: dict[str, list[CleanupTarget]] = {}
        for target in plan.targets:
            targets_by_volume.setdefault(target.volume_name, []).append(target)

        current_volumes: dict[str, VolumeMetadata] = {}
        for volume_policy in self.policy.volumes:
            document, metadata = self.luks_reader.read_document(volume_policy)
            current_volumes[volume_policy.name] = metadata
            if not any(
                token.policy_hashes == plan.target_policy_hashes
                and token.bank == self.policy.tpm.bank
                and tuple(sorted(token.pcrs)) == self.policy.tpm.pcrs
                for token in metadata.tpm_tokens
            ):
                raise CleanupError(
                    f"{volume_policy.name} no longer contains the verified target TPM policy"
                )
            volume_targets = targets_by_volume.get(volume_policy.name, [])
            for target in volume_targets:
                if target.keyslot in metadata.keyslots:
                    raise CleanupError(
                        f"obsolete keyslot {target.keyslot} still exists on {volume_policy.name}"
                    )
                if _token_by_id(metadata, target.token_id) is not None:
                    raise CleanupError(
                        f"obsolete token {target.token_id} still exists on {volume_policy.name}"
                    )

            recorded = manifest["volumes"][volume_policy.name].get("after_enroll")
            if not isinstance(recorded, dict):
                raise CleanupError(
                    f"transaction lacks post-enrollment metadata for {volume_policy.name}"
                )
            try:
                expected_keyslots = {int(item) for item in recorded.get("keyslots", [])}
                expected_tokens_raw = recorded.get("tpm_tokens", [])
                if not isinstance(expected_tokens_raw, list):
                    raise TypeError
                expected_tokens = {
                    _recorded_token_basic(item)[0]: _recorded_token_basic(item)
                    for item in expected_tokens_raw
                }
            except (TypeError, ValueError) as exc:
                raise CleanupError(
                    f"transaction contains invalid post-enrollment metadata for {volume_policy.name}"
                ) from exc
            expected_keyslots -= {target.keyslot for target in volume_targets}
            for target in volume_targets:
                expected_tokens.pop(target.token_id, None)
            current_tokens = {token.token_id: _token_basic(token) for token in metadata.tpm_tokens}
            if set(metadata.keyslots) != expected_keyslots or current_tokens != expected_tokens:
                raise CleanupError(
                    f"unexpected LUKS metadata remains on {volume_policy.name} after cleanup"
                )

            if self.policy.audit.luks_dump:
                self.state_store.write_evidence_json(
                    plan.transaction_id,
                    f"volume-{volume_policy.uuid}-after-cleanup.json",
                    document,
                )

        self._validate_recovery_access(current_volumes)
        self._validate_approved_state(expected_pcrs)

        for volume_targets in manifest.get("cleanup_targets", {}).values():
            if not isinstance(volume_targets, list):
                raise CleanupError("transaction contains invalid cleanup target state")
            if any(item.get("state") != "REMOVED" for item in volume_targets):
                raise CleanupError("not all cleanup targets are recorded as removed")

    def _set_target_state(
        self,
        transaction_id: str,
        target: CleanupTarget,
        state: str,
    ) -> None:
        manifest = self.state_store.load_manifest(transaction_id)
        raw_targets = manifest.get("cleanup_targets")
        if not isinstance(raw_targets, dict):
            raise CleanupError("transaction lacks cleanup targets")
        volume_targets = raw_targets.get(target.volume_name)
        if not isinstance(volume_targets, list):
            raise CleanupError("transaction lacks volume cleanup targets")
        for item in volume_targets:
            if (
                item.get("token_id") == target.token_id
                and item.get("keyslot") == target.keyslot
            ):
                item["state"] = state
                item["updated_at"] = _now()
                self.state_store.write_manifest(transaction_id, manifest)
                return
        raise CleanupError("cleanup target disappeared from transaction manifest")

    def _mark_failure(
        self,
        transaction_id: str,
        exc: BaseException,
        target: CleanupTarget | None,
    ) -> None:
        updates: dict[str, Any] = {
            "state": "FAILED_CLEANUP",
            "cleanup_failed_at": _now(),
            "cleanup_error": str(exc),
        }
        if target is not None:
            updates["failed_volume"] = target.volume_name
            updates["failed_token"] = target.token_id
            updates["failed_keyslot"] = target.keyslot
        try:
            self.state_store.update_manifest(transaction_id, **updates)
        except StateError:
            pass

    @staticmethod
    def _token_users(document: dict[str, Any], keyslot: int) -> set[int]:
        raw_tokens = document.get("tokens", {})
        if not isinstance(raw_tokens, dict):
            raise CleanupError("LUKS metadata tokens field is not an object")
        users: set[int] = set()
        for raw_id, token in raw_tokens.items():
            if not isinstance(token, dict):
                raise CleanupError(f"LUKS token {raw_id} is not an object")
            raw_keyslots = token.get("keyslots", [])
            if not isinstance(raw_keyslots, list):
                raise CleanupError(f"LUKS token {raw_id} has invalid keyslots")
            try:
                keyslots = {int(item) for item in raw_keyslots}
                token_id = int(raw_id)
            except (TypeError, ValueError) as exc:
                raise CleanupError(f"LUKS token {raw_id} has invalid identifiers") from exc
            if keyslot in keyslots:
                users.add(token_id)
        return users

    @staticmethod
    def _parse_target_policy_hashes(raw: Any) -> tuple[str, ...]:
        if not isinstance(raw, list) or not raw or any(not isinstance(item, str) for item in raw):
            raise CleanupError("transaction contains invalid target_policy_hashes")
        return tuple(raw)

    @staticmethod
    def _parse_cleanup_targets(raw: Any) -> tuple[CleanupTarget, ...]:
        if not isinstance(raw, dict):
            raise CleanupError("transaction contains invalid cleanup_targets")
        targets: list[CleanupTarget] = []
        for volume_name, items in raw.items():
            if not isinstance(volume_name, str) or not isinstance(items, list):
                raise CleanupError("transaction contains invalid cleanup_targets")
            for item in items:
                if not isinstance(item, dict):
                    raise CleanupError("transaction contains invalid cleanup target")
                try:
                    volume_uuid = str(item["volume_uuid"])
                    token_id = int(item["token_id"])
                    keyslot = int(item["keyslot"])
                    policy_hashes = tuple(str(value) for value in item["policy_hashes"])
                except (KeyError, TypeError, ValueError) as exc:
                    raise CleanupError("transaction contains invalid cleanup target") from exc
                if not policy_hashes:
                    raise CleanupError("cleanup target lacks policy hash")
                targets.append(
                    CleanupTarget(
                        volume_name=volume_name,
                        volume_uuid=volume_uuid,
                        token_id=token_id,
                        keyslot=keyslot,
                        policy_hashes=policy_hashes,
                    )
                )
        return tuple(targets)

    @staticmethod
    def _serialize_targets(
        targets: tuple[CleanupTarget, ...],
    ) -> dict[str, list[dict[str, Any]]]:
        result: dict[str, list[dict[str, Any]]] = {}
        for target in targets:
            result.setdefault(target.volume_name, []).append(
                {
                    "volume_uuid": target.volume_uuid,
                    "token_id": target.token_id,
                    "keyslot": target.keyslot,
                    "policy_hashes": list(target.policy_hashes),
                    "state": "PENDING",
                }
            )
        return result
