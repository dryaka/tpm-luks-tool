from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class DriftState(StrEnum):
    MATCH = "MATCH"
    DRIFT = "DRIFT"
    POLICY_CHANGE = "POLICY_CHANGE"
    UNINITIALIZED = "UNINITIALIZED"


@dataclass(frozen=True)
class TPMPolicy:
    device: str
    bank: str
    pcrs: tuple[int, ...]


@dataclass(frozen=True)
class VolumePolicy:
    name: str
    uuid: str

    @property
    def device_path(self) -> Path:
        return Path("/dev/disk/by-uuid") / self.uuid


@dataclass(frozen=True)
class LUKSPolicy:
    preserve_non_tpm_slots: bool = True
    require_recovery_slot: bool = True
    minimum_recovery_slots: int = 1


@dataclass(frozen=True)
class AuditPolicy:
    event_log: bool = True
    luks_dump: bool = True
    header_backup: bool = True
    header_backup_dir: str | None = None
    journal: bool = True


@dataclass(frozen=True)
class Policy:
    policy_name: str
    tpm: TPMPolicy
    volumes: tuple[VolumePolicy, ...]
    luks: LUKSPolicy
    audit: AuditPolicy


@dataclass(frozen=True)
class PCRState:
    policy_name: str
    bank: str
    pcrs: tuple[int, ...]
    values: dict[int, str]


# Compatibility name for manifests/tests produced by versions <= 0.3.
ApprovedState = PCRState


@dataclass(frozen=True)
class TPMToken:
    token_id: int
    keyslots: tuple[int, ...]
    pcrs: tuple[int, ...]
    bank: str | None
    policy_hashes: tuple[str, ...] = ()


@dataclass(frozen=True)
class VolumeMetadata:
    name: str
    uuid: str
    device: str
    keyslots: tuple[int, ...]
    tpm_tokens: tuple[TPMToken, ...]
    non_tpm_keyslots: tuple[int, ...]
    token_bound_keyslots: tuple[int, ...] = ()
    recovery_keyslots: tuple[int, ...] = ()


@dataclass(frozen=True)
class PCRComparison:
    pcr: int
    operational: str | None
    desired: str | None
    current: str
    matches_operational: bool | None
    matches_desired: bool | None


@dataclass(frozen=True)
class SystemSnapshot:
    policy: Policy
    current_pcrs: dict[int, str]
    operational_state: PCRState | None
    desired_state: PCRState | None
    drift_state: DriftState
    pcr_comparisons: tuple[PCRComparison, ...]
    volumes: tuple[VolumeMetadata, ...]
    secure_boot: bool | None
    pending_transaction_id: str | None = None
    pending_transaction_state: str | None = None
