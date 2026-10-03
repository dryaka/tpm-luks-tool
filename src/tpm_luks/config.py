from __future__ import annotations

import tomllib
import uuid as uuidlib
from pathlib import Path
from typing import Any

from .models import AuditPolicy, LUKSPolicy, Policy, TPMPolicy, VolumePolicy


class PolicyError(ValueError):
    pass


def _expect_table(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise PolicyError(f"{key} must be a TOML table")
    return value


def _reject_unknown(table: dict[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise PolicyError(f"unknown {context} option(s): {', '.join(unknown)}")


def _expect_bool(table: dict[str, Any], key: str, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise PolicyError(f"{key} must be a boolean")
    return value


def load_policy(path: str | Path) -> Policy:
    policy_path = Path(path)
    try:
        with policy_path.open("rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError as exc:
        raise PolicyError(f"policy file not found: {policy_path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"invalid TOML in {policy_path}: {exc}") from exc

    _reject_unknown(data, {"policy_name", "tpm", "volume", "luks", "audit"}, "top-level")

    policy_name = data.get("policy_name")
    if not isinstance(policy_name, str) or not policy_name.strip():
        raise PolicyError("policy_name must be a non-empty string")

    tpm_data = _expect_table(data, "tpm")
    _reject_unknown(tpm_data, {"device", "bank", "pcrs"}, "tpm")
    device = tpm_data.get("device", "auto")
    bank = tpm_data.get("bank", "sha256")
    pcrs = tpm_data.get("pcrs")
    if not isinstance(device, str) or not device:
        raise PolicyError("tpm.device must be a non-empty string")
    if device != "auto":
        raise PolicyError("Phase 1 supports only tpm.device = 'auto'")
    if bank != "sha256":
        raise PolicyError("Phase 1 supports only tpm.bank = 'sha256'")
    if not isinstance(pcrs, list) or not pcrs:
        raise PolicyError("tpm.pcrs must be a non-empty array")
    if any(type(pcr) is not int or not 0 <= pcr <= 23 for pcr in pcrs):
        raise PolicyError("tpm.pcrs entries must be integers in range 0..23")
    if len(set(pcrs)) != len(pcrs):
        raise PolicyError("tpm.pcrs must not contain duplicates")

    volume_data = data.get("volume")
    if not isinstance(volume_data, list) or not volume_data:
        raise PolicyError("at least one [[volume]] entry is required")

    volumes: list[VolumePolicy] = []
    names: set[str] = set()
    uuids: set[str] = set()
    for index, raw_volume in enumerate(volume_data):
        if not isinstance(raw_volume, dict):
            raise PolicyError(f"volume[{index}] must be a TOML table")
        _reject_unknown(raw_volume, {"name", "uuid"}, f"volume[{index}]")
        name = raw_volume.get("name")
        raw_uuid = raw_volume.get("uuid")
        if not isinstance(name, str) or not name.strip():
            raise PolicyError(f"volume[{index}].name must be a non-empty string")
        if not isinstance(raw_uuid, str):
            raise PolicyError(f"volume[{index}].uuid must be a string")
        try:
            normalized_uuid = str(uuidlib.UUID(raw_uuid))
        except ValueError as exc:
            raise PolicyError(f"volume[{index}].uuid is not a valid UUID") from exc
        if name in names:
            raise PolicyError(f"duplicate volume name: {name}")
        if normalized_uuid in uuids:
            raise PolicyError(f"duplicate volume UUID: {normalized_uuid}")
        names.add(name)
        uuids.add(normalized_uuid)
        volumes.append(VolumePolicy(name=name, uuid=normalized_uuid))

    luks_data = data.get("luks", {})
    if not isinstance(luks_data, dict):
        raise PolicyError("luks must be a TOML table")
    _reject_unknown(
        luks_data,
        {"preserve_non_tpm_slots", "require_recovery_slot", "minimum_recovery_slots"},
        "luks",
    )
    preserve_non_tpm_slots = _expect_bool(luks_data, "preserve_non_tpm_slots", True)
    require_recovery_slot = _expect_bool(luks_data, "require_recovery_slot", True)
    minimum_recovery_slots = luks_data.get("minimum_recovery_slots", 1)
    if type(minimum_recovery_slots) is not int or minimum_recovery_slots < 0:
        raise PolicyError("luks.minimum_recovery_slots must be a non-negative integer")
    if require_recovery_slot and minimum_recovery_slots < 1:
        raise PolicyError("luks.minimum_recovery_slots must be at least 1 when recovery is required")

    audit_data = data.get("audit", {})
    if not isinstance(audit_data, dict):
        raise PolicyError("audit must be a TOML table")
    _reject_unknown(audit_data, {"event_log", "luks_dump", "header_backup", "journal"}, "audit")

    return Policy(
        policy_name=policy_name.strip(),
        tpm=TPMPolicy(device=device, bank=bank, pcrs=tuple(sorted(pcrs))),
        volumes=tuple(volumes),
        luks=LUKSPolicy(
            preserve_non_tpm_slots=preserve_non_tpm_slots,
            require_recovery_slot=require_recovery_slot,
            minimum_recovery_slots=minimum_recovery_slots,
        ),
        audit=AuditPolicy(
            event_log=_expect_bool(audit_data, "event_log", True),
            luks_dump=_expect_bool(audit_data, "luks_dump", True),
            header_backup=_expect_bool(audit_data, "header_backup", True),
            journal=_expect_bool(audit_data, "journal", True),
        ),
    )
