from __future__ import annotations

import json
from typing import Any

from .models import TPMToken, VolumeMetadata, VolumePolicy
from .runner import Runner


class LUKSMetadataError(RuntimeError):
    pass


class LUKSMetadataReader:
    def __init__(self, runner: Runner):
        self.runner = runner

    def read_document(self, volume: VolumePolicy) -> tuple[dict[str, Any], VolumeMetadata]:
        device = str(volume.device_path)
        result = self.runner.run(["cryptsetup", "luksDump", "--dump-json-metadata", device])
        try:
            metadata = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise LUKSMetadataError(f"invalid LUKS2 JSON metadata for {volume.name}: {exc}") from exc
        if not isinstance(metadata, dict):
            raise LUKSMetadataError(f"LUKS2 JSON metadata for {volume.name} is not an object")
        return metadata, parse_luks_metadata(volume, device, metadata)

    def read(self, volume: VolumePolicy) -> VolumeMetadata:
        return self.read_document(volume)[1]


def _numeric_ids(mapping: Any, field: str) -> tuple[int, ...]:
    if not isinstance(mapping, dict):
        raise LUKSMetadataError(f"LUKS2 metadata field '{field}' must be an object")
    result: list[int] = []
    for raw_id in mapping:
        try:
            result.append(int(raw_id))
        except (TypeError, ValueError) as exc:
            raise LUKSMetadataError(f"invalid {field} identifier: {raw_id!r}") from exc
    return tuple(sorted(result))


def _token_keyslots(token_id: str, token: dict[str, Any]) -> tuple[int, ...]:
    raw_keyslots = token.get("keyslots", [])
    if not isinstance(raw_keyslots, list):
        raise LUKSMetadataError(f"token {token_id} has invalid keyslots field")
    try:
        return tuple(sorted(int(item) for item in raw_keyslots))
    except (TypeError, ValueError) as exc:
        raise LUKSMetadataError(f"token {token_id} has a non-numeric keyslot") from exc


def _policy_hashes(token_id: int, token: dict[str, Any]) -> tuple[str, ...]:
    raw = token.get("tpm2-policy-hash")
    if raw is None:
        return ()
    values = [raw] if isinstance(raw, str) else raw
    if not isinstance(values, list) or not values or any(not isinstance(item, str) for item in values):
        raise LUKSMetadataError(f"TPM token {token_id} has invalid tpm2-policy-hash field")
    normalized: list[str] = []
    for item in values:
        if not item or len(item) % 2:
            raise LUKSMetadataError(f"TPM token {token_id} has invalid tpm2-policy-hash field")
        try:
            bytes.fromhex(item)
        except ValueError as exc:
            raise LUKSMetadataError(
                f"TPM token {token_id} has invalid tpm2-policy-hash field"
            ) from exc
        normalized.append(item.lower())
    return tuple(normalized)


def parse_luks_metadata(volume: VolumePolicy, device: str, metadata: dict[str, Any]) -> VolumeMetadata:
    if not isinstance(metadata, dict):
        raise LUKSMetadataError("LUKS2 metadata root must be an object")

    keyslots_raw = metadata.get("keyslots", {})
    tokens_raw = metadata.get("tokens", {})
    keyslots = _numeric_ids(keyslots_raw, "keyslots")
    if not isinstance(tokens_raw, dict):
        raise LUKSMetadataError("LUKS2 metadata field 'tokens' must be an object")

    tpm_tokens: list[TPMToken] = []
    tpm_keyslots: set[int] = set()
    all_token_keyslots: set[int] = set()
    for raw_token_id, token in tokens_raw.items():
        if not isinstance(token, dict):
            raise LUKSMetadataError(f"token {raw_token_id} must be an object")
        token_keyslots = _token_keyslots(str(raw_token_id), token)
        all_token_keyslots.update(token_keyslots)
        if token.get("type") != "systemd-tpm2":
            continue
        try:
            token_id = int(raw_token_id)
        except (TypeError, ValueError) as exc:
            raise LUKSMetadataError(f"invalid token identifier: {raw_token_id!r}") from exc

        raw_pcrs = token.get("tpm2-pcrs", [])
        if not isinstance(raw_pcrs, list) or any(type(item) is not int for item in raw_pcrs):
            raise LUKSMetadataError(f"TPM token {token_id} has invalid tpm2-pcrs field")
        bank = token.get("tpm2-pcr-bank")
        if bank is not None and not isinstance(bank, str):
            raise LUKSMetadataError(f"TPM token {token_id} has invalid tpm2-pcr-bank field")

        tpm_keyslots.update(token_keyslots)
        tpm_tokens.append(
            TPMToken(
                token_id=token_id,
                keyslots=token_keyslots,
                pcrs=tuple(sorted(raw_pcrs)),
                bank=bank,
                policy_hashes=_policy_hashes(token_id, token),
            )
        )

    return VolumeMetadata(
        name=volume.name,
        uuid=volume.uuid,
        device=device,
        keyslots=keyslots,
        tpm_tokens=tuple(sorted(tpm_tokens, key=lambda token: token.token_id)),
        non_tpm_keyslots=tuple(slot for slot in keyslots if slot not in tpm_keyslots),
        token_bound_keyslots=tuple(sorted(all_token_keyslots)),
        recovery_keyslots=tuple(slot for slot in keyslots if slot not in all_token_keyslots),
    )
