from __future__ import annotations

import json
from typing import Any

from .models import SystemSnapshot


def _short(value: str | None) -> str:
    return "-" if value is None else f"{value[:12]}..."


def format_status(snapshot: SystemSnapshot) -> str:
    secure_boot = {True: "enabled", False: "disabled", None: "unknown"}[snapshot.secure_boot]
    lines = [
        f"Policy:      {snapshot.policy.policy_name}",
        f"TPM device:  {snapshot.policy.tpm.device}",
        f"PCR bank:    {snapshot.policy.tpm.bank}",
        f"PCRs:        {','.join(map(str, snapshot.policy.tpm.pcrs))}",
        f"Secure Boot: {secure_boot}",
        f"State:       {snapshot.drift_state.value}",
        "",
        "PCR  APPROVED         CURRENT          STATUS",
    ]
    for item in snapshot.pcr_comparisons:
        if item.matches is True:
            status = "MATCH"
        elif item.matches is False:
            status = "CHANGED"
        else:
            status = "-"
        lines.append(f"{item.pcr:<4} {_short(item.approved):<16} {_short(item.current):<16} {status}")

    for volume in snapshot.volumes:
        lines.extend(["", f"Volume: {volume.name}", f"  UUID: {volume.uuid}", f"  Device: {volume.device}"])
        lines.append("  Keyslots: " + (", ".join(map(str, volume.keyslots)) or "none"))
        lines.append("  Non-TPM keyslots: " + (", ".join(map(str, volume.non_tpm_keyslots)) or "none"))
        if not volume.tpm_tokens:
            lines.append("  TPM tokens: none")
        else:
            lines.append("  TPM tokens:")
            for token in volume.tpm_tokens:
                pcrs = "+".join(map(str, token.pcrs)) or "none"
                bank = token.bank or "unspecified"
                slots = ",".join(map(str, token.keyslots)) or "none"
                lines.append(f"    token {token.token_id}: keyslot={slots} bank={bank} pcrs={pcrs}")
    return "\n".join(lines)


def snapshot_to_dict(snapshot: SystemSnapshot) -> dict[str, Any]:
    return {
        "policy_name": snapshot.policy.policy_name,
        "drift_state": snapshot.drift_state.value,
        "secure_boot": snapshot.secure_boot,
        "tpm": {
            "device": snapshot.policy.tpm.device,
            "bank": snapshot.policy.tpm.bank,
            "pcrs": list(snapshot.policy.tpm.pcrs),
        },
        "pcrs": [
            {
                "pcr": item.pcr,
                "approved": item.approved,
                "current": item.current,
                "matches": item.matches,
            }
            for item in snapshot.pcr_comparisons
        ],
        "volumes": [
            {
                "name": volume.name,
                "uuid": volume.uuid,
                "device": volume.device,
                "keyslots": list(volume.keyslots),
                "non_tpm_keyslots": list(volume.non_tpm_keyslots),
                "tpm_tokens": [
                    {
                        "token_id": token.token_id,
                        "keyslots": list(token.keyslots),
                        "bank": token.bank,
                        "pcrs": list(token.pcrs),
                    }
                    for token in volume.tpm_tokens
                ],
            }
            for volume in snapshot.volumes
        ],
    }


def format_check_json(snapshot: SystemSnapshot) -> str:
    return json.dumps(snapshot_to_dict(snapshot), indent=2, sort_keys=True)
