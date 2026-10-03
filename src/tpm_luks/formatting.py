from __future__ import annotations

import json
from typing import Any

from .cleanup import CleanupPlan
from .models import SystemSnapshot
from .transaction import EnrollmentPlan


def _short(value: str | None) -> str:
    return "-" if value is None else f"{value[:12]}..."


def format_status(snapshot: SystemSnapshot) -> str:
    secure_boot = {True: "enabled", False: "disabled", None: "unknown"}[snapshot.secure_boot]
    pending = (
        f"{snapshot.pending_transaction_id} ({snapshot.pending_transaction_state})"
        if snapshot.pending_transaction_id
        else "none"
    )
    lines = [
        f"Policy:      {snapshot.policy.policy_name}",
        f"TPM device:  {snapshot.policy.tpm.device}",
        f"PCR bank:    {snapshot.policy.tpm.bank}",
        f"PCRs:        {','.join(map(str, snapshot.policy.tpm.pcrs))}",
        f"Secure Boot: {secure_boot}",
        f"State:       {snapshot.drift_state.value}",
        f"Pending tx:  {pending}",
        "",
        "PCR  APPROVED         STATUS   CURRENT",
    ]
    for item in snapshot.pcr_comparisons:
        if item.matches is True:
            status = "MATCH"
        elif item.matches is False:
            status = "CHANGED"
        else:
            status = "-"
        lines.append(f"{item.pcr:<4} {_short(item.approved):<16} {status:<8} {item.current}")

    for volume in snapshot.volumes:
        lines.extend(["", f"Volume: {volume.name}", f"  UUID: {volume.uuid}", f"  Device: {volume.device}"])
        lines.append("  Keyslots: " + (", ".join(map(str, volume.keyslots)) or "none"))
        lines.append(
            "  Passphrase/recovery keyslots: "
            + (", ".join(map(str, volume.recovery_keyslots)) or "none")
        )
        if not volume.tpm_tokens:
            lines.append("  TPM tokens: none")
        else:
            lines.append("  TPM tokens:")
            for token in volume.tpm_tokens:
                pcrs = "+".join(map(str, token.pcrs)) or "none"
                bank = token.bank or "unspecified"
                slots = ",".join(map(str, token.keyslots)) or "none"
                policy_hash = (
                    ",".join(_short(value) for value in token.policy_hashes)
                    if token.policy_hashes
                    else "unknown"
                )
                lines.append(
                    f"    token {token.token_id}: keyslot={slots} bank={bank} "
                    f"pcrs={pcrs} policy={policy_hash}"
                )
    return "\n".join(lines)


def format_enrollment_plan(plan: EnrollmentPlan) -> str:
    snapshot = plan.snapshot
    lines = [
        f"Transaction: {plan.transaction_id}",
        f"Type:        {plan.transaction_type}",
        f"Policy:      {snapshot.policy.policy_name}",
        f"PCR policy:  {snapshot.policy.tpm.bank}:{'+'.join(map(str, snapshot.policy.tpm.pcrs))}",
        "",
        "PCR  APPROVED         CURRENT",
    ]
    for item in snapshot.pcr_comparisons:
        lines.append(f"{item.pcr:<4} {_short(item.approved):<16} {item.current}")

    lines.append("")
    lines.append("Volumes:")
    for volume in snapshot.volumes:
        recovery = ",".join(map(str, volume.recovery_keyslots)) or "none"
        tokens = ", ".join(
            f"token {token.token_id}->keyslot {','.join(map(str, token.keyslots))}"
            for token in volume.tpm_tokens
        ) or "none"
        lines.append(f"  {volume.name}: recovery/passphrase keyslots={recovery}; TPM={tokens}")
    if plan.header_backup_dir:
        lines.append(f"Header backups: {plan.header_backup_dir}")
    else:
        lines.append("Header backups: disabled")
    lines.extend(
        [
            "",
            "The operation only ADDS new TPM enrollments.",
            "No existing keyslot or token will be removed in Phase 2.",
        ]
    )
    return "\n".join(lines)


def format_cleanup_plan(plan: CleanupPlan) -> str:
    lines = [
        f"Transaction: {plan.transaction_id}",
        f"State:       {plan.previous_state}",
        f"Boot check:  {plan.boot_verification}",
        "Target TPM policy hash:",
    ]
    for value in plan.target_policy_hashes:
        lines.append(f"  {value}")

    if plan.boot_verification == "LEGACY_OPERATOR_ATTESTATION":
        lines.extend(
            [
                "",
                "WARNING: this transaction predates boot-ID recording.",
                "Your confirmation is the evidence that reboot and TPM unlock succeeded.",
            ]
        )

    lines.extend(["", "Cleanup targets:"])
    if not plan.targets:
        lines.append("  none")
    else:
        for target in plan.targets:
            lines.append(
                f"  {target.volume_name}: token {target.token_id}, keyslot {target.keyslot}"
            )

    if plan.header_backup_dir:
        lines.append(f"Pre-cleanup header backups: {plan.header_backup_dir}")
    else:
        lines.append("Pre-cleanup header backups: disabled")

    lines.extend(
        [
            "",
            "DESTRUCTIVE: listed keyslots will be wiped before their LUKS2 tokens are removed.",
            "Tokens carrying the verified target TPM policy are preserved.",
        ]
    )
    return "\n".join(lines)


def snapshot_to_dict(snapshot: SystemSnapshot) -> dict[str, Any]:
    return {
        "policy_name": snapshot.policy.policy_name,
        "drift_state": snapshot.drift_state.value,
        "secure_boot": snapshot.secure_boot,
        "pending_transaction": (
            {
                "id": snapshot.pending_transaction_id,
                "state": snapshot.pending_transaction_state,
            }
            if snapshot.pending_transaction_id
            else None
        ),
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
                "token_bound_keyslots": list(volume.token_bound_keyslots),
                "recovery_keyslots": list(volume.recovery_keyslots),
                "tpm_tokens": [
                    {
                        "token_id": token.token_id,
                        "keyslots": list(token.keyslots),
                        "bank": token.bank,
                        "pcrs": list(token.pcrs),
                        "policy_hashes": list(token.policy_hashes),
                    }
                    for token in volume.tpm_tokens
                ],
            }
            for volume in snapshot.volumes
        ],
    }


def format_check_json(snapshot: SystemSnapshot) -> str:
    return json.dumps(snapshot_to_dict(snapshot), indent=2, sort_keys=True)
