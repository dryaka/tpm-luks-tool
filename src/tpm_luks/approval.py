from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .luks import LUKSMetadataReader
from .models import DriftState, PCRState, Policy, SystemSnapshot, TPMToken, VolumeMetadata
from .pcr import PCRReader
from .service import collect_snapshot
from .state import StateError, StateStore


class ApprovalError(RuntimeError):
    pass


class ApprovalInterrupted(ApprovalError):
    pass


@dataclass(frozen=True)
class ApprovalPlan:
    transaction_type: str
    snapshot: SystemSnapshot


_DEFAULT_EVENT_LOG = Path("/sys/kernel/security/tpm0/binary_bios_measurements")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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


class ApprovalService:
    def __init__(
        self,
        policy: Policy,
        pcr_reader: PCRReader,
        luks_reader: LUKSMetadataReader,
        state_store: StateStore,
        *,
        event_log_path: Path = _DEFAULT_EVENT_LOG,
    ):
        self.policy = policy
        self.pcr_reader = pcr_reader
        self.luks_reader = luks_reader
        self.state_store = state_store
        self.event_log_path = event_log_path

    def prepare(self) -> ApprovalPlan:
        active = self.state_store.find_active_transaction()
        if active is not None:
            raise ApprovalError(
                f"transaction {active.get('id')} is already {active.get('state')}; "
                "finish or repair it before approving another PCR target"
            )
        operational, desired = self.state_store.load_policy_states()
        if desired is not None:
            raise ApprovalError(
                "a desired PCR target exists without an active transaction; manual repair is required"
            )

        snapshot = collect_snapshot(
            self.policy,
            self.pcr_reader,
            self.luks_reader,
            self.state_store,
        )
        if snapshot.drift_state == DriftState.MATCH:
            raise ApprovalError(
                "current PCR state already matches the operational baseline; nothing to approve"
            )

        transaction_type = {
            DriftState.UNINITIALIZED: "INITIAL_ENROLLMENT",
            DriftState.DRIFT: "PCR_DRIFT",
            DriftState.POLICY_CHANGE: "POLICY_CHANGE",
        }[snapshot.drift_state]
        return ApprovalPlan(transaction_type=transaction_type, snapshot=snapshot)

    def execute(self, plan: ApprovalPlan) -> dict[str, Any]:
        active = self.state_store.find_active_transaction()
        if active is not None:
            raise ApprovalError(
                f"transaction {active.get('id')} appeared before approval could be recorded"
            )

        current = self.pcr_reader.read(self.policy.tpm.pcrs, self.policy.tpm.bank)
        if current != plan.snapshot.current_pcrs:
            raise ApprovalError("PCR values changed while approval was awaiting confirmation")

        manifest = {
            "workflow_version": 2,
            "target_source": "desired",
            "type": plan.transaction_type,
            "state": "PREPARING_APPROVAL",
            "created_at": _now(),
            "policy": {
                "name": self.policy.policy_name,
                "device": self.policy.tpm.device,
                "bank": self.policy.tpm.bank,
                "pcrs": list(self.policy.tpm.pcrs),
            },
            "old_values": (
                {
                    str(pcr): value
                    for pcr, value in plan.snapshot.operational_state.values.items()
                }
                if plan.snapshot.operational_state
                else {}
            ),
            "new_values": {
                str(pcr): value for pcr, value in plan.snapshot.current_pcrs.items()
            },
            "secure_boot": plan.snapshot.secure_boot,
            "volumes": {
                volume.name: {
                    "uuid": volume.uuid,
                    "before": _volume_summary(volume),
                    "header_backup": None,
                    "enrollment_result": None,
                    "new_token": None,
                    "new_keyslot": None,
                }
                for volume in plan.snapshot.volumes
            },
        }
        transaction_id = self.state_store.create_transaction(manifest)

        try:
            self.state_store.write_evidence_json(
                transaction_id,
                "pcrs-approved.json",
                {str(pcr): value for pcr, value in plan.snapshot.current_pcrs.items()},
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

            approved_at = _now()
            desired = PCRState(
                policy_name=self.policy.policy_name,
                bank=self.policy.tpm.bank,
                pcrs=self.policy.tpm.pcrs,
                values=dict(plan.snapshot.current_pcrs),
            )
            self.state_store.write_desired_state(
                desired,
                transaction_id=transaction_id,
                approved_at=approved_at,
            )
            return self.state_store.update_manifest(
                transaction_id,
                state="APPROVED_PENDING_ENROLLMENT",
                approved_at=approved_at,
            )
        except KeyboardInterrupt as exc:
            interruption = ApprovalInterrupted("interrupted while recording PCR approval")
            self._mark_failure(transaction_id, interruption)
            raise interruption from exc
        except Exception as exc:
            self._mark_failure(transaction_id, exc)
            raise ApprovalError(f"PCR approval failed: {exc}") from exc

    def _capture_event_log(self, transaction_id: str) -> None:
        try:
            data = self.event_log_path.read_bytes()
        except OSError as exc:
            raise ApprovalError(
                f"cannot read TPM event log {self.event_log_path}: {exc}"
            ) from exc
        if not data:
            raise ApprovalError(f"TPM event log is empty: {self.event_log_path}")
        self.state_store.write_evidence_bytes(
            transaction_id,
            "tpm-eventlog-approved.bin",
            data,
        )

    def _mark_failure(self, transaction_id: str, exc: BaseException) -> None:
        try:
            self.state_store.update_manifest(
                transaction_id,
                state="FAILED_PRECHECK",
                failed_at=_now(),
                error=str(exc),
            )
        except StateError:
            pass
