from __future__ import annotations

from .luks import LUKSMetadataReader
from .models import DriftState, PCRComparison, Policy, SystemSnapshot
from .pcr import PCRReader, read_secure_boot
from .state import StateStore


def collect_snapshot(
    policy: Policy,
    pcr_reader: PCRReader,
    luks_reader: LUKSMetadataReader,
    state_store: StateStore,
) -> SystemSnapshot:
    current = pcr_reader.read(policy.tpm.pcrs, policy.tpm.bank)
    approved = state_store.load_approved_state()

    comparisons: list[PCRComparison] = []
    if approved is None:
        drift_state = DriftState.UNINITIALIZED
        for pcr in policy.tpm.pcrs:
            comparisons.append(PCRComparison(pcr, None, current[pcr], None))
    elif (
        approved.policy_name != policy.policy_name
        or approved.bank != policy.tpm.bank
        or approved.pcrs != policy.tpm.pcrs
    ):
        drift_state = DriftState.POLICY_CHANGE
        for pcr in policy.tpm.pcrs:
            old_value = approved.values.get(pcr)
            comparisons.append(
                PCRComparison(pcr, old_value, current[pcr], old_value == current[pcr] if old_value else None)
            )
    else:
        drift_state = DriftState.MATCH
        for pcr in policy.tpm.pcrs:
            old_value = approved.values[pcr]
            matches = old_value == current[pcr]
            if not matches:
                drift_state = DriftState.DRIFT
            comparisons.append(PCRComparison(pcr, old_value, current[pcr], matches))

    volumes = tuple(luks_reader.read(volume) for volume in policy.volumes)
    return SystemSnapshot(
        policy=policy,
        current_pcrs=current,
        approved_state=approved,
        drift_state=drift_state,
        pcr_comparisons=tuple(comparisons),
        volumes=volumes,
        secure_boot=read_secure_boot(),
    )
