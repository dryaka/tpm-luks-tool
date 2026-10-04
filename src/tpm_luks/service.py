from __future__ import annotations

from .luks import LUKSMetadataReader
from .models import DriftState, PCRComparison, PCRState, Policy, SystemSnapshot
from .pcr import PCRReader, read_secure_boot
from .state import StateStore


def state_matches_policy(state: PCRState, policy: Policy) -> bool:
    return (
        state.policy_name == policy.policy_name
        and state.bank == policy.tpm.bank
        and state.pcrs == policy.tpm.pcrs
    )


def collect_snapshot(
    policy: Policy,
    pcr_reader: PCRReader,
    luks_reader: LUKSMetadataReader,
    state_store: StateStore,
) -> SystemSnapshot:
    current = pcr_reader.read(policy.tpm.pcrs, policy.tpm.bank)
    operational, desired = state_store.load_policy_states()

    comparisons: list[PCRComparison] = []
    if operational is None:
        drift_state = DriftState.UNINITIALIZED
    elif not state_matches_policy(operational, policy):
        drift_state = DriftState.POLICY_CHANGE
    else:
        drift_state = DriftState.MATCH
        if any(operational.values[pcr] != current[pcr] for pcr in policy.tpm.pcrs):
            drift_state = DriftState.DRIFT

    desired_matches_policy = desired is not None and state_matches_policy(desired, policy)
    operational_matches_policy = (
        operational is not None and state_matches_policy(operational, policy)
    )

    for pcr in policy.tpm.pcrs:
        operational_value = (
            operational.values.get(pcr) if operational_matches_policy and operational else None
        )
        desired_value = desired.values.get(pcr) if desired_matches_policy and desired else None
        current_value = current[pcr]
        comparisons.append(
            PCRComparison(
                pcr=pcr,
                operational=operational_value,
                desired=desired_value,
                current=current_value,
                matches_operational=(
                    operational_value == current_value if operational_value is not None else None
                ),
                matches_desired=(
                    desired_value == current_value if desired_value is not None else None
                ),
            )
        )

    volumes = tuple(luks_reader.read(volume) for volume in policy.volumes)
    active = state_store.find_active_transaction()
    return SystemSnapshot(
        policy=policy,
        current_pcrs=current,
        operational_state=operational,
        desired_state=desired,
        drift_state=drift_state,
        pcr_comparisons=tuple(comparisons),
        volumes=volumes,
        secure_boot=read_secure_boot(),
        pending_transaction_id=str(active.get("id")) if active else None,
        pending_transaction_state=str(active.get("state")) if active else None,
    )
