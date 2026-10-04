# tpm-luks-tool

A small, policy-driven Linux administration tool for managing TPM2-bound LUKS2 unlock across one or more encrypted volumes.

The tool is intended to:

- detect PCR drift against the last operationally verified policy,
- explain what changed in the measured boot state,
- safely enroll replacement TPM-backed LUKS2 keyslots,
- preserve passphrase/recovery access,
- verify a new enrollment before removing obsolete TPM keyslots and tokens,
- maintain a durable audit trail for every re-enrollment event.

Configuration is explicit and local using TOML. Runtime state and transaction history are kept separately from configuration.

## Design principles

- **Safe by default** — add and verify before removing.
- **Operator visible** — show policy, drift, affected volumes, keyslots, tokens, and planned changes.
- **Transactional** — treat re-enrollment as a multi-step change with explicit states.
- **Recovery preserving** — never remove configured passphrase/recovery access.
- **Auditable** — record measurements, LUKS metadata snapshots, decisions, and results.
- **Small scope** — manage PCR-bound systemd TPM2 enrollment rather than becoming a general TPM policy engine.

## Current implementation

The implemented workflow separates three different concerns:

- **approval** — an explicit trust decision about the currently observed PCR values,
- **reenrollment** — idempotent reconciliation of configured LUKS2 volumes to an already trusted target,
- **cleanup** — destructive retirement of proven obsolete TPM enrollments only after reboot verification.

The runtime PCR state distinguishes:

- **operational** — the PCR target that completed enrollment, reboot verification, and cleanup,
- **desired** — a newly approved target that is still progressing through enrollment/boot verification.

Read-only functionality includes strict TOML validation, PCR reads through `systemd-analyze pcrs`, Secure Boot inspection, LUKS2 JSON metadata inspection, TPM token/keyslot associations, human-readable `status`, machine-readable `check`, and transaction `history`/`show`.

The mutating workflow provides:

- `approve` with no LUKS mutation,
- additive/idempotent `systemd-cryptenroll` reconciliation,
- exact PCR-value binding,
- recovery/passphrase keyslot validation,
- pre-enrollment and pre-cleanup LUKS header backups when configured,
- per-volume `ADDED` / `ALREADY_PRESENT` outcomes,
- boot-ID evidence,
- TPM policy-hash based cleanup targeting,
- resumable enrollment/cleanup failure states,
- final promotion of desired -> operational only when cleanup reaches `COMPLETE`.

The current implementation supports the SHA-256 PCR bank and automatic TPM device selection. PCR selection itself is policy-driven and may contain one or more PCR indices.

## Development installation

Python 3.11 or newer is required. There are no Python runtime dependencies outside the standard library.

For development:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Native RPM/DEB packaging is planned for normal administrator installation.

## Configuration

Start from:

```bash
cp examples/tpm-luks.toml ./test-policy.toml
```

When header backup is enabled, `audit.header_backup_dir` must point to an existing protected directory outside the runtime state directory. For transactional rollback, another independent filesystem on the same machine is acceptable. Off-machine or otherwise independent storage provides stronger protection against whole-disk or whole-machine loss.

The example deliberately uses a placeholder backup path:

```toml
[audit]
header_backup = true
header_backup_dir = "/mnt/secure-backup/tpm-luks"
```

Adjust it before running `reenroll`.

## CLI

Implemented:

```text
tpm-luks status
tpm-luks check
tpm-luks approve
tpm-luks reenroll
tpm-luks cleanup
tpm-luks history
tpm-luks show <transaction-id>
```

### Read-only inspection

```bash
sudo .venv/bin/tpm-luks status \
  --config ./test-policy.toml \
  --state-dir /tmp/tpm-luks-test-state
```

### Approve PCR drift

When the current PCR state differs from the operational baseline, approval is a separate trust decision:

```bash
sudo .venv/bin/tpm-luks approve \
  --config ./test-policy.toml \
  --state-dir ../tpm-luks-test-state
```

`approve` shows the operational and current PCR values and asks for confirmation. It records the current values as the **desired** target and creates an `APPROVED_PENDING_ENROLLMENT` transaction. It does **not** modify any LUKS keyslot or token.

If the current PCR values already match the operational baseline, there is nothing to approve.

### Reconcile LUKS enrollments

`reenroll` is a privileged reconciliation command:

```bash
sudo .venv/bin/tpm-luks reenroll \
  --config ./test-policy.toml \
  --state-dir ../tpm-luks-test-state
```

If a desired target exists, `reenroll` reconciles every configured volume to that target. If no desired target exists, it may reconcile to the existing operational target only when the current PCR values still match that operational baseline. Therefore PCR drift can never be trusted implicitly by `reenroll`.

The command:

1. selects the desired or operational target,
2. verifies current PCR values exactly match that already trusted target,
3. validates recovery/passphrase keyslots,
4. shows the target and affected volumes,
5. asks for confirmation,
6. backs up every configured LUKS header when enabled,
7. invokes `systemd-cryptenroll` for each volume,
8. records `ADDED` or `ALREADY_PRESENT` per volume,
9. verifies the resulting LUKS metadata and recovery access,
10. finishes as `PENDING_BOOT_TEST`.

`systemd-cryptenroll` may request an existing LUKS passphrase or recovery key for each volume. Existing keyslots/tokens are never removed by `reenroll`.

There is no `--force` trust override. If current PCRs differ from the operational baseline and no desired target exists, `reenroll` refuses and instructs the operator to run `approve`.

After successful enrollment, reboot and verify TPM unlock, then run:

```bash
sudo .venv/bin/tpm-luks cleanup \
  --config ./test-policy.toml \
  --state-dir ../tpm-luks-test-state
```

`cleanup` shows the exact token/keyslot pairs it proposes to remove. Confirmation attests that reboot and TPM unlock succeeded. For transactions that recorded an enrollment boot ID, the tool also refuses cleanup if the Linux boot ID has not changed.

Cleanup is resumable after a handled interruption or command failure. A failed cleanup remains active in `FAILED_CLEANUP`; rerunning `cleanup` reconciles the actual LUKS state with the recorded cleanup progress.

For a desired-target transaction, successful cleanup promotes **desired -> operational** and clears desired. For an operational reconciliation transaction, the operational baseline is unchanged.

Use `--yes` only when intentionally skipping an interactive confirmation. On `approve`, `--yes` is an explicit trust approval. On `cleanup`, it is also the operator attestation that reboot and TPM unlock succeeded.

## Runtime data

Default runtime location:

```text
/var/lib/tpm-luks/
├── state.json        # operational + optional desired PCR target
└── history/
    └── <transaction-id>/
        ├── manifest.json
        ├── pcrs-before.json
        ├── pcrs-after.json
        ├── tpm-eventlog-before.bin
        ├── volume-<uuid>-before.json
        ├── volume-<uuid>-after-enroll.json
        └── volume-<uuid>-after-cleanup.json
```

State/history directories are created with mode `0700`; generated files are mode `0600`.

Version 0.4 remains compatible with the flat `state.json` written by versions up to 0.3. If such a state belongs to an active legacy `PENDING_BOOT_TEST`/cleanup transaction, it is interpreted as the desired target and successful cleanup migrates it to the new operational/desired format. Otherwise the flat state is treated as the operational baseline.

Phase 2 creates a pre-enrollment header backup. Phase 3 creates a separate pre-cleanup header backup before deleting any obsolete keyslot, because the pre-enrollment backup does not contain the replacement TPM enrollment.

LUKS header backups are deliberately stored outside this runtime tree and are sensitive. The concern is not that the live LUKS header is normally secret; rather, an old backup preserves historical keyslot/authentication state. Restoring it can therefore make an authentication method that was later removed or rotated valid again, provided the corresponding secret is still known. Retain and dispose of old backups accordingly.

## Check exit codes

`check` emits JSON and uses:

| Code | Meaning |
| ---: | --- |
| 0 | Current PCR state matches the operational baseline |
| 1 | Configuration, command, metadata, or runtime error |
| 2 | PCR drift from the operational baseline |
| 3 | No operational baseline exists |
| 4 | Configured policy differs from the operational baseline |

## Development

Run the test suite without installing:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

See [docs/architecture.md](docs/architecture.md) for the architecture and safety model.
