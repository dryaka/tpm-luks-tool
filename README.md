# tpm-luks-tool

A small, policy-driven Linux administration tool for managing TPM2-bound LUKS2 unlock across one or more encrypted volumes.

The tool is intended to:

- detect PCR drift against an approved policy,
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

Phase 1 provides the read-only model:

- strict TOML policy loading and validation,
- PCR reads through `systemd-analyze pcrs`,
- Secure Boot state read from the EFI variable filesystem when available,
- LUKS2 JSON metadata reads through `cryptsetup luksDump --dump-json-metadata`,
- TPM token/keyslot association inspection,
- comparison with stored approved PCR state,
- human-readable `status`,
- machine-readable JSON `check`,
- read-only `history` and `show`.

Phase 2 adds safe enrollment:

- transaction creation and durable manifests,
- pre-change PCR and LUKS metadata evidence,
- TPM event-log capture as the raw firmware event-log binary,
- recovery/passphrase keyslot validation,
- optional LUKS header backup before any enrollment,
- explicit operator confirmation,
- additive `systemd-cryptenroll` enrollment only,
- idempotent handling when the exact TPM policy is already enrolled,
- post-enrollment token/keyslot verification,
- exact PCR-value binding for the configured policy,
- approved-state update only after every configured volume verifies,
- final transaction state `PENDING_BOOT_TEST`.

Phase 2 never removes an existing LUKS keyslot or token.

Phase 3 adds explicit cleanup after a successful boot test:

- verifies the pending transaction, approved PCR state, and current PCR values,
- detects a reboot by boot ID for transactions created by version 0.3.0 and later,
- requires operator confirmation that reboot and TPM unlock succeeded,
- derives the exact target TPM policy hash from the replacement enrollment,
- refuses cleanup when obsolete enrollment identity cannot be proven,
- creates fresh pre-cleanup LUKS header backups when header backup is enabled,
- removes only recorded obsolete TPM keyslot/token pairs,
- supports retry after an interrupted or failed cleanup,
- captures post-cleanup LUKS metadata and marks the transaction `COMPLETE`.

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

### Safe re-enrollment

`reenroll` is a privileged, mutating command:

```bash
sudo .venv/bin/tpm-luks reenroll \
  --config ./test-policy.toml \
  --state-dir /var/lib/tpm-luks
```

The command:

1. validates policy and recovery/passphrase keyslots,
2. captures pre-change evidence,
3. shows the exact plan,
4. asks for confirmation,
5. backs up every configured LUKS header when enabled,
6. adds one new TPM enrollment per volume when the exact policy is not already present,
7. accepts systemd's successful exact-policy no-op as `ALREADY_PRESENT`,
8. verifies that no existing keyslot/token disappeared and recovery access remains,
9. records the approved PCR state,
10. finishes as `PENDING_BOOT_TEST`.

`systemd-cryptenroll` may request an existing LUKS passphrase or recovery key for each volume.

After success, reboot and verify TPM unlock, then run:

```bash
sudo .venv/bin/tpm-luks cleanup \
  --config ./test-policy.toml \
  --state-dir /var/lib/tpm-luks
```

`cleanup` shows the exact token/keyslot pairs it proposes to remove. Confirmation attests that the reboot and TPM unlock succeeded. For transactions created by version 0.3.0 and later, the tool additionally refuses cleanup if the Linux boot ID has not changed since enrollment. Older transactions do not contain that evidence and are therefore reported as requiring operator attestation.

Cleanup is resumable after a handled interruption or command failure. A failed cleanup remains an active transaction in `FAILED_CLEANUP`; rerunning `cleanup` reconciles current LUKS metadata with the recorded cleanup targets and continues only when the partial state is safe and explainable.

Use `--yes` only when you intentionally want to skip the interactive confirmation. For `cleanup`, `--yes` is also the operator attestation that the post-enrollment reboot and TPM unlock were successful. `reenroll --force` allows re-enrollment even when the current PCR state already matches the approved state.

## Runtime data

Default runtime location:

```text
/var/lib/tpm-luks/
├── state.json
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

Phase 2 creates a pre-enrollment header backup. Phase 3 creates a separate pre-cleanup header backup before deleting any obsolete keyslot, because the pre-enrollment backup does not contain the replacement TPM enrollment.

LUKS header backups are deliberately stored outside this runtime tree and are sensitive. The concern is not that the live LUKS header is normally secret; rather, an old backup preserves historical keyslot/authentication state. Restoring it can therefore make an authentication method that was later removed or rotated valid again, provided the corresponding secret is still known. Retain and dispose of old backups accordingly.

## Check exit codes

`check` emits JSON and uses:

| Code | Meaning |
| ---: | --- |
| 0 | Current PCR policy matches approved state |
| 1 | Configuration, command, metadata, or runtime error |
| 2 | PCR drift |
| 3 | No approved state exists |
| 4 | Configured policy differs from stored approved policy |

## Development

Run the test suite without installing:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

See [docs/architecture.md](docs/architecture.md) for the architecture and safety model.
