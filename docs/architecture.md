# tpm-luks-tool architecture

## 1. Purpose

`tpm-luks-tool` is a small Linux administration utility for managing TPM2-bound LUKS2 unlock across one or more encrypted volumes.

Its primary use case is a system where LUKS2 volumes are unlocked automatically by a TPM2 policy bound to selected Platform Configuration Registers (PCRs). When the measured boot state changes, the tool detects drift, explains it to the operator, and manages safe re-enrollment of replacement TPM-backed LUKS keyslots.

The tool is deliberately conservative. It automates evidence collection, validation, enrollment, verification, and bookkeeping, while keeping trust approval and destructive cleanup under explicit operator control.

## 2. Scope

### In scope

- Configurable TPM2 PCR policy:
  - PCR bank, initially SHA-256.
  - One or more PCR indices.
- One or more LUKS2 volumes.
- Detection of PCR drift.
- Comparison of the current measured state with the last approved state.
- TPM event-log capture and PCR-focused drift explanation.
- TPM2 enrollment through `systemd-cryptenroll`.
- Preservation of existing non-TPM recovery keyslots.
- Verification of newly created TPM tokens and keyslots.
- Deferred cleanup of obsolete TPM keyslots and LUKS2 tokens.
- Durable transaction and audit history.
- Passive boot-time drift checking through an optional systemd oneshot service.

### Out of scope for the initial design

The first version is not intended to be a general TPM policy engine. In particular, the initial scope does not attempt to manage:

- arbitrary TPM policy expressions,
- signed PCR policies,
- `systemd-pcrlock` policy construction,
- TPM NV policy state,
- TPM PIN workflows,
- remote attestation,
- automatic destructive cleanup,
- automatic trust approval after PCR drift.

These can be considered later if a concrete operational need appears.

## 3. Design principles

### 3.1 Add before remove

A new TPM enrollment is always created before an old enrollment is removed.

At no point during re-enrollment should the tool intentionally reduce the configured recovery options.

### 3.2 Recovery access is invariant

The configured minimum number of non-TPM recovery keyslots must remain available throughout the transaction.

The tool must refuse destructive operations if the recovery-access policy would be violated.

### 3.3 Cleanup is deferred

A successful `reenroll` operation creates new TPM-backed keyslots and tokens but does not immediately remove the old enrollment.

Cleanup is a separate operation after a successful boot with the new TPM policy.

### 3.4 Operator-visible changes

Before modifying a LUKS header, the tool must show:

- active TPM policy,
- current and approved PCR values,
- affected volumes,
- current TPM tokens and associated keyslots,
- recovery keyslots,
- proposed additions,
- any later cleanup candidates.

### 3.5 Durable evidence

Each re-enrollment event is stored as a transaction containing enough evidence to reconstruct what changed and what the tool did.

Secrets, passphrases, raw LUKS keys, and TPM-unsealed key material must never be written to the audit history.

## 4. High-level architecture

```text
                    +----------------------+
                    |  /etc/tpm-luks.toml  |
                    |  operator policy     |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    |      tpm-luks CLI    |
                    |                      |
                    | status / check       |
                    | reenroll / cleanup   |
                    | history / show       |
                    +-----+----------+-----+
                          |          |
                +---------+          +----------------+
                v                                     v
       +-------------------+                +-------------------+
       | TPM / measured    |                | LUKS2 metadata    |
       | boot inspection   |                | inspection        |
       |                   |                |                   |
       | systemd-analyze   |                | cryptsetup        |
       | TPM event log     |                | JSON metadata     |
       +---------+---------+                +---------+---------+
                 |                                    |
                 +----------------+-------------------+
                                  |
                                  v
                       +----------------------+
                       | transaction engine   |
                       |                      |
                       | preflight            |
                       | evidence capture     |
                       | enroll               |
                       | verify               |
                       | pending boot test    |
                       | cleanup              |
                       +----------+-----------+
                                  |
                                  v
                       +----------------------+
                       | /var/lib/tpm-luks/   |
                       | state + history      |
                       +----------------------+
```

## 5. Configuration

The policy is administrator-controlled and stored in TOML.

Initial path:

```text
/etc/tpm-luks.toml
```

Example:

```toml
policy_name = "fedora-root"

[tpm]
device = "auto"
bank = "sha256"
pcrs = [7]

[[volume]]
name = "FEDORA-A"
uuid = "9f36aa12-4b29-4e3d-9b1a-2d4ce85f71a0"

[[volume]]
name = "FEDORA-B"
uuid = "3a80df27-6c14-49b7-a526-1f9de3b4c802"

[luks]
preserve_non_tpm_slots = true
require_recovery_slot = true
minimum_recovery_slots = 1

[audit]
event_log = true
luks_dump = true
header_backup = true
header_backup_dir = "/mnt/secure-backup/tpm-luks"
journal = true
```

The PCR list is policy, not application logic. A future move from PCR 7 to, for example, PCRs 7 and 11 should require only a configuration change and explicit policy migration transaction.

## 6. Runtime state

Runtime state is stored separately from policy configuration:

```text
/var/lib/tpm-luks/
├── state.json
├── history/
│   └── <transaction-id>/
│       ├── manifest.json
│       ├── pcrs-before.json
│       ├── pcrs-after.json
│       ├── tpm-eventlog-before.bin
│       ├── <volume>-before.json
│       ├── <volume>-after-enroll.json
│       ├── <volume>-after-cleanup.json
│       └── transaction.log
└── ...
```

LUKS header backups contain sensitive recovery metadata and must not be treated as ordinary audit files. If header backup is enabled, `audit.header_backup_dir` must be explicitly configured. Phase 2 requires this directory to exist and to be outside the runtime state directory.

For protection against a failed header modification, another independent filesystem on the same machine is sufficient. Off-machine or otherwise independent storage is stronger when protection against whole-disk or whole-machine loss is also required.

The sensitivity of a header backup does not come from the live LUKS header being inherently secret. A backup preserves historical keyslot and authentication state. Restoring an older header can therefore re-enable a keyslot or authentication method that was later removed or rotated, if the corresponding secret is still available. Old header backups must consequently have an explicit retention and disposal policy.

The repository must never contain runtime state, LUKS headers, TPM blobs captured from production systems, passwords, keys, or other private material.

## 7. Policy state

The approved state should record at least:

```json
{
  "policy_name": "fedora-root",
  "bank": "sha256",
  "pcrs": [7],
  "values": {
    "7": "<approved-PCR-value>"
  }
}
```

The tool must distinguish:

- **PCR drift** — configured PCR selection is unchanged, but one or more values differ.
- **Policy change** — PCR bank or selected PCR set changes.

A policy change always requires explicit re-enrollment.

In Phase 2, the operator's confirmed `reenroll` transaction is the trust-approval action. The approved PCR state is updated only after all configured volumes have received and passed verification of their new TPM enrollment and the selected PCR values are confirmed unchanged. The transaction then remains `PENDING_BOOT_TEST` until Phase 3 cleanup after a successful reboot.

## 8. CLI responsibilities

### `tpm-luks status`

Read-only human-oriented overview.

Shows:

- configured policy,
- current PCR values,
- approved PCR values,
- drift state,
- Secure Boot status where available,
- configured volumes,
- current TPM2 tokens,
- associated keyslots,
- detected recovery keyslots,
- pending transaction state.

### `tpm-luks check`

Read-only machine-friendly check.

Intended for boot-time or monitoring use.

Responsibilities:

1. Load policy.
2. Read current selected PCRs.
3. Compare with approved state.
4. Capture or summarize evidence when drift exists.
5. Log the result.
6. Never modify LUKS metadata.

### `tpm-luks reenroll`

Explicit privileged transaction.

Preconditions include:

- configured volumes are present and LUKS2,
- TPM2 is available,
- current PCR values can be read,
- recovery-access policy is satisfied,
- no conflicting incomplete transaction exists.

Workflow:

```text
preflight
   |
capture before-state evidence
   |
optional LUKS header backup
   |
show proposed policy and affected volumes
   |
operator confirmation
   |
enroll new TPM token/keyslot on each volume
   |
verify token metadata and keyslot associations
   |
capture after-enrollment evidence
   |
mark transaction PENDING_BOOT_TEST
```

Enrollment is performed using the configured policy and the exact PCR digests captured during preflight, conceptually:

```text
systemd-cryptenroll
  --tpm2-device=<configured-device>
  --tpm2-pcrs=<PCR>:<bank>=<captured-digest>[+...]
  --tpm2-pcrlock=
  --tpm2-with-pin=no
  <volume>
```

Binding to the captured digest avoids silently enrolling against a different PCR value if the measured state changes between preflight and enrollment. Automatic `pcrlock` discovery is disabled because it is outside the configured policy model. If systemd's automatic signed-PCR public-key file is present, Phase 2 refuses enrollment rather than silently adding signed-policy semantics that the tool does not yet manage.

The tool must not remove old TPM enrollments during this command. Enrollment is verified as additive: existing keyslots and TPM tokens must remain, exactly one new TPM token/keyslot pair must appear, and configured passphrase/recovery access must remain present.

### `tpm-luks cleanup`

Explicit privileged destructive step.

Preconditions include:

- a transaction is in `PENDING_BOOT_TEST`,
- the current PCR state matches the newly approved transaction state,
- the new TPM token/keyslot still exists on every configured volume,
- required recovery keyslots remain present.

The tool must show the exact obsolete keyslots and tokens that will be removed before confirmation.

Cleanup uses explicit keyslot and token identifiers discovered from LUKS2 JSON metadata. It must never assume fixed keyslot numbers.

After successful cleanup, the transaction becomes `COMPLETE`.

### `tpm-luks history`

Lists prior transactions with compact fields such as:

```text
DATE                 TYPE           POLICY        STATE
2026-09-10 22:41     PCR_DRIFT      sha256:7      COMPLETE
2027-03-14 09:12     POLICY_CHANGE  sha256:7+11   COMPLETE
```

### `tpm-luks show <transaction-id>`

Displays the detailed manifest and relevant captured evidence for one transaction.

## 9. LUKS metadata handling

LUKS2 JSON metadata should be the authoritative source for identifying TPM tokens and their keyslot associations.

The implementation should use:

```text
cryptsetup luksDump --dump-json-metadata
```

rather than scraping the human-formatted `luksDump` output.

The tool must identify tokens by type:

```json
{
  "type": "systemd-tpm2"
}
```

and resolve associated keyslots from the token metadata.

Keyslot and token identifiers are independent. Removing an obsolete TPM enrollment can therefore require both:

1. removal of the obsolete keyslot,
2. removal of the obsolete LUKS2 token.

## 10. PCR drift analysis

The minimum useful drift report identifies which configured PCRs changed.

Example:

```text
PCR   APPROVED       CURRENT        STATUS
7     7b88d175...    dc09b805...    CHANGED
```

For PCRs backed by meaningful event-log data, the tool should also provide a higher-level explanation.

For PCR 7, for example:

```text
SecureBoot   unchanged
PK           unchanged
KEK          changed
db           changed
dbx          changed
SbatLevel    unchanged
MokListRT    unchanged
```

The drift analyzer should remain PCR-aware rather than assume PCR 7 is always configured. Unsupported PCR-specific interpretation should fall back to reporting the raw changed measurements rather than inventing semantics.

## 11. Transaction state machine

Initial states:

```text
NONE
  |
  | reenroll
  v
PREPARING
  |
  | all new enrollments verified
  v
PENDING_BOOT_TEST
  |
  | operator invokes cleanup after successful boot
  v
CLEANING
  |
  | obsolete keyslots/tokens removed and verified
  v
COMPLETE
```

Failure states should preserve the evidence already collected:

```text
FAILED_PRECHECK
FAILED_ENROLLMENT
FAILED_VERIFICATION
FAILED_CLEANUP
CANCELLED
```

`CANCELLED` is used when the operator declines the plan after evidence capture but before any LUKS metadata change.

A partial enrollment across multiple volumes must never be silently treated as complete.

The operator must be able to inspect and resume or repair an incomplete transaction.

## 12. Multi-volume safety

Volumes configured under one policy form one logical management set.

For re-enrollment:

- all configured volumes are inspected before modification,
- each new TPM enrollment is recorded independently,
- failure on one volume stops further destructive progression,
- old TPM enrollments remain until all new enrollments have been verified,
- cleanup proceeds only against the exact obsolete objects recorded in the transaction.

The system should tolerate temporary coexistence of old and new TPM tokens.

## 13. Boot-time integration

An optional systemd oneshot service may call:

```text
tpm-luks check
```

after boot.

Its purpose is detection and visibility only.

It must not:

- enroll keys,
- delete keyslots,
- delete tokens,
- approve a changed PCR state.

A boot-time check is useful because firmware or Secure Boot database changes may only become represented in the TPM PCR state after reboot.

## 14. Logging and audit

Two complementary logging paths are useful:

### Journal

Operational messages can be emitted under a stable identifier, for example:

```text
tpm-luks
```

This allows:

```text
journalctl -t tpm-luks
```

### Transaction history

Each change transaction stores a structured manifest.

Example:

```json
{
  "id": "20261003T163104+0200",
  "type": "PCR_DRIFT",
  "policy": {
    "bank": "sha256",
    "pcrs": [7]
  },
  "old_values": {
    "7": "7b88d175..."
  },
  "new_values": {
    "7": "dc09b805..."
  },
  "volumes": {
    "FEDORA-A": {
      "old_token": 0,
      "old_keyslot": 1,
      "new_token": 1,
      "new_keyslot": 2
    }
  },
  "state": "PENDING_BOOT_TEST"
}
```

The manifest must contain metadata only, never passphrases or unsealed key material.

## 15. Implementation direction

Python is the preferred implementation language.

Reasons:

- TOML reading is available through `tomllib` in Python 3.11 and later.
- LUKS2 metadata can be handled as JSON rather than parsed from human-readable output.
- transaction state and validation are easier to express safely than in shell,
- subprocess invocation can remain narrow and explicit.

Expected external interfaces initially include:

- `systemd-analyze`
- `systemd-cryptenroll`
- `cryptsetup`
- `tpm2_eventlog` when event-log decoding is enabled
- systemd/journald interfaces for optional boot-time checking and logging

External command output must be treated as untrusted input and validated before use in destructive operations.

## 16. Security invariants

The implementation must maintain these invariants:

1. Never remove the last configured recovery keyslot.
2. Never delete an old TPM enrollment before a replacement has been successfully created and verified.
3. Never infer destructive keyslot/token identifiers from fixed numbering.
4. Never approve PCR drift automatically.
5. Never store passphrases, plaintext volume keys, or other secrets in logs or repository files.
6. Never mark a multi-volume transaction complete if only a subset of volumes succeeded.
7. Always show destructive cleanup targets before execution.
8. Record enough metadata to explain every change later.

## 17. Initial development phases

### Phase 1 — read-only model

- TOML policy loader.
- PCR reader.
- LUKS2 JSON metadata reader.
- `status`.
- `check`.
- state and history model.

### Phase 2 — safe enrollment

Implemented:

- transaction creation and private on-disk state,
- pre-change PCR, TPM event-log, and optional LUKS metadata evidence,
- passphrase/recovery keyslot validation,
- explicit LUKS header backup location and pre-change backups,
- operator confirmation,
- additive `reenroll`,
- exact captured-PCR binding,
- post-enrollment token/keyslot verification,
- approved-state update,
- `PENDING_BOOT_TEST` hand-off to Phase 3.

### Phase 3 — cleanup

- boot-test state handling,
- obsolete enrollment identification,
- explicit `cleanup`,
- final transaction verification.

### Phase 4 — drift explanation and integration

- TPM event-log parser integration,
- PCR-specific drift explanation,
- systemd oneshot unit,
- improved history/reporting.

## 18. Glossary

**LUKS2** — Linux Unified Key Setup version 2, the metadata and key-management format used for Linux disk encryption.

**TPM2** — Trusted Platform Module 2.0, a hardware or firmware security component capable of protecting secrets and evaluating platform state.

**PCR** — Platform Configuration Register, a TPM register extended with measurements representing parts of the boot or runtime state.

**PCR bank** — The hashing algorithm namespace used for a set of PCRs, for example SHA-256.

**TPM token** — LUKS2 metadata describing how a TPM-protected secret can unlock a LUKS keyslot.

**Keyslot** — A LUKS metadata object containing protected material capable of recovering the volume encryption key.

**Secure Boot** — UEFI mechanism that restricts executable boot components to those trusted by the configured signing policy.

**UKI** — Unified Kernel Image, an EFI executable bundling kernel and associated boot payloads for a more integrated boot and measurement model.
