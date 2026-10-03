# tpm-luks-tool

A small, policy-driven Linux administration tool for managing TPM2-bound LUKS2 unlock across one or more encrypted volumes.

The tool is intended to:

- detect PCR drift against an approved policy,
- explain what changed in the measured boot state,
- safely enroll replacement TPM-backed LUKS2 keyslots,
- preserve non-TPM recovery access,
- verify a new enrollment before removing obsolete TPM keyslots and tokens,
- maintain a durable audit trail for every re-enrollment event.

Configuration is explicit and local using TOML. Runtime state and transaction history are kept separately from configuration.

## Design principles

- **Safe by default** — add and verify before removing.
- **Operator visible** — show policy, drift, affected volumes, keyslots, tokens, and planned changes.
- **Transactional** — treat re-enrollment as a multi-step change with explicit states.
- **Recovery preserving** — never remove configured non-TPM recovery access.
- **Auditable** — record measurements, LUKS metadata snapshots, decisions, and results.
- **Small scope** — manage PCR-bound systemd TPM2 enrollment rather than becoming a general TPM policy engine.

## Current implementation

Phase 1 implements the read-only model:

- strict TOML policy loading and validation,
- PCR reads through `systemd-analyze pcrs`,
- Secure Boot state read from the EFI variable filesystem when available,
- LUKS2 JSON metadata reads through `cryptsetup luksDump --dump-json-metadata`,
- TPM token/keyslot association inspection,
- comparison with stored approved PCR state,
- human-readable `status`,
- machine-readable JSON `check`,
- read-only `history` and `show` views for future transaction manifests.

Phase 1 currently supports the SHA-256 PCR bank and automatic TPM device selection. PCR selection itself is policy-driven and may contain one or more PCR indices.

A fresh installation has no approved state yet and therefore reports `UNINITIALIZED`. Phase 1 intentionally does not provide an operation that silently accepts the current PCR state; approved state will be created or updated by the explicit enrollment workflow in Phase 2.

## Installation

Python 3.11 or newer is required. There are no Python runtime dependencies outside the standard library.

```bash
python3 -m pip install .
```

Copy and edit the example policy:

```bash
sudo cp examples/tpm-luks.toml /etc/tpm-luks.toml
```

Read-only inspection normally needs sufficient privileges to read the configured block devices:

```bash
sudo tpm-luks status
sudo tpm-luks check
```

## CLI

Implemented:

```text
tpm-luks status
tpm-luks check
tpm-luks history
tpm-luks show <transaction-id>
```

Planned:

```text
tpm-luks reenroll
tpm-luks cleanup
```

`check` emits JSON and uses these exit codes:

| Code | Meaning |
| ---: | --- |
| 0 | Current PCR policy matches approved state |
| 1 | Configuration, command, metadata, or runtime error |
| 2 | PCR drift |
| 3 | No approved state exists |
| 4 | Configured policy differs from stored approved policy |

## Development

Run the test suite without installing the package:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

See [docs/architecture.md](docs/architecture.md) for the architecture and safety model.
