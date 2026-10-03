# tpm-luks-tool

A small, policy-driven Linux administration tool for managing TPM2-bound LUKS2 unlock across one or more encrypted volumes.

The tool is intended to:

- detect PCR drift against an approved policy,
- explain what changed in the measured boot state,
- safely enroll replacement TPM-backed LUKS2 keyslots,
- preserve non-TPM recovery access,
- verify a new enrollment before removing obsolete TPM keyslots and tokens,
- maintain a durable audit trail for every re-enrollment event.

Configuration is explicit and local, with TOML planned for policy configuration. Runtime state and transaction history are kept separately from configuration.

## Design principles

- **Safe by default** — add and verify before removing.
- **Operator visible** — show policy, drift, affected volumes, keyslots, tokens, and planned changes.
- **Transactional** — treat re-enrollment as a multi-step change with explicit states.
- **Recovery preserving** — never remove configured non-TPM recovery access.
- **Auditable** — record measurements, LUKS metadata snapshots, decisions, and results.
- **Small scope** — manage PCR-bound systemd TPM2 enrollment rather than becoming a general TPM policy engine.

## Planned CLI

```text
tpm-luks status
tpm-luks check
tpm-luks reenroll
tpm-luks cleanup
tpm-luks history
tpm-luks show <transaction-id>
```

See [docs/architecture.md](docs/architecture.md) for the initial architecture.
